#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Compiler-only cache controls; real cold/warm C compiles where ccache exists."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('wine_cache', ROOT / 'tools/wine_compile_cache.py')
cache = importlib.util.module_from_spec(spec); spec.loader.exec_module(cache)


class CacheFixture:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='wine-cache-control-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def state(self, phase='host', identity=None, ccache='/inert/ccache', compilers=None, suffix='', repo=None):
        repo = repo or ROOT
        compilers = compilers or {role: (Path('/inert') / name, 'gcc') for role, name in
            [('cc', 'clang'), ('cxx', 'clang++'), ('i386', 'i686-w64-mingw32-gcc'), ('x86_64', 'x86_64-w64-mingw32-gcc')]}
        identity = identity or {'phase': phase, 'compiler': 'synthetic-inputs'}
        identity = dict({'schema': cache.SCHEMA, **cache.source_selection(repo, phase),
                         'recipe': cache.recipe_inputs(repo)}, **identity)
        out = self.root / ('evidence' + suffix)
        state = cache.write_state(out, self.root / 'objects', identity, compilers, ccache,
                                  {'commit': 'a'*40, 'tree': 'b'*40}, repo=repo)
        return out, state


class CacheContracts(CacheFixture, unittest.TestCase):
    def test_project_receipt_changes_without_changing_compiler_key(self):
        one, a = self.state()
        b = cache.write_state(self.root / 'other', self.root / 'objects', json.loads((one/'compatibility.json').read_text()),
                             {}, '/inert/ccache', {'commit': 'c'*40, 'tree': 'd'*40}, repo=ROOT)
        self.assertEqual(a['key'], b['key'])
        self.assertNotEqual(a['project'], b['project'])
        self.assertEqual((one / 'compatibility.json').read_bytes(), (self.root / 'other/compatibility.json').read_bytes())

    def test_compiler_key_changes_for_recipe_provider_flags_and_mode(self):
        _, baseline = self.state(identity={'phase': 'host', 'patch': '1', 'provider': '2', 'flags': '-O2', 'mode': 0})
        for name, changed in [('patch', '9'), ('provider', '8'), ('flags', '-g'), ('mode', 1)]:
            identity = {'phase': 'host', 'patch': '1', 'provider': '2', 'flags': '-O2', 'mode': 0}
            identity[name] = changed
            _, state = self.state(identity=identity, suffix=name)
            self.assertNotEqual(baseline['key'], state['key'])

    def test_actual_recipe_and_provider_bytes_invalidate_compatibility(self):
        repo = self.root/'repo'; repo.mkdir()
        subprocess.run(['git','init','-q',str(repo)],check=True)
        files = {
            'tools/build_wine_ps5.sh':'WINE_COMMIT=' + 'a'*40 + '\n',
            'tools/build_host_wine.sh':'host recipe', 'tools/stage_vk_batch.py':'stage',
            'tools/generate_vk_codecs.py':'generate', 'tools/wine_compile_cache.py':'cache recipe',
            'tools/wine_focus_neutral.py':'focus recipe',
            'wine/patches/0001-test.patch':'patch', 'wine/ps5/staged.h':'staged header',
            '.github/workflows/windows-child-fixture.yml':'workflow'}
        for name, (path, macro) in cache.ABI_INPUTS.items():
            prefix = '+' if path.endswith('.patch') else ''
            value = 962 if name.endswith('protocol') else 1
            files[path] = files.get(path, '') + f'{prefix}#define {macro} {value}u\n'
        files[cache.ABI_INPUTS['server_protocol'][0]] = (ROOT/cache.ABI_INPUTS['server_protocol'][0]).read_text()
        files['wine/ps5/pw_wine_focus_neutral.h'] = (ROOT/'wine/ps5/pw_wine_focus_neutral.h').read_text()
        files['wine/ps5/pw_wine_creation.h'] = (ROOT/'wine/ps5/pw_wine_creation.h').read_text()
        for name, text in files.items():
            path=repo/name; path.parent.mkdir(parents=True,exist_ok=True); path.write_text(text)
        subprocess.run(['git','-C',str(repo),'add','.'],check=True)
        cc = self.root/'ccache'; cc.write_text('inert compiler-cache binary')
        compiler = self.root/'compiler'; compiler.write_text('inert selected backend')
        sdk=self.root/'sdk'; sdk.mkdir(); (sdk/'native.h').write_text('sdk header')
        tls=self.root/'tls'; tls.mkdir(); (tls/'lib.a').write_text('inert archive')
        real_command, real_tree = cache.command, cache.tree_record
        def command(argv):
            if str(argv[0]) == str(cc): return 'modeled ccache version'
            if argv[0] == 'dpkg-query': return 'modeled-package=1'
            return real_command(argv)
        def tree(path, *rest):
            if str(path).startswith('/usr/'): return {'modeled_system_headers':'unchanged'}
            return real_tree(path, *rest)
        def identity():
            with mock.patch.object(cache,'command',side_effect=command), mock.patch.object(cache,'tree_record',side_effect=tree):
                return cache.canonical(cache.compatibility(repo,'ps5',{'cc':cache.file_record(compiler)},cc,sdk=sdk,tls=tls))
        base=identity()
        for path in [repo/name for name in files] + [cc, compiler, sdk/'native.h', tls/'lib.a']:
            original=path.read_bytes(); path.write_bytes(original+b'changed')
            self.assertNotEqual(base, identity(),str(path)); path.write_bytes(original)
            self.assertEqual(base, identity(),str(path))
        with mock.patch.dict(os.environ, {'PW_WINE_SERVICE_FIXTURE':'1','CFLAGS':'-O3'}):
            self.assertNotEqual(base,identity())
        # A new project commit with identical compiler inputs leaves compatibility stable.
        subprocess.run(['git','-C',str(repo),'-c','user.name=Test','-c','user.email=test@example.invalid',
                        'commit','-qm','Original inert inputs'],check=True)
        self.assertEqual(base,identity())

    def test_recipe_changes_archive_key_but_preserves_compile_partition(self):
        identity = {'phase': 'host', 'settings': cache.SETTINGS, 'compiler': 'exact provider',
                    'recipe': {'unit.c': 'old source'}}
        first, before = self.state(identity=identity)
        identity = dict(identity, recipe={'unit.c': 'changed source'})
        second, after = self.state(identity=identity, suffix='changed')
        self.assertNotEqual(before['key'], after['key'])
        self.assertNotEqual(before['compatibility_sha256'], after['compatibility_sha256'])
        self.assertEqual(before['partition_key'], after['partition_key'])
        self.assertEqual(before['restore_prefix'], after['restore_prefix'])
        self.assertEqual(before['partition_sha256'], after['partition_sha256'])
        self.assertTrue(after['key'].startswith(before['restore_prefix']))
        self.assertEqual((first/'partition.json').read_bytes(), (second/'partition.json').read_bytes())
        for directory, state in ((first, before), (second, after)):
            config = (directory/'ccache.conf').read_text()
            self.assertIn('namespace = ' + state['partition_key'] + '\n', config)
            self.assertIn('extra_files_to_hash = ' + str(directory/'partition.json') + '\n', config)
            self.assertNotIn(str(directory/'compatibility.json'), config)

    def test_global_compiler_and_abi_inputs_do_not_cross_partitions(self):
        identity = {'phase': 'ps5', 'settings': cache.SETTINGS, 'wine_commit': 'a'*40,
                    'compilers': {'cc': 'backend bytes'}, 'abi_contracts': {'creation': 1},
                    'sdk': 'headers and wrappers', 'tls': 'headers and libraries',
                    'flags': {'CFLAGS': '-O2'}, 'system_headers': 'system bytes',
                    'cross_headers': 'MinGW bytes', 'packages': 'versions', 'recipe': {}}
        _, before = self.state('ps5', identity=identity)
        for name in ('phase', 'settings', 'wine_commit', 'compilers', 'abi_contracts',
                     'sdk', 'tls', 'flags', 'system_headers', 'cross_headers', 'packages'):
            changed = dict(identity)
            changed[name] = 'host' if name == 'phase' else 'changed'
            _, after = self.state('ps5', identity=changed, suffix=name)
            self.assertNotEqual(before['partition_key'], after['partition_key'], name)
            self.assertFalse(after['key'].startswith(before['restore_prefix']), name)

    def test_partition_or_key_tampering_refuses_before_command(self):
        for kind in ('bytes', 'meaning', 'key'):
            with self.subTest(kind=kind):
                directory, state = self.state(suffix=kind)
                if kind == 'bytes':
                    (directory/'partition.json').write_text('{}')
                elif kind == 'meaning':
                    (directory/'partition.json').write_text('{}')
                    state['partition_sha256'] = cache.sha(directory/'partition.json')
                    (directory/'state.json').write_bytes(cache.canonical(state))
                else:
                    state['restore_prefix'] = 'wine-ccache-v2-'
                    (directory/'state.json').write_bytes(cache.canonical(state))
                with mock.patch.object(cache.subprocess, 'run') as run:
                    with self.assertRaises(ValueError):
                        cache.run_stage(directory, 'changed', ['false'])
                    run.assert_not_called()

    def test_actual_abi_identifiers_are_unambiguous_and_protocols_match(self):
        repo = self.root/'repo'; repo.mkdir()
        for name, (path, macro) in cache.ABI_INPUTS.items():
            target = repo/path; target.parent.mkdir(parents=True, exist_ok=True)
            value = 962 if name.endswith('protocol') else 1
            with target.open('a') as stream:
                stream.write(('+' if path.endswith('.patch') else '') + f'#define {macro} {value}u\n')
        (repo/cache.ABI_INPUTS['server_protocol'][0]).write_text((ROOT/cache.ABI_INPUTS['server_protocol'][0]).read_text())
        (repo/'wine/ps5/pw_wine_focus_neutral.h').write_text((ROOT/'wine/ps5/pw_wine_focus_neutral.h').read_text())
        (repo/'wine/ps5/pw_wine_creation.h').write_text((ROOT/'wine/ps5/pw_wine_creation.h').read_text())
        self.assertEqual(cache.abi_contracts(repo)['creation']['value'], 1)
        path, macro = cache.ABI_INPUTS['creation']
        target = repo/path
        original = target.read_text()
        target.write_text(original.replace('#define ' + macro + ' 1u', '#define ' + macro + ' 2u'))
        self.assertEqual(cache.abi_contracts(repo)['creation']['value'], 2)
        target.write_text(original + '#define ' + macro + ' 1u\n')
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            cache.abi_contracts(repo)
        target.write_text(original)
        server = repo/cache.ABI_INPUTS['server_protocol'][0]
        server.write_text(server.read_text().replace('#define SERVER_PROTOCOL_VERSION 962', '#define SERVER_PROTOCOL_VERSION 963'))
        with self.assertRaisesRegex(ValueError, 'protocol identifiers differ'):
            cache.abi_contracts(repo)

    def test_directory_links_bind_real_target_bytes_and_reject_cycles(self):
        inputs = self.root / 'sdk'; inputs.mkdir()
        external = self.root / 'headers'; external.mkdir()
        header = external / 'native.h'; header.write_text('first')
        (inputs / 'include').symlink_to(external, target_is_directory=True)
        before = cache.tree_record(inputs)
        header.write_text('second')
        self.assertNotEqual(before, cache.tree_record(inputs))
        (external / 'loop').symlink_to(inputs, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'cyclic'):
            cache.tree_record(inputs)

    def test_no_cache_evidence_overlap_or_existing_state(self):
        for output, objects in [(self.root/'same', self.root/'same'),
                                (self.root/'parent', self.root/'parent/objects'),
                                (self.root/'objects/evidence', self.root/'objects')]:
            with self.assertRaises(ValueError):
                cache.write_state(output, objects, {'phase':'host'}, {}, '/inert', {}, repo=ROOT)
        self.state()
        with self.assertRaises(FileExistsError): self.state()

    def test_exact_config_and_explicit_triple_names(self):
        directory, state = self.state()
        text = (directory / 'ccache.conf').read_text()
        for value in ('compiler_check = content', 'hard_link = false', 'sloppiness = \n',
                      'hash_dir = true', 'direct_mode = false'):
            self.assertIn(value, text)
        self.assertEqual(Path(state['launchers']['i386']).name, 'i686-w64-mingw32-gcc')
        self.assertEqual(Path(state['launchers']['x86_64']).name, 'x86_64-w64-mingw32-gcc')
        with mock.patch.dict(os.environ, {'CCACHE_SLOPPINESS': 'time_macros', 'CCACHE_DISABLE': '1'}):
            env = cache.cache_env(state, directory)
        self.assertNotIn('CCACHE_SLOPPINESS', env); self.assertNotIn('CCACHE_DISABLE', env)
        self.assertEqual(env['CCACHE_CONFIGPATH'], str(directory/'ccache.conf'))

    def test_command_failure_survives_statistics_failure(self):
        directory, _ = self.state()
        real_run = subprocess.run
        real_output = subprocess.check_output
        def output(argv, **kwargs):
            return 'inert config' if argv[0] == '/inert/ccache' else real_output(argv, **kwargs)
        def run(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0) if argv[0] == '/inert/ccache' else real_run(argv, **kwargs)
        with mock.patch.object(cache, 'stats', side_effect=[{}, OSError('injected stats failure')]), \
             mock.patch.object(cache.subprocess, 'run', side_effect=run), \
             mock.patch.object(cache.subprocess, 'check_output', side_effect=output), \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(OSError): cache.run_stage(directory, 'failed', ['sh','-c','exit 7'])
        record = json.loads((directory/'failed.json').read_text())
        self.assertEqual(record['exit'], 7)
        self.assertGreaterEqual(record['elapsed_seconds'], 0)
        self.assertEqual(record['statistics_error'], 'injected stats failure')

    def test_changed_compatibility_refuses_before_command(self):
        directory, _ = self.state()
        (directory/'compatibility.json').write_text('{}')
        with mock.patch.object(cache.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'changed'):
                cache.run_stage(directory, 'changed', ['false'])
            run.assert_not_called()

    def test_real_wine_target_inference_from_generated_launcher_names(self):
        source = os.environ.get('PROSPERO_WINE_SOURCE')
        if not source:
            self.skipTest('pinned Wine source not supplied')
        text = (Path(source)/'configure.ac').read_text()
        start = text.index('    target=""\n    set x $CC\n')
        end = text.index('    dnl Check if cross compiler supports -target argument', start)
        block = text[start:end]
        _, state = self.state()
        for role, expected in [('i386','i686-w64-mingw32'),('x86_64','x86_64-w64-mingw32')]:
            result = subprocess.run(['sh','-c','CC=$1\n'+block+'\nprintf "%s" "$target"','test',state['launchers'][role]],
                                    text=True,capture_output=True,check=True)
            self.assertEqual(result.stdout, expected)
        result = subprocess.run(['sh','-c','CC=$1\n'+block+'\nprintf "%s" "$target"','test','/inert/generic-launcher'],
                                text=True,capture_output=True,check=True)
        self.assertEqual(result.stdout, '')

    def test_target_default_relative_sdk_and_explicit_launcher_guard(self):
        source = (ROOT/'tools/build_wine_ps5.sh').read_text()
        block = source[source.index('wine_cc=${'):source.index('stamp=$(', source.index('wine_cc=${'))]
        def route(value):
            env = dict(os.environ); env.pop('PW_WINE_CACHED_CC', None)
            if value is not None: env['PW_WINE_CACHED_CC'] = value
            return subprocess.run(['sh'], input='set -eu\nsdk=./sdk\nfail() { echo "$*" >&2; exit 1; }\n' + block + '\nprintf "%s" "$wine_cc"\n',
                                  env=env, text=True, capture_output=True)
        self.assertEqual(route(None).stdout, './sdk/bin/prospero-clang')
        for value in ('relative-compiler', '/missing-compiler'):
            self.assertNotEqual(route(value).returncode, 0)
        self.assertEqual(route('/bin/true').stdout, '/bin/true')



class NeutralSelection(CacheFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.repo = self.root/'repo'
        shutil.copytree(ROOT, self.repo, ignore=shutil.ignore_patterns('.git', '__pycache__'))
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)
        subprocess.run(['git', '-C', str(self.repo), 'add', '.'], check=True)
        self.clean = mock.patch.dict(os.environ, {k: '0' for k in
            ('PW_WINE_FOCUS_NEUTRAL', 'PW_WINE_PRIVATE_DISPATCH', 'PW_WINE_SERVICE_FIXTURE')})
        self.clean.start(); self.addCleanup(self.clean.stop)
        for flag in cache.FLAGS:
            if not flag.startswith('PW_WINE_'):
                os.environ.pop(flag, None)

    def neutral(self):
        return mock.patch.dict(os.environ, {k: '1' for k in
            ('PW_WINE_FOCUS_NEUTRAL', 'PW_WINE_PRIVATE_DISPATCH', 'PW_WINE_SERVICE_FIXTURE')})

    def rejected_stage(self, directory):
        # Refusal precedes even ccache statistics resets, not just the build.
        with mock.patch.object(cache.subprocess, 'run') as run:
            with self.assertRaises((ValueError, FileNotFoundError)):
                cache.run_stage(directory, 'must-not-run', ['false'])
            run.assert_not_called()
        self.assertFalse((directory/'must-not-run.json').exists())

    def test_real_source_default_and_selected_protocol_contract(self):
        default = cache.source_selection(self.repo, 'ps5')
        self.assertEqual(default['focus'], {'mode': 0, 'protocol': 962})
        self.assertEqual(cache.source_selection(self.repo, 'host'), default)
        with self.neutral():
            selected = cache.source_selection(self.repo, 'ps5')
        for name in ('creation_protocol', 'server_protocol'):
            self.assertEqual(default['abi_contracts'][name]['value'], 962)
            self.assertEqual(selected['abi_contracts'][name]['value'], 963)
        focus = selected['focus']
        self.assertEqual(tuple(focus['optional_patches']), (
            '0001-server-adapter.patch', '0002-server-requests.patch',
            '0003-neutral-cohort.patch', '0004-tracked-mouse-button.patch'))
        self.assertGreater(len(focus['contract']['sources']), 100)
        self.assertRegex(focus['generated_header_sha256'], '^[a-f0-9]{64}$')
        self.assertFalse(focus['contract']['runtime_validated'])
        for path in ('tools/wine_focus_neutral.py', 'wine/focus-neutral/0003-neutral-cohort.patch',
                     'wine/focus-neutral/0004-tracked-mouse-button.patch'):
            self.assertIn(path, cache.recipe_inputs(self.repo))

    @unittest.skipUnless(shutil.which('gcc'), 'GCC unavailable for actual preprocessing')
    def test_real_native_header_preprocessor_matches_each_selected_mode(self):
        with self.neutral():
            focus = cache.source_selection(self.repo, 'ps5')['focus']
        spec = importlib.util.spec_from_file_location('focus_test', self.repo/'tools/wine_focus_neutral.py')
        helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
        include = self.root/'include/wine'; include.mkdir(parents=True)
        header = include/'pw_focus_build.h'; header.write_text(helper.header(focus['contract']))
        self.assertEqual(cache.sha(header), focus['generated_header_sha256'])
        self.assertEqual(sum(line.startswith('#define PW_FOCUS_SOURCE_WORD_') for line in header.read_text().splitlines()), 8)
        for mode, protocol in ((0, 962), (1, 963)):
            argv = ['gcc', '-E', '-dM', '-x', 'c', '-I'+str(include.parent),
                    '-I'+str(self.repo/'wine/ps5'), '-DPW_WINE_FOCUS_NEUTRAL='+str(mode), '-']
            result = subprocess.run(argv, input='#include "pw_wine_creation.h"\n',
                                    text=True, capture_output=True, check=True)
            self.assertEqual(cache.single_number(result.stdout, 'PW_WINE_CREATION_PROTOCOL'), protocol)
            self.assertEqual(cache.abi_contracts(self.repo, mode)['creation_protocol']['value'], protocol)

    @unittest.skipUnless(shutil.which('gcc'), 'GCC unavailable for actual preprocessing')
    def test_actual_patched_server_header_matches_each_mode(self):
        source = os.environ.get('PROSPERO_WINE_SOURCE')
        if not source:
            self.skipTest('pinned Wine source not supplied')
        tree = self.root/'wine-source'
        shutil.copytree(Path(source)/'include', tree/'include')
        subprocess.run(['git', 'init', '-q', str(tree)], check=True)
        for patch in sorted((self.repo/'wine/patches').glob('*.patch')):
            subprocess.run(['git', '-C', str(tree), 'apply', '--include=include/*', str(patch)],
                           check=True, capture_output=True)
        for mode, protocol in ((0, 962), (1, 963)):
            if mode:
                for patch in sorted((self.repo/'wine/focus-neutral').glob('*.patch')):
                    subprocess.run(['git', '-C', str(tree), 'apply', '--include=include/*', str(patch)],
                                   check=True, capture_output=True)
            result = subprocess.run(['gcc', '-E', '-dM', '-x', 'c', '-D__WINESRC__',
                                     '-I'+str(tree/'include'), '-'],
                                    input='#include "wine/server_protocol.h"\n',
                                    text=True, capture_output=True, check=True)
            self.assertEqual(cache.single_number(result.stdout, 'SERVER_PROTOCOL_VERSION'), protocol)
            self.assertEqual(cache.abi_contracts(self.repo, mode)['server_protocol']['value'], protocol)

    def test_strict_selector_host_default_and_prerequisites(self):
        for value in ('', '2', '-1', 'true', '01', ' 1'):
            with self.subTest(value=value), mock.patch.dict(os.environ, {'PW_WINE_FOCUS_NEUTRAL': value}):
                with self.assertRaisesRegex(ValueError, 'must be 0 or 1'):
                    cache.source_selection(self.repo, 'ps5')
        with self.neutral():
            with self.assertRaisesRegex(ValueError, 'host compiler cache requires default'):
                cache.source_selection(self.repo, 'host')
            for key in ('PW_WINE_PRIVATE_DISPATCH', 'PW_WINE_SERVICE_FIXTURE'):
                with mock.patch.dict(os.environ, {key: '0'}):
                    with self.assertRaisesRegex(ValueError, 'requires private-dispatch'):
                        cache.source_selection(self.repo, 'ps5')

    def test_manual_focus_and_protocol_definitions_refused(self):
        for name in cache.FLAGS:
            if name.startswith('PW_WINE_'):
                continue
            for definition in ('-DPW_WINE_FOCUS_NEUTRAL=1', '-UPW_FOCUS_BUILD_MODE',
                               '-DPW_WINE_CREATION_PROTOCOL=963', '-DSERVER_PROTOCOL_VERSION=963'):
                with self.subTest(flag=name, definition=definition), mock.patch.dict(os.environ, {name: definition}):
                    with self.assertRaisesRegex(ValueError, 'manual focus/protocol'):
                        cache.source_selection(self.repo, 'ps5')

    def test_unknown_or_extra_native_protocol_conditions_refused(self):
        path = self.repo/'wine/ps5/pw_wine_creation.h'; original = path.read_text()
        changes = [original.replace('#if PW_WINE_FOCUS_NEUTRAL', '#if UNKNOWN'),
                   original.replace('#if PW_WINE_FOCUS_NEUTRAL', '#ifdef PW_WINE_FOCUS_NEUTRAL'),
                   original.replace('#if PW_WINE_FOCUS_NEUTRAL', '#if 0\n#if PW_WINE_FOCUS_NEUTRAL'),
                   original.replace('#else\n#define PW_WINE_CREATION_PROTOCOL', '#elif UNKNOWN\n#define PW_WINE_CREATION_PROTOCOL'),
                   original + '\n#define PW_WINE_CREATION_PROTOCOL 962u\n',
                   original + '\n#define PW_WINE_CREATION_PROTOCOL(value) value\n',
                   original + '\n#undef PW_WINE_CREATION_PROTOCOL\n',
                   original + '\n#de\\\nfine PW_WINE_CREATION_PROTOCOL 962u\n',
                   original.replace('963u', '964u'),
                   original.replace('#if PW_WINE_FOCUS_NEUTRAL', '#define PW_WINE_FOCUS_NEUTRAL 0\n#if PW_WINE_FOCUS_NEUTRAL')]
        for index, changed in enumerate(changes):
            path.write_text(changed)
            with self.subTest(case=index), self.assertRaises(ValueError):
                cache.abi_contracts(self.repo)
        path.write_text(original)
        selector = self.repo/'wine/ps5/pw_wine_focus_neutral.h'
        selector.write_text(selector.read_text().replace('#define PW_WINE_FOCUS_NEUTRAL 0', '#define PW_WINE_FOCUS_NEUTRAL 1'))
        with self.assertRaises(ValueError): cache.abi_contracts(self.repo)

    def test_unknown_or_extra_server_protocol_definitions_refused(self):
        path = self.repo/cache.ABI_INPUTS['server_protocol'][0]; original = path.read_text()
        for changed in (original.replace('+#define SERVER_PROTOCOL_VERSION 962', '+#if UNKNOWN\n+#define SERVER_PROTOCOL_VERSION 962\n+#endif'),
                        original.replace('diff --git a/include/wine/server_protocol.h b/include/wine/server_protocol.h\n',
                            'diff --git a/include/wine/server_protocol.h b/include/wine/server_protocol.h\n@@ -1,0 +1,1 @@\n+#if UNKNOWN\n'),
                        original+'\n+#define SERVER_PROTOCOL_VERSION 962\n',
                        original+'\n+#undef SERVER_PROTOCOL_VERSION\n',
                        original.replace('+#define SERVER_PROTOCOL_VERSION 962', '+#define SERVER_PROTOCOL_VERSION 963')):
            path.write_text(changed)
            with self.assertRaises(ValueError): cache.abi_contracts(self.repo)
        path.write_text(original)
        optional = self.repo/'wine/focus-neutral/0003-neutral-cohort.patch'
        optional.write_text(optional.read_text()+'\n+#define SERVER_PROTOCOL_VERSION 963\n')
        with self.assertRaises(ValueError): cache.abi_contracts(self.repo, 1)

    def test_focus_namespace_and_wrong_mode_state_refused_before_command(self):
        default_dir, default = self.state('ps5', repo=self.repo)
        with self.neutral():
            neutral_dir, neutral = self.state('ps5', repo=self.repo, suffix='neutral')
            self.rejected_stage(default_dir)
        self.rejected_stage(neutral_dir)
        self.assertIn('-ps5-focus0-', default['partition_key'])
        self.assertIn('-ps5-focus1-', neutral['partition_key'])
        self.assertNotEqual(default['restore_prefix'], neutral['restore_prefix'])
        self.assertFalse(neutral['key'].startswith(default['restore_prefix']))

    def test_stale_schema_and_missing_patch_refused_before_command(self):
        directory, state = self.state('ps5', repo=self.repo)
        state['schema'] = 'pw-wine-compiler-cache/2'
        (directory/'state.json').write_bytes(cache.canonical(state))
        self.rejected_stage(directory)
        with self.neutral():
            directory, _ = self.state('ps5', repo=self.repo, suffix='neutral')
            (self.repo/'wine/focus-neutral/0003-neutral-cohort.patch').unlink()
            self.rejected_stage(directory)

    def test_full_source_optional_patch_and_generated_header_drift_refused(self):
        with self.neutral():
            directory, _ = self.state('ps5', repo=self.repo)
            for name in ('native/pw_wine_child_data.c', 'wine/ps5/pw_wine_focus_neutral.h',
                         'wine/focus-neutral/0003-neutral-cohort.patch', 'wine/focus-neutral/0001-server-adapter.patch',
                         'tools/wine_focus_neutral.py'):
                path = self.repo/name; original = path.read_bytes()
                path.write_bytes(original+b'\n# changed\n' if path.suffix == '.py' else original+b'\n/* changed */\n')
                with self.subTest(path=name): self.rejected_stage(directory)
                path.write_bytes(original)
            helper = self.repo/'tools/wine_focus_neutral.py'; original = helper.read_text()
            helper.write_text(original.replace('#define PW_FOCUS_BUILD_MODE 1', '#define PW_FOCUS_BUILD_MODE 0'))
            self.rejected_stage(directory)
            helper.write_text(original)
            cache.checked_identity(directory, json.loads((directory/'state.json').read_text()))

    def test_inert_stage_executes_each_selected_mode_with_explicit_environment(self):
        real_output = subprocess.check_output
        def output(argv, **kwargs):
            return 'inert config' if argv[0] == '/inert/ccache' else real_output(argv, **kwargs)
        real_run = subprocess.run
        def run(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0) if argv[0] == '/inert/ccache' else real_run(argv, **kwargs)
        for mode in (0, 1):
            with mock.patch.dict(os.environ, {'PW_WINE_FOCUS_NEUTRAL': str(mode),
                'PW_WINE_PRIVATE_DISPATCH': '1', 'PW_WINE_SERVICE_FIXTURE': '1'}):
                directory, _ = self.state('ps5', repo=self.repo, suffix=str(mode))
                with mock.patch.object(cache, 'stats', return_value={}), \
                     mock.patch.object(cache.subprocess, 'run', side_effect=run), \
                     mock.patch.object(cache.subprocess, 'check_output', side_effect=output), \
                     contextlib.redirect_stdout(io.StringIO()):
                    result = cache.run_stage(directory, 'inert', ['sh', '-c',
                        'test "$PW_WINE_FOCUS_NEUTRAL" = '+str(mode)])
                self.assertEqual(result, 0)
                self.assertEqual(json.loads((directory/'inert.json').read_text())['focus']['mode'], mode)


@unittest.skipUnless(shutil.which('ccache') and shutil.which('gcc'), 'real ccache/GCC not installed; matched workflow installs both')
class RealCompilerCache(CacheFixture, unittest.TestCase):
    # These controls compile original inert C into objects; they execute no compiled program.
    def real_state(self, phase='host', wrapper=False):
        compiler = Path(shutil.which('gcc'))
        if wrapper:
            compiler = self.root/'sdk/bin/prospero-clang'; compiler.parent.mkdir(parents=True)
            compiler.write_text('#!/bin/sh\nexec ' + shutil.which('gcc') + ' "$@"\n'); compiler.chmod(0o755)
        compilers = {role: (compiler, 'gcc') for role in ('cc','cxx','i386','x86_64')}
        identity = {'phase':phase, 'compiler':cache.file_record(compiler), 'settings':cache.SETTINGS}
        return self.state(phase, identity, shutil.which('ccache'), compilers)

    def compile(self, directory, stage, phase='host', flags=''):
        envname = 'CC' if phase == 'host' else 'PW_WINE_CACHED_CC'
        command = f'"${envname}" {flags} -c "{self.root}/input.c" -o "{self.root}/output.o"'
        with contextlib.redirect_stdout(io.StringIO()):
            result = cache.run_stage(directory, stage, ['sh','-c',command])
        self.assertEqual(result, 0)
        return json.loads((directory/(stage+'.json')).read_text()), (self.root/'output.o').read_bytes()

    def test_actual_cold_warm_headers_flags_and_output_equality(self):
        directory, _ = self.real_state()
        header = self.root/'value.h'; header.write_text('#define VALUE 7\n')
        (self.root/'input.c').write_text('#include "value.h"\nint original_value(void) { return VALUE; }\n')
        cold, first = self.compile(directory, 'cold')
        self.assertGreater(cold['compiler_misses'], 0)
        (self.root/'output.o').unlink()
        warm, second = self.compile(directory, 'warm')
        self.assertGreater(warm['compiler_hits'], 0); self.assertEqual(first, second)
        header.write_text('#define VALUE 8\n')
        changed, third = self.compile(directory, 'header-change')
        self.assertGreater(changed['compiler_misses'], 0); self.assertNotEqual(first, third)
        flags, _ = self.compile(directory, 'flag-change', flags='-O2')
        self.assertGreater(flags['compiler_misses'], 0)

    def test_actual_script_dispatcher_routing_and_key_value_options(self):
        directory, _ = self.real_state('ps5', wrapper=True)
        (self.root/'input.c').write_text('int original_value(void) { return 11; }\n')
        cold, first = self.compile(directory, 'sdk-cold', 'ps5')
        warm, second = self.compile(directory, 'sdk-warm', 'ps5')
        self.assertGreater(cold['compiler_misses'], 0); self.assertGreater(warm['compiler_hits'], 0)
        self.assertEqual(first, second)
        self.assertIn('compiler_check = content', (directory/'sdk-warm-config.txt').read_text())

    def test_real_clang_script_and_complete_smoke_control(self):
        clang = shutil.which('clang-18') or shutil.which('clang')
        if not clang and Path('/usr/lib/llvm-19/bin/clang').is_file():
            clang = '/usr/lib/llvm-19/bin/clang'
        if not clang:
            self.skipTest('Clang unavailable for script-dispatch control')
        compiler = self.root/'sdk/bin/prospero-clang'; compiler.parent.mkdir(parents=True)
        compiler.write_text('#!/bin/sh\nexec ' + clang + ' "$@"\n'); compiler.chmod(0o755)
        compilers = {role: (compiler, 'clang') for role in ('cc','cxx','i386','x86_64')}
        identity = {'phase':'ps5', 'compiler':cache.file_record(compiler), 'backend':cache.file_record(Path(clang))}
        directory, _ = self.state('ps5', identity, shutil.which('ccache'), compilers)
        with contextlib.redirect_stdout(io.StringIO()):
            report = cache.compiler_smoke(directory, self.root/'smoke', self.root/'smoke-objects')
        self.assertGreater(report['cold_misses'], 0); self.assertGreater(report['warm_hits'], 0)
        self.assertEqual(report['cold_sha256'], report['warm_sha256'])
        self.assertFalse(report['target_code_executed'])
        with self.assertRaisesRegex(ValueError, 'fresh'):
            cache.compiler_smoke(directory, self.root/'other-smoke', self.root/'smoke-objects')


if __name__ == '__main__':
    unittest.main()
