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

    def state(self, phase='host', identity=None, ccache='/inert/ccache', compilers=None, suffix=''):
        compilers = compilers or {role: (Path('/inert') / name, 'gcc') for role, name in
            [('cc', 'clang'), ('cxx', 'clang++'), ('i386', 'i686-w64-mingw32-gcc'), ('x86_64', 'x86_64-w64-mingw32-gcc')]}
        identity = identity or {'phase': phase, 'compiler': 'synthetic-inputs'}
        out = self.root / ('evidence' + suffix)
        state = cache.write_state(out, self.root / 'objects', identity, compilers, ccache,
                                  {'commit': 'a'*40, 'tree': 'b'*40})
        return out, state


class CacheContracts(CacheFixture, unittest.TestCase):
    def test_project_receipt_changes_without_changing_compiler_key(self):
        one, a = self.state()
        b = cache.write_state(self.root / 'other', self.root / 'objects', {'phase': 'host', 'compiler': 'synthetic-inputs'},
                             {}, '/inert/ccache', {'commit': 'c'*40, 'tree': 'd'*40})
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
            'wine/patches/0001-test.patch':'patch', 'wine/ps5/staged.h':'staged header',
            '.github/workflows/windows-child-fixture.yml':'workflow'}
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
                cache.write_state(output, objects, {'phase':'host'}, {}, '/inert', {})
        self.state()
        with self.assertRaises(FileExistsError): self.state()

    def test_exact_config_and_explicit_triple_names(self):
        directory, state = self.state()
        text = (directory / 'ccache.conf').read_text()
        for value in ('compiler_check = content', 'hard_link = false', 'sloppiness = \n', 'hash_dir = true'):
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
        def run(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0) if argv[0] == '/inert/ccache' else real_run(argv, **kwargs)
        with mock.patch.object(cache, 'stats', side_effect=[{}, OSError('injected stats failure')]), \
             mock.patch.object(cache.subprocess, 'run', side_effect=run), \
             mock.patch.object(cache.subprocess, 'check_output', return_value='inert config'), \
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
