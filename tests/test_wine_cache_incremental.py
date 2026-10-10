#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Real compile-only cache controls; no produced object is linked or executed.

The small SDK/compiler fixtures model partition metadata. Their actual bytes
and GCC object outputs are checked; these are not PS5 compiler or runtime tests.
"""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
HELPER = Path(os.environ.get('PW_CACHE_HELPER', ROOT / 'tools/wine_compile_cache.py'))
spec = importlib.util.spec_from_file_location('incremental_cache_under_test', HELPER)
cache = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cache)


@unittest.skipUnless(shutil.which('ccache') and shutil.which('gcc'), 'real ccache/GCC required')
class IncrementalCompilerControls(unittest.TestCase):
    def setUp(self):
        evidence = os.environ.get('PW_CACHE_CONTROL_OUTPUT')
        if evidence:
            self.root = Path(evidence).resolve() / self._testMethodName
            self.root.mkdir(parents=True, exist_ok=False)
        else:
            temporary = tempfile.TemporaryDirectory(prefix='wine-incremental-cache-')
            self.addCleanup(temporary.cleanup)
            self.root = Path(temporary.name)
        self.cc = Path(shutil.which('gcc')).resolve()
        self.ccache = Path(shutil.which('ccache')).resolve()
        self.inputs = self.root / 'input'; self.inputs.mkdir()
        self.front = self.inputs / 'first'; self.front.mkdir()
        self.back = self.inputs / 'second'; self.back.mkdir()
        self.header = self.inputs / 'generated.h'
        self.header.write_text('#define GENERATED_VALUE 7\n')
        (self.back / 'choice.h').write_text('#define CHOICE_VALUE 3\n')
        self.a = self.inputs / 'a.c'; self.b = self.inputs / 'b.c'
        self.a.write_text('#include "generated.h"\n#include <choice.h>\n'
                          '#ifndef ABI_VALUE\n#define ABI_VALUE 0\n#endif\n'
                          'int original_a(void) { return GENERATED_VALUE + CHOICE_VALUE + ABI_VALUE + 1; }\n')
        self.b.write_text('int original_b(void) { return 43; }\n')
        self.records = []
        self.sequence = 0
        self.sdk = self.root / 'modeled-sdk'; self.sdk.mkdir()
        (self.sdk / 'native.h').write_text('/* original owned SDK-identity fixture */\n')
        self.identity = {'schema': cache.SCHEMA, 'phase': 'host',
                         'compiler': cache.file_record(self.cc),
                         'ccache': cache.file_record(self.ccache),
                         'settings': copy.deepcopy(cache.SETTINGS),
                         'sdk_fixture': cache.tree_record(self.sdk),
                         'flags': {'CFLAGS': '-O2'}, 'abi_fixture': 'original-v1'}
        self.addCleanup(self.save_receipt)

    def save_receipt(self):
        # Register this after temporary cleanup so unittest saves before removal.
        self.root.mkdir(parents=True, exist_ok=True)
        record = {'scope': 'real GCC/ccache compile-only; owned SDK metadata fixture; no target execution',
                  'helper_sha256': cache.sha(HELPER),
                  'compiler': cache.file_record(self.cc),
                  'compiler_version': subprocess.check_output([str(self.cc), '--version'], text=True),
                  'ccache': cache.file_record(self.ccache),
                  'ccache_version': subprocess.check_output([str(self.ccache), '--version'], text=True),
                  'stages': self.records}
        (self.root / 'RESULT.json').write_text(json.dumps(record, indent=2) + '\n')

    def state(self, identity=None, compiler=None):
        self.sequence += 1
        value = copy.deepcopy(identity or self.identity)
        value['recipe'] = {str(p.relative_to(self.inputs)): cache.sha(p)
                           for p in sorted(self.inputs.rglob('*')) if p.is_file()}
        compiler = compiler or self.cc
        compilers = {role: (compiler, 'gcc') for role in ('cc', 'cxx', 'i386', 'x86_64')}
        project = {'commit': f'{self.sequence:040x}', 'tree': f'{self.sequence + 100:040x}',
                   'run_id': str(1000 + self.sequence)}
        directory = self.root / f'evidence-{self.sequence}'
        state = cache.write_state(directory, self.root / 'objects', value, compilers,
                                  str(self.ccache), project)
        return directory, state

    def compile_one(self, directory, state, label, source, flags=()):
        object_path = self.root / (source.stem + '.o')
        if object_path.exists(): object_path.unlink()
        args = ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                '-I' + str(self.front), '-I' + str(self.back), *flags,
                '-c', str(source), '-o', str(object_path)]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = cache.run_stage(directory, label, [state['launchers']['cc'], *args])
        (directory / (label + '-driver.log')).write_text(output.getvalue())
        self.assertEqual(result, 0)
        cached = object_path.read_bytes()
        uncached = self.root / ('uncached-' + source.stem + '.o')
        direct_args = [str(self.cc), *args[:-1], str(uncached)]
        started = time.monotonic()
        direct = subprocess.run(direct_args, text=True, capture_output=True)
        uncached_seconds = time.monotonic() - started
        self.assertEqual(direct.returncode, 0, direct.stderr)
        self.assertEqual(cached, uncached.read_bytes())
        receipt = json.loads((directory / (label + '.json')).read_text())
        self.assertEqual(receipt['project'], state['project'])
        self.assertEqual(receipt['exit'], 0)
        receipt.update(source_sha256=cache.sha(source), object_sha256=hashlib.sha256(cached).hexdigest(),
                       uncached_sha256=cache.sha(uncached), uncached_seconds=uncached_seconds,
                       uncached_argv=direct_args, uncached_stderr=direct.stderr,
                       case=label)
        self.records.append(receipt)
        return receipt, cached

    def test_cross_recipe_source_generated_header_and_shadowing(self):
        one, first = self.state()
        a, initial_a = self.compile_one(one, first, 'cold-a', self.a)
        b, initial_b = self.compile_one(one, first, 'cold-b', self.b)
        self.assertEqual((a['compiler_hits'], a['compiler_misses']), (0, 1))
        self.assertEqual((b['compiler_hits'], b['compiler_misses']), (0, 1))
        for source in (self.a, self.b):
            warm, _ = self.compile_one(one, first, 'warm-' + source.stem, source)
            self.assertEqual((warm['compiler_hits'], warm['compiler_misses']), (1, 0))
        prior = first; prior_dir = one; previous_a = initial_a
        for case in ('source-patch', 'generated-header', 'shadowed-include'):
            if case == 'source-patch': self.a.write_text(self.a.read_text().replace('+ 1;', '+ 2;'))
            elif case == 'generated-header': self.header.write_text('#define GENERATED_VALUE 19\n')
            else: (self.front / 'choice.h').write_text('#define CHOICE_VALUE 29\n')
            directory, current = self.state()
            affected, changed_a = self.compile_one(directory, current, case + '-a', self.a)
            unaffected, unchanged_b = self.compile_one(directory, current, case + '-b', self.b)
            self.assertEqual((affected['compiler_hits'], affected['compiler_misses']), (0, 1))
            # Baseline-compatible first red: the old recipe-wide namespace
            # discards this reusable object's entry and produces a miss.
            self.assertEqual((unaffected['compiler_hits'], unaffected['compiler_misses']), (1, 0))
            self.assertNotEqual(previous_a, changed_a); self.assertEqual(initial_b, unchanged_b)
            self.assertNotEqual(prior['key'], current['key'])
            self.assertEqual(prior['partition_key'], current['partition_key'])
            self.assertEqual(prior['restore_prefix'], current['restore_prefix'])
            self.assertNotEqual(prior['project'], current['project'])
            self.assertNotEqual((prior_dir / 'compatibility.json').read_bytes(),
                                (directory / 'compatibility.json').read_bytes())
            self.assertEqual((prior_dir / 'partition.json').read_bytes(), (directory / 'partition.json').read_bytes())
            self.assertIn('direct_mode = false', (directory / 'ccache.conf').read_text())
            self.assertTrue((self.back / 'choice.h').is_file())
            prior, prior_dir, previous_a = current, directory, changed_a

    def test_partition_changes_cannot_reuse_prior_entries(self):
        compiler = self.root / 'owned-compiler' / 'gcc'; compiler.parent.mkdir()
        original_wrapper = '#!/bin/sh\nexec ' + shlex.quote(str(self.cc)) + ' "$@"\n'
        compiler.write_text(original_wrapper); compiler.chmod(0o755)
        original_sdk = (self.sdk / 'native.h').read_bytes()
        baseline = copy.deepcopy(self.identity)
        baseline['compiler'] = cache.file_record(compiler)
        directory, state = self.state(baseline, compiler)
        for source in (self.a, self.b): self.compile_one(directory, state, 'seed-' + source.stem, source)
        for case in ('compiler', 'sdk', 'abi'):
            compiler.write_text(original_wrapper)
            (self.sdk / 'native.h').write_bytes(original_sdk)
            identity = copy.deepcopy(baseline); flags = []
            if case == 'compiler':
                compiler.write_text(original_wrapper + '# changed owned compiler-provider bytes\n')
                identity['compiler'] = cache.file_record(compiler)
                self.assertEqual(identity['compiler']['path'], baseline['compiler']['path'])
                self.assertNotEqual(identity['compiler']['sha256'], baseline['compiler']['sha256'])
            elif case == 'sdk':
                (self.sdk / 'native.h').write_text('/* changed owned SDK-identity fixture */\n')
                identity['sdk_fixture'] = cache.tree_record(self.sdk)
            else:
                identity['abi_fixture'] = 'original-v2'
                identity['flags']['CFLAGS'] = '-O2 -DABI_VALUE=31'
                flags = ['-DABI_VALUE=31']
            changed_dir, changed = self.state(identity, compiler)
            self.assertNotEqual(state['partition_key'], changed['partition_key'])
            self.assertNotEqual(state['restore_prefix'], changed['restore_prefix'])
            for source in (self.a, self.b):
                result, _ = self.compile_one(changed_dir, changed, case + '-' + source.stem, source, flags)
                self.assertEqual((result['compiler_hits'], result['compiler_misses']), (0, 1))

    def test_debug_cwd_and_absolute_source_path_match_uncached(self):
        self.a.write_text('const char *original_file(void) { return __FILE__; }\n'
                          'int original_debug_value(void) { return 53; }\n')
        self.identity['flags']['CFLAGS'] = '-O2 -g'
        directory, state = self.state()
        original_cwd = Path.cwd()
        objects = []
        try:
            for number in (1, 2):
                cwd = self.root / ('cwd-' + str(number)); cwd.mkdir()
                os.chdir(cwd)
                cold, data = self.compile_one(directory, state, 'cwd-' + str(number), self.a, ['-g'])
                self.assertEqual((cold['compiler_hits'], cold['compiler_misses']), (0, 1))
                self.assertIn(str(self.a).encode(), data)
                self.assertIn(str(cwd).encode(), data)
                warm, again = self.compile_one(directory, state, 'cwd-warm-' + str(number), self.a, ['-g'])
                self.assertEqual((warm['compiler_hits'], warm['compiler_misses']), (1, 0))
                self.assertEqual(data, again); objects.append(data)
        finally:
            os.chdir(original_cwd)
        self.assertNotEqual(objects[0], objects[1])
        self.assertIn('hash_dir = true', (directory / 'ccache.conf').read_text())


if __name__ == '__main__':
    unittest.main(verbosity=2)
