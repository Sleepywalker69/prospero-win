#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Real source/metadata admission controls with explicitly inert ELF/tool boundaries."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import build_owned_helper as helper


class InertElf:
    def __init__(self, value, **kwargs):
        helper.require(value == b'original inert target bytes', 'inert ELF identity differs')
        self.kind = 3
        self.entry = 512
        self.needed = list(helper.PROVIDERS)


class Admission(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pw-owned-helper-admission-')
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.repo, self.out = base / 'repo', base / 'out'
        self.repo.mkdir(); self.out.mkdir()
        def put(name, value=b'original inert source\n'):
            path = self.repo / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(value)
        for name in (*helper.UNITS, *helper.HEADERS, 'LICENSE'):
            put(helper.DIRECTORY + '/' + name)
        for name in ('native/ps5log/ps5log.h', 'native/lapy_elevation_protocol.h',
                     'tools/native_probe_elf.py', 'tools/tls_manifest.py'):
            put(name)
        put('tools/build_owned_helper.py', Path(helper.__file__).read_bytes())
        origin = {'schema': 'pw-owned-helper-upstream/1', 'repository': helper.UPSTREAM_URL,
                  'commit': helper.UPSTREAM, 'license': 'MIT',
                  'license_sha256': helper.digest(self.repo / helper.DIRECTORY / 'LICENSE')}
        put(helper.DIRECTORY + '/UPSTREAM.json', helper.canonical(origin))
        cohort = {'schema': 'pw-owned-helper-reviewed-cohort/1',
                  'upstream': {'repository': helper.UPSTREAM_URL, 'commit': helper.UPSTREAM, 'candidate_is_modified': True},
                  'files': [{'path': name, **helper.record(self.repo / helper.DIRECTORY / name)}
                            for name in (*helper.UNITS, *helper.HEADERS, 'LICENSE')],
                  'license_notes': ['Preserve the root MIT LICENSE copyright and disclaimer verbatim.',
                    'lapy_elevation_protocol.h carries SPDX LGPL-2.1-or-later; preserve it. Do not describe the entire mixed cohort as MIT-only.']}
        put(helper.DIRECTORY + '/REVIEWED-COHORT.json', helper.canonical(cohort))
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)
        subprocess.run(['git', '-C', str(self.repo), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(self.repo), '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
                        'commit', '-qm', 'Original inert source'], check=True)
        self.project = helper.project_identity(self.repo)
        self.source = helper.source_record(self.repo, self.project)
        self.write('lapy-source.json', self.source)
        (self.out / 'lapy.elf').write_bytes(b'original inert target bytes')
        self.sdk = {'bin/prospero-clang': 'a'*64, 'target/lib/crt1.o': 'b'*64, 'target/lib/libc.a': 'c'*64}
        self.llvm = {'version': '18.1.0', 'tools': {name: {'sha256': 'd'*64, 'version': 'LLVM version18', 'path': '/inert/' + name} for name in
                       helper.LLVM_TOOLS},
                     'resource_headers': {'original.h': 'e'*64}}
        self.host_llvm = {**self.llvm, 'config': '/inert/llvm-config', 'bindir': '/inert'}
        self.inputs = {'source': self.source, 'flags': helper.FLAGS, 'sdk': self.sdk, 'llvm': helper.stable_toolchain(self.host_llvm)}
        self.build = {'schema': 'pw-owned-helper-build/1', 'project': self.project,
                      'inputs': self.inputs, 'compiled_units': list(helper.UNITS),
                      'objects': {}, 'host_llvm': self.host_llvm, 'console_validated': False,
                      'sdk_path': '/inert-sdk', 'environment': helper.compiler_environment(self.host_llvm),
                      'command_paths': {'REPO': str(self.repo), 'SDK': '/inert-sdk', 'OUT': str(self.out), 'LLVM': '/inert'},
                      'commands': [],
                      'inspection': {'entry': '0x200', 'needed': list(helper.PROVIDERS)},
                      'source': helper.record(self.out / 'lapy-source.json'), 'elf': helper.record(self.out / 'lapy.elf')}
        self.manifest = {'schema': 'lapy-owned-build/1', 'mode': 'elf-helper', 'target_title': 'PPSA99995',
                         'max_requests': 1, 'service': False, 'require_client_result': False, 'console_validated': False,
                         'features': helper.FEATURES, 'protocol_version': 2, 'protocol_bytes': 32,
                         'protocol_sha256': self.source['protocol_sha256']}
        (self.out / 'obj').mkdir()
        for unit in helper.UNITS:
            obj = self.out / 'obj' / (unit + '.o'); obj.write_bytes(b'ordinary inert object ' + unit.encode())
            self.build['objects'][unit] = helper.record(obj)
        (self.out / 'lapy.map').write_bytes(b'inert map, never from target execution')
        self.build['link_map'] = helper.record(self.out / 'lapy.map')
        for command in helper.expected_commands():
            argv = list(command)
            for name, path in self.build['command_paths'].items():
                argv = [arg.replace('$' + name, path) for arg in argv]
            self.build['commands'].append({'argv': argv, 'exit': 0, 'output': ''})
        self.rebind()
        self.elf = patch.object(helper, 'Elf', InertElf); self.elf.start(); self.addCleanup(self.elf.stop)

    def write(self, name, value):
        (self.out / name).write_bytes(helper.canonical(value))

    def rebind(self):
        self.build['build_id'] = hashlib.sha256(helper.canonical(self.build['inputs'])).hexdigest()
        (self.out / 'owned_identity.h').write_text('#define LAPY_OWNED_ID "' + self.build['build_id'] + '"\n')
        self.build['identity_header'] = helper.record(self.out / 'owned_identity.h')
        self.write('lapy-build.json', self.build)
        self.manifest.update(build_id=self.build['build_id'], elf_sha256=helper.digest(self.out / 'lapy.elf'),
                             source_sha256=helper.digest(self.out / 'lapy-source.json'),
                             build_sha256=helper.digest(self.out / 'lapy-build.json'))
        self.write('lapy-manifest.json', self.manifest)

    def verify(self):
        return helper.validate_owned_helper(self.out, self.repo, self.project)

    def test_valid_metadata_path(self):
        value = self.verify()
        self.assertEqual(value['elf'], helper.record(self.out / 'lapy.elf'))
        self.assertFalse(value['runtime_validated'])

    def test_old_protocol_and_lifecycle_refused_even_rehashed(self):
        for field, value in [('protocol_version', 1), ('protocol_bytes', 24), ('features', ['root_layout_probe_retry']),
                             ('service', True), ('target_title', 'other'), ('max_requests', 0),
                             ('console_validated', True), ('require_client_result', True)]:
            original = copy.deepcopy(self.manifest)
            self.manifest[field] = value; self.rebind()
            with self.subTest(field=field), self.assertRaises(ValueError): self.verify()
            self.manifest = original; self.rebind()

    def test_output_mutation_is_refused(self):
        for name in helper.OUTPUTS:
            path = self.out / name; original = path.read_bytes(); path.write_bytes(original + b' ')
            with self.subTest(name=name), self.assertRaises((ValueError, json.JSONDecodeError)): self.verify()
            path.write_bytes(original)

    def test_rehashed_wrong_source_and_project_are_refused(self):
        changed = copy.deepcopy(self.source); changed['project']['commit'] = '0'*40
        self.write('lapy-source.json', changed); self.rebind()
        with self.assertRaises(ValueError): self.verify()
        self.write('lapy-source.json', self.source); self.rebind()
        with self.assertRaises(ValueError): helper.validate_owned_helper(self.out, self.repo, {'commit':'0'*40})

    def test_dirty_source_and_protocol_mismatch_are_refused(self):
        path = self.repo / 'native/lapy_elevation_protocol.h'; path.write_bytes(b'changed protocol')
        with self.assertRaises(ValueError): self.verify()
        with self.assertRaises(ValueError): helper.source_record(self.repo, self.project)

    def test_rehashed_missing_units_tools_and_wrong_compiler_refused(self):
        for mutate in (lambda b: b['compiled_units'].pop(), lambda b: b['objects'].pop(helper.UNITS[0]),
                       lambda b: b['inputs']['llvm'].update(version='19.1.0'),
                       lambda b: b['inputs']['llvm']['tools'].pop('clang'),
                       lambda b: b['inputs']['sdk'].pop('target/lib/crt1.o'),
                       lambda b: b['inspection'].update(entry='0x400')):
            original = copy.deepcopy(self.build); mutate(self.build); self.rebind()
            with self.assertRaises(ValueError): self.verify()
            self.build = original; self.rebind()

    def test_linked_output_is_refused(self):
        for name in helper.OUTPUTS:
            path = self.out / name; original = path.read_bytes(); target=self.out / 'original'
            target.write_bytes(original); path.unlink(); path.symlink_to(target)
            with self.subTest(name=name), self.assertRaises(ValueError): self.verify()
            path.unlink(); path.write_bytes(original); target.unlink()

    def test_sdk_or_actual_inspection_mismatch_refused(self):
        sdk = self.out / 'inert-sdk'; sdk.mkdir()
        self.build['sdk_path'] = str(sdk)
        self.build['command_paths']['SDK'] = str(sdk)
        for command in self.build['commands']:
            command['argv'] = [arg.replace('/inert-sdk', str(sdk)) for arg in command['argv']]
        self.rebind()
        with patch.object(helper, 'producer_llvm_identity', return_value=self.host_llvm) as llvm, \
             patch.object(helper, 'sdk_record', return_value={}) as sdk_inputs, \
             patch.object(helper, 'inspect_elf') as inspect:
            with self.assertRaisesRegex(ValueError, 'helper SDK/link inspection differs'):
                helper.validate_owned_helper(self.out, self.repo, sdk=sdk)
            llvm.assert_called_once_with(sdk.resolve())
            sdk_inputs.assert_called_once_with(sdk.resolve())
            inspect.assert_not_called()
        with patch.object(helper, 'sdk_record', return_value=self.sdk), patch.object(helper, 'producer_llvm_identity', return_value=self.host_llvm), patch.object(helper, 'inspect_elf', return_value={}):
            with self.assertRaises(ValueError): helper.validate_owned_helper(self.out, self.repo, sdk=sdk)

    def test_build_failure_emits_no_admitted_manifest(self):
        sdk=self.out/'sdk';sdk.mkdir();output=self.out/'failed-build'
        llvm={**self.llvm, 'config':'/inert/llvm-config', 'bindir':'/inert', 'resource_headers':{'original.h':'e'*64}}
        with patch.object(helper, 'producer_llvm_identity', return_value=llvm), patch.object(helper, 'sdk_record', return_value=self.sdk), \
             patch.object(helper, 'project_identity', return_value=self.project), \
             patch.object(helper.subprocess, 'run', return_value=subprocess.CompletedProcess([],1,'','compile failed')):
            with self.assertRaises(ValueError): helper.build_owned_helper(self.repo,sdk,output)
        self.assertFalse((output/'lapy-manifest.json').exists())


    def test_duplicate_noncanonical_unknown_and_boolean_metadata_rejected(self):
        original = (self.out / 'lapy-manifest.json').read_bytes()
        for data in (original + b' ', original.replace(b'{', b'{"mode":"elf-helper",', 1),
                     original.replace(b'"max_requests":1', b'"max_requests":true'),
                     original.replace(b'"max_requests":1', b'"max_requests":NaN')):
            (self.out / 'lapy-manifest.json').write_bytes(data)
            with self.subTest(data=data[:60]), self.assertRaises(ValueError): self.verify()
        (self.out / 'lapy-manifest.json').write_bytes(original)
        self.manifest['unrecognized'] = 1; self.rebind()
        with self.assertRaises(ValueError): self.verify()

    def test_actual_object_map_and_identity_mutation_rejected(self):
        for path in [self.out / 'obj' / (unit + '.o') for unit in helper.UNITS] + [
                self.out / 'lapy.map', self.out / 'owned_identity.h']:
            original = path.read_bytes(); path.write_bytes(original + b' altered')
            with self.subTest(path=path), self.assertRaises(ValueError): self.verify()
            path.write_bytes(original)

    def test_command_or_host_tool_substitution_rejected_even_rehashed(self):
        mutations = [lambda b: b['commands'][0]['argv'].insert(1, '-DUNREVIEWED=1'),
                     lambda b: b['commands'][0].update(exit=1),
                     lambda b: b['commands'].pop(),
                     lambda b: b['commands'][4]['argv'].remove('-Wl,--no-undefined'),
                     lambda b: b['commands'][4]['argv'].insert(1, '/unreviewed.o'),
                     lambda b: b['commands'][-1]['argv'].__setitem__(0, '/unreviewed-analyzer'),
                     lambda b: b.update(console_validated=True),
                     lambda b: b.update(unrecognized=True)]
        for mutate in mutations:
            original = copy.deepcopy(self.build); mutate(self.build); self.rebind()
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): self.verify()
            self.build = original; self.rebind()

    def test_reviewed_cohort_and_license_mutation_rejected(self):
        path = self.repo / helper.DIRECTORY / 'REVIEWED-COHORT.json'
        original = path.read_bytes(); value = json.loads(original)
        for changed in [dict(value, files=[]), dict(value, license_notes=['MIT only'])]:
            path.write_bytes(helper.canonical(changed))
            with self.assertRaises(ValueError): helper.source_record(self.repo, self.project)
        path.write_bytes(original)

    def test_complete_mocked_build_preserves_actual_command_and_object_boundaries(self):
        sdk = self.out / 'sdk'; sdk.mkdir(); output = self.out / 'successful-inert-build'
        inspection = {'entry': '0x200', 'needed': list(helper.PROVIDERS)}
        seen = []
        def fake_run(argv, **kwargs):
            seen.append(argv)
            self.assertEqual(kwargs['env'], helper.compiler_environment(self.host_llvm))
            self.assertNotIn('CPATH', kwargs['env'])
            self.assertNotIn('C_INCLUDE_PATH', kwargs['env'])
            self.assertNotIn('LIBRARY_PATH', kwargs['env'])
            if '-c' in argv:
                Path(argv[argv.index('-o') + 1]).write_bytes(b'inert object ' + argv[argv.index('-c') + 1].encode())
            elif '-Wl,--no-undefined' in argv:
                Path(argv[argv.index('-o') + 1]).write_bytes(b'original inert target bytes')
                (output / 'lapy.map').write_bytes(b'inert compiler map')
            text = '1: 0000000000000200 16 FUNC GLOBAL DEFAULT 1 _start\n2: 0000000000000400 16 FUNC GLOBAL DEFAULT 1 main\n' if 'llvm-readelf' in argv[0] else ''
            return subprocess.CompletedProcess(argv, 0, text, '')
        with patch.dict(helper.os.environ, {'CPATH': '/untrusted', 'C_INCLUDE_PATH': '/untrusted', 'LIBRARY_PATH': '/untrusted'}), \
             patch.object(helper, 'producer_llvm_identity', return_value=self.host_llvm), \
             patch.object(helper, 'sdk_record', return_value=self.sdk), \
             patch.object(helper, 'project_identity', return_value=self.project), \
             patch.object(helper, 'inspect_elf', return_value=inspection), \
             patch.object(helper.subprocess, 'run', side_effect=fake_run):
            result = helper.build_owned_helper(self.repo, sdk, output)
        self.assertEqual(len(seen), 7)
        self.assertFalse(result['runtime_validated'])
        self.assertEqual(result['elf'], helper.record(output / 'lapy.elf'))
        self.assertEqual(helper.read_json(output / 'lapy-build.json', output=True)['commands'][0]['argv'], seen[0])

    def test_build_outputs_must_be_outside_source_and_sdk(self):
        sdk = self.out / 'sdk'; sdk.mkdir()
        for output in [self.repo / 'output', sdk / 'output', self.repo]:
            with self.subTest(output=output), self.assertRaises(ValueError): helper.build_owned_helper(self.repo, sdk, output)


    def test_coordinated_analyzer_root_and_argv_mutation_rejected(self):
        self.build['command_paths']['LLVM'] = '/unreviewed'
        for command in self.build['commands'][-len(helper.ANALYZERS):]:
            command['argv'][0] = command['argv'][0].replace('/inert/', '/unreviewed/')
        self.rebind()
        with self.assertRaises(ValueError): self.verify()

    def test_recorded_analyzer_path_and_environment_mutation_rejected(self):
        original = copy.deepcopy(self.build)
        self.build['host_llvm']['tools']['llvm-readelf']['path'] = '/other/llvm-readelf'
        self.rebind()
        with self.assertRaises(ValueError): self.verify()
        self.build = original; self.build['environment']['CPATH'] = '/unreviewed'; self.rebind()
        with self.assertRaises(ValueError): self.verify()

    def test_nested_float_and_boolean_byte_counts_rejected(self):
        original = copy.deepcopy(self.build)
        for value in (float(self.build['elf']['bytes']), True):
            self.build['elf']['bytes'] = value; self.rebind()
            with self.subTest(value=value), self.assertRaises(ValueError): self.verify()
            self.build = copy.deepcopy(original)
        self.rebind()


if __name__ == '__main__':
    unittest.main()
