#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Original byte/filesystem controls; no Wine, GPU, socket or target execution."""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import prepare_windows_child_prefix as prefix
import portable_prefix_audit as audit


def image():
    value = bytearray(512)
    value[:2] = b'MZ'
    struct.pack_into('<I', value, 60, 128)
    value[128:132] = b'PE\0\0'
    struct.pack_into('<H', value, 132, 0x8664)
    struct.pack_into('<H', value, 152, 0x20b)
    struct.pack_into('<II', value, 152 + 152, 0x1000, 16)
    return value


class FixturePackage(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='pw-fixture-controls-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def pair(self):
        source = self.root / 'pair'; source.mkdir()
        for name in ('parent.exe', 'child.exe'):
            (source / name).write_bytes(image())
        project = {'commit': '1' * 40, 'tree': '2' * 40}
        metadata = {'schema': 'pw-original-windows-child-msvc/1', 'project': project, 'architecture': 'x64',
                    'compiler': {'name': 'MSVC cl.exe', 'file_version': '19.44', 'sha256': 'a' * 64},
                    'reference': {'exit': 0, 'deadline_seconds': 45}, 'files': {
            n: {'bytes': (source / n).stat().st_size, 'sha256': prefix.sha(source / n)}
            for n in ('parent.exe', 'child.exe')}}
        prefix.json_out(source / 'fixture-source.json', metadata)
        return source, project

    def test_pair_identity_and_machine(self):
        source, project = self.pair()
        self.assertEqual(prefix.validate_pair(source, project)['architecture'], 'x64')
        with self.assertRaisesRegex(ValueError, 'identity'):
            prefix.validate_pair(source, {'commit': '3' * 40, 'tree': '2' * 40})
        (source / 'child.exe').write_bytes(b'different')
        with self.assertRaisesRegex(ValueError, 'identical'):
            prefix.validate_pair(source, project)

    def test_pair_refuses_matching_but_non_amd64(self):
        source, project = self.pair()
        data = image(); struct.pack_into('<H', data, 132, 0x14c)
        for name in ('parent.exe', 'child.exe'):
            (source / name).write_bytes(data)
        metadata = json.loads((source / 'fixture-source.json').read_text())
        for record in metadata['files'].values():
            record['sha256'] = prefix.sha(source / 'parent.exe')
        (source / 'fixture-source.json').write_text(json.dumps(metadata))
        with self.assertRaisesRegex(ValueError, 'AMD64'):
            prefix.validate_pair(source, project)

    def test_changed_fixture_between_validation_and_copy_refused(self):
        source, project = self.pair()
        metadata = prefix.validate_pair(source, project)
        prefix.verify_pair_copy(source, metadata)
        (source / 'parent.exe').write_bytes(b'changed after validation')
        with self.assertRaisesRegex(ValueError, 'exported original'):
            prefix.verify_pair_copy(source, metadata)

    def test_inventory_binds_root_mode_and_empty_directories(self):
        root = self.root / 'tree'; root.mkdir(mode=0o700)
        (root / 'empty').mkdir(); (root / 'a').write_bytes(b'a')
        old = prefix.inventory(root)
        root.chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'mutation'):
            prefix.verify_delta(old, prefix.inventory(root), {})
        root.chmod(0o700); (root / 'empty').rmdir()
        with self.assertRaisesRegex(ValueError, 'additions'):
            prefix.verify_delta(old, prefix.inventory(root), {})

    def test_no_overwrite_or_input_nesting(self):
        owned = self.root / 'input'; owned.mkdir()
        with self.assertRaisesRegex(ValueError, 'exists'):
            prefix.absent(owned)
        with self.assertRaisesRegex(ValueError, 'overlaps'):
            prefix.absent(owned / 'out', (owned,))
        (self.root / 'alias').symlink_to(owned, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            prefix.absent(self.root / 'alias/out')

    def test_inventory_rejects_link_alias_and_special_objects(self):
        root = self.root / 'tree'; root.mkdir(); (root / 'empty').mkdir()
        (root / 'alias').symlink_to(root / 'empty', target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'link'):
            prefix.inventory(root)
        (root / 'alias').unlink(); (root / 'A').write_bytes(b'a'); (root / 'a').write_bytes(b'a')
        with self.assertRaisesRegex(ValueError, 'case-colliding'):
            prefix.inventory(root)

    def pe_tree(self):
        root, work = self.root / 'prefix', self.root / 'wine'
        expected = {}
        for arch, names in [('i386-windows', [f'm{i}' for i in range(10)]),
                            ('x86_64-windows', [f'm{i}' for i in range(12)])]:
            for name in names:
                directory = 'system32' if arch.startswith('x86_64') else 'syswow64'
                target = root / 'drive_c/windows' / directory / (name + '.dll')
                target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(b'host')
                source = work / 'pe' / arch / (name + '.dll')
                source.parent.mkdir(parents=True, exist_ok=True); source.write_bytes((arch + name).encode())
                expected[arch + '/' + name + '.dll'] = prefix.sha(source)
        (root / 'system.reg').write_bytes(b'registry unchanged')
        return root, work, expected

    def test_all_22_pe_changes_and_no_other_mutation(self):
        root, work, expected = self.pe_tree()
        before = prefix.inventory(root)
        changes = prefix.replace_pes(root, work, expected)
        self.assertEqual(len(changes), 22)
        prefix.verify_delta(before, prefix.inventory(root), changes)
        (root / 'system.reg').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'mutation'):
            prefix.verify_delta(before, prefix.inventory(root), changes)

    def test_pe_parent_link_never_writes_input(self):
        root, work, expected = self.pe_tree()
        system = root / 'drive_c/windows/syswow64'
        import shutil
        shutil.rmtree(system)
        victim = self.root / 'victim'; victim.mkdir()
        (victim / 'm0.dll').write_bytes(b'untouched')
        system.symlink_to(victim, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            prefix.replace_pes(root, work, expected)
        self.assertEqual((victim / 'm0.dll').read_bytes(), b'untouched')

    def test_stale_pe_hash_rejected(self):
        root, work, expected = self.pe_tree()
        name = sorted(expected)[0]
        (work / 'pe' / name).write_bytes(b'stale')
        with self.assertRaisesRegex(ValueError, 'changed'):
            prefix.replace_pes(root, work, expected)

    def test_cpu_substitution_rejected(self):
        root = self.root / 'cpu'; (root / 'x86_64-windows').mkdir(parents=True)
        dll = root / 'x86_64-windows/wowprospero.dll'; dll.write_bytes(b'bound-built-cpu')
        expected = {'project': {'commit': '1' * 40, 'tree': '2' * 40}, 'recipe_sha256': '3' * 64}
        prefix.json_out(root / 'cpu-build.json', {'schema': 'pw-fixture-cpu-build/1', 'inputs': expected,
            'outputs': {'x86_64-windows/wowprospero.dll': {'bytes': dll.stat().st_size, 'sha256': prefix.sha(dll)}},
            'executed': False})
        prefix.verify_cpu(root, expected)
        dll.write_bytes(b'substituted-cpu')
        with self.assertRaisesRegex(ValueError, 'output changed'):
            prefix.verify_cpu(root, expected)

    def test_unstaged_source_edit_rejected_without_index_change(self):
        source = self.root / 'source'; source.mkdir()
        subprocess.run(['git', 'init', '-q', str(source)], check=True)
        (source / 'loader.c').write_bytes(b'original')
        subprocess.run(['git', '-C', str(source), 'add', 'loader.c'], check=True)
        expected = prefix.source_snapshot(source)
        index = prefix.git(source, 'write-tree')
        prefix.verify_source_snapshot(source, expected)
        (source / 'loader.c').write_bytes(b'changed after staging')
        self.assertEqual(prefix.git(source, 'write-tree'), index)
        with self.assertRaisesRegex(ValueError, 'source bytes'):
            prefix.verify_source_snapshot(source, expected)

    def test_consumed_build_headers_tools_and_libraries_are_bound(self):
        work = self.root / 'host'
        names = ('tools/winegcc/winegcc', 'tools/winebuild/winebuild', 'dlls/ntdll/ntdll.so',
                 'dlls/wow64/x86_64-windows/libwow64.a', 'dlls/ntdll/x86_64-windows/libntdll.a',
                 'libs/winecrt0/x86_64-windows/libwinecrt0.a', 'libs/compiler-rt/x86_64-windows/libcompiler-rt.a',
                 'include/config.h', 'include/wine/exception.h')
        for name in names:
            path = work / 'build' / name
            path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(name.encode())
        before = prefix.consumed_build_inputs(work)
        self.assertEqual(set(before), set(names))
        for name in ('include/config.h', 'tools/winegcc/winegcc', 'dlls/ntdll/x86_64-windows/libntdll.a'):
            path = work / 'build' / name; original = path.read_bytes(); path.write_bytes(b'changed')
            self.assertNotEqual(before, prefix.consumed_build_inputs(work))
            path.write_bytes(original)
        external = self.root / 'external'; external.mkdir(); (external / 'private.h').write_bytes(b'not an input')
        (work / 'build/include/alias').symlink_to(external, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'topology'):
            prefix.consumed_build_inputs(work)

    def test_selected_compiler_and_linker_bytes_are_bound(self):
        tools = self.root / 'compiler'; tools.mkdir()
        for name in ('gcc', 'cc1', 'as', 'ld'):
            (tools / name).write_bytes(name.encode())
        include = tools / 'include'; include.mkdir(); (include / 'stddef.h').write_bytes(b'header')
        def query(command, **kwargs):
            flag = command[1]
            value = ('original compiler version' if flag == '--version' else str(include) if flag.endswith('=include')
                     else str(tools / flag.split('=', 1)[1]))
            return subprocess.CompletedProcess(command, 0, value + '\n', '')
        with (mock.patch.object(prefix.shutil, 'which', return_value=str(tools / 'gcc')),
              mock.patch.object(prefix.subprocess, 'run', side_effect=query)):
            before = prefix.compiler_inputs('gcc')
            (tools / 'ld').write_bytes(b'changed linker')
            self.assertNotEqual(before, prefix.compiler_inputs('gcc'))

    def test_registry_audit_does_not_broaden_root_exemption(self):
        for key in audit.ROOT_DEVICE_KEYS:
            data = ('WINE REGISTRY Version 2\n[' + key.replace('\\', '\\\\') + '] 1\n').encode()
            audit.audit_text(data, 'system.reg')
        with self.assertRaisesRegex(ValueError, 'host path'):
            audit.audit_text(b'WINE REGISTRY Version 2\n[Environment] 1\n"PATH"="/home/private"\n', 'system.reg')
        with self.assertRaisesRegex(ValueError, 'host path'):
            audit.audit_text(b'WINE REGISTRY Version 2\n[System\\\\ROOT\\\\UNKNOWN] 1\n', 'system.reg')

    def test_metadata_diagnostics_never_accept_arbitrary_text(self):
        with self.assertRaisesRegex(ValueError, 'unexpected metadata'):
            audit.unapproved_metadata({'files': [{'path': 'bad', 'bytes': 1, 'sha256': '0' * 64, 'contents': 'private'}],
                                       'scan_complete': True})
        encoded = audit.unapproved_metadata({'files': [{'path': 'unknown.dat', 'bytes': 1, 'sha256': '0' * 64}],
                                            'scan_complete': True})
        self.assertNotIn(b'contents', encoded)

    def test_filesystem_remote_keeps_link_tables_and_refuses_delete(self):
        remote = audit.FilesystemRemote(self.root / 'console')
        remote.makedirs('/data/prospero-win/prefixes/' + prefix.SLUG)
        with self.assertRaises(ValueError):
            remote.delete('/data/prospero-win/prefixes/' + prefix.SLUG)
        with self.assertRaises(ValueError):
            remote.path('/data/prospero-win/../escape')

    def test_actual_profile_constructor_uses_fixed_pe64_slot(self):
        import pw_install
        host = self.root / 'host'; (host / 'bin').mkdir(parents=True)
        for name in ('wine', 'wineserver'):
            (host / 'bin' / name).write_bytes(b'not executed')
        library = self.root / 'library'
        app = library / 'prefixes' / prefix.SLUG / prefix.APP
        app.mkdir(parents=True)
        (app / 'parent.exe').write_bytes(image())
        args = argparse.Namespace(slug=prefix.SLUG, library=str(library), wine=str(host / 'bin/wine'),
                                  resolution='1920x1080', file=[], input=[], disc=None, mesa_zink=None)
        setup = pw_install.Installer(prefix.recipe(), ROOT / 'tools/prepare_windows_child_prefix.py', args)
        profile = setup.profile([])
        for line in ('id = windows-child-fixture-v1', 'executable = C:\\windows-child-fixture\\parent.exe',
                     'working_directory = C:\\windows-child-fixture', 'prefix = windows-child-fixture-v1',
                     'runtime = wine-wow64', 'architecture = pe64', 'graphics = auto'):
            self.assertIn(line + '\n', profile)
        self.assertNotIn('dll_overrides', profile)
        self.assertNotIn('arguments =', profile)
        audit.audit_text(profile.encode(), 'profile')

    def test_initialize_calls_only_existing_prefix_task_and_server_wait(self):
        repo, host_work = self.root / 'repo', self.root / 'host-work'
        repo.mkdir(); host_work.mkdir()
        args = argparse.Namespace(repo=repo, host_work=host_work, work=self.root / 'sterile', cohort=self.root / 'cohort')
        setup = mock.Mock()
        setup.gamedir = args.work / 'library/prefixes' / prefix.SLUG
        setup.wineserver = host_work / 'install/usr/bin/wineserver'
        setup.wine_env.return_value = {'USER': 'prospero'}
        with (mock.patch.dict(os.environ, {}, clear=True),
              mock.patch.object(prefix, 'host_identity', return_value=({}, host_work / 'install/usr')),
              mock.patch.object(prefix, 'installer', return_value=setup),
              mock.patch.object(prefix.subprocess, 'run') as run):
            prefix.initialize(args)
        setup.task.assert_called_once_with({'name': 'create_prefix'})
        run.assert_called_once_with([str(setup.wineserver), '-w'], env={'USER': 'prospero'}, check=True, timeout=60)


if __name__ == '__main__':
    unittest.main()
