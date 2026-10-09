#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Original filesystem-only controls. Never invokes Wine, sockets or a console."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest
import zipfile
from types import SimpleNamespace

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('seed_export', ROOT / 'tools/export_notepad_seed.py')
seed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(seed)


class SeedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def converter(self):
        original = Path(os.environ.get('PW_SEED_TEST_ORIGINAL', ROOT / 'tools/pw_prefix.py'))
        checkpoint = self.root / 'checkpoint'
        (checkpoint / 'pc/tools').mkdir(parents=True)
        shutil.copy2(original, checkpoint / 'pc/tools/pw_prefix.py')
        return seed.load_converter(checkpoint)

    def fixture(self):
        converter = self.converter()
        library = self.root / 'library'
        prefix = library / 'prefixes' / seed.SLUG
        for name in ['dosdevices', 'drive_c/windows/system32', 'drive_c/windows/syswow64',
                     'drive_c/windows/winsxs', 'drive_c/users/prospero', 'drive_c/windows/Fonts']:
            (prefix / name).mkdir(parents=True, exist_ok=True)
        (prefix / 'dosdevices/c:').symlink_to('../drive_c')
        (prefix / 'dosdevices/z:').symlink_to('/')
        system = b'WINE REGISTRY Version 2\n\n#arch=win64\n' + converter.CPU_KEY + b'\n@="wow64cpu.dll"\n'
        (prefix / 'system.reg').write_bytes(system)
        for name in ['user.reg', 'userdef.reg']:
            (prefix / name).write_text('WINE REGISTRY Version 2\n\n#arch=win64\n')
        (prefix / '.update-timestamp').write_text('1791470000\n')
        host = self.root / 'host'
        (host / 'lib/wine/x86_64-windows').mkdir(parents=True)
        (host / 'lib/wine/i386-windows').mkdir(parents=True)
        (host / 'share/wine/fonts').mkdir(parents=True)
        records = {}
        for name in ['drive_c/windows/system32/notepad.exe', 'drive_c/windows/system32/kernel32.dll',
                     'drive_c/windows/syswow64/kernel32.dll']:
            data = ('original inert fixture: ' + name).encode()
            (prefix / name).write_bytes(data)
            arch = 'i386-windows' if '/syswow64/' in name else 'x86_64-windows'
            host_name = 'lib/wine/' + arch + '/' + Path(name).name
            (host / host_name).write_bytes(data)
            records['pc/host-wine/usr/' + host_name] = {'sha256': hashlib.sha256(data).hexdigest()}
        font = host / 'share/wine/fonts/original.ttf'
        font.write_bytes(b'original inert font fixture')
        records['pc/host-wine/usr/share/wine/fonts/original.ttf'] = {'sha256': seed.sha(font)}
        (prefix / 'drive_c/windows/Fonts/original.ttf').symlink_to(font)
        profiles = library / 'profiles'
        profiles.mkdir()
        (profiles / (seed.SLUG + '.profile')).write_text('[application]\nid = diagnostic-notepad\n')
        return converter, library, prefix, host, records

    def test_metadata_binds_run_and_both_digests(self):
        run = {'id': seed.RUN, 'head_sha': seed.HEAD, 'status': 'completed', 'conclusion': 'success',
               'run_attempt': 1, 'path': '.github/workflows/diagnostic-kit.yml',
               'repository': {'full_name': seed.REPOSITORY}}
        records = {'artifacts': [{'id': v[0], 'digest': 'sha256:' + v[1], 'expired': False,
                   'workflow_run': {'id': seed.RUN, 'head_sha': seed.HEAD,
                                    'repository_id': 1410835302, 'head_repository_id': 1410835302}}
                                  for v in seed.INPUTS.values()]}
        seed.metadata(run, records)
        for change in [{'head_sha': '0' * 40}, {'conclusion': 'failure'}, {'run_attempt': 2}]:
            with self.assertRaises(ValueError): seed.metadata(dict(run, **change), records)
        records['artifacts'][0]['expired'] = True
        with self.assertRaises(ValueError): seed.metadata(run, records)

    def test_remote_never_escapes_or_overwrites(self):
        remote = seed.FilesystemRemote(self.root / 'export')
        remote.makedirs('/data/prospero-win/prefixes/diagnostic-notepad')
        target = '/data/prospero-win/prefixes/diagnostic-notepad/test'
        remote.write(target, b'first')
        with self.assertRaises(FileExistsError): remote.write(target, b'second')
        for path in ['/etc/passwd', '/data/prospero-win/../escape', '/data/prospero-win//escape']:
            with self.assertRaises(ValueError): remote.path(path)
        (remote.root / 'data/prospero-win/redirect').symlink_to(self.root)
        with self.assertRaises(ValueError): remote.path('/data/prospero-win/redirect/file')
        with self.assertRaises(ValueError): remote.delete(target)
        with self.assertRaises(ValueError): seed.FilesystemRemote(remote.root)
        self.assertEqual(remote.read(target), b'first')

    def test_original_sync_conversion_and_source_audit(self):
        converter, library, prefix, host, records = self.fixture()
        audit = seed.audit_source(converter, prefix, host, records)
        self.assertEqual(audit['drive_c/windows/Fonts/original.ttf']['source'], 'bound-host-runtime')
        cpu = self.root / 'original-cpu.dll'
        cpu.write_bytes(b'original inert CPU fixture')
        remote = seed.FilesystemRemote(self.root / 'export')
        self.assertEqual(converter.main(['push', seed.SLUG, '--library', str(library), '--cpu-dll', str(cpu)], remote), 0)
        out = remote.root / 'data/prospero-win'
        exported = out / 'prefixes' / seed.SLUG
        self.assertEqual((exported / 'system.reg').read_bytes(), converter.to_console('system.reg', (prefix / 'system.reg').read_bytes()))
        self.assertEqual((exported / 'dosdevices/.pw-symlinks').read_text(), 'c:\t../drive_c\nz:\t/\n')
        self.assertEqual((exported / converter.CPU_DLL).read_bytes(), cpu.read_bytes())
        self.assertFalse((out / 'profiles/profiles.lst').exists())
        self.assertFalse(any(p.is_symlink() for p in exported.rglob('*')))

    def test_unapproved_external_file_rejected(self):
        converter, _, prefix, host, records = self.fixture()
        outside = self.root / 'private.txt'
        outside.write_text('synthetic outside file')
        (prefix / 'outside.txt').symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'unapproved dereferenced'):
            seed.audit_source(converter, prefix, host, records)

    def test_unknown_bytes_and_case_collision_rejected(self):
        converter, _, prefix, host, records = self.fixture()
        unknown = prefix / 'drive_c/windows/system32/unknown.dll'
        unknown.write_bytes(b'unknown original fixture')
        with self.assertRaisesRegex(ValueError, 'unapproved generated/copied'):
            seed.audit_source(converter, prefix, host, records)
        unknown.unlink()
        (prefix / 'USER.REG').write_bytes((prefix / 'user.reg').read_bytes())
        with self.assertRaisesRegex(ValueError, 'case-colliding'):
            seed.audit_source(converter, prefix, host, records)

    def test_bound_file_in_wrong_core_location_rejected(self):
        converter, _, prefix, host, records = self.fixture()
        source = prefix / 'drive_c/windows/system32/kernel32.dll'
        (prefix / 'drive_c/windows/system32/notepad.exe').write_bytes(source.read_bytes())
        with self.assertRaisesRegex(ValueError, 'wrong initialized core module'):
            seed.audit_source(converter, prefix, host, records)

    def test_virtual_link_case_collisions_rejected(self):
        converter, _, prefix, host, records = self.fixture()
        alias = prefix / 'dosdevices/C:'
        alias.symlink_to('../drive_c')
        with self.assertRaisesRegex(ValueError, 'case-colliding prefix path'):
            seed.audit_source(converter, prefix, host, records)
        alias.unlink()
        alias.write_bytes((prefix / 'drive_c/windows/system32/notepad.exe').read_bytes())
        with self.assertRaisesRegex(ValueError, 'case-colliding prefix path'):
            seed.audit_source(converter, prefix, host, records)

    def test_registry_host_path_and_disable_timestamp_rejected(self):
        converter, _, prefix, host, records = self.fixture()
        with self.assertRaises(ValueError):
            seed.audit_text(b'WINE REGISTRY Version 2\n"path"="Z:\\\\home\\\\runner\\\\secret"', 'fixture')
        (prefix / '.update-timestamp').write_text('disable\n')
        with self.assertRaisesRegex(ValueError, 'timestamp'):
            seed.audit_source(converter, prefix, host, records)

    def test_archive_hash_and_traversal_rejected(self):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode='w:gz') as tar:
            item = tarfile.TarInfo('../escape')
            item.size = 1
            tar.addfile(item, io.BytesIO(b'x'))
        archive = self.root / 'original.zip'
        with zipfile.ZipFile(archive, 'w') as zipped:
            zipped.writestr('original.tar.gz', raw.getvalue())
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            seed.unpack(archive, self.root / 'hash-failure', '0' * 64, 'original.tar.gz')
        with self.assertRaisesRegex(ValueError, 'unsafe relative'):
            seed.unpack(archive, self.root / 'path-failure', seed.sha(archive), 'original.tar.gz')
        self.assertFalse((self.root / 'escape').exists())

    def test_failure_diagnostics_filter_and_bound(self):
        work = self.root / 'work'
        work.mkdir()
        (work / 'initialization.log').write_text('pw_install: failed under ' + str(work) + '\n')
        output = self.root / 'safe-diagnostics'
        seed.diagnostics(SimpleNamespace(work=work, out=output))
        self.assertIn('<seed-work>', (output / 'initialization.filtered.log').read_text())
        (work / 'initialization.log').write_text('Authorization: Bearer synthetic-secret\n')
        output = self.root / 'withheld-diagnostics'
        seed.diagnostics(SimpleNamespace(work=work, out=output))
        self.assertFalse((output / 'initialization.filtered.log').exists())
        self.assertIn('withheld', json.loads((output / 'DIAGNOSTICS.json').read_text())['initialization_log'])


if __name__ == '__main__':
    unittest.main()
