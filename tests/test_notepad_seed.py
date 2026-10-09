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
import struct
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

    def test_timestamp_text_mode_line_endings_preserved(self):
        converter, library, prefix, host, records = self.fixture()
        timestamp = prefix / '.update-timestamp'
        # wineboot uses _wopen without O_BINARY; MSVCRT _write turns LF
        # into CRLF. The filesystem converter preserves those original bytes.
        for data in (b'1791470000\r\n', b'1791470000\n', b'1791470000'):
            with self.subTest(data=data):
                timestamp.write_bytes(data)
                audit = seed.audit_source(converter, prefix, host, records)
                self.assertEqual(audit['.update-timestamp']['sha256'], hashlib.sha256(data).hexdigest())
        timestamp.write_bytes(b'1791470000\r\n')
        cpu = self.root / 'original-cpu.dll'
        cpu.write_bytes(b'original inert CPU fixture')
        remote = seed.FilesystemRemote(self.root / 'export')
        self.assertEqual(converter.main(['push', seed.SLUG, '--library', str(library), '--cpu-dll', str(cpu)], remote), 0)
        exported = remote.root / 'data/prospero-win/prefixes' / seed.SLUG / '.update-timestamp'
        self.assertEqual(exported.read_bytes(), b'1791470000\r\n')

    def test_timestamp_empty_markers_and_malformed_endings_rejected(self):
        converter, _, prefix, host, records = self.fixture()
        for data in (b'', b'disable', b'disable\r\n', b'12\r', b'12\r\r\n',
                     b'12\nextra', b'1\n2\n', b' 123\r\n', b'+123\r\n', b'-1\r\n',
                     b'\xef\xbb\xbf123\r\n', b'123\x00\r\n'):
            with self.subTest(data=data):
                (prefix / '.update-timestamp').write_bytes(data)
                with self.assertRaisesRegex(ValueError, 'invalid initialization timestamp'):
                    seed.audit_source(converter, prefix, host, records)

    def ne_container(self, duplicate=False):
        """Original inert PE/NE data fixture; never executed."""
        data = bytearray(1536)
        def word(at, n): struct.pack_into('<H', data, at, n)
        def dword(at, n): struct.pack_into('<I', data, at, n)
        data[:2] = b'MZ'; data[64:81] = b'Wine builtin DLL\0'; dword(60, 128)
        data[128:132] = b'PE\0\0'; word(132, 0x14c); word(134, 1); word(148, 224)
        word(152, 0x10b); dword(152 + 92, 16); dword(152 + 96, 4096); dword(152 + 100, 128)
        section = 152 + 224
        dword(section + 8, 1024); dword(section + 12, 4096)
        dword(section + 16, 1024); dword(section + 20, 512)
        count = 2 if duplicate else 1
        dword(532, count); dword(536, count)
        dword(540, 0x1040); dword(544, 0x1050); dword(548, 0x1058)
        for index in range(count):
            dword(576 + 4 * index, 0x1200); dword(592 + 4 * index, 0x1060); word(600 + 2 * index, index)
        name = b'__wine_spec_dos_header\0'
        data[608:608 + len(name)] = name
        data[1024:1026] = b'MZ'; dword(1024 + 40, 160); dword(1024 + 60, 96)
        data[1120:1122] = b'NE'
        return data

    def test_embedded_ne_exact_slice_and_source_unchanged(self):
        data = self.ne_container()
        path = self.root / 'original.exe16'; path.write_bytes(data)
        expected = bytearray(data[1024:1184]); expected[40:44] = b'\0' * 4
        self.assertEqual(seed.embedded_ne_image(path), bytes(expected))
        self.assertEqual(path.read_bytes(), bytes(data))

    def test_embedded_ne_malformed_sources_refused(self):
        cases = [self.ne_container(duplicate=True)]
        for at, form, value in ((1024 + 40, '<I', 4096), (1024 + 60, '<I', 159),
                                 (132, '<H', 0x8664), (600, '<H', 9), (152 + 96, '<I', 0xffffffff)):
            data = self.ne_container(); struct.pack_into(form, data, at, value); cases.append(data)
        data = self.ne_container(); data[1120:1122] = b'PE'; cases.append(data)
        for index, data in enumerate(cases):
            with self.subTest(index=index):
                path = self.root / ('bad-' + str(index) + '.exe16'); path.write_bytes(data)
                with self.assertRaises(ValueError): seed.embedded_ne_image(path)

    def test_generated_hash_and_destination_both_required(self):
        converter, _, prefix, host, records = self.fixture()
        container = self.root / 'original.exe16'; container.write_bytes(self.ne_container())
        image = seed.embedded_ne_image(container)
        name = 'drive_c/windows/rundll.exe'
        generated = {hashlib.sha256(image).hexdigest(): {'method': 'original-fixture-derivation',
                     'names': ['rundll.exe'], 'paths': [name], 'bytes': len(image)}}
        target = prefix / name; target.write_bytes(image)
        audit = seed.audit_source(converter, prefix, host, records, generated=generated)
        self.assertEqual(audit[name]['source'], 'bound-runtime-generated-module')
        target.write_bytes(image[:-1] + b'X')
        with self.assertRaisesRegex(ValueError, 'unapproved generated/copied'):
            seed.audit_source(converter, prefix, host, records, generated=generated)
        target.unlink()
        (prefix / 'drive_c/windows/system32/rundll.exe').write_bytes(image)
        with self.assertRaisesRegex(ValueError, 'unapproved generated/copied'):
            seed.audit_source(converter, prefix, host, records, generated=generated)

    def test_placeholder_exact_byte_identities(self):
        expected = {False: 'cbae5b921774d73c6fbcb5a9fcc54156783f360a69db802382ee8cc1585b9fe4',
                    True: 'db51e6e7b76795c95f8fe77732b1367e22a33c6b499305af135a568823a4c607'}
        for is_dll, digest in expected.items():
            image = seed.placeholder_i386(is_dll)
            self.assertEqual(len(image), 1032)
            self.assertEqual(hashlib.sha256(image).hexdigest(), digest)
            self.assertEqual(struct.unpack_from('<H', image, 100)[0], 0x14c)
            self.assertEqual(struct.unpack_from('<H', image, 118)[0], 0x2000 if is_dll else 0)
            self.assertEqual(image[1024:], b'\0' * 8)

    def test_vulkan_json_exact_values_bytes_and_paths(self):
        converter, _, prefix, host, records = self.fixture()
        content = (b'{\n    "file_format_version": "1.0.0",\n    "ICD": {\n'
                   b'        "library_path": ".\\\\winevulkan.dll",\n'
                   b'        "api_version": "1.4.357"\n    }\n}\n')
        self.assertEqual(hashlib.sha256(content).hexdigest(), seed.VULKAN_JSON_SHA)
        paths = ['drive_c/windows/system32/winevulkan.json', 'drive_c/windows/syswow64/winevulkan.json']
        generated = {seed.VULKAN_JSON_SHA: {'kind': 'data', 'names': ['winevulkan.json'], 'paths': paths}}
        for name in paths: (prefix / name).write_bytes(content)
        audit = seed.audit_source(converter, prefix, host, records, generated=generated)
        self.assertTrue(all(audit[name]['source'] == 'bound-runtime-generated-data' for name in paths))
        for changed in (content.replace(b'.\\\\winevulkan.dll', b'C:\\\\other.dll'),
                        content.replace(b'1.4.357', b'1.4.999'), content.replace(b'{\n', b'{ \n', 1),
                        content.replace(b'"ICD": {', b'"extra": 1, "ICD": {')):
            with self.subTest(changed=changed):
                (prefix / paths[0]).write_bytes(changed)
                with self.assertRaisesRegex(ValueError, 'unapproved generated/copied'):
                    seed.audit_source(converter, prefix, host, records, generated=generated)
        (prefix / paths[0]).write_bytes(content)
        (prefix / 'drive_c/windows/winevulkan.json').write_bytes(content)
        with self.assertRaisesRegex(ValueError, 'unapproved generated/copied'):
            seed.audit_source(converter, prefix, host, records, generated=generated)

    def test_unknown_metadata_collects_all_and_does_not_skip_text_guards(self):
        converter, _, prefix, host, records = self.fixture()
        unknown = {'drive_c/aaa-original.bin': b'first unapproved fixture',
                   'drive_c/zzz-original.bin': b'second unapproved fixture'}
        for name, content in unknown.items(): (prefix / name).write_bytes(content)
        (prefix / 'user.reg').write_bytes(b'WINE REGISTRY Version 2\n"path"="Z:\\\\home\\\\runner"')
        issues = {}
        with self.assertRaisesRegex(ValueError, '2 total; export refused'):
            seed.audit_source(converter, prefix, host, records, issues=issues)
        self.assertTrue(issues['scan_complete'])
        self.assertEqual(issues['files'], [{'path': name, 'bytes': len(data),
                         'sha256': hashlib.sha256(data).hexdigest()} for name, data in sorted(unknown.items())])
        encoded = seed.unapproved_metadata(issues)
        self.assertNotIn(b'first unapproved fixture', encoded)
        self.assertNotIn(b'user.reg', encoded)
        for name in unknown: (prefix / name).unlink()
        with self.assertRaisesRegex(ValueError, 'host path/environment'):
            seed.audit_source(converter, prefix, host, records)

    def test_unknown_scan_stops_on_unsafe_file_and_marks_incomplete(self):
        converter, _, prefix, host, records = self.fixture()
        (prefix / 'drive_c/aaa-original.bin').write_bytes(b'original unknown')
        outside = self.root / 'outside'; outside.write_bytes(b'not read or uploaded')
        (prefix / 'zzz-outside').symlink_to(outside)
        issues = {}
        with self.assertRaisesRegex(ValueError, 'unapproved dereferenced'):
            seed.audit_source(converter, prefix, host, records, issues=issues)
        self.assertFalse(issues['scan_complete'])
        self.assertEqual(len(issues['files']), 1)
        self.assertNotIn(b'not read or uploaded', seed.unapproved_metadata(issues))

    def test_unknown_metadata_rejects_extra_fields_escape_and_bounds(self):
        record = {'path': 'drive_c/windows/unknown.bin', 'bytes': 4, 'sha256': 'a' * 64}
        issues = {'files': [record], 'scan_complete': True}
        seed.unapproved_metadata(issues)
        for changed in (dict(record, content='never upload'), dict(record, path='../outside'),
                        dict(record, path='/absolute'), dict(record, path='x' * 1025),
                        dict(record, bytes=True), dict(record, sha256='not-a-hash')):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                seed.unapproved_metadata({'files': [changed], 'scan_complete': True})
        with self.assertRaises(ValueError):
            seed.unapproved_metadata({'files': [record, record], 'scan_complete': True})
        old = seed.MAX_METADATA_BYTES
        try:
            seed.MAX_METADATA_BYTES = 8
            with self.assertRaises(ValueError): seed.unapproved_metadata(issues)
        finally:
            seed.MAX_METADATA_BYTES = old

    def test_diagnostics_retains_only_valid_unknown_metadata(self):
        work = self.root / 'work'; work.mkdir()
        issues = {'scan_complete': True, 'files': [{'path': 'drive_c/windows/unknown.bin',
                  'bytes': 4, 'sha256': 'a' * 64}]}
        metadata = work / 'UNAPPROVED-FILES.json'; metadata.write_bytes(seed.unapproved_metadata(issues))
        out = self.root / 'approved-diagnostics'
        seed.diagnostics(SimpleNamespace(work=work, out=out))
        self.assertEqual(json.loads((out / 'UNAPPROVED-FILES.json').read_text()), issues)
        issues['files'][0]['content'] = 'private synthetic content'
        metadata.write_text(json.dumps(issues))
        out = self.root / 'withheld-diagnostics'
        seed.diagnostics(SimpleNamespace(work=work, out=out))
        self.assertFalse((out / 'UNAPPROVED-FILES.json').exists())
        self.assertIn('withheld', json.loads((out / 'DIAGNOSTICS.json').read_text())['unapproved_files'])

    def text_report(self, data, name='system.reg'):
        record = seed.text_findings(data, name)
        return {'schema': 'pw-seed-text-audit/1', 'files': [record],
                'scan_complete': record['scan_complete']}

    def test_text_metadata_all_files_without_changing_rejection(self):
        converter, _, prefix, host, records = self.fixture()
        key = br'Software\\Microsoft\\Windows NT\\CurrentVersion\\Fonts'
        original = (prefix / 'system.reg').read_bytes()
        system = original + b'\n[' + key + b'] 123\n"Unknown font face"="Z:\\\\home\\\\runner\\\\private-font.ttf"\n'
        (prefix / 'system.reg').write_bytes(system)
        user = b'WINE REGISTRY Version 2\n[Environment] 123\n"TEMP"="Z:\\\\tmp\\\\synthetic-private"\n'
        (prefix / 'user.reg').write_bytes(user)
        ini = b'[original]\npath=/opt/synthetic-private\n'
        (prefix / 'drive_c/windows/win.ini').write_bytes(ini)
        issues = {}
        with self.assertRaisesRegex(ValueError, 'host path/environment in generated text: drive_c/windows/win.ini'):
            seed.audit_source(converter, prefix, host, records, text_issues=issues)
        self.assertTrue(issues['scan_complete'])
        self.assertEqual(sum(len(r['findings']) for r in issues['files']), 3)
        finding = next(r for r in issues['files'] if r['path'] == 'system.reg')['findings'][0]
        self.assertEqual(finding['key'], r'Software\Microsoft\Windows NT\CurrentVersion\Fonts')
        self.assertIsNone(finding['value_name'])
        self.assertEqual(finding['value_name_sha256'], hashlib.sha256(b'Unknown font face').hexdigest())
        self.assertEqual(finding['classifications'], ['host-home'])
        encoded = seed.text_metadata(issues)
        for private in (b'private-font', b'synthetic-private', b'Unknown font face', b'home\\\\runner'):
            self.assertNotIn(private, encoded)
        self.assertEqual((prefix / 'system.reg').read_bytes(), system)
        self.assertEqual((prefix / 'user.reg').read_bytes(), user)
        self.assertEqual((prefix / 'drive_c/windows/win.ini').read_bytes(), ini)

    def test_text_metadata_labels_are_only_static_allowlist(self):
        data = (b'WINE REGISTRY Version 2\n[Software\\\\Private-Customer-Name] 1\n'
                b'"synthetic-secret-name"="/home/synthetic-secret-value"\n'
                b'[Environment] 2\n"TEMP"="/tmp/another-secret"\n'
                b'[broken /home/private-key\n"TEMP"="/usr/private"\n')
        report = self.text_report(data)
        encoded = seed.text_metadata(report)
        for private in (b'Private-Customer', b'synthetic-secret', b'another-secret', b'private-key'):
            self.assertNotIn(private, encoded)
        findings = report['files'][0]['findings']
        self.assertIsNone(findings[0]['key'])
        self.assertIsNone(findings[0]['value_name'])
        self.assertEqual(findings[1]['key'], 'Environment')
        self.assertEqual(findings[1]['value_name'], 'TEMP')
        self.assertIsNone(findings[2]['key'])
        self.assertIsNone(findings[3]['key'])
        self.assertEqual(report['files'][0]['sha256'], hashlib.sha256(data).hexdigest())

    def test_text_metadata_invalid_encoding_header_nul_and_position(self):
        data = b'invalid header\n"name"="/home/private"\n;\xff\x00\n'
        report = self.text_report(data)
        self.assertEqual([f['line'] for f in report['files'][0]['findings']], [1, 2, 3])
        self.assertEqual(report['files'][0]['findings'][0]['classifications'], ['invalid-registry-header'])
        self.assertEqual(report['files'][0]['findings'][2]['classifications'], ['invalid-utf8', 'nul'])
        self.assertNotIn(b'private', seed.text_metadata(report))

    def test_text_metadata_bound_and_structural_incompleteness(self):
        data = b'WINE REGISTRY Version 2\n' + b'"TEMP"="/tmp/private"\n' * (seed.MAX_TEXT_FINDINGS + 1)
        report = self.text_report(data)
        self.assertFalse(report['scan_complete'])
        self.assertEqual(len(report['files'][0]['findings']), seed.MAX_TEXT_FINDINGS)
        seed.text_metadata(report)
        converter, _, prefix, host, records = self.fixture()
        (prefix / 'drive_c/unknown').write_bytes(b'unknown inert bytes')
        issues = {}
        with self.assertRaisesRegex(ValueError, 'unapproved generated/copied'):
            seed.audit_source(converter, prefix, host, records, text_issues=issues)
        self.assertEqual(issues, {'schema': 'pw-seed-text-audit/1', 'files': [], 'scan_complete': False})
        seed.text_metadata(issues)

    def test_text_metadata_rejects_extra_fields_names_and_types(self):
        report = self.text_report(b'WINE REGISTRY Version 2\n[Environment] 1\n"TEMP"="/tmp/private"\n')
        changes = [('content', 'private'), ('key', 'Software\\Private'), ('value_name', 'private'),
                   ('line', True), ('line', -1), ('record_bytes', True), ('record_bytes', 100000),
                   ('classifications', ['raw-private-classification']), ('key_sha256', 'invalid')]
        for field, value in changes:
            changed = json.loads(json.dumps(report))
            changed['files'][0]['findings'][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                seed.text_metadata(changed)
        changed = json.loads(json.dumps(report)); changed['files'][0]['path'] = '../system.reg'
        with self.assertRaises(ValueError): seed.text_metadata(changed)
        changed = json.loads(json.dumps(report)); changed['files'][0]['scan_complete'] = False
        with self.assertRaises(ValueError): seed.text_metadata(changed)
        old = seed.MAX_TEXT_METADATA_BYTES
        try:
            seed.MAX_TEXT_METADATA_BYTES = 8
            with self.assertRaises(ValueError): seed.text_metadata(report)
        finally:
            seed.MAX_TEXT_METADATA_BYTES = old

    def test_diagnostics_retains_only_whitelisted_text_metadata(self):
        work = self.root / 'work'; work.mkdir()
        report = self.text_report(b'WINE REGISTRY Version 2\n[Environment] 1\n"TEMP"="/tmp/private"\n')
        metadata = work / 'TEXT-AUDIT.json'; metadata.write_bytes(seed.text_metadata(report))
        output = self.root / 'approved-text-diagnostics'
        seed.diagnostics(SimpleNamespace(work=work, out=output))
        self.assertEqual(json.loads((output / 'TEXT-AUDIT.json').read_text()), report)
        report['files'][0]['findings'][0]['content'] = 'private-value-never-uploaded'
        metadata.write_text(json.dumps(report))
        output = self.root / 'withheld-text-diagnostics'
        seed.diagnostics(SimpleNamespace(work=work, out=output))
        self.assertFalse((output / 'TEXT-AUDIT.json').exists())
        self.assertIn('withheld', json.loads((output / 'DIAGNOSTICS.json').read_text())['text_findings'])

    def portable_fixture(self):
        converter, library, prefix, host, records = self.fixture()
        for filename in seed.FONT_FACES:
            font = host / 'share/wine/fonts' / filename
            font.write_bytes(('original inert font: ' + filename).encode())
            records['pc/host-wine/usr/share/wine/fonts/' + filename] = {'sha256': seed.sha(font)}
        originals = {}
        for name in sorted(seed.REGISTRIES):
            data = (prefix / name).read_bytes()
            for key in seed.FONT_KEYS[name]:
                data += b'\n[' + key.replace('\\', '\\\\').encode() + b'] 123\n'
                for filename, face in seed.FONT_FACES.items():
                    source = 'Z:' + str((host / 'share/wine/fonts' / filename).resolve()).replace('/', '\\')
                    data += seed.font_registry_line(face, source) + b'\n'
            data += b'\n[Software\\\\OriginalFixture] 123\n"Keep"="C:\\\\portable-unrelated"\n'
            if name == 'system.reg':
                for key in sorted(seed.ROOT_DEVICE_KEYS):
                    data += b'\n[' + key.replace('\\', '\\\\').encode() + b'] 123\n"Keep"=dword:00000001\n'
            (prefix / name).write_bytes(data)
            originals[name] = data
        return converter, library, prefix, host, records, originals

    def test_exact_root_section_headers_only(self):
        for key in seed.ROOT_DEVICE_KEYS:
            section = '[' + key.replace('\\', '\\\\') + '] 123'
            data = ('WINE REGISTRY Version 2\n' + section + '\n"Keep"="C:\\\\portable"\n').encode()
            seed.audit_text(data, 'system.reg')
            with self.assertRaisesRegex(ValueError, 'host path/environment'):
                seed.audit_text(data, 'user.reg')
            for changed in (section + ' /home/private', section.replace('] 123', '\\\\extra] 123'),
                            section.replace('] 123', '] bad'), section.replace('] 123', '] 123\r')):
                with self.subTest(section=changed), self.assertRaisesRegex(ValueError, 'host path/environment'):
                    seed.audit_text(changed.encode(), 'system.reg')
            with self.assertRaisesRegex(ValueError, 'host path/environment'):
                seed.audit_text((section + '\n"Keep"="Z:\\\\root\\\\private"\n').encode(), 'system.reg')
        with self.assertRaises(ValueError):
            seed.audit_text(b'[System\\\\ControlSet001\\\\Enum\\\\ROOT\\\\UNKNOWN] 123\n', 'system.reg')

    def test_portable_font_conversion_preserves_originals_and_unrelated_values(self):
        converter, library, prefix, host, records, originals = self.portable_fixture()
        assets = seed.copy_portable_fonts(prefix, host, records)
        self.assertEqual(len(assets), 6)
        plans = {name: seed.portable_registry(name, data, host) for name, data in originals.items()}
        self.assertEqual(sum(len(p['rewrites']) for p in plans.values()), 18)
        self.assertEqual(plans['userdef.reg']['data'], originals['userdef.reg'])
        issues = {}
        audit = seed.audit_source(converter, prefix, host, records, registry_plans=plans, text_issues=issues)
        self.assertEqual(len(audit['system.reg']['font_portability']['rewrites']), 12)
        self.assertEqual(audit['system.reg']['sha256'], hashlib.sha256(originals['system.reg']).hexdigest())
        self.assertEqual(audit['user.reg']['font_portability']['portable_sha256'],
                         hashlib.sha256(plans['user.reg']['data']).hexdigest())
        self.assertNotIn('data', audit['system.reg']['font_portability'])
        old_converter = converter.to_console
        cpu = self.root / 'original-cpu.dll'; cpu.write_bytes(b'original inert CPU fixture')
        remote = seed.FilesystemRemote(self.root / 'portable-export')
        args = ['push', seed.SLUG, '--library', str(library), '--cpu-dll', str(cpu)]
        self.assertEqual(seed.sync_portable_registry(converter, args, remote, plans, prefix), 0)
        self.assertIs(converter.to_console, old_converter)
        exported = remote.root / 'data/prospero-win/prefixes' / seed.SLUG
        for name, plan in plans.items():
            self.assertEqual((prefix / name).read_bytes(), originals[name])
            self.assertEqual((exported / name).read_bytes(), converter.to_console(name, plan['data']))
            self.assertIn(b'"Keep"="C:\\\\portable-unrelated"', plan['data'])
        for asset in assets.values():
            self.assertEqual(seed.sha(exported / asset['destination']), asset['sha256'])
        # The source diagnostic remains raw-input metadata; it is not a success flag.
        self.assertEqual(sum(len(r['findings']) for r in issues['files']), 25)

    def test_font_asset_mismatch_escape_and_case_collision_refused(self):
        _, _, prefix, host, records, _ = self.portable_fixture()
        assets = seed.copy_portable_fonts(prefix, host, records)
        self.assertEqual(seed.copy_portable_fonts(prefix, host, records), assets)
        font = prefix / assets['marlett.ttf']['destination']
        font.write_bytes(b'wrong existing bytes')
        with self.assertRaisesRegex(ValueError, 'existing portable font differs'):
            seed.copy_portable_fonts(prefix, host, records)
        font.write_bytes((host / 'share/wine/fonts/marlett.ttf').read_bytes())
        outside = self.root / 'outside-font'; outside.write_bytes(font.read_bytes())
        font.unlink(); font.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'destination escapes'):
            seed.copy_portable_fonts(prefix, host, records)
        font.unlink(); font.write_bytes(outside.read_bytes())
        alias = font.with_name('MARLETT.TTF'); alias.write_bytes(font.read_bytes())
        with self.assertRaisesRegex(ValueError, 'case-colliding portable-font file'):
            seed.copy_portable_fonts(prefix, host, records)
        alias.unlink()
        (host / 'share/wine/fonts/marlett.ttf').write_bytes(b'changed parent')
        with self.assertRaisesRegex(ValueError, 'differs from bound runtime'):
            seed.copy_portable_fonts(prefix, host, records)

    def test_font_directory_redirect_refused(self):
        _, _, prefix, host, records, _ = self.portable_fixture()
        directory = prefix / 'drive_c/windows/Fonts'
        (directory / 'original.ttf').unlink(); directory.rmdir()
        outside = self.root / 'outside-directory'; outside.mkdir()
        directory.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'unsafe portable-font directory'):
            seed.copy_portable_fonts(prefix, host, records)
        self.assertEqual(list(outside.iterdir()), [])

    def test_font_registry_exact_path_type_name_and_count_required(self):
        _, _, prefix, host, _, originals = self.portable_fixture()
        original = originals['user.reg']
        line = next(line for line in original.splitlines() if line.startswith(b'"Tahoma (TrueType)"='))
        changes = [original.replace(line + b'\n', b''),
                   original.replace(line, line + b'\n' + line),
                   original.replace(line, line.replace(b'="', b'=str(2):"')),
                   original.replace(line, line.replace(b'"Tahoma', b'"tahoma')),
                   original.replace(line, line.replace(b'tahoma.ttf', b'unknown.ttf')),
                   original.replace(line, line.replace(b'"Tahoma', b'"T\\x61homa')),
                   original.replace(line, line + b'\n"Tahoma (TrueType)"="C:\\\\elsewhere.ttf"'),
                   original + original]
        for changed in changes:
            with self.subTest(changed_sha=hashlib.sha256(changed).hexdigest()), self.assertRaises(ValueError):
                seed.portable_registry('user.reg', changed, host)
        self.assertEqual((prefix / 'user.reg').read_bytes(), original)

    def test_unrelated_host_path_still_rejected_after_exact_relocation(self):
        converter, _, prefix, host, records, originals = self.portable_fixture()
        seed.copy_portable_fonts(prefix, host, records)
        bad = originals['user.reg'] + b'\n[Software\\\\Unrelated] 123\n"path"="Z:\\\\home\\\\private"\n'
        (prefix / 'user.reg').write_bytes(bad); originals['user.reg'] = bad
        plans = {n: seed.portable_registry(n, d, host) for n, d in originals.items()}
        with self.assertRaisesRegex(ValueError, 'host path/environment'):
            seed.audit_source(converter, prefix, host, records, registry_plans=plans)
        self.assertIn(b'Z:\\\\home\\\\private', plans['user.reg']['data'])

    def test_converter_restored_on_push_failure_and_late_registry_change(self):
        converter, library, prefix, host, records, originals = self.portable_fixture()
        seed.copy_portable_fonts(prefix, host, records)
        plans = {n: seed.portable_registry(n, d, host) for n, d in originals.items()}
        original_converter = converter.to_console
        cpu = self.root / 'original-cpu.dll'; cpu.write_bytes(b'inert CPU fixture')
        args = ['push', seed.SLUG, '--library', str(library), '--cpu-dll', str(cpu)]
        class FailedRemote(seed.FilesystemRemote):
            def write(self, path, data):
                raise RuntimeError('original deliberate filesystem write failure')
        with self.assertRaisesRegex(RuntimeError, 'deliberate filesystem write failure'):
            seed.sync_portable_registry(converter, args, FailedRemote(self.root / 'failed-export'), plans, prefix)
        self.assertIs(converter.to_console, original_converter)
        for name, data in originals.items(): self.assertEqual((prefix / name).read_bytes(), data)
        (prefix / 'system.reg').write_bytes(originals['system.reg'] + b'\n;late change\n')
        with self.assertRaisesRegex(ValueError, 'registry changed'):
            seed.sync_portable_registry(converter, args, seed.FilesystemRemote(self.root / 'late-export'), plans, prefix)
        self.assertIs(converter.to_console, original_converter)

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
