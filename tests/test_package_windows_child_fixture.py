#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Original inert bytes/filesystem controls; no Wine, socket or target execution."""
from contextlib import ExitStack
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
if os.environ.get('PW_WINDOWS_CHILD_DEPENDENCY_TOOLS'):
    sys.path.append(os.environ['PW_WINDOWS_CHILD_DEPENDENCY_TOOLS'])
import package_windows_child_fixture as package
import check_private_dispatch_abi as abi
import private_dispatch_wow64 as wow
from check_wine_prx_build import MODULES, PE


def pe(anchor, mode=1):
    """An original inert one-section PE holding one named syscall-shaped thunk."""
    value = bytearray(2048)
    value[:2] = b'MZ'; struct.pack_into('<I', value, 60, 128)
    value[128:132] = b'PE\0\0'; struct.pack_into('<HH', value, 132, 0x8664, 1)
    struct.pack_into('<H', value, 148, 240); struct.pack_into('<H', value, 152, 0x20b)
    struct.pack_into('<I', value, 260, 1); struct.pack_into('<II', value, 264, 0x1100, 40)
    struct.pack_into('<IIII', value, 400, 0x600, 0x1000, 0x600, 512)
    struct.pack_into('<IIHHIIIIIII', value, 768, 0, 0, 0, 0, 0, 1, 1, 1, 0x1200, 0x1210, 0x1220)
    struct.pack_into('<I', value, 1024, 0x1000); struct.pack_into('<I', value, 1040, 0x1230)
    value[1072:1072 + len(anchor) + 1] = anchor.encode() + b'\0'
    value[512:544] = abi.PREFIX + struct.pack('<I', 7) + abi.MIDDLE + struct.pack('<I', abi.SLOTS[mode]) + b'\xc3'
    return bytes(value)


def capability_pe(machine, payload=b'original inert data'):
    """Bounded original raw PE containers, never executable fixture approval."""
    data = bytearray(2048); data[:2] = b'MZ'; struct.pack_into('<I', data, 60, 128)
    data[128:132] = b'PE\0\0'; optional_size = 224 if machine == 0x14c else 240
    struct.pack_into('<HHIIIHH', data, 132, machine, 1, 0, 0, 0, optional_size, 0)
    struct.pack_into('<H', data, 152, 0x10b if machine == 0x14c else 0x20b)
    struct.pack_into('<II', data, 208, 8192, 512)
    struct.pack_into('<IIII', data, 152 + optional_size + 8, 1536, 4096, 1536, 512)
    data[512:512 + len(payload)] = payload
    return bytes(data)


class ArchiveControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pw-child-package-controls-')
        self.addCleanup(temporary.cleanup)
        self.temp = Path(temporary.name)
        self.root = self.temp / 'package'; self.root.mkdir(mode=0o755)
        self.project = {'commit': '1' * 40, 'tree': '2' * 40}
        self.run_url = 'https://github.com/Sleepywalker69/prospero-win/actions/runs/123'

    def put(self, name, value=b'original fixture bytes'):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        path.write_bytes(value); path.chmod(package.normal_mode(name))

    def json(self, name, value):
        self.put(name, package.json_bytes(value))

    def finish(self, battlenet=False):
        for name in (package.MANIFEST, package.SUMS):
            (self.root / name).unlink(missing_ok=True)
        value = {'schema': 'pw-windows-child-fixture/1', 'project': self.project,
                 'fixture_executed': False, 'console_validated': False, 'battlenet_enabled': battlenet,
                 'patches': {}, 'run_url': self.run_url,
                 'inventory': package.inventory(self.root)}
        if battlenet:
            value['optional_roles'] = {'battlenet_profile': package.BATTLE_PROFILE,
                                       'battlenet_capability': package.BATTLE_CAPABILITY}
        self.json(package.MANIFEST, value)
        self.put(package.SUMS, package.checksums(package.inventory(self.root)))
        return value

    def prepared(self):
        for name in ('PPSA99995/eboot.bin', 'PPSA99995/native-wine-child.self', 'PPSA99995/LICENSE',
                     'PPSA99995/THIRD_PARTY.md', 'BUILD-INFO.txt', package.PROFILE,
                     package.RUNTIME + '/share/wine/ca-certificates.crt', 'sources/project.tar.gz'):
            self.put(name)
        self.put('BUILD-INFO.txt', ('Mode: windows-child-fixture\nCommit: ' + self.project['commit'] +
                                  '\nRun: ' + self.run_url + '\n').encode())
        for name in ('parent.exe', 'child.exe'):
            self.put(package.FIXTURE + '/' + name, b'original same fixture image')
        modules = {}
        for name, anchor in (('ntdll', 'NtClose'), ('win32u', 'NtUserGetThreadState')):
            data = pe(anchor)
            self.put(package.LIB + '/x86_64-windows/' + name + '.dll', data)
            self.put(package.CONSOLE_PREFIX + '/drive_c/windows/system32/' + name + '.dll', data)
            modules[name] = abi.check_image(data, anchor, 1)
        expected_pe = {a + '/' + n + '.dll' for a in ('i386-windows', 'x86_64-windows') for n in PE}
        expected_pe |= {'x86_64-windows/wow64.dll', 'x86_64-windows/wow64win.dll'}
        built_pe, delta = {}, {}
        for name in sorted(expected_pe):
            arch, leaf = name.split('/')
            target = self.root / package.LIB / name
            if not target.exists(): self.put(package.LIB + '/' + name, ('inert PE ' + name).encode())
            relative = 'drive_c/windows/' + ('system32' if arch == 'x86_64-windows' else 'syswow64') + '/' + leaf
            self.put(package.CONSOLE_PREFIX + '/' + relative, target.read_bytes())
            built_pe[name] = package.digest_file(target)
            delta[relative] = {'after': package.record(target)}
        cpu_name = 'x86_64-windows/wowprospero.dll'
        self.put(package.LIB + '/' + cpu_name, b'original inert CPU PE')
        self.put(package.CONSOLE_PREFIX + '/drive_c/windows/system32/wowprospero.dll', b'original inert CPU PE')
        cpu = {'outputs': {cpu_name: package.record(self.root / package.LIB / cpu_name)}}
        declaration = {'mode': 1, 'executed': False, 'pe_identity': {'abi': 1, 'modules': modules}}
        self.json(package.ABI_REPORT, declaration)
        checked = {}
        for name in MODULES:
            target = package.LIB + '/x86_64-unix/' + name + '.prx'
            self.put(target, ('inert ' + name).encode())
            checked[name] = {'sha256': package.digest_file(self.root / target)}
        worker = {'schema': 'pw-wine-service-child/1', 'project': self.project,
                  'runtime': {'private_dispatch_abi': 1, 'ntdll_sha256': checked['ntdll']['sha256']},
                  'worker': package.record(self.root / 'PPSA99995/native-wine-child.self')}
        self.json('PPSA99995/native-wine-child-build.json', worker)
        pair = {'project': self.project, 'architecture': 'x64', 'files': {
            n: package.record(self.root / package.FIXTURE / n) for n in ('parent.exe', 'child.exe')}}
        prepared = {'schema': 'pw-windows-child-prefix/1', 'project': self.project,
                    'private_dispatcher': declaration, 'fixture_executed': False, 'fixture': pair,
                    'patches': {}, 'patched_pe_delta': delta, 'cpu': cpu,
                    'inventory': package.prefix.inventory(self.root / 'console')}
        self.json('provenance/prefix.json', prepared)
        self.json('provenance/fixture-source.json', pair)
        self.json('provenance/wine-prx-checks.json', {'schema': 'pw-prx-ci-check/1', 'modules': checked})
        self.json('provenance/wine-build.json', {'wine_commit': package.prefix.WINE, 'patches': [], 'pe': built_pe})
        self.json('provenance/retained-sources.json', {'schema': 'pw-windows-child-retained-sources/1',
                  'project': self.project, 'inventory': package.prefix.inventory(self.root / 'sources')})
        self.json('provenance/title.json', {'schema': 'pw-windows-child-title/1', 'project': self.project,
                  'fixture_child_sha256': pair['files']['child.exe']['sha256'],
                  'files': {'eboot.bin': {'mode': 0o755, **package.record(self.root / 'PPSA99995/eboot.bin')}}})
        return self.finish()

    def prepared_battle(self):
        self.prepared()
        built = package.read_json(self.root / 'provenance/wine-build.json')
        prepared = package.read_json(self.root / 'provenance/prefix.json')
        declaration = package.read_json(self.root / package.ABI_REPORT)
        modules = {}
        replacements = {'x86_64-windows/wow64.dll': capability_pe(0x8664,
            wow.BACKEND_MESSAGE + '\\wowprospero.dll\0'.encode('utf-16le'))}
        for name, anchor, export in (('ntdll', 'NtClose', '__wine_syscall_dispatcher'),
                                      ('win32u', 'NtUserGetThreadState', 'Wow64Transition')):
            data = capability_pe(0x14c, ('inert ' + name).encode())
            replacements['i386-windows/' + name + '.dll'] = data
            modules[name] = {'sha256': hashlib.sha256(data).hexdigest(), 'machine': 'I386',
                'anchor': anchor, 'dispatcher_export': export, 'executed': False,
                'preferred_base_mapping_sha256': hashlib.sha256(wow.mapped_pe(data)).hexdigest()}
        for name, data in replacements.items():
            arch, leaf = name.split('/')
            relative = 'drive_c/windows/' + ('system32' if arch == 'x86_64-windows' else 'syswow64') + '/' + leaf
            self.put(package.LIB + '/' + name, data); self.put(package.CONSOLE_PREFIX + '/' + relative, data)
            built['pe'][name] = hashlib.sha256(data).hexdigest()
            prepared['patched_pe_delta'][relative] = {'after': package.record(self.root / package.LIB / name)}
        declaration['wow64'] = {'schema': 'pw-private-dispatch-wow64-build/1', 'abi': 1,
            'native_export': wow.EXPORT, 'runtime_validated': False, 'executed': False,
            'cpu_pe_required_separately': True, 'i386_modules': modules,
            'native': {'self': package.record(self.root / package.LIB / 'x86_64-unix/ntdll.prx')},
            'translator_prx': package.record(self.root / package.LIB / 'x86_64-unix/wowprospero.prx'),
            'backend': wow.check_backend(replacements['x86_64-windows/wow64.dll'])}
        prepared['private_dispatcher'] = declaration
        prepared['inventory'] = package.prefix.inventory(self.root / 'console')
        self.json('provenance/prefix.json', prepared); self.json(package.ABI_REPORT, declaration)
        self.json('provenance/wine-build.json', built)
        for source in sorted((self.root / package.CONSOLE_PREFIX).rglob('*')):
            relative = source.relative_to(self.root / package.CONSOLE_PREFIX).as_posix()
            if relative == 'drive_c/windows-child-fixture' or relative.startswith('drive_c/windows-child-fixture/'):
                continue
            if source.is_file(): self.put(package.BATTLE_PREFIX + '/' + relative, source.read_bytes())
        (self.root / package.BATTLE_PREFIX / 'drive_c/installer').mkdir(mode=0o755)
        repo = Path(os.environ['PW_WINDOWS_CHILD_DEPENDENCY_TOOLS']).parent if os.environ.get('PW_WINDOWS_CHILD_DEPENDENCY_TOOLS') else ROOT
        self.put(package.BATTLE_PROFILE, package.prefix.battle_profile(repo).encode())
        all_console = package.prefix.inventory(self.root / 'console')
        battle_inventory = {n: v for n, v in all_console.items() if
            n not in prepared['inventory'] or v['type'] == 'directory' and
            (n == '.' or n in ('data', 'data/prospero-win', 'data/prospero-win/prefixes', 'data/prospero-win/profiles'))}
        battle = {'schema': 'pw-battlenet-experimental-prefix/1', 'project': self.project,
            'wine_commit': package.prefix.WINE, 'patches': {}, 'private_dispatcher': declaration,
            'installer_included': False, 'console_execution_verified': False, 'cpu': prepared['cpu'],
            'patched_pe_delta': prepared['patched_pe_delta'], 'inventory': battle_inventory}
        self.json(package.BATTLE_REPORT, battle); self.json(package.BATTLE_CPU, prepared['cpu'])
        runtime = {'private_dispatcher': declaration, 'cpu': prepared['cpu'],
            'cpu_manifest_sha256': package.digest_file(self.root / package.BATTLE_CPU),
            'translator_pe': package.record(self.root / package.LIB / 'x86_64-windows/wowprospero.dll'),
            'runtime_validated': False}
        self.json(package.BATTLE_CAPABILITY, package.battle_capability(self.project,
            (self.root / package.BATTLE_PROFILE).read_bytes(), (self.root / package.BATTLE_REPORT).read_bytes(), runtime))
        return self.finish(True)

    def test_battle_inert_archive_identity_and_disabled_refusal(self):
        expected = self.prepared_battle()
        self.assertEqual(package.verify_directory(self.root), expected)
        archive = self.temp / 'battle.tar.gz'; package.write_archive(self.root, archive)
        self.assertEqual(package.verify_archive(archive), expected)
        self.finish(False)
        with self.assertRaisesRegex(ValueError, 'disabled package'):
            package.verify_directory(self.root)

    def test_battle_installer_and_profile_mutations_are_rejected(self):
        self.prepared_battle()
        self.put(package.BATTLE_INSTALLER, b'original inert bytes, never vendor software')
        self.finish(True)
        with self.assertRaises(ValueError): package.verify_directory(self.root)
        (self.root / package.BATTLE_INSTALLER).unlink()
        profile = self.root / package.BATTLE_PROFILE
        value = profile.read_text()
        for old, new in [('cpu = translator', 'cpu = native'), ('architecture = pe32', 'architecture = pe64'),
                         ('graphics = auto', 'graphics = auto\narguments = --unreviewed')]:
            profile.write_text(value.replace(old, new)); self.finish(True)
            with self.assertRaises(ValueError): package.verify_directory(self.root)
        profile.write_text(value)

    def test_battle_changed_runtime_capability_and_false_claims_are_rejected(self):
        self.prepared_battle(); original = package.read_json(self.root / package.BATTLE_CAPABILITY)
        variants = []
        for key in ('runtime_validated', 'installer_executed', 'installer_included', 'descendants_supported', 'child_gui_supported'):
            changed = copy.deepcopy(original); changed[key] = True; variants.append(changed)
        changed = copy.deepcopy(original); changed['runtime_check']['private_dispatcher'].pop('wow64'); variants.append(changed)
        changed = copy.deepcopy(original); changed['runtime_check']['cpu_manifest_sha256'] = '0' * 64; variants.append(changed)
        for changed in variants:
            self.json(package.BATTLE_CAPABILITY, changed); self.finish(True)
            with self.assertRaises(ValueError): package.verify_directory(self.root)
        self.json(package.BATTLE_CAPABILITY, original)
        self.put(package.BATTLE_PREFIX + '/drive_c/windows/syswow64/win32u.dll', b'changed original data')
        self.finish(True)
        with self.assertRaises(ValueError): package.verify_directory(self.root)

    def test_console_merge_rejects_cross_profile_and_directory_aliases(self):
        fixture = {'.': {'type': 'directory', 'mode': 0o755}}
        battle = {'.': {'type': 'directory', 'mode': 0o700}}
        with self.assertRaisesRegex(ValueError, 'overlapping'):
            package.merge_console_inventories(fixture, battle)
        battle = {'data/prospero-win/profiles/windows-child-fixture-v1.profile': {'type': 'file'}}
        with self.assertRaisesRegex(ValueError, 'unreviewed'):
            package.merge_console_inventories(fixture, battle)

    def test_battle_admission_replays_checker_and_propagates_refusal(self):
        self.prepared_battle()
        names = ('repo', 'host_work', 'wine_work', 'cohort', 'cpu_output', 'llvm_bindir')
        paths = {n: self.temp / n for n in names}
        paths['battlenet_prefix'] = self.temp / 'battle-input'
        paths['battlenet_prefix'].mkdir()
        battle = package.read_json(self.root / package.BATTLE_REPORT)
        fixture = package.read_json(self.root / 'provenance/prefix.json')
        capability = package.read_json(self.root / package.BATTLE_CAPABILITY)
        runtime = capability['runtime_check']; battle['host_stamp'] = 'original bound stamp'
        for name, entry in battle['inventory'].items():
            target = paths['battlenet_prefix'] / name
            if entry['type'] == 'directory': target.mkdir(parents=True, exist_ok=True, mode=0o755)
            else:
                target.write_bytes((self.root / 'console' / name).read_bytes()); target.chmod(entry['mode'])
        paths['battlenet_prefix_report'] = self.temp / 'battle-report.json'
        paths['battlenet_prefix_report'].write_bytes(package.json_bytes(battle))
        paths['cpu_output'].mkdir()
        (paths['cpu_output'] / 'cpu-build.json').write_bytes((self.root / package.BATTLE_CPU).read_bytes())
        profile = (self.root / package.BATTLE_PROFILE).read_bytes()
        with patch.object(package.prefix, 'check_battlenet_runtime', return_value=runtime) as checked, \
             patch.object(package.prefix, 'battle_profile', return_value=profile):
            actual = package.check_battle_inputs(paths, self.project, fixture,
                       runtime['private_dispatcher'], 'original bound stamp')
            self.assertEqual(actual, (battle, runtime, profile))
            checked.assert_called_once_with(*(paths[n] for n in names))
            checked.side_effect = ValueError('actual linked capability rejected')
            with self.assertRaisesRegex(ValueError, 'actual linked capability rejected'):
                package.check_battle_inputs(paths, self.project, fixture,
                    runtime['private_dispatcher'], 'original bound stamp')

    def test_real_tar_round_trip_is_deterministic_and_mode_preserving(self):
        expected = self.prepared()
        self.assertEqual(package.verify_directory(self.root), expected)
        a, b = self.temp / 'a.tar.gz', self.temp / 'b.tar.gz'
        package.write_archive(self.root, a); package.write_archive(self.root, b)
        self.assertEqual(a.read_bytes(), b.read_bytes())
        self.assertEqual(package.verify_archive(a), expected)
        unpacked = self.temp / 'unpacked'; unpacked.mkdir()
        with tarfile.open(a) as archive:
            archive.extractall(unpacked, filter='data')
        self.assertEqual(package.inventory(unpacked), package.inventory(self.root))
        self.assertEqual(package.verify_directory(unpacked), expected)

    def test_missing_or_unlisted_bytes_and_checksum_lines_are_rejected(self):
        self.prepared()
        path = self.root / package.FIXTURE / 'child.exe'
        original = path.read_bytes(); path.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'SHA256SUMS'):
            package.verify_directory(self.root)
        path.write_bytes(original)
        self.put('unlisted.txt')
        with self.assertRaisesRegex(ValueError, 'SHA256SUMS'):
            package.verify_directory(self.root)
        (self.root / 'unlisted.txt').unlink()
        sums = (self.root / package.SUMS).read_bytes()
        (self.root / package.SUMS).write_bytes(sums + sums.splitlines(keepends=True)[0])
        with self.assertRaisesRegex(ValueError, 'SHA256SUMS'):
            package.verify_directory(self.root)

    def test_rehashed_mixed_runtime_or_legacy_operand_fails_semantic_check(self):
        self.prepared()
        target = self.root / package.LIB / 'x86_64-windows/ntdll.dll'
        target.write_bytes(pe('NtClose', 0)); self.finish()
        with self.assertRaisesRegex(ValueError, 'dispatcher PE mismatch'):
            package.verify_directory(self.root)
        (self.root / package.CONSOLE_PREFIX / 'drive_c/windows/system32/ntdll.dll').write_bytes(target.read_bytes())
        self.finish()
        with self.assertRaisesRegex(ValueError, 'dispatcher operand mismatch'):
            package.verify_directory(self.root)

    def test_rehashed_wrong_worker_project_and_ntdll_binding_fail(self):
        self.prepared()
        path = self.root / 'PPSA99995/native-wine-child-build.json'
        worker = package.read_json(path)
        for field in ('project', 'runtime'):
            changed = copy.deepcopy(worker)
            if field == 'project': changed['project']['commit'] = '3' * 40
            else: changed['runtime']['ntdll_sha256'] = '4' * 64
            self.json('PPSA99995/native-wine-child-build.json', changed); self.finish()
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'identity differs'):
                package.verify_directory(self.root)

    def test_rehashed_non_dispatch_pe_and_cpu_mismatch_fail(self):
        self.prepared()
        path = self.root / package.LIB / 'x86_64-windows/wow64win.dll'
        before = path.read_bytes(); path.write_bytes(b'wrong paired wow64win'); self.finish()
        with self.assertRaisesRegex(ValueError, 'patched PE mismatch'):
            package.verify_directory(self.root)
        path.write_bytes(before)
        (self.root / package.LIB / 'x86_64-windows/wowprospero.dll').write_bytes(b'old CPU')
        self.finish()
        with self.assertRaisesRegex(ValueError, 'CPU DLL binding'):
            package.verify_directory(self.root)

    def test_consumer_build_identity_and_directory_members_are_required(self):
        self.prepared()
        self.put('BUILD-INFO.txt', b'Mode: windows-child-fixture\nCommit: wrong\n'); self.finish()
        with self.assertRaisesRegex(ValueError, 'BUILD-INFO'):
            package.verify_directory(self.root)

    def test_unreviewed_additional_battle_profile_cannot_silently_enter_package(self):
        self.prepared()
        self.put('console/data/prospero-win/profiles/battlenet-experimental-v1.profile', b'original inert profile text')
        path = self.root / 'provenance/prefix.json'
        report = package.read_json(path)
        report['inventory'] = package.prefix.inventory(self.root / 'console')
        self.json('provenance/prefix.json', report); self.finish()
        with self.assertRaisesRegex(ValueError, 'unreviewed console profile'):
            package.verify_directory(self.root)

    def test_regular_files_only_windows_names_and_entry_cap(self):
        for name in ('../x', '/x', 'a//b', 'a/./b', 'a\\b', 'a:b', 'x\ny', 'AUX.txt', 'x/COM1',
                     'nul.dll', 'x.', 'x ', 'x/../b', 'x|y'):
            with self.subTest(name=name), self.assertRaises(ValueError): package.safe_name(name)
        self.assertEqual(package.safe_name('Program Files/Test/file.exe'), 'Program Files/Test/file.exe')
        self.put('a'); (self.root / 'link').symlink_to('a')
        with self.assertRaisesRegex(ValueError, 'symlink'): package.inventory(self.root)
        (self.root / 'link').unlink(); os.mkfifo(self.root / 'fifo')
        with self.assertRaisesRegex(ValueError, 'special'): package.inventory(self.root)
        (self.root / 'fifo').unlink(); self.put('A')
        with self.assertRaisesRegex(ValueError, 'case-colliding'): package.inventory(self.root)
        (self.root / 'A').unlink()
        with patch.object(package, 'MAX_ENTRIES', 0), self.assertRaisesRegex(ValueError, 'bounds'):
            package.inventory(self.root)

    def test_duplicate_json_and_unreviewed_enabled_claim_fail(self):
        with self.assertRaisesRegex(ValueError, 'duplicate JSON'):
            package.decode_json(b'{"abi":0,"abi":1}')
        self.prepared()
        manifest = package.read_json(self.root / package.MANIFEST)
        manifest['battlenet_enabled'] = True
        self.json(package.MANIFEST, manifest)
        self.put(package.SUMS, package.checksums(package.inventory(self.root)))
        with self.assertRaisesRegex(ValueError, 'capability/prefix/profile/CPU report missing'):
            package.verify_directory(self.root)

    def test_unsafe_archive_members_are_rejected_without_extraction(self):
        for name, kind, link in (('../escape', tarfile.REGTYPE, ''), ('a', tarfile.SYMTYPE, '../escape'),
                                 ('a', tarfile.LNKTYPE, 'b'), ('a', tarfile.FIFOTYPE, '')):
            path = self.temp / 'unsafe.tar.gz'
            with tarfile.open(path, 'w:gz') as archive:
                item = tarfile.TarInfo(name); item.type = kind; item.linkname = link; item.mode = 0o644
                archive.addfile(item, io.BytesIO())
            with self.subTest(name=name, kind=kind), self.assertRaises(ValueError): package.verify_archive(path)
        self.assertFalse((self.temp / 'escape').exists())

    def test_duplicate_member_and_bad_modes_fail(self):
        path = self.temp / 'duplicate.tar.gz'
        with tarfile.open(path, 'w:gz') as archive:
            for name in ('a', 'A'):
                item = tarfile.TarInfo(name); item.mode = 0o644; archive.addfile(item, io.BytesIO())
        with self.assertRaisesRegex(ValueError, 'duplicate/case-colliding'): package.verify_archive(path)
        self.put('license'); (self.root / 'license').chmod(0o777)
        with self.assertRaisesRegex(ValueError, 'file mode'): package.inventory(self.root)

    def test_source_copy_rejects_mutation_missing_directories_and_extra_file(self):
        source = self.temp / 'source'; source.mkdir(); (source / 'empty').mkdir(); (source / 'a').write_bytes(b'a')
        expected = package.prefix.inventory(source)
        package.copy_tree(self.root, 'copied', source, expected=expected)
        package.copied_inventory(package.inventory(self.root), 'copied', expected)
        self.put('copied/extra')
        with self.assertRaisesRegex(ValueError, 'extra/missing'):
            package.copied_inventory(package.inventory(self.root), 'copied', expected)
        (source / 'a').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'source tree differs'):
            package.copy_tree(self.root, 'other', source, expected=expected)

    def test_correctly_labelled_wrong_source_archives_are_rejected(self):
        source = self.temp / 'retained'; source.mkdir()
        for name, value in (('project.tar.gz', gzip.compress(b'wrong source')),
                            ('wine.tar.gz', b'same previously verified Wine archive'),
                            ('foundation.tar.gz', gzip.compress(b'wrong foundation')), ('LICENSE', b'original notice')):
            (source / name).write_bytes(value)
        service = {'title_foundation': '3' * 40, 'converter_foundation': '3' * 40,
                   'prx_foundation': '4' * 40}
        revisions = {'project': self.project['commit'], 'wine': package.prefix.WINE,
                     'title-foundation': service['title_foundation'], 'prx-foundation': service['prx_foundation']}
        roles = {}
        for role in ('project', 'wine', 'title-foundation', 'prx-foundation', 'sdk', 'freetype', 'gnutls',
                     'nettle', 'zlib', 'ca-bundle', 'lapy'):
            name = 'project.tar.gz' if role == 'project' else 'wine.tar.gz' if role == 'wine' else 'foundation.tar.gz'
            roles[role] = {'path': name, 'revision': revisions.get(role, 'original test pin'),
                           'url': 'https://example.invalid/original-fixture', 'notices': ['LICENSE']}
        metadata = self.temp / 'sources.json'
        def save():
            metadata.write_bytes(package.json_bytes({'schema': 'pw-windows-child-retained-sources/1',
                                'project': self.project, 'roles': roles, 'inventory': package.prefix.inventory(source)}))
        save()
        args = (self.temp, source, metadata, self.project, source / 'wine.tar.gz', service,
                self.temp / 'title/.deps/native/ps5-payload-sdk', self.temp / 'foundation', self.temp / 'wine')
        service['converter_foundation'] = service['prx_foundation']
        with self.assertRaisesRegex(ValueError, 'executable converter'):
            package.retained_sources(*args)
        service['converter_foundation'] = service['title_foundation']
        roles['prx-foundation']['revision'] = service['title_foundation']; save()
        with self.assertRaisesRegex(ValueError, 'source revision mismatch: prx-foundation'):
            package.retained_sources(*args)
        roles['prx-foundation']['revision'] = service['prx_foundation']; save()
        with patch.object(package.subprocess, 'run', return_value=SimpleNamespace(stdout=b'actual Git archive')):
            with self.assertRaisesRegex(ValueError, 'not exact source'): package.retained_sources(*args)
            (source / 'project.tar.gz').write_bytes(gzip.compress(b'actual Git archive')); save()
            with patch.object(package.prefix, 'git', return_value=service['title_foundation']):
                with self.assertRaisesRegex(ValueError, 'foundation archive differs'): package.retained_sources(*args)

    def test_service_reuses_complete_builder_verifier_and_rejects_other_project(self):
        paths = [self.temp / n for n in ('repo', 'service', 'wine', 'sdk', 'foundation', 'llvm', 'inspection')]
        repo, directory, wine, sdk, foundation, bindir, inspection = paths
        declaration = {'original': 'ABI record'}
        calls = []
        def verify(args, commands):
            calls.append(args)
            return {'project': self.project, 'runtime': {'abi_check': declaration}}, ()
        builder = SimpleNamespace(verify_child=verify, Commands=lambda path: path)
        with patch.object(package.prefix, 'load_tool', return_value=builder):
            value = package.validate_service(repo, directory, self.project, wine, declaration,
                                             sdk, foundation, bindir, inspection)
            self.assertEqual(value['project'], self.project)
            self.assertEqual(vars(calls[0]), dict(work=repo, sdk=sdk, foundation=foundation,
                             runtime=wine, llvm_bindir=bindir, service_work=directory))
            with self.assertRaisesRegex(ValueError, 'cohort differs'):
                package.validate_service(repo, directory, {'commit': '5' * 40, 'tree': '6' * 40}, wine,
                                         declaration, sdk, foundation, bindir, inspection)

    def test_title_replays_actual_builder_check_and_rejects_changed_graph(self):
        names = ('repo', 'sdk', 'foundation', 'wine_work', 'llvm_bindir', 'service_work', 'title',
                 'title_build', 'sdk_source_archive', 'fixture')
        paths = {n: self.temp / n for n in names}
        expected = {'original': 'compiled identity, graph and embedded child'}
        calls = []
        def checked(args):
            calls.append(args)
            return expected
        with patch.object(package.prefix, 'load_tool', return_value=SimpleNamespace(check_title=checked)):
            self.assertEqual(package.validate_title(paths, expected, self.temp / 'inspect'), expected)
            self.assertEqual(calls[0].build, paths['title_build'])
            self.assertEqual(calls[0].sdk_source_archive, paths['sdk_source_archive'])
            self.assertEqual(calls[0].fixture, paths['fixture'])
            with self.assertRaisesRegex(ValueError, 'replayed title'):
                package.validate_title(paths, {'original': 'stale provider graph'}, self.temp / 'inspect2')

    def test_rehashed_title_bound_to_another_fixture_is_rejected(self):
        self.prepared()
        value = package.read_json(self.root / 'provenance/title.json')
        value['fixture_child_sha256'] = '0' * 64
        self.json('provenance/title.json', value); self.finish()
        with self.assertRaisesRegex(ValueError, 'title provenance differs'):
            package.verify_directory(self.root)


class SourceRetentionFlow(unittest.TestCase):
    """Real Git/files/tar/manifest flow; only SDK and TLS authorities are modeled."""
    def setUp(self):
        import subprocess
        self.subprocess = subprocess
        temp = tempfile.TemporaryDirectory(prefix='retained source flow ')
        self.addCleanup(temp.cleanup); self.base = Path(temp.name)
        self.paths = {name: self.base / name for name in ('repo', 'wine_source', 'title_foundation',
            'foundation', 'tls_work', 'wine_work', 'title_build')}
        for path in self.paths.values(): path.mkdir()
        def write(path, data):
            path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
        self.write = write
        def archive(name, prefix=''):
            path = self.base / name
            mode = 'w:xz' if name.endswith('.xz') else 'w:gz'
            with tarfile.open(path, mode) as stream:
                value = ('Original inert notice for ' + name).encode()
                item = tarfile.TarInfo(prefix + 'LICENSE'); item.size = len(value); item.mode = 0o644
                stream.addfile(item, io.BytesIO(value))
            return path
        self.archive = archive
        ft = archive('freetype.tar.xz', 'freetype/'); zlib = archive('zlib.tar.gz', 'zlib/')
        sdk = archive('sdk.tar.gz')
        tls = {'inputs': {'sources': {}}}
        for role, extension in (('gnutls', 'xz'), ('nettle', 'gz')):
            path = archive(role + '-1.tar.' + extension, role + '/')
            (self.paths['tls_work'] / path.name).write_bytes(path.read_bytes())
            tls['inputs']['sources'][role] = {'version': '1', 'url': 'https://example.invalid/' + role,
                                            'sha256': package.digest_file(path)}
        ca = self.paths['tls_work'] / 'root/ca-certificates.crt'; write(ca, b'original inert CA bytes')
        tls['inputs']['sources']['ca_bundle'] = {'date': '2026-10-09', 'url': 'https://example.invalid/ca',
                                                'sha256': package.digest_file(ca)}
        self.tls = tls
        def commit(name):
            path = self.paths[name]; write(path / 'LICENSE', ('Original test licence for ' + name).encode())
            subprocess.run(['git', '-C', str(path), 'init', '-q'], check=True)
            subprocess.run(['git', '-C', str(path), 'add', '.'], check=True)
            subprocess.run(['git', '-C', str(path), '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
                            'commit', '-qm', 'original inert source'], check=True)
            return package.prefix.git(path, 'rev-parse', 'HEAD')
        self.wine = commit('wine_source'); self.title = commit('title_foundation')
        self.assertNotEqual(self.wine, self.title)
        write(self.paths['foundation'] / 'tools/setup-native-dependencies.sh',
              ('zlib_version=1\nzlib_url=https://example.invalid/zlib\nzlib_hash=' + package.digest_file(zlib) + '\n').encode())
        self.foundation = commit('foundation')
        repo = self.paths['repo']
        write(repo / 'tools/build_wine_ps5.sh', ('MODULE_EXPORTS_COMMIT=' + self.foundation +
            '\nFREETYPE_VERSION=1\nFREETYPE_URL=https://example.invalid/freetype\nFREETYPE_SHA256=' + package.digest_file(ft) + '\n').encode())
        write(repo / 'tools/build_native.sh', ('pin=' + self.title + '\nlapy_release=v-test\nlapy_elf_sha256=' + 'b'*64 + '\n').encode())
        for name in ('MPL-2.0.txt', 'Lapy-MIT.txt'): write(repo / 'LICENSES' / name, b'Original inert notice')
        commit('repo')
        wine_archive = self.base / 'wine.tar.gz'
        wine_archive.write_bytes(gzip.compress(subprocess.check_output(['git', '-C', str(self.paths['wine_source']), 'archive', self.wine]), mtime=0))
        self.paths.update(wine_archive=wine_archive, sdk_source_archive=sdk, freetype_archive=ft, zlib_archive=zlib)
        write(self.paths['wine_work'] / 'report.json', package.json_bytes({'wine_commit': self.wine,
              'sources': {'prx_foundation': self.foundation}, 'tls': {'build': tls}}))
        write(self.paths['title_build'] / 'lapy-helper-release.json', package.json_bytes({'tag_name': 'v-test',
              'repository': 'mpereiraesaa/PS5-Lapy-JB-Daemon',
              'release_url': 'https://github.com/mpereiraesaa/PS5-Lapy-JB-Daemon/releases/tag/v-test'}))
        write(self.paths['title_build'] / 'lapy-helper-manifest.json', package.json_bytes({'elf_sha256': 'b'*64}))
        self.config = {'schema': 'pw-windows-child-source-inputs/1', 'paths': {k: str(v) for k,v in self.paths.items()}}
        self.sdk_record = {'commit': 'a'*40, 'sha256': package.digest_file(sdk)}
        self.sdk_patch = patch('check_native_suite.source_archive', return_value=self.sdk_record)
        self.sdk_patch.start(); self.addCleanup(self.sdk_patch.stop)
        tls_patch = patch.object(package.prefix, 'load_tool', return_value=SimpleNamespace(verify=lambda root: self.tls))
        tls_patch.start(); self.addCleanup(tls_patch.stop)
        wine_patch = patch.object(package.prefix, 'WINE', self.wine); wine_patch.start(); self.addCleanup(wine_patch.stop)

    def test_complete_source_retention_and_replay(self):
        out, report = self.base / 'retained-sources', self.base / 'retained-sources.json'
        result = package.retain_sources(self.config, out, report)
        self.assertEqual(result, package.read_json(report))
        self.assertEqual(len(result['roles']), 11)
        self.assertEqual(result['inventory'], package.prefix.inventory(out))
        service = {'title_foundation': self.title, 'converter_foundation': self.title, 'prx_foundation': self.foundation}
        self.assertEqual(package.retained_sources(self.paths['repo'], out, report, package.prefix.project(self.paths['repo']),
            self.paths['wine_archive'], service, self.paths['title_foundation'] / '.deps/native/ps5-payload-sdk',
            self.paths['foundation'], self.paths['wine_work']), result)
        title_archive = out / result['roles']['title-foundation']['path']
        title_bytes = title_archive.read_bytes()
        title_archive.write_bytes((out / result['roles']['prx-foundation']['path']).read_bytes())
        altered = copy.deepcopy(result); altered['inventory'] = package.prefix.inventory(out)
        report.write_bytes(package.json_bytes(altered))
        with self.assertRaisesRegex(ValueError, 'foundation archive differs'):
            package.retained_sources(self.paths['repo'], out, report, package.prefix.project(self.paths['repo']),
                self.paths['wine_archive'], service, self.paths['title_foundation'] / '.deps/native/ps5-payload-sdk',
                self.paths['foundation'], self.paths['wine_work'])
        title_archive.write_bytes(title_bytes); report.write_bytes(package.json_bytes(result))
        with self.assertRaises(ValueError): package.retain_sources(self.config, out, self.base / 'another.json')
        changed = out / result['roles']['nettle']['path']; changed.write_bytes(b'changed source')
        with self.assertRaises(ValueError): package.retained_sources(self.paths['repo'], out, report,
            package.prefix.project(self.paths['repo']), self.paths['wine_archive'], service,
            self.paths['title_foundation'] / '.deps/native/ps5-payload-sdk', self.paths['foundation'], self.paths['wine_work'])

    def test_source_outputs_refuse_aliases_existing_and_symlink_paths(self):
        alias = self.base / 'alias'; alias.mkdir()
        cases = [('equal', self.base / 'same', self.base / 'same'),
                 ('spelling-alias', self.base / 'same', alias / '../same'),
                 ('nested-report', self.base / 'outer', self.base / 'outer/report.json'),
                 ('nested-output', self.base / 'outer/inner', self.base / 'outer')]
        for name, out, report in cases:
            with self.subTest(name=name), self.assertRaises((ValueError, FileNotFoundError)):
                package.retain_sources(self.config, out, report)
            self.assertFalse(out.exists()); self.assertFalse(report.exists())
        for name in ('existing', 'symlink'):
            report = self.base / name
            if name == 'existing': report.write_bytes(b'keep')
            else: report.symlink_to(self.base / 'missing')
            out = self.base / ('out-' + name)
            with self.subTest(name=name), self.assertRaises(ValueError): package.retain_sources(self.config, out, report)
            self.assertFalse(out.exists())
        parent_alias = self.base / 'parent-link'; parent_alias.symlink_to(self.base, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            package.retain_sources(self.config, parent_alias / 'out', self.base / 'fresh-report.json')
        output_alias = self.base / 'output-link'; output_alias.symlink_to(self.base / 'missing-output')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            package.retain_sources(self.config, output_alias, self.base / 'fresh-report.json')
        internal = self.paths['tls_work'] / 'inner'; internal.mkdir()
        with self.assertRaisesRegex(ValueError, 'overlaps input'):
            package.retain_sources(self.config, internal / '../../tls_work/new-output', self.base / 'fresh-report.json')
        self.assertFalse((self.paths['tls_work'] / 'new-output').exists())
        missing = self.paths['wine_archive']; missing.unlink()
        with self.assertRaises(FileNotFoundError): package.retain_sources(self.config, self.base / 'out', self.base / 'report')



class FullAssembleControls(unittest.TestCase):
    """Real assembly/retention consistency/manifest/tar paths with inert inputs.

    Only external compiled-artifact validators and Git/SDK provenance are
    mocked. No Wine, PE, native program, target compiler or network is run.
    """
    def setup_inputs(self, battle):
        helper = ArchiveControls()
        helper.setUp(); self.addCleanup(helper.doCleanups)
        self.temp, self.seed, self.project = helper.temp, helper.root, helper.project
        (helper.prepared_battle if battle else helper.prepared)()
        inputs = self.temp / 'inputs'; inputs.mkdir()
        names = {'repo', 'host_work', 'wine_work', 'prefix', 'fixture', 'service_work',
                 'title', 'title_build', 'sources_root', 'foundation', 'llvm_bindir'}
        if battle: names |= {'battlenet_prefix', 'cpu_output'}
        self.p = {n: inputs / n for n in names}
        for p in self.p.values(): p.mkdir()
        self.title_foundation = inputs / 'title-foundation'
        self.p['sdk'] = self.title_foundation / '.deps/native/ps5-payload-sdk'
        self.p['sdk'].mkdir(parents=True)
        for n in ('cohort', 'prefix_report', 'title_report', 'sources_manifest', 'wine_archive', 'sdk_source_archive'):
            self.p[n] = inputs / (n + '.json')
        if battle: self.p['battlenet_prefix_report'] = inputs / 'battlenet-prefix.json'
        self.out = self.temp / 'fresh-output'
        self.config = {'schema': 'pw-windows-child-package-inputs/1', 'run_url': helper.run_url,
                       'battlenet_enabled': battle, 'paths': {k: str(v) for k,v in self.p.items()}}
        self.abi = package.read_json(self.seed / package.ABI_REPORT)
        self.prepared = package.read_json(self.seed / 'provenance/prefix.json')
        self.checked = package.read_json(self.seed / 'provenance/wine-prx-checks.json')
        self.build = package.read_json(self.seed / 'provenance/wine-build.json')
        self.pair = package.read_json(self.seed / 'provenance/fixture-source.json')
        self.compiler = {'name': 'explicitly mocked target compiler validation'}
        self.service = package.read_json(self.seed / 'PPSA99995/native-wine-child-build.json')
        self.service.update(host_llvm=self.compiler, title_foundation='3'*40, converter_foundation='3'*40, prx_foundation='4'*40)
        self.service['runtime']['abi_check'] = self.abi
        self.put(self.p['repo'] / 'tests/fixtures/windows_child_process.c', b'original inert source')
        self.pair['source_sha256'] = package.digest_file(self.p['repo'] / 'tests/fixtures/windows_child_process.c')
        (self.p['repo'] / 'wine/patches').mkdir(parents=True)
        self.put(self.p['repo'] / 'src/pw_game_profile.c', b'original generator input marker')
        for n in ('LICENSE', 'THIRD_PARTY.md', 'LICENSES/original.txt'):
            self.put(self.p['repo'] / n, b'original inert licence notice')
        for n in ('parent.exe', 'child.exe'):
            self.put(self.p['fixture'] / n, (self.seed / package.FIXTURE / n).read_bytes())
        self.host = self.p['host_work'] / 'install/usr'; self.host.mkdir(parents=True)
        for name in self.build['pe']:
            data = (self.seed / package.LIB / name).read_bytes()
            self.put(self.p['wine_work'] / 'pe' / name, data)
            self.put(self.host / 'lib/wine' / name, b'original host input overwritten by exact cohort')
        self.put(self.host / 'share/wine/nls/original.nls', b'original inert NLS')
        self.put(self.host / 'lib/wine/x86_64-windows/extra.dll', b'original retained host PE')
        for name in MODULES:
            self.put(self.p['wine_work'] / 'prx/sce_module' / (name+'.prx'),
                     (self.seed / package.LIB / 'x86_64-unix' / (name+'.prx')).read_bytes())
        for name in ('LICENSE','COPYING.LIB','AUTHORS','NOTICES.md','libs/original/LICENSE'):
            self.put(self.p['wine_work'] / 'source' / name, b'original inert source notice')
        self.put(self.p['wine_work'] / 'source/fonts/original.ttf', b'original inert font')
        self.put(self.p['wine_work'] / 'prx/fonts/original.ttf', b'original inert font')
        self.put(self.p['wine_work'] / 'prx/ca-certificates.crt', b'original inert trust input')
        for name in ('LICENSE.TXT','docs/FTL.TXT'):
            self.put(self.p['wine_work'] / 'freetype/src' / name, b'original inert font licence')
        for name in ('gnutls','nettle'):
            self.put(self.p['wine_work'] / 'prx/licenses' / name / 'LICENSE', b'original inert TLS notice')
        self.prepared.update(wine_commit=package.prefix.WINE,host_stamp='inert-stamp',
                             console_execution_verified=False,fixture=self.pair)
        self.materialize_inventory(self.p['prefix'], self.prepared['inventory'], self.seed / 'console')
        self.save(self.p['prefix_report'], self.prepared)
        self.save(self.p['cohort'], {'ps5_source': {'inert.c': 'external source-cohort validator mock'}})
        self.put(self.p['title'] / 'eboot.bin', b'original inert title', 0o755)
        self.put(self.p['title'] / 'sce_module/libc.prx', b'original inert libc', 0o755)
        self.service['libc_companion'] = package.record(self.p['title'] / 'sce_module/libc.prx')
        for n in ('title','service_work'):
            self.put(self.p[n] / 'native-wine-child.self', (self.seed / 'PPSA99995/native-wine-child.self').read_bytes(), 0o755)
            self.save(self.p[n] / 'native-wine-child-build.json', self.service)
        self.title = {'schema':'pw-windows-child-title/1','project':self.project,
            'fixture_child_sha256':self.pair['files']['child.exe']['sha256'],
            'service_manifest_sha256':package.digest_file(self.p['service_work'] / 'native-wine-child-build.json'),
            'runtime':self.service['runtime'],'compiler':self.compiler,'console_execution_verified':False,
            'files':package.title_files(package.prefix.inventory(self.p['title']))}
        self.save(self.p['title_report'],self.title)
        if battle:
            self.battle = package.read_json(self.seed / package.BATTLE_REPORT)
            self.battle['host_stamp']='inert-stamp'
            self.runtime = package.read_json(self.seed / package.BATTLE_CAPABILITY)['runtime_check']
            self.materialize_inventory(self.p['battlenet_prefix'],self.battle['inventory'],self.seed/'console')
            self.save(self.p['battlenet_prefix_report'],self.battle)
            self.save(self.p['cpu_output'] / 'cpu-build.json', self.prepared['cpu'])
        self.prepare_retained_sources()
        self.refresh_host_identity()

    @staticmethod
    def put(path, value, mode=0o644):
        path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(value);path.chmod(mode)

    def save(self,path,value): self.put(path,package.json_bytes(value))

    def materialize_inventory(self,root,inventory,source):
        for name, entry in inventory.items():
            path=root if name=='.' else root/name
            if entry['type']=='directory':path.mkdir(parents=True,exist_ok=True);path.chmod(entry['mode'])
            else:self.put(path,(source/name).read_bytes(),entry['mode'])

    def prepare_retained_sources(self):
        # Real tiny tar bytes; external Git and SDK identity analyzers are the
        # explicit mock boundary, while retained_sources checks all real bytes.
        raw=io.BytesIO()
        with tarfile.open(fileobj=raw,mode='w') as archive:
            item=tarfile.TarInfo('LICENSE');value=b'Original synthetic source notice\n';item.size=len(value)
            archive.addfile(item,io.BytesIO(value))
        self.archive_bytes=raw.getvalue();data=gzip.compress(self.archive_bytes,mtime=0)
        revisions={'project':self.project['commit'],'wine':package.prefix.WINE,
                   'title-foundation':self.service['title_foundation'],'prx-foundation':self.service['prx_foundation']}
        roles={}
        for name in ('project','wine','title-foundation','prx-foundation','sdk','freetype','gnutls','nettle','zlib','ca-bundle','lapy'):
            path=name+'.tar.gz';self.put(self.p['sources_root']/path,data)
            notice='notices/'+name+'/LICENSE';self.put(self.p['sources_root']/notice,b'Original synthetic notice')
            roles[name]={'path':path,'revision':revisions.get(name,'original-test-revision'),
                         'url':'https://example.invalid/original-inert-test','notices':[notice]}
        self.put(self.p['wine_archive'],data);self.put(self.p['sdk_source_archive'],data)
        self.sdk_identity={'commit':'5'*40,'tree':'6'*40,'sha256':package.digest_file(self.p['sdk_source_archive'])}
        self.sources={'schema':'pw-windows-child-retained-sources/1','project':self.project,'roles':roles,
                      'inventory':package.prefix.inventory(self.p['sources_root']),'sdk_source':self.sdk_identity}
        self.save(self.p['sources_manifest'],self.sources)
        self.put(self.p['repo']/'tools/build_wine_ps5.sh',
            ('MODULE_EXPORTS_COMMIT='+'4'*40+'\nFREETYPE_SHA256='+package.digest_file(self.p['sources_root']/'freetype.tar.gz')+'\n').encode())
        self.put(self.p['foundation']/'tools/setup-native-dependencies.sh',
            ('zlib_hash='+package.digest_file(self.p['sources_root']/'zlib.tar.gz')+'\n').encode())
        self.build['tls']={'build':{'inputs':{'host_llvm':self.compiler,'sources':{k:{'sha256':package.digest_file(self.p['sources_root']/ (v+'.tar.gz'))} for k,v in [('gnutls','gnutls'),('nettle','nettle'),('ca_bundle','ca-bundle')]}}}}
        self.save(self.p['wine_work']/'report.json',self.build)

    def refresh_host_identity(self):
        self.host_identity={'stamp':'inert-stamp','files':package.prefix.inventory(self.host,True),'host_files':{}}
        for f in self.host.rglob('*'):
            if f.is_file():self.host_identity['host_files']['pc/host-wine/usr/'+f.relative_to(self.host).as_posix()]=package.record(f)

    def external_validators(self):
        stack=ExitStack();self.addCleanup(stack.close)
        abi_mock=SimpleNamespace(check_build=lambda *a,**kw:copy.deepcopy(self.abi))
        prx_mock=SimpleNamespace(MODULES=MODULES,PE=PE,validate=lambda *a,**kw:copy.deepcopy(self.checked))
        def load_tool(root,name):
            self.assertEqual(root,self.p['repo'])
            return {'check_private_dispatch_abi':abi_mock,'check_wine_prx_build':prx_mock}[name]
        def git(root,*args):
            if args[:2]==('rev-parse','HEAD'):
                return self.service['title_foundation'] if root==self.title_foundation else self.service['prx_foundation']
            self.assertEqual(args,('show','-s','--format=%P',self.project['commit']));return '0'*40
        def run(command,**kwargs):
            if command[:1]==['git']:
                self.assertEqual(command[1],'-C');self.assertEqual(command[3],'archive')
                return subprocess.CompletedProcess(command,0,stdout=self.archive_bytes)
            self.assertEqual(command,[sys.executable,str(self.p['repo']/'tools/tls_manifest.py'),'verify-runtime','--root',str(self.p['wine_work'])])
            return subprocess.CompletedProcess(command,0)
        # No assembly, archive writer/verifier, manifest or filesystem helper is mocked.
        stack.enter_context(patch.object(package.prefix,'project',return_value=self.project))
        stack.enter_context(patch.object(package.prefix,'host_identity',side_effect=lambda *a:(copy.deepcopy(self.host_identity),self.host)))
        stack.enter_context(patch.object(package.prefix,'verify_source_snapshot'))
        stack.enter_context(patch.object(package.prefix,'validate_pair',return_value=self.pair))
        stack.enter_context(patch.object(package.prefix,'load_tool',side_effect=load_tool))
        stack.enter_context(patch.object(package.prefix,'git',side_effect=git))
        stack.enter_context(patch.object(package,'validate_service',return_value=self.service))
        stack.enter_context(patch.object(package,'validate_title',return_value=self.title))
        stack.enter_context(patch.object(package.subprocess,'run',side_effect=run))
        stack.enter_context(patch('check_native_suite.source_archive',return_value=self.sdk_identity))
        if self.config['battlenet_enabled']:
            stack.enter_context(patch.object(package.prefix,'check_battlenet_runtime',return_value=self.runtime))
        return stack

    def test_complete_assembly_real_directory_and_archive_both_modes(self):
        for battle in (False,True):
            with self.subTest(battle=battle):
                self.setup_inputs(battle)
                before=package.prefix.inventory(self.temp/'inputs')
                with self.external_validators():result=package.assemble(self.config,self.out)
                directory=self.out/'windows-child-fixture';archive=self.out/'windows-child-fixture.tar.gz'
                actual=package.verify_directory(directory)
                self.assertEqual(package.verify_archive(archive),actual)
                self.assertEqual(actual['inventory'],{n:v for n,v in package.inventory(directory).items() if n not in (package.MANIFEST,package.SUMS)})
                self.assertEqual(result['archive'],package.record(archive));self.assertEqual(result['battlenet_enabled'],battle)
                self.assertEqual(package.prefix.inventory(self.temp/'inputs'),before)
                self.assertFalse((directory/package.BATTLE_INSTALLER).exists())
                self.assertEqual((directory/package.BATTLE_CAPABILITY).exists(),battle)
                self.assertEqual(package.prefix.inventory(directory/'sources'),self.sources['inventory'])

    def test_existing_output_and_duplicate_runtime_destination_fail(self):
        self.setup_inputs(False);self.out.mkdir();self.put(self.out/'keep',b'keep')
        with self.external_validators(),self.assertRaisesRegex(ValueError,'output already exists'):
            package.assemble(self.config,self.out)
        self.assertEqual((self.out/'keep').read_bytes(),b'keep')
        self.out=self.temp/'fresh-second-output'
        self.put(self.host/'lib/wine/x86_64-windows/wowprospero.dll',b'duplicate original CPU');self.refresh_host_identity()
        with self.external_validators(),self.assertRaisesRegex(ValueError,'duplicate package destination'):
            package.assemble(self.config,self.out)
        self.assertFalse((self.out/'windows-child-fixture.tar.gz').exists())

    def test_changed_retained_sources_fail_inside_real_validator(self):
        self.setup_inputs(False)
        self.put(self.p['sources_root']/'project.tar.gz',b'changed original bytes')
        with self.external_validators(),self.assertRaisesRegex(ValueError,'retained source inventory differs'):
            package.assemble(self.config,self.out)
        self.assertFalse((self.out/'windows-child-fixture.tar.gz').exists())

    def test_battle_profile_and_capability_remain_real_checks(self):
        self.setup_inputs(True)
        profile=self.p['battlenet_prefix']/package.BATTLE_PROFILE.removeprefix('console/')
        profile.write_text(profile.read_text().replace('cpu = translator','cpu = native'))
        self.battle['inventory']=package.prefix.inventory(self.p['battlenet_prefix']);self.save(self.p['battlenet_prefix_report'],self.battle)
        with self.external_validators(),self.assertRaisesRegex(ValueError,'Battle profile differs'):
            package.assemble(self.config,self.out)
        self.assertFalse((self.out/'windows-child-fixture.tar.gz').exists())

    def reseal_inventory(self, directory):
        manifest = package.read_json(directory / package.MANIFEST)
        manifest['inventory'] = {n: v for n, v in package.inventory(directory).items()
                                 if n not in (package.MANIFEST, package.SUMS)}
        self.save(directory / package.MANIFEST, manifest)
        self.put(directory / package.SUMS, package.checksums(package.inventory(directory)))

    def test_assembled_battle_capability_is_required_and_cannot_claim_execution(self):
        self.setup_inputs(True)
        with self.external_validators(): package.assemble(self.config, self.out)
        directory = self.out / 'windows-child-fixture'
        target = directory / package.BATTLE_CAPABILITY
        original = target.read_bytes()
        for missing in (True, False):
            with self.subTest(missing=missing):
                if missing:
                    target.unlink()
                    error = 'Battle capability/prefix/profile/CPU report missing'
                else:
                    value = package.decode_json(original); value['runtime_validated'] = True
                    self.save(target, value)
                    error = 'Battle capability scope/profile/installer identity differs'
                self.reseal_inventory(directory)
                with self.assertRaisesRegex(ValueError, error): package.verify_directory(directory)
                archive = self.temp / ('bad-capability-' + str(missing) + '.tar.gz')
                package.write_archive(directory, archive)
                with self.assertRaisesRegex(ValueError, error): package.verify_archive(archive)

    def test_assembled_exact_manifest_and_duplicate_archive_path(self):
        self.setup_inputs(False)
        with self.external_validators(): package.assemble(self.config, self.out)
        directory = self.out / 'windows-child-fixture'
        manifest = package.read_json(directory / package.MANIFEST)
        del manifest['inventory']['sources/project.tar.gz']
        self.save(directory / package.MANIFEST, manifest)
        self.put(directory / package.SUMS, package.checksums(package.inventory(directory)))
        with self.assertRaisesRegex(ValueError, 'complete package inventory differs'):
            package.verify_directory(directory)
        incomplete = self.temp / 'incomplete-manifest.tar.gz'
        package.write_archive(directory, incomplete)
        with self.assertRaisesRegex(ValueError, 'complete package inventory differs'):
            package.verify_archive(incomplete)
        duplicate = self.temp / 'duplicate-member.tar.gz'
        with tarfile.open(self.out / 'windows-child-fixture.tar.gz', 'r:gz') as original:
            with tarfile.open(duplicate, 'w:gz', format=tarfile.PAX_FORMAT) as changed:
                for member in original:
                    changed.addfile(member, original.extractfile(member) if member.isfile() else None)
                member = original.getmember('BUILD-INFO.txt')
                changed.addfile(member, original.extractfile(member))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            package.verify_archive(duplicate)

    def test_assembled_manifest_false_claim_rejected_after_rehash(self):
        self.setup_inputs(False)
        with self.external_validators():package.assemble(self.config,self.out)
        directory=self.out/'windows-child-fixture';manifest=package.read_json(directory/package.MANIFEST)
        manifest['console_validated']=True;self.save(directory/package.MANIFEST,manifest)
        self.put(directory/package.SUMS,package.checksums(package.inventory(directory)))
        with self.assertRaisesRegex(ValueError,'schema/scope'):package.verify_directory(directory)
        archive=self.temp/'false-claim.tar.gz';package.write_archive(directory,archive)
        with self.assertRaisesRegex(ValueError,'schema/scope'):package.verify_archive(archive)


if __name__ == '__main__':
    unittest.main()
