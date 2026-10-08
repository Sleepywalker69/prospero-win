#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Bounded producer CI, portable owned files, and a no-vendor Notepad recipe."""
from pathlib import Path
import importlib.util
import json
import struct
import sys
import tempfile
import unittest
import yaml

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
spec = importlib.util.spec_from_file_location('kit', ROOT / 'tools/package_diagnostic_kit.py')
kit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kit)


class KitTests(unittest.TestCase):
    def test_public_repository_binding(self):
        self.assertEqual(kit.repository('https://github.com/owner/repo'), 'https://github.com/owner/repo')
        for value in ('http://github.com/owner/repo', 'https://token@github.com/owner/repo',
                      'https://github.com/owner/repo?secret=x', 'https://example.com/owner/repo',
                      'https://github.com/../repo'):
            with self.assertRaises(ValueError):
                kit.repository(value)

    def test_owned_tree_and_portable_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root / 'source'; source.mkdir()
            (source / 'binary').write_bytes(b'owned')
            (source / 'absolute').symlink_to(source / 'binary')
            kit.copy_owned_tree(source, root / 'copy')
            self.assertEqual((root / 'copy/absolute').read_bytes(), b'owned')
            self.assertFalse((root / 'copy/absolute').readlink().is_absolute())
            (root / 'private').write_bytes(b'not an artifact')
            (source / 'escape').symlink_to(root / 'private')
            with self.assertRaises(ValueError):
                kit.copy_owned_tree(source, root / 'rejected')
            self.assertFalse((root / 'rejected').exists())

    def test_pe_identity_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'synthetic-header.dll'
            value = bytearray(256); value[:2] = b'MZ'; struct.pack_into('<I', value, 60, 128)
            value[128:132] = b'PE\0\0'; struct.pack_into('<H', value, 132, 0x8664)
            struct.pack_into('<H', value, 152, 0x20b); path.write_bytes(value)
            kit.pe(path, 0x8664)
            with self.assertRaises(ValueError):
                kit.pe(path, 0x14c)
            struct.pack_into('<I', value, 60, 0xffffffff); path.write_bytes(value)
            with self.assertRaises(ValueError):
                kit.pe(path, 0x8664)

    def test_recipe_creates_only_owned_prefix(self):
        recipe = yaml.safe_load(kit.NOTEPAD_RECIPE)
        self.assertEqual(recipe['prospero']['graphics'], 'gdi')
        self.assertEqual(recipe['script']['game']['exe'], 'drive_c/windows/system32/notepad.exe')
        self.assertEqual(recipe['script']['installer'], [{'task': {'name': 'create_prefix', 'prefix': '$GAMEDIR',
                                                                  'install_gecko': False, 'install_mono': False}}])
        self.assertFalse(recipe['script']['wine']['dxvk'])

    def test_native_linkage_actual_providers_and_hostile_inputs(self):
        # Synthetic ELF metadata plus analyzer transcripts, never executable code.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); sdk = root / 'sdk'; prx = root / 'prx'; bindir = root / 'bin'
            (sdk / 'target/lib').mkdir(parents=True); prx.mkdir()
            shared = root / 'wow64native.shared.elf'
            value = bytearray(256); value[:7] = b'\x7fELF\x02\x01\x01'
            struct.pack_into('<HHIQQQIHHHHHH', value, 16, 3, 62, 1, 0x80, 64, 0, 0, 64, 56, 1, 0, 0, 0)
            struct.pack_into('<IIQQQQQQ', value, 64, 1, 5, 0, 0, 0, 256, 256, 0x1000)
            shared.write_bytes(value)
            ntdll = prx / 'ntdll.shared.elf'; ntdll.write_bytes(b'fixture ntdll provider')
            kernel = sdk / 'target/lib/libkernel_stub_weak.so'; kernel.write_bytes(b'fixture alias provider')
            class Analyzer:
                needed = ['ntdll.prx', 'libkernel.sprx']
                alias = 'libkernel.sprx'
                import_kind = 'FUNC'
                provider_binding = 'GLOBAL'
                provider_visibility = 'DEFAULT'
                provider_name = 'called'
                first_provider_kind = 'FUNC'
                disassembly = '00000000 <module_start>:\n 0: retq\n'
                failed = False
                def run(self, *args):
                    if self.failed:
                        raise ValueError('artifact analyzer failed')
                    path = Path(args[-1])
                    if Path(args[0]).name == 'llvm-objdump':
                        return self.disassembly
                    if '--dyn-syms' in args:
                        if path == shared:
                            return ('1: 0 0 FUNC GLOBAL DEFAULT 1 module_start\n'
                                    '2: 0 0 OBJECT GLOBAL DEFAULT 1 __wine_unix_call_funcs\n'
                                    f'3: 0 0 {self.import_kind} GLOBAL DEFAULT UND called\n')
                        kind = self.first_provider_kind if path == ntdll else 'FUNC'
                        return f'1: 0 0 {kind} {self.provider_binding} {self.provider_visibility} 1 {self.provider_name}\n'
                    if path == shared:
                        return 'Library soname: [wow64native.prx]\n' + ''.join(f'Shared library: [{n}]\n' for n in self.needed)
                    return f'Library soname: [{"ntdll.prx" if path == ntdll else self.alias}]\n'
            analyzer = Analyzer()
            result = kit.validate_native_link(shared, sdk, prx, bindir, analyzer)
            self.assertEqual(result['imports'], ['called'])
            # The filename looks weak/benign but the actual SONAME is forbidden.
            for field, bad, message in (
                ('alias', 'libkernel_web.sprx', 'missing provider'),
                ('needed', ['ntdll.prx', 'libkernel_web.sprx'], 'forbidden import'),
                ('needed', ['ntdll.prx', 'libkernel_sys.sprx'], 'forbidden import'),
                ('needed', ['libkernel.sprx'], 'ntdll linkage'),
                ('provider_name', 'unrelated', 'unresolved actual imports'),
                ('provider_binding', 'LOCAL', 'empty dynamic provider'),
                ('provider_visibility', 'HIDDEN', 'empty dynamic provider'),
                ('first_provider_kind', 'OBJECT', 'incompatible first provider'),
                ('first_provider_kind', 'TLS', 'incompatible first provider'),
                ('first_provider_kind', 'NOTYPE', 'incompatible first provider'),
                ('import_kind', 'OBJECT', 'data/TLS import'),
                ('import_kind', 'TLS', 'data/TLS import'),
                ('disassembly', '0: syscall\n', 'raw syscall'),
                ('disassembly', '', 'empty disassembly'),
                ('failed', True, 'analyzer failed'),
            ):
                with self.subTest(field=field, value=bad):
                    original = getattr(analyzer, field); setattr(analyzer, field, bad)
                    with self.assertRaisesRegex(ValueError, message):
                        kit.validate_native_link(shared, sdk, prx, bindir, analyzer)
                    setattr(analyzer, field, original)

    def test_workflow_is_bounded_and_fail_closed(self):
        workflow = yaml.load((ROOT / '.github/workflows/diagnostic-kit.yml').read_text(), Loader=yaml.BaseLoader)
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        self.assertNotIn('pull_request_target', workflow['on'])
        job = workflow['jobs']['diagnostic-kit']
        self.assertEqual(job['runs-on'], 'ubuntu-24.04')
        self.assertEqual(job['timeout-minutes'], '330')
        self.assertIn('github.event.pull_request.head.repo.full_name == github.repository', job['if'])
        self.assertIn('build-diagnostic-kit', job['if'])
        runs = '\n'.join(s.get('run', '') for s in job['steps'])
        for command in ('make -j2 all', 'make -j2 sanitize', 'tools/build_host_wine.sh',
                        'tools/build_native.sh', 'tools/build_wine_ps5.sh', 'tools/build_wowprospero.sh',
                        'tools/build_wow64native.sh', 'tools/check_wine_prx_build.py',
                        'tools/package_diagnostic_kit.py software-gdi-kit'):
            self.assertIn(command, runs)
        self.assertNotIn('detect_leaks=0', runs)
        self.assertNotIn('--force', runs)
        self.assertIn('libkernel_web.so|libkernel_stub_weak.so|libkernel_sys.so|libScePosixForWebKit.so', runs)
        self.assertIn('--wine \"$RUNNER_TEMP/host-checkpoint/pc/host-wine/usr/bin/wine\"', runs)
        self.assertIn('--sdk \"$PS5_PAYLOAD_SDK\"', runs)
        checkpoint = next(i for i,s in enumerate(job['steps']) if s.get('name','').startswith('Retain completed host'))
        cross = next(i for i,s in enumerate(job['steps']) if s.get('name','').startswith('Run the existing Wine PRX'))
        self.assertLess(checkpoint, cross)
        for step in job['steps']:
            self.assertNotIn('continue-on-error', step)
            if 'uses' in step:
                self.assertRegex(step['uses'], r'^actions/[a-z-]+@[0-9a-f]{40}$')
                if step['uses'].startswith('actions/checkout@'):
                    self.assertEqual(step['with']['persist-credentials'], 'false')


if __name__ == '__main__':
    unittest.main()
