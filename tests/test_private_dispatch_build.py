#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Original PE bytes and scripted analyzers; no Wine or target execution."""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('dispatcher_build', ROOT/'tools/check_private_dispatch_abi.py')
abi = importlib.util.module_from_spec(spec); spec.loader.exec_module(abi)


def pe(anchor, mode):
    data = bytearray(2048); data[:2] = b'MZ'; struct.pack_into('<I', data, 60, 0x80)
    data[0x80:0x84] = b'PE\0\0'; struct.pack_into('<HH', data, 0x84, 0x8664, 1)
    struct.pack_into('<H', data, 0x94, 0xf0); struct.pack_into('<H', data, 0x98, 0x20b)
    struct.pack_into('<I', data, 0x98+108, 1); struct.pack_into('<II', data, 0x98+112, 0x1100, 40)
    struct.pack_into('<IIII', data, 0x188+8, 0x600, 0x1000, 0x600, 0x200)
    struct.pack_into('<IIHHIIIIIII', data, 0x300, 0, 0, 0, 0, 0, 1, 1, 1, 0x1200, 0x1210, 0x1220)
    struct.pack_into('<I', data, 0x400, 0x1000); struct.pack_into('<I', data, 0x410, 0x1230)
    data[0x430:0x430+len(anchor)+1] = anchor.encode()+b'\0'
    data[0x200:0x220] = abi.PREFIX+struct.pack('<I', 7)+abi.MIDDLE+struct.pack('<I', abi.SLOTS[mode])+b'\xc3'
    return data


class BuildIdentity(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.tool = self.root/'readelf'
        self.native = self.root/'build/dlls/ntdll/ntdll.so'; self.native.parent.mkdir(parents=True)
        self.native.write_bytes(b'original synthetic ELF fixture')
        self.shared = self.root/'prx/ntdll.shared.elf'; self.shared.parent.mkdir(parents=True)
        self.shared.write_bytes(b'original shared ELF fixture')

    def prepare(self, mode):
        modules = {}
        for name, anchor in [('ntdll', 'NtClose'), ('win32u', 'NtUserGetThreadState')]:
            path = self.root/'pe/x86_64-windows'/(name+'.dll'); path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(pe(anchor, mode)); modules[name] = abi.check_image(path.read_bytes(), anchor, mode)
        identity = {'abi': mode, 'executed': False, 'scope': 'PE thunk bytes only', 'modules': modules}
        digest = hashlib.sha256(self.native.read_bytes()).hexdigest()
        self.report = {'prx': {'status': '0'}, 'errors': [], 'targets': {'dlls/ntdll/ntdll.so': {'sha256': digest}}}
        if mode:
            self.report['private_dispatcher'] = {'abi': 1, 'runtime_validated': False,
                'native_abi_export': '__wine_ps5_private_dispatch_abi', 'native_elf_sha256': digest, 'pe_identity': identity}
        (self.root/'private-dispatch-pe.json').write_text(json.dumps(identity))
        self.save(); self.analyzer(mode)

    def save(self):
        (self.root/'report.json').write_text(json.dumps(self.report))

    def analyzer(self, mode, row=None, fail=False, empty=False):
        row = row if row is not None else '1: 1000 6 FUNC GLOBAL DEFAULT 1 __wine_ps5_private_dispatch_abi'
        text = '' if empty else "Symbol table '.dynsym' contains 2 entries:\n" + (row+'\n' if mode else '')
        self.tool.write_text('#!/bin/sh\n' + ('exit 7\n' if fail else "cat <<'END'\n"+text+'END\n'))
        self.tool.chmod(0o755)

    def test_actual_pe_operands_and_report_bind_both_modes(self):
        for mode in (0, 1):
            self.prepare(mode); result = abi.check_build(self.root, mode, self.tool)
            self.assertEqual(result['mode'], mode); self.assertFalse(result['executed'])
            self.assertEqual(set(result['pe_identity']['modules']), {'ntdll', 'win32u'})
            with self.assertRaises(ValueError): abi.check_build(self.root, 1-mode, self.tool)

    def test_failed_analyzer_and_nonfunction_exports_fail(self):
        self.prepare(1)
        row = '1: 1000 6 FUNC GLOBAL DEFAULT 1 __wine_ps5_private_dispatch_abi'
        for bad in (row.replace('FUNC', 'OBJECT'), row.replace('GLOBAL', 'LOCAL'),
                    row.replace('DEFAULT', 'HIDDEN'), row.replace('DEFAULT 1', 'DEFAULT UND'), row+'\n'+row, ''):
            self.analyzer(1, row=bad)
            with self.subTest(row=bad), self.assertRaises(ValueError): abi.check_build(self.root, 1, self.tool)
        self.analyzer(1, fail=True)
        with self.assertRaises(subprocess.CalledProcessError): abi.check_build(self.root, 1, self.tool)
        self.analyzer(1, empty=True)
        with self.assertRaises(ValueError): abi.check_build(self.root, 1, self.tool)
        self.prepare(0); self.analyzer(1)
        with self.assertRaises(ValueError): abi.check_build(self.root, 0, self.tool)

    def test_skips_changed_artifacts_and_false_runtime_claims_fail(self):
        for mutation in ('skip', 'errors', 'native', 'report-native', 'report-pe', 'staged-pe', 'runtime', 'off-record'):
            self.prepare(0 if mutation == 'off-record' else 1)
            if mutation == 'skip': self.report['prx']['status'] = 'skipped'
            if mutation == 'errors': self.report['errors'] = ['compile failed']
            if mutation == 'native': self.native.write_bytes(b'changed after report')
            if mutation == 'report-native': self.report['private_dispatcher']['native_elf_sha256'] = '0'*64
            if mutation == 'report-pe': self.report['private_dispatcher']['pe_identity']['modules']['ntdll']['sha256'] = '0'*64
            if mutation == 'staged-pe': (self.root/'private-dispatch-pe.json').write_text('{}')
            if mutation == 'runtime': self.report['private_dispatcher']['runtime_validated'] = True
            if mutation == 'off-record': self.report['private_dispatcher'] = None
            self.save()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                abi.check_build(self.root, 0 if mutation == 'off-record' else 1, self.tool)


if __name__ == '__main__':
    unittest.main()
