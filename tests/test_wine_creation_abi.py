#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Original inert ELF/SELF fixtures exercise the real creation identity reader."""
import copy
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'tests'))
import wine_creation_abi as check
from test_native_suite import self_fixture


def creation_elf(name, *, kind=3, abi=1, protocol=962):
    exports = check.EXPORTS[name]
    data = bytearray(0x3004)
    data[:8] = b'\x7fELF\x02\x01\x01\x09'
    struct.pack_into('<HHIQQ', data, 16, kind, 62, 1, 0, 64)
    strings = bytearray(b'\0'); offsets = []
    for export in exports:
        offsets.append(len(strings)); strings.extend(export.encode() + b'\0')
    tags = [(5, 0x2300), (10, len(strings)), (6, 0x2500), (11, 24), (0x6100003F, 24*(len(exports)+1)),
            (7, 0x2800), (8, 48*len(exports)), (9, 24), (0, 0)]
    programs = [(1, 5, 0x400, 0x1000, 0x1000, 0x400, 0x400, 0x1000),
                (1, 6, 0x1000, 0x2000, 0x2000, 0x2000, 0x2000, 0x1000),
                (2, 6, 0x1000, 0x2000, 0x2000, len(tags)*16, len(tags)*16, 8),
                (0x6fffff01, 0, 0x3000, 0, 0, 4, 4, 1)]
    struct.pack_into('<HHH', data, 52, 64, 56, len(programs))
    for i, row in enumerate(programs): struct.pack_into('<IIQQQQQQ', data, 64+i*56, *row)
    for i, row in enumerate(tags): struct.pack_into('<qQ', data, 0x1000+i*16, *row)
    data[0x1300:0x1300+len(strings)] = strings
    data[0x1c00:0x1c08] = b'PRXDESC1';struct.pack_into('<II', data, 0x1c08, 1, len(exports))
    for i, export in enumerate(exports):
        address = 0x1000+i*32
        code = b'\xb8'+struct.pack('<I', abi if export==check.ABI_EXPORT else protocol if export==check.PROTOCOL_EXPORT else 0)+b'\xc3'
        data[0x400+i*32:0x400+i*32+len(code)] = code
        struct.pack_into('<IBBHQQ', data, 0x1500+(i+1)*24, offsets[i], 0x12, 0, 1, address, len(code))
        for j, value in enumerate((0x2300+offsets[i], address)):
            struct.pack_into('<QQq', data, 0x1800+(2*i+j)*24, 0x2c10+i*16+j*8, 8, value)
    data[-4:] = b'VERS'
    return bytes(data)


def cohort(root):
    report = {'creation': dict(check.DECLARATION), 'targets': {}, 'prx': {'modules': {}}}
    for name in check.EXPORTS:
        native_path = 'dlls/ntdll/ntdll.so' if name=='ntdll' else 'server/wineserver'
        images = {'build/'+native_path: creation_elf(name), 'prx/'+name+'.shared.elf': creation_elf(name),
                  'prx/'+name+'.elf': creation_elf(name, kind=0xfe18)}
        images['prx/sce_module/'+name+'.prx'] = self_fixture(images['prx/'+name+'.elf'])
        for leaf, data in images.items():
            path=root/leaf;path.parent.mkdir(parents=True, exist_ok=True);path.write_bytes(data)
        report['targets'][native_path] = check.record(images['build/'+native_path])
        report['prx']['modules'][name] = check.record(images['prx/sce_module/'+name+'.prx'])
    return report


class CreationABI(unittest.TestCase):
    def test_complete_cohort_and_offline_replay(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);report=cohort(root);result=check.check_runtime(root,report)
            check.check_package(result,report,lambda n:(root/'prx/sce_module'/f'{n}.prx').read_bytes())
            self.assertEqual(result['protocol'],962);self.assertFalse(result['executed'])

    def test_old_or_wrong_declaration_refused_before_artifact_access(self):
        for value in ({}, {'creation': {}}, {'creation': {**check.DECLARATION,'protocol':961}},
                      {'creation': {**check.DECLARATION,'maximum_depth':3}}):
            with self.assertRaises(ValueError):check.check_runtime(Path('/absent'),value)

    def test_actual_marker_and_descriptor_mutations_refused(self):
        for name in check.EXPORTS:
            for abi,protocol in [(0,962),(1,961),(2,962)]:
                with self.assertRaises(ValueError):check.module_identity(self_fixture(creation_elf(name,kind=0xfe18,abi=abi,protocol=protocol)),name)
            for at,fmt,value in [(0x1c08,'<I',2),(0x1800+8,'<Q',7),(0x1800+24+16,'<q',0x2000)]:
                data=bytearray(creation_elf(name,kind=0xfe18));struct.pack_into(fmt,data,at,value)
                with self.assertRaises(ValueError):check.module_identity(self_fixture(bytes(data)),name)

    def test_short_marker_at_executable_load_end(self):
        for name in check.EXPORTS:
            for index in (0,1):
                data=bytearray(creation_elf(name,kind=0xfe18))
                data[0x7fa:0x800]=data[0x400+index*32:0x406+index*32]
                struct.pack_into('<Q',data,0x1500+(index+1)*24+8,0x13fa)
                struct.pack_into('<q',data,0x1800+(2*index+1)*24+16,0x13fa)
                self.assertEqual(check.module_identity(self_fixture(bytes(data)),name)['self'],
                                 check.record(self_fixture(bytes(data))))
                data[0x7ff]=0
                with self.assertRaises(ValueError):check.module_identity(self_fixture(bytes(data)),name)

    def test_build_hash_visibility_and_converted_body_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);report=cohort(root)
            bad=copy.deepcopy(report);bad['targets']['server/wineserver']['sha256']='0'*64
            with self.assertRaises(ValueError):check.check_runtime(root,bad)
            path=root/'prx/ntdll.shared.elf';old=path.read_bytes();bad=bytearray(old);bad[0x1500+24+5]=2;path.write_bytes(bad)
            with self.assertRaises(ValueError):check.check_runtime(root,report)
            path.write_bytes(old)
            path=root/'prx/ntdll.elf';bad=bytearray(path.read_bytes());bad[0x400+64+1]^=1;path.write_bytes(bad)
            with self.assertRaises(ValueError):check.check_runtime(root,report)

    def test_offline_stale_receipt_and_swapped_modules_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);report=cohort(root);result=check.check_runtime(root,report)
            reader=lambda n:(root/'prx/sce_module'/f'{n}.prx').read_bytes()
            for field,value in [('abi',0),('protocol',961),('executed',True),('runtime_validated',True)]:
                bad=copy.deepcopy(result);bad[field]=value
                with self.assertRaises(ValueError):check.check_package(bad,report,reader)
            with self.assertRaises(ValueError):check.check_package(result,report,lambda n:reader('wineserver' if n=='ntdll' else 'ntdll'))


if __name__ == '__main__': unittest.main()
