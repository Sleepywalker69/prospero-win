#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Original static byte-reader/report controls; no target or Wine execution."""
import copy
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest
from unittest import mock
sys.dont_write_bytecode = True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import private_dispatch_wow64 as check
from native_probe_elf import Elf, extract_self
sys.path.insert(0,str(ROOT/'tests'))
from test_native_suite import elf_fixture, self_fixture


def pe_fixture(anchor='NtClose',slot='__wine_syscall_dispatcher'):
    data=bytearray(8192)
    def put(fmt,at,*values):struct.pack_into(fmt,data,at,*values)
    data[:2]=b'MZ';put('<I',60,0x80);put('<I',0x80,0x4550)
    put('<HH',0x84,0x14c,3);put('<H',0x94,0xe0);put('<H',0x98,0x10b)
    put('<I',0x98+28,0x10000000);put('<II',0x98+56,8192,0x400);put('<I',0x98+92,16)
    put('<II',0x98+96,0x1000,0x80);put('<II',0x98+136,0x1400,12)
    for at,span,rva,flags in [(0x178,0x400,0x400,0x60000020),(0x1a0,0x400,0x800,0xc0000040),
                               (0x1c8,0x1000,0x1000,0x40000040)]:
        put('<IIII',at+8,span,rva,span,rva);put('<I',at+36,flags)
    put('<IIIII',0x1014,2,2,0x1100,0x1120,0x1140)
    put('<II',0x1100,0x400,0x800);put('<II',0x1120,0x1160,0x1180);put('<HH',0x1140,0,1)
    for at,name in [(0x1160,anchor),(0x1180,slot)]:data[at:at+len(name)+1]=name.encode()+b'\0'
    data[0x400:0x40f]=bytes.fromhex('b80f000000ba40040010ffd2c20400')
    data[0x440:0x446]=bytes.fromhex('ff2500080010')
    put('<IIHH',0x1400,0,12,0x3406,0x3442)
    return data


def new_side(patch,name):
    body=patch.read_text().split('+++ b/'+name+'\n',1)[1].split('\n--- ',1)[0]
    return '\n'.join(line[1:] for h in ('\n'+body).split('\n@@')[1:]
                     for line in h.splitlines()[1:] if line.startswith((' ','+')))+'\n'


class WoW64Build(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='pw-wow64-inert-tests-'); cls.addClassCleanup(cls.temp.cleanup)
        cls.root=Path(cls.temp.name); source=cls.root/'source'; (source/'include/wine').mkdir(parents=True)
        override=os.environ.get('PW_WOW64_HEADER_DIR')
        for name,number in [('pw_private_dispatch.h','0910'),('pw_private_dispatch_i386.h','0914')]:
            dest=source/'include/wine'/name
            if override:dest.write_bytes((Path(override)/name).read_bytes())
            else:
                patches=list((ROOT/'wine/patches').glob(number+'-*.patch'))
                if len(patches)!=1:raise AssertionError('required checked validator patch unavailable: '+number)
                dest.write_text(new_side(patches[0],'include/wine/'+name))
        compiler=os.environ.get('PW_DISPATCH_CLANG') or shutil.which('cc')
        if not compiler:raise AssertionError('host compiler required for inert byte-reader tests')
        cls.reader,cls.identity=check.build_reader(source,cls.root,compiler)

    def test_real_reader_both_module_roles(self):
        for anchor,slot in [('NtClose','__wine_syscall_dispatcher'),('NtUserGetThreadState','Wow64Transition')]:
            result=check.check_i386(bytes(pe_fixture(anchor,slot)),anchor,slot,self.reader)
            self.assertEqual(result['machine'],'I386');self.assertFalse(result['executed'])

    def test_shared_page_wrong_slot_and_missing_relocation_refused(self):
        for at,fmt,value in [(0x442,'<I',0x7ffe1000),(0x442,'<I',0x7ffe4000),
                             (0x800,'<I',1),(0x1408,'<H',0),(0x140a,'<H',0),
                             (0x1a0+36,'<I',0xe0000040),(0x178+36,'<I',0xe0000020)]:
            with self.subTest(at=at,value=value):
                data=pe_fixture();struct.pack_into(fmt,data,at,value)
                with self.assertRaisesRegex(ValueError,'contract failed'):
                    check.check_i386(bytes(data),'NtClose','__wine_syscall_dispatcher',self.reader)

    def test_mapper_refuses_raw_virtual_alias_and_architecture(self):
        for at,value in [(0x1a0+12,0x600),(0x1a0+20,0x400),(0x98+56,check.LIMIT+1)]:
            data=pe_fixture();struct.pack_into('<I',data,at,value)
            with self.assertRaises(ValueError):check.mapped_pe(data)
        data=pe_fixture();struct.pack_into('<H',data,0x84,0x8664)
        with self.assertRaises(ValueError):check.mapped_pe(data)

    def test_bad_compiler_or_reader_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(Exception):check.build_reader(self.root/'source',Path(directory),'/missing/compiler')
        with mock.patch.object(check.subprocess,'run',return_value=type('Result',(),{'returncode':2,'stdout':b'','stderr':b''})()):
            with self.assertRaisesRegex(ValueError,'contract failed'):
                check.check_i386(bytes(pe_fixture()),'NtClose','__wine_syscall_dispatcher',self.reader)

    def test_native_export_type_value_and_function_bytes(self):
        elf=type('Image',(),{})();elf.data=bytes.fromhex('b801000000c3')
        elf.offset=lambda value,size,flags:0
        elf.symbols=[{'name':check.EXPORT,'type':2,'binding':1,'visibility':0,'section':1,'size':6,'value':0x1000}]
        _,code=check.function(elf,check.EXPORT);check.returns_one(code)
        for field,value in [('type',1),('type',6),('section',0),('visibility',2),('size',0)]:
            old=elf.symbols[0][field];elf.symbols[0][field]=value
            with self.assertRaises(ValueError):check.function(elf,check.EXPORT)
            elf.symbols[0][field]=old
        for code in [bytes.fromhex('31c0c3'),bytes.fromhex('b802000000c3'),b'\xc3']:
            with self.assertRaises(ValueError):check.returns_one(code)

    def test_descriptor_pointer_requires_exact_owned_relocation(self):
        elf=type('Image',(),{})();elf.offset=lambda address,size,flags:0
        elf.symbols=[{}, {'section':1,'value':0x1000}]
        elf.relocations=[{'address':0x2000,'type':8,'symbol':0,'addend':0x1000}]
        self.assertEqual(check.pointer(elf,0x2000),0x1000)
        for value in [[],elf.relocations*2,[{**elf.relocations[0],'address':0x2001}],
                      [{**elf.relocations[0],'type':7}],[{**elf.relocations[0],'symbol':1}]]:
            saved=elf.relocations;elf.relocations=value
            with self.assertRaises(ValueError):check.pointer(elf,0x2000)
            elf.relocations=saved

    def test_actual_descriptor_table_not_marker_alone(self):
        data=bytearray(512);data[:8]=b'PRXDESC1';struct.pack_into('<II',data,8,1,1)
        data[128:128+len(check.EXPORT)+1]=check.EXPORT.encode()+b'\0'
        elf=type('Image',(),{})();elf.data=bytes(data)
        elf.programs=[(1,4,0,0x2000,0x2000,len(data),len(data),16)]
        elf.offset=lambda address,size,flags:address-0x2000 if 0x2000<=address<=0x2200-size else (_ for _ in ()).throw(ValueError('mapping'))
        elf.relocations=[{'address':0x2010,'type':8,'symbol':0,'addend':0x2080},
                         {'address':0x2018,'type':8,'symbol':0,'addend':0x2100}]
        self.assertEqual(check.descriptor(elf,check.EXPORT)[1],0x2100)
        elf.relocations.pop()
        with self.assertRaises(ValueError):check.descriptor(elf,check.EXPORT)

    def test_actual_producer_module_directory_without_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            work=Path(directory);stage=work/'prx/sce_module';stage.mkdir(parents=True)
            for name in ('ntdll','wowprospero'):
                (stage/(name+'.prx')).write_bytes(b'actual staged module')
                (work/'prx'/(name+'.prx')).write_bytes(b'wrong old path')
                self.assertEqual(check.module_bytes(work,name),b'actual staged module')
                (stage/(name+'.prx')).unlink()
                with self.assertRaises(ValueError):check.module_bytes(work,name)

    def test_old_abi_only_refused_before_artifact_access(self):
        for report in [{},{'private_dispatcher':{'abi':1}},{'private_dispatcher':{'wow64_abi':0}},
                       {'private_dispatcher':{'wow64_abi':1,'native_wow64_abi_export':'other'}}]:
            with self.assertRaisesRegex(ValueError,'older ABI1'):
                check.check_runtime(Path('/no/artifacts'),report,'cc')

    def test_module_mode_preserves_default_executable_guards(self):
        data=bytearray(elf_fixture());struct.pack_into('<Q',data,24,0)
        with self.assertRaises(ValueError):Elf(bytes(data))
        Elf(bytes(data),module=True)
        converted=bytearray(elf_fixture(True));struct.pack_into('<H',converted,16,0xfe18)
        with self.assertRaises(ValueError):Elf(bytes(converted))
        Elf(bytes(converted),module=True)
        container=self_fixture(bytes(converted))
        self.assertEqual(extract_self(container,module=True),bytes(converted))
        with self.assertRaises(ValueError):extract_self(container)

    def test_module_entry_alias_is_still_refused(self):
        data=bytearray(elf_fixture());count=struct.unpack_from('<H',data,56)[0]
        struct.pack_into('<H',data,56,count+1)
        struct.pack_into('<IIQQQQQQ',data,64+count*56,1,4,0x401,0x1000,0x1000,1,1,1)
        with self.assertRaisesRegex(ValueError,'ambiguous'):Elf(bytes(data),module=True)

    def test_backend_fallback_is_explicitly_refused(self):
        with mock.patch.object(check,'mapped_pe',return_value=b''):
            data=check.BACKEND_MESSAGE+'%s\\wowprospero.dll\0'.encode('utf-16le')
            self.assertEqual(check.check_backend(data)['backend'],'wowprospero.dll')
            for extra in [b'WINE_PS5_WOW64_CPU\0','WINE_PS5_WOW64_CPU\0'.encode('utf-16le')]:
                with self.assertRaisesRegex(ValueError,'fallback'):check.check_backend(data+extra)
            with self.assertRaises(ValueError):check.check_backend(data.replace(check.BACKEND_MESSAGE,b''))

if __name__=='__main__':unittest.main(verbosity=2)
