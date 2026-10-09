#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Original metadata fixtures for the separate RADV module acceptance gate."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import yaml

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import check_radv_prx as check
import prepare_radv_prx as prepare


def binary(kind=3):
    b = bytearray(224); b[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI', b, 16, kind, 62, 1); struct.pack_into('<Q', b, 32, 64)
    struct.pack_into('<HHH', b, 52, 64, 56, 2)
    struct.pack_into('<IIQQQQQQ', b, 64, 1, 5, 192, 0, 0, 16, 16, 16)
    struct.pack_into('<IIQQQQQQ', b, 120, 1, 6, 208, 0x1000, 0, 16, 32, 16)
    b[192] = 0xc3
    return bytes(b)


class Fixture:
    def __init__(self, root):
        self.work, self.sdk, self.foundation, self.llvm, self.output = [root/x for x in ('work','sdk','foundation','llvm','evidence')]
        self.locale_name = None; self.locale_kind = 'OBJECT'; self.locale_provider_kind = 'OBJECT'
        self.locale_shadow = False; self.locale_addend = '0'; self.locale_reloc = 'R_X86_64_GLOB_DAT'
        self.locale_address = '0000000000001000'; self.locale_no_reloc = False
        self.mode = ''; self.bad_export = 'module_start'; self.export_kind = 'FUNC'; self.needed = ['libkernel.sprx', 'libSceLibcInternal.sprx', 'libSceAgc.prx', 'libSceAgcDriver.prx']
        for name in ('libkernel','libSceLibcInternal'):
            p=self.sdk/'target/lib'/(name+'.so');p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(binary()+name.encode())
        self.hashes={p.name:check.sha(p) for p in (self.sdk/'target/lib').glob('*.so')}
        for name in ('libSceAgc','libSceAgcDriver'):
            self.write('radv/stubs/'+name+'.so', binary()+name.encode())
        self.write('libvulkan.shared.elf',binary());self.write('radv/libvulkan.elf',binary(0xfe18))
        self.write('sce_module/libvulkan.prx',struct.pack('<I',0x1d3d154f)+bytes(64))
        self.write('libvulkan.link.log',b'converted\n');self.output.mkdir()
    def write(self,name,data):
        p=self.work/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);return p
    def run(self,*argv):
        command=Path(argv[0]).name;path=Path(argv[-1]);name=path.name.split('.')[0]
        if self.mode=='analyzer-failed' and command.startswith('llvm-'):raise ValueError('analyzer failed')
        if command=='git':return check.FOUNDATION if 'rev-parse' in argv else ''
        if command=='llvm-config':return '18.1.8'
        if command=='llvm-readelf':
            if '--dyn-syms' in argv:
                if name=='libvulkan':
                    defs=set(check.REQUIRED_EXPORTS)
                    if self.mode=='missing-export':defs.remove('vkGetInstanceProcAddr')
                    text='\n'.join(f'{i}: 0 1 {self.export_kind if n == self.bad_export else "FUNC"} GLOBAL DEFAULT 1 {n}' for i,n in enumerate(sorted(defs),1))
                    text+='\n20: 0 0 FUNC GLOBAL DEFAULT UND malloc\n'
                    if self.mode=='unresolved':text+='21: 0 0 FUNC GLOBAL DEFAULT UND missing\n'
                    if self.mode in ('data','bad-reloc','bad-range'):text+='22: 0 0 OBJECT GLOBAL DEFAULT UND environ\n'
                    if self.mode=='unknown-data':text+='22: 0 0 OBJECT GLOBAL DEFAULT UND unknown_data\n'
                    if self.mode=='tls':text+='22: 0 0 TLS GLOBAL DEFAULT UND thread_data\n'
                    if self.locale_name:text+=f'23: 0 0 {self.locale_kind} GLOBAL DEFAULT UND {self.locale_name}\n'
                    return text
                visibility='HIDDEN' if self.mode=='hidden-provider' else 'DEFAULT'
                kind='OBJECT' if self.mode=='wrong-function-provider' else 'FUNC'
                text=f'1: 0 1 {kind} GLOBAL {visibility} 1 malloc\n'
                if name=='libkernel' and self.mode in ('data','bad-reloc','bad-range'):
                    text+='2: 0 0 OBJECT GLOBAL DEFAULT 1 environ\n'
                if self.locale_name and (name=='libSceLibcInternal' or self.locale_shadow and name=='libkernel'):
                    text+=f'3: 0 0 {self.locale_provider_kind} GLOBAL DEFAULT 1 {self.locale_name}\n'
                return text
            if '-r' in argv:
                if self.locale_name:
                    if self.locale_no_reloc:return ''
                    return f'{self.locale_address} 0000001700000006 {self.locale_reloc} 0 {self.locale_name} + {self.locale_addend}\n'
                kind='R_X86_64_64' if self.mode=='bad-reloc' else 'R_X86_64_GLOB_DAT'
                address='0000000000000000' if self.mode=='bad-range' else '0000000000001000'
                return f'{address} 0000001600000006 {kind} 0 environ + 0\n'
            soname=name+('.prx' if name in ('libvulkan','libSceAgc','libSceAgcDriver') else '.sprx')
            if name=='libvulkan':
                if self.mode=='wrong-soname':soname='wrong.prx'
                needed=self.needed+(['libkernel_web.sprx'] if self.mode=='forbidden' else [])
                return f'Library soname: [{soname}]\n'+''.join(f'Shared library: [{n}]\n' for n in needed)
            return f'Library soname: [{soname}]\n'
        if command=='llvm-objdump':
            instruction={'syscall':'syscall','sysenter':'sysenter','int80':'int $0x80'}.get(self.mode,'retq')
            return '' if self.mode=='empty' else f'00000000 <module_start>:\n 0: {instruction}\n'
        if command=='ps5-native-tool':
            b=bytearray(binary(0xfe18));b[7]=9
            if '--inspect' in argv:
                text='container: signed, plaintext\nintegrity: valid\ndigest: '+hashlib.sha256(b).hexdigest()+'\n'
                if self.mode=='bad-integrity':text=text.replace('integrity: valid','integrity: INVALID')
                if self.mode=='bad-digest':text=text.replace(hashlib.sha256(b).hexdigest(),'0'*64)
                return text
            if self.mode=='changed-load':b[-1]^=1
            if self.mode=='changed-header':b[24]=1
            path.write_bytes(b);return ''
        raise AssertionError(argv)
    def validate(self):
        with patch.object(check,'SYSTEM_PROVIDER_HASHES',self.hashes), patch.object(check,'Commands',return_value=self):
            return check.validate(self.work,self.sdk,self.foundation,self.llvm,self.output)


class RadvPrxTests(unittest.TestCase):
    def test_actual_graph_and_container_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Fixture(Path(tmp));value=f.validate()
            self.assertFalse(value['runtime_verified']);self.assertFalse(value['drop_in_package_approved'])
            self.assertEqual(value['module']['needed'],f.needed)
            f.mode='data';self.assertEqual(f.validate()['module']['system_data_imports']['environ']['provider'],'libkernel.sprx')

    def test_hostile_graph_syscalls_relocations_and_container_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Fixture(Path(tmp))
            for mode in ('missing-export','unresolved','unknown-data','tls','hidden-provider',
                         'wrong-function-provider','wrong-soname','forbidden','syscall','sysenter','int80',
                         'empty','analyzer-failed','bad-reloc','bad-range','bad-integrity','bad-digest',
                         'changed-load','changed-header'):
                with self.subTest(mode=mode),self.assertRaises(ValueError):f.mode=mode;f.validate()
            f.mode='';f.write('libvulkan.link.log',b'warning: undefined symbol: missing\n')
            with self.assertRaisesRegex(ValueError,'unresolved'):f.validate()

    def test_exact_locale_objects_require_ordinary_first_provider_and_pointer_relocations(self):
        import check_wine_prx_build as wine
        names=('_CurrentRuneLocale','_DefaultRuneLocale','__mb_cur_max','__mb_sb_limit')
        self.assertTrue(set(names).isdisjoint(wine.SYSTEM_DATA))
        with tempfile.TemporaryDirectory() as tmp:
            f=Fixture(Path(tmp))
            for name in names:
                f.locale_name=name
                value=f.validate()['module']['system_data_imports'][name]
                self.assertEqual(value['provider'],'libSceLibcInternal.sprx')
                self.assertEqual(value['relocations'][0]['type'],'R_X86_64_GLOB_DAT')
                for attr,bad in (('locale_kind','TLS'),('locale_kind','FUNC'),
                                 ('locale_provider_kind','FUNC'),('locale_shadow',True),
                                 ('locale_addend','8'),('locale_reloc','R_X86_64_COPY'),
                                 ('locale_address','0000000000000000'),('locale_no_reloc',True)):
                    old=getattr(f,attr);setattr(f,attr,bad)
                    with self.subTest(name=name,attribute=attr),self.assertRaises(ValueError):f.validate()
                    setattr(f,attr,old)

    def test_required_export_names_cannot_hide_data_or_untyped_symbols(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Fixture(Path(tmp))
            for name in ('module_start', 'vkGetInstanceProcAddr'):
                for kind in ('OBJECT', 'TLS', 'NOTYPE'):
                    f.bad_export=name; f.export_kind=kind
                    with self.subTest(name=name,kind=kind),self.assertRaisesRegex(ValueError,'function entry'):
                        f.validate()

    def test_packaging_revalidates_every_checked_object_and_provider(self):
        with tempfile.TemporaryDirectory() as tmp:
            work=Path(tmp)
            names={'prx/sce_module/libvulkan.prx':'prx_sha256',
                   'prx/libvulkan.shared.elf':'shared_sha256',
                   'prx/radv/libvulkan.elf':'converted_sha256',
                   'inspection/libvulkan.extracted.elf':'extracted_sha256'}
            module={'providers':{},'gpu_stubs':{}}
            for name,key in names.items():
                path=work/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(name.encode())
                module[key]=prepare.sha(path)
            for name,collection in [('prx/radv/stubs/libSceAgc.so','gpu_stubs'),
                                    ('radv/.deps/native/ps5-payload-sdk/target/lib/libkernel.so','providers')]:
                path=work/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(name.encode())
                module[collection][path.name]={'file':str(path),'sha256':prepare.sha(path)}
            checks={'schema':'pw-radv-prx-check/1','module':module}
            prepare.verify_checked_graph(work,checks)
            for name in [*names,'prx/radv/stubs/libSceAgc.so',
                         'radv/.deps/native/ps5-payload-sdk/target/lib/libkernel.so']:
                path=work/name;original=path.read_bytes();path.write_bytes(original+b'changed')
                with self.subTest(name=name),self.assertRaises(ValueError):prepare.verify_checked_graph(work,checks)
                path.write_bytes(original)

    def test_failure_retains_owned_binary_and_matching_sources_without_sdk_dump(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);work=root/'work';consumer=root/'consumer';consumer.mkdir()
            for name in ('LICENSE','NOTICE.md','THIRD_PARTY.md'):(consumer/name).write_text('owned source notice')
            for name in ('prx/libvulkan.shared.elf','prx/radv/stubs/libSceAgc.so',
                         'inputs/sources/sdk.tar.gz','inputs/sources/payload.tar.gz',
                         'inputs/sources/ps5-payload-sdk.zip','inputs/LICENSES/GPL.txt','INPUTS-VERIFIED.json'):
                path=work/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(name.encode())
            outside=root/'outside';outside.write_bytes(b'not an artifact')
            (work/'prx/radv/libvulkan.elf').symlink_to(outside)
            def archive(source,destination):
                destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(b'owned source archive')
            out=root/'failure'
            with patch.object(prepare,'ROOT',consumer),patch.object(prepare,'archive',archive):
                prepare.collect_failure(types.SimpleNamespace(work=work,out=out,foundation=None))
            self.assertEqual((out/'prx/libvulkan.shared.elf').read_bytes(),b'prx/libvulkan.shared.elf')
            self.assertTrue((out/'sources/sdk.tar.gz').is_file())
            self.assertTrue((out/'sources/payload.tar.gz').is_file())
            self.assertFalse((out/'sources/ps5-payload-sdk.zip').exists())
            self.assertFalse((out/'prx/radv/libvulkan.elf').exists())
            record=json.loads((out/'FAILURE-INPUTS.json').read_text())
            self.assertIn('not an accepted driver',record['scope'])
            self.assertEqual(len(record['omitted']),2)

    def test_repaired_link_is_bound_to_clean_consumer_source_and_archived_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); consumer=root/'consumer'; work=root/'work'; work.mkdir()
            for name in prepare.LINK_INPUTS:
                path=consumer/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(name)
            status=''; commit='a'*40; tree='b'*40
            def git(root,*args):
                if args[0]=='status':return status
                return tree if args[-1]=='HEAD^{tree}' else commit
            def archive(root,path):path.write_bytes(b'exact consumer source archive')
            with patch.object(prepare,'ROOT',consumer),patch.object(prepare,'git',git),patch.object(prepare,'archive',archive):
                value=prepare.snapshot_consumer(work,'https://github.com/Sleepywalker69/prospero-win')
                (work/'INPUTS-VERIFIED.json').write_text(json.dumps({'link_consumer':value}))
                self.assertEqual(prepare.verify_consumer(work)['commit'],commit)
                for name in prepare.LINK_INPUTS:
                    path=consumer/name;old=path.read_bytes();path.write_bytes(old+b'changed')
                    with self.subTest(file=name),self.assertRaises(ValueError):prepare.verify_consumer(work)
                    path.write_bytes(old)
                status=' M tools/link_radv_prx.sh'
                with self.assertRaises(ValueError):prepare.verify_consumer(work)
                status='';commit='c'*40
                with self.assertRaises(ValueError):prepare.verify_consumer(work)
                commit='a'*40;tree='d'*40
                with self.assertRaises(ValueError):prepare.verify_consumer(work)
                tree='b'*40;(work/'consumer-source.tar.gz').write_bytes(b'changed')
                with self.assertRaises(ValueError):prepare.verify_consumer(work)

    def test_real_system_provider_identity_is_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Fixture(Path(tmp))
            with self.assertRaisesRegex(ValueError,'system provider differs'):
                check.inspect_link(f.work,f.sdk,f.llvm,f)

    def test_fixed_artifact_identity_and_changed_hash_rejection(self):
        run={'id':prepare.RUN,'head_sha':prepare.HEAD,'run_attempt':1,'status':'completed','conclusion':'success',
             'path':'.github/workflows/radv-archive.yml','repository':{'full_name':'Sleepywalker69/prospero-win'}}
        item={'id':prepare.ARTIFACT,'digest':'sha256:'+prepare.ZIP_SHA,'expired':False,
              'workflow_run':{'id':prepare.RUN,'head_sha':prepare.HEAD,'repository_id':1410835302,'head_repository_id':1410835302}}
        prepare.metadata(run,item)
        for key,value in [('digest','sha256:'+'0'*64),('expired',True),('id',1)]:
            bad=dict(item);bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):prepare.metadata(run,bad)

    def test_read_only_bounded_lane_preserves_original_gate(self):
        w=yaml.load((ROOT/'.github/workflows/radv-prx.yml').read_text(),Loader=yaml.BaseLoader)
        self.assertEqual(w['permissions'],{'contents':'read','actions':'read'})
        self.assertNotIn('pull_request_target',w['on']);job=w['jobs']['radv-prx']
        self.assertEqual(job['timeout-minutes'],'35');self.assertEqual(job['runs-on'],'ubuntu-24.04')
        self.assertIn('head.repo.full_name == github.repository',job['if'])
        runs='\n'.join(s.get('run','') for s in job['steps'])
        for required in ('libclang-rt-18-dev','bash tools/link_radv_prx.sh',
                         'tools/check_radv_prx.py','--skip-sdk','verify-consumer',
                         'build/host/test_pw_radv_mkstemp',str(prepare.ARTIFACT)):
            self.assertIn(required,runs)
        for forbidden in ('build_wine_ps5.sh','build-radv.sh release','--force','continue-on-error'):
            self.assertNotIn(forbidden,runs)
        for s in job['steps']:
            self.assertNotIn('continue-on-error',s)
            if 'uses' in s:self.assertRegex(s['uses'],r'^actions/[a-z-]+@[0-9a-f]{40}$')
        self.assertNotIn('libvulkan',__import__('check_wine_prx_build').MODULES)
        self.assertEqual(len(__import__('check_wine_prx_build').MODULES),14)


if __name__=='__main__':unittest.main()
