#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Original inert PE/JSON/log controls. No Windows or Wine instructions run."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.dont_write_bytecode = True
PROPOSAL = Path(__file__).resolve().parents[1]
DEFAULT_BASE = PROPOSAL if (PROPOSAL / 'tools/private_dispatch_wow64.py').is_file() else PROPOSAL.parent / 'child-dnsapi-on-perf'
BASE = Path(os.environ.get('PW_USER_BASE_REPO', str(DEFAULT_BASE)))
sys.path.insert(0, str(BASE / 'tools'))
spec = importlib.util.spec_from_file_location('user_contract', PROPOSAL / 'tools/windows_child_user_contract.py')
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


def make_pe(role):
    """Minimal original bytes containing headers/tables, never loadable test code."""
    data=bytearray(0x4600); data[:2]=b'MZ'; struct.pack_into('<I',data,60,0x80)
    data[0x80:0x84]=b'PE\0\0';struct.pack_into('<HHIIIHH',data,0x84,0x8664,3,0,0,0,240,0x22)
    op=0x98;struct.pack_into('<H',data,op,0x20b);struct.pack_into('<I',data,op+16,0x1000)
    struct.pack_into('<Q',data,op+24,0x140000000);struct.pack_into('<II',data,op+32,0x1000,0x200)
    struct.pack_into('<II',data,op+56,0x7000,0x200);struct.pack_into('<HH',data,op+68,3,0x140)
    struct.pack_into('<I',data,op+108,16)
    for i,(name,rva,size,raw,flags) in enumerate([(b'.text',0x1000,0x200,0x200,0x60000020),(b'.rdata',0x2000,0x4000,0x400,0x40000040),(b'.reloc',0x6000,0x200,0x4400,0x42000040)]):
        at=op+240+i*40;data[at:at+len(name)]=name;struct.pack_into('<IIII',data,at+8,size,rva,size,raw);struct.pack_into('<I',data,at+36,flags)
    # Inert marker and a file-backed DIR64 target. Nothing executes these bytes.
    data[0x200:0x208]=b'ORIGINAL';struct.pack_into('<Q',data,0x220,0x140001000)
    imports=contract.REQUIRED[role];struct.pack_into('<II',data,op+112+8,0x2000,(len(imports)+1)*20)
    cursor=0x2100
    def alloc(blob):
        nonlocal cursor
        rva=cursor;off=0x400+rva-0x2000;data[off:off+len(blob)]=blob;cursor+=len(blob);return rva
    for i,(dll,names) in enumerate(imports.items()):
        dll_rva=alloc(dll.encode()+b'\0');symbols=[alloc(b'\0\0'+name.encode()+b'\0') for name in sorted(names)]
        cursor=(cursor+7)&~7;table=b''.join(struct.pack('<Q',x) for x in symbols+[0]);ilt=alloc(table);iat=alloc(table)
        struct.pack_into('<IIIII',data,0x400+i*20,ilt,0,0,dll_rva,iat)
    struct.pack_into('<II',data,op+112+40,0x6000,12);struct.pack_into('<IIHH',data,0x4400,0x1000,12,0xa020,0)
    return bytes(data)


def log_line(role,stage,tid,**fields):
    items={'role':role,'stage':stage,'pid':11 if role=='parent' else 21,'tid':tid,**fields}
    return 'PW_CHILD_USER '+' '.join(str(k)+'='+str(v) for k,v in items.items())+'\r\n'


def make_logs():
    start={'mode':'original_user_control','child_presentation':'unverified','child_input':'unverified'}
    finish={'prior_status':0,'diagnostic_cleanup':'completed','final_log_close':'pending','native_settlement':'unverified'}
    parent=''.join([log_line('parent','start',12,**start),log_line('parent','create_process',12,result='attempt',child='user-child.exe',inherited_handles=0,arguments='none'),log_line('parent','create_process',12,result='returned_success',child_pid=21,child_tid=22,initialized='unverified'),log_line('parent','child_exit',12,query_ok=1,observed_code=37,expected=37,matches=1,native_settlement='unverified'),log_line('parent','finish',12,planned_exit=0,**finish)])
    child=''.join([log_line('child','start',22,**start),log_line('child','top_window',22,hwnd=1024,width=320,height=240,visible=0),log_line('child','worker_first_user',23,next='GetAncestor_GA_ROOT',top=1024,main_tid=22),log_line('child','ancestor',23,returned=1024,expected=1024,matches=1),log_line('child','geometry',23,window_match=1,client_match=1,width=320,height=240),log_line('child','static',23,created=1,visible=0,hwnd=2048),log_line('child','custom_class',23,registered=1,created=1,visible=0),log_line('child','dib',23,width=32,height=16,stride=128,local_readback='matched',presentation='unverified'),log_line('child','worker_cleanup',23,status=0,local_operations_only=1),log_line('child','worker_exit',22,query_ok=1,observed_code=0,recorded_code=0,finished=1,distinct_tid=1),log_line('child','finish',22,planned_exit=37,**finish)])
    return parent.encode(),child.encode()


def make_bundle():
    """Synthetic receipts only, deliberately not actual compiler/run evidence."""
    parent,child=make_logs();source=b'original synthetic source\n';recipe=b'original synthetic recipe\n';validator=b'original synthetic validator\n'
    project={'commit':'a'*40,'tree':'b'*40};source_hashes={'source_sha256':contract.digest(source),'recipe_sha256':contract.digest(recipe),'validator_sha256':contract.digest(validator)}
    files={'user-parent.exe':make_pe('parent'),'user-child.exe':make_pe('child'),'windows_child_user.c':source,'build_windows_child_user.ps1':recipe,'user-parent-11-100.log':parent,'user-child-21-200.log':child,'reference.stdout.log':parent,'reference.stderr.log':b''}
    commands={};header=r'C:\SDK\include\windows.h';src=r'D:\a\repo\tests\fixtures\windows_child_user.c'
    for i,role in enumerate(('parent','child')):
        commands[role]=('call "C:\\VS\\VC\\Auxiliary\\Build\\vcvars64.bat" > nul && "C:\\VS\\VC\\Tools\\MSVC\\14\\bin\\Hostx64\\x64\\cl.exe" /nologo /std:c11 /W4 /WX /O2 /MT /D_CRT_SECURE_NO_WARNINGS /DPW_USER_CHILD='+str(i)+' /sourceDependencies "D:\\temp\\user\\dependencies-'+role+'.json" "'+src+'" user32.lib gdi32.lib /Fe:"D:\\temp\\user\\user-'+role+'.exe" /Fo:"D:\\temp\\user\\user-'+role+'.obj" /link /DYNAMICBASE /FIXED:NO /NXCOMPAT /INCREMENTAL:NO')
        files['dependencies-'+role+'.json']=json.dumps({'Version':'1.2','Data':{'Source':src,'Includes':[header]}}).encode()
    meta={'schema':'pw-original-windows-child-user-msvc/1','architecture':'x64','project':project,'run_id':'123','run_attempt':'1',**source_hashes,'headers':{header:{'bytes':50,'sha256':'c'*64}},'compile_commands':commands,'compiler':{'name':'MSVC cl.exe','file_version':'original-inert-test','sha256':'d'*64},'inspector':{'name':'MSVC dumpbin.exe','sha256':'e'*64},'files':{name:{**contract.record(files[name]),'machine':'AMD64','selector':i} for i,name in enumerate(contract.NAMES)},'reference':{'executed':True,'exit':0,'deadline_seconds':105,'stdout':contract.record(parent),'stderr':contract.record(b''),'role_logs':{n:contract.record(files[n]) for n in ('user-parent-11-100.log','user-child-21-200.log')}},'runtime_validated':False,'child_presentation':False,'child_input':False,'import_policy_verified':False,'relocation_entries_verified':False}
    files['user-source.json']=json.dumps(meta).encode()
    return files,meta,project,source_hashes,validator


class ContractTests(unittest.TestCase):
    def setUp(self): self.files,self.meta,self.project,self.hashes,self.validator=make_bundle()
    def check(self):
        self.files['user-source.json']=json.dumps(self.meta).encode();detail={}
        result=contract.validate_contents(self.files.__getitem__,set(self.files),self.project,'123','1',self.hashes,detail)
        self.assertEqual(result,self.meta);self.assertTrue(detail['import_policy_verified']);return detail
    def refuse(self):
        with self.assertRaises((ValueError,TypeError,KeyError,IndexError,UnicodeError)): self.check()
    def pe_edit(self,role,offset,fmt,value):
        name='user-'+role+'.exe';data=bytearray(self.files[name]);struct.pack_into(fmt,data,offset,value);self.files[name]=bytes(data);self.meta['files'][name].update(contract.record(data))
    def log_edit(self,role,old,new):
        name='user-'+role+('-11-100.log' if role=='parent' else '-21-200.log');self.files[name]=self.files[name].replace(old.encode(),new.encode());self.meta['reference']['role_logs'][name]=contract.record(self.files[name])
    def test_valid_byte_only(self): self.check()
    def test_valid_filesystem_and_copy(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'repo';out=Path(temp)/'out';out.mkdir();
            for name,b in self.files.items():(out/name).write_bytes(b)
            for name,b in [(contract.SOURCE,self.files['windows_child_user.c']),(contract.RECIPE,self.files['build_windows_child_user.ps1']),(contract.VALIDATOR,self.validator)]:
                p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
            contract.validate_pair(out,self.project,root,'123','1');contract.verify_pair_copy(out,self.meta)
            (out/'user-child.exe').write_bytes(b'wrong');
            with self.assertRaises(ValueError):contract.verify_pair_copy(out,self.meta)
    def test_link_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'real').write_bytes(b'x');(root/'link').symlink_to(root/'real')
            with self.assertRaises(ValueError):contract.regular(root/'link',100)
    def test_truncated_pe(self):
        self.files['user-child.exe']=self.files['user-child.exe'][:-1];self.meta['files']['user-child.exe'].update(contract.record(self.files['user-child.exe']));self.refuse()
    def test_no_aslr(self):self.pe_edit('parent',0x98+70,'<H',0x100);self.refuse()
    def test_no_nx(self):self.pe_edit('parent',0x98+70,'<H',0x40);self.refuse()
    def test_relocations_stripped(self):self.pe_edit('parent',0x80+22,'<H',0x23);self.refuse()
    def test_dll_image(self):self.pe_edit('parent',0x80+22,'<H',0x2022);self.refuse()
    def test_wrong_machine(self):self.pe_edit('parent',0x84,'<H',0x14c);self.refuse()
    def test_noncode_entry(self):self.pe_edit('parent',0x98+16,'<I',0x2000);self.refuse()
    def test_bad_import_name_rva(self):self.pe_edit('parent',0x400+12,'<I',0xfffffff0);self.refuse()
    def test_nonbacked_import_tail(self):self.pe_edit('parent',0x98+112+12,'<I',0x5000);self.refuse()
    def test_bad_iat(self):self.pe_edit('parent',0x400+16,'<I',0x6fff);self.refuse()
    def test_ordinal_import(self):
        ilt=struct.unpack_from('<I',self.files['user-parent.exe'],0x400)[0];self.pe_edit('parent',0x400+ilt-0x2000,'<Q',1<<63|1);self.refuse()
    def test_partial_hint(self):
        ilt=struct.unpack_from('<I',self.files['user-parent.exe'],0x400)[0];self.pe_edit('parent',0x400+ilt-0x2000,'<Q',0x5fff);self.refuse()
    def test_delay_import(self):self.pe_edit('parent',0x98+112+13*8,'<I',0x2000);self.refuse()
    def test_no_actual_relocation(self):self.pe_edit('parent',0x4408,'<H',0);self.refuse()
    def test_duplicate_relocation(self):self.pe_edit('parent',0x440a,'<H',0xa020);self.refuse()
    def test_wrong_relocation_type(self):self.pe_edit('parent',0x4408,'<H',0x3020);self.refuse()
    def test_bad_relocation_block(self):self.pe_edit('parent',0x4404,'<I',10);self.refuse()
    def test_bad_relocation_target(self):self.pe_edit('parent',0x4408,'<H',0xafff);self.refuse()
    def test_overlapping_sections(self):self.pe_edit('parent',0x98+240+40+12,'<I',0x1000);self.refuse()
    def test_extra_role_image(self):self.files['user-other.exe']=make_pe('parent');self.refuse()
    def test_case_alias(self):self.files['USER-PARENT.EXE']=make_pe('parent');self.refuse()
    def test_unsafe_name(self):self.files['../user-parent.exe']=b'x';self.refuse()
    def test_missing_source_copy(self):del self.files['windows_child_user.c'];self.refuse()
    def test_changed_recipe_copy(self):self.files['build_windows_child_user.ps1']+=b'changed';self.refuse()
    def test_wrong_project(self):self.meta['project']={'commit':'f'*40,'tree':'b'*40};self.refuse()
    def test_wrong_run(self):self.meta['run_id']='124';self.refuse()
    def test_no_reference(self):self.meta['reference']['executed']=False;self.refuse()
    def test_failed_external_exit(self):self.meta['reference']['exit']=37;self.refuse()
    def test_overclaimed_runtime(self):self.meta['runtime_validated']=True;self.refuse()
    def test_wrong_selector(self):self.meta['files']['user-child.exe']['selector']=0;self.refuse()
    def test_boolean_selector(self):self.meta['files']['user-child.exe']['selector']=True;self.refuse()
    def test_swapped_role_images(self):
        self.files['user-parent.exe'],self.files['user-child.exe']=self.files['user-child.exe'],self.files['user-parent.exe']
        for n in contract.NAMES:self.meta['files'][n].update(contract.record(self.files[n]))
        self.refuse()
    def test_changed_compile_flags(self):self.meta['compile_commands']['child']=self.meta['compile_commands']['child'].replace('/DYNAMICBASE','/DYNAMICBASE:NO');self.refuse()
    def test_changed_command_selector(self):self.meta['compile_commands']['child']=self.meta['compile_commands']['child'].replace('PW_USER_CHILD=1','PW_USER_CHILD=0');self.refuse()
    def test_appended_compile_argument(self):self.meta['compile_commands']['child']+=' /FORCE';self.refuse()
    def test_changed_command_source(self):self.meta['compile_commands']['child']=self.meta['compile_commands']['child'].replace('windows_child_user.c','other.c');self.refuse()
    def test_missing_dependency_header(self):self.meta['headers']={};self.refuse()
    def test_unconsumed_header(self):self.meta['headers'][r'C:\SDK\unused.h']={'bytes':1,'sha256':'f'*64};self.refuse()
    def test_dependency_source_change(self):
        x=json.loads(self.files['dependencies-child.json']);x['Data']['Source']=r'C:\other.c';self.files['dependencies-child.json']=json.dumps(x).encode();self.refuse()
    def test_dependency_module(self):
        x=json.loads(self.files['dependencies-child.json']);x['Data']['ImportedModules']=['other'];self.files['dependencies-child.json']=json.dumps(x).encode();self.refuse()
    def test_duplicate_json(self):
        self.files['user-source.json']=b'{"a":1,"a":2}'
        with self.assertRaises(ValueError):contract.validate_contents(self.files.__getitem__,set(self.files),self.project,'123','1',self.hashes)
    def test_duplicate_log_field(self):self.log_edit('child','matches=1','matches=1 matches=1');self.refuse()
    def test_extra_log_field(self):self.log_edit('child','matches=1','matches=1 ignored=1');self.refuse()
    def test_wrong_worker_thread(self):self.log_edit('child','tid=23','tid=22');self.refuse()
    def test_bad_ancestor(self):self.log_edit('child','returned=1024','returned=999');self.refuse()
    def test_bad_geometry(self):self.log_edit('child','width=320','width=321');self.refuse()
    def test_log_reordered(self):
        n='user-child-21-200.log';lines=self.files[n].splitlines(True);lines[3],lines[4]=lines[4],lines[3];self.files[n]=b''.join(lines);self.meta['reference']['role_logs'][n]=contract.record(self.files[n]);self.refuse()
    def test_worker_cleanup_failed(self):self.log_edit('child','status=0 local_operations_only','status=20 local_operations_only');self.refuse()
    def test_missing_post_cleanup_marker(self):self.log_edit('child','finished=1','finished=0');self.refuse()
    def test_missing_actual_thread_exit(self):self.log_edit('child','query_ok=1','query_ok=0');self.refuse()
    def test_missing_actual_process_exit(self):self.log_edit('parent','query_ok=1','query_ok=0');self.refuse()
    def test_wrong_observed_exit(self):self.log_edit('parent','observed_code=37','observed_code=0');self.refuse()
    def test_final_close_claim(self):self.log_edit('child','final_log_close=pending','final_log_close=complete');self.refuse()
    def test_extra_role_log(self):self.files['user-child-21-201.log']=self.files['user-child-21-200.log'];self.refuse()
    def test_role_log_hash_changed(self):self.files['user-child-21-200.log']+=b'x';self.refuse()
    def test_nonempty_stderr(self):self.files['reference.stderr.log']=b'error';self.meta['reference']['stderr']=contract.record(b'error');self.refuse()
    def test_unbounded_pid(self):self.log_edit('child','pid=21','pid=4294967296');self.refuse()


if __name__=='__main__': unittest.main()
