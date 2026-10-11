#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Original inert PE/JSON/log controls. No Windows or Wine instructions run."""
import copy
import importlib.util
import json
import os
import re
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.dont_write_bytecode = True
PROPOSAL = Path(__file__).resolve().parents[1]
DEFAULT_BASE = PROPOSAL if (PROPOSAL / 'tools/private_dispatch_wow64.py').is_file() else PROPOSAL.parent / 'child-user-probe-v2'
BASE = Path(os.environ.get('PW_NETWORK_BASE_REPO', str(DEFAULT_BASE)))
sys.path.insert(0, str(BASE / 'tools'))
spec = importlib.util.spec_from_file_location('network_contract', PROPOSAL / 'tools/windows_child_network_contract.py')
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


def log_line(role,stage,**fields):
    items={'role':role,'stage':stage,'pid':11 if role=='parent' else 21,'tid':12 if role=='parent' else 22,**fields}
    return 'PW_CHILD_NET '+' '.join(str(k)+'='+str(v) for k,v in items.items())+'\r\n'


def make_logs(dns='full',fqdn_code=0,refusal=11004,config_code=50):
    start={'mode':'original_network_control','network_success':'unverified','child_presentation':'unverified','child_input':'unverified'}
    finish={'prior_status':0,'diagnostic_cleanup':'completed','final_log_close':'pending','native_settlement':'unverified'}
    parent=''.join([log_line('parent','start',**start),log_line('parent','create_process',result='attempt',child='net-child.exe',inherited_handles=0,arguments='none'),log_line('parent','create_process',result='returned_success',child_pid=21,child_tid=22,initialized='unverified'),log_line('parent','child_exit',query_ok=1,observed_code=37,expected=37,matches=1,native_settlement='unverified'),log_line('parent','finish',planned_exit=0,**finish)])
    child=[log_line('child','start',**start),log_line('child','winsock_module',result='loaded',error=0),log_line('child','wsa_startup',domain='winsock',code=0,version=514,high_version=514)]
    def resolve(name,optional,flags,code):
        child.append(log_line('child','resolve_attempt',case=name,optional=optional,family='AF_INET',service=80,flags=flags))
        child.append(log_line('child','resolve_result',case=name,domain='winsock',code=code,count=1 if code==0 else 0,shape_valid=1,optional=optional,success=1 if code==0 else 0,elapsed_ms=2))
    resolve('127.0.0.1',0,4,0);resolve('not-numeric.invalid',0,4,refusal)
    child.extend([log_line('child','socket_create',domain='winsock',created=1,code=0,remote_traffic=0),log_line('child','socket_close',domain='winsock',result=0,code=0)])
    if dns=='missing':child.append(log_line('child','dnsapi_module',result='unavailable',error=126))
    elif dns=='directory':child.append(log_line('child','dnsapi_module',result='unavailable',operation='system_directory',returned_length=0,capacity=260,error=5))
    else:
        child.append(log_line('child','dnsapi_module',result='loaded',error=0))
        if dns=='export':child.append(log_line('child','export',result='unavailable',name='DnsQueryConfig',error=127))
        else:
            child.extend([log_line('child','dnsapi_numeric',domain='dns_status',code=0,record_present=1,shape_valid=1,optional=1),log_line('child','dnsapi_config',domain='dns_status',code=config_code,capacity=260,returned_bytes=260 if config_code else 8,count=0 if config_code else 1,shape_valid=1,untouched=1 if config_code else 0,optional=1,server_config_available=0 if config_code else 1)])
        child.append(log_line('child','dnsapi_unload',result=1,error=0,prior_status=0))
    resolve('example.com.',1,0,fqdn_code)
    child.extend([log_line('child','wsa_cleanup',domain='winsock',result=0,code=0),log_line('child','winsock_unload',result=1,error=0,prior_status=0),log_line('child','network_cleanup',status=0,local_contract_complete=1,fqdn_success_is_separate=1,native_settlement='unverified'),log_line('child','finish',planned_exit=37,**finish)])
    return parent.encode(),''.join(child).encode()


def make_bundle(**log_options):
    """Synthetic original tables/receipts; no real PE code, compiler or network proof."""
    parent,child=make_logs(**log_options);source=b'original synthetic source\n';recipe=b'original synthetic recipe\n';validator=b'original synthetic validator\n';header_bytes=b'original synthetic header\n'
    project={'commit':'a'*40,'tree':'b'*40};hashes={key:contract.digest(data) for key,data in [('source_sha256',source),('recipe_sha256',recipe),('validator_sha256',validator),('header_sha256',header_bytes)]}
    files={'net-parent.exe':make_pe('parent'),'net-child.exe':make_pe('child'),'windows_child_network.c':source,'build_windows_child_network.ps1':recipe,'windows_child_network_contract.py':validator,'windows_child_network_contract.h':header_bytes,'net-parent-11-100.log':parent,'net-child-21-200.log':child,'reference.stdout.log':parent,'reference.stderr.log':b''}
    commands={};header=r'C:\SDK\include\windows.h';src=r'D:\a\repo\tests\fixtures\windows_child_network.c';local_header=r'D:\a\repo\tests\fixtures\windows_child_network_contract.h'
    for i,role in enumerate(('parent','child')):
        commands[role]=('call "C:\\VS\\VC\\Auxiliary\\Build\\vcvars64.bat" > nul && "C:\\VS\\VC\\Tools\\MSVC\\14\\bin\\Hostx64\\x64\\cl.exe" /nologo /std:c11 /W4 /WX /O2 /MT /D_CRT_SECURE_NO_WARNINGS /DPW_NET_CHILD='+str(i)+' /sourceDependencies "D:\\temp\\net\\dependencies-'+role+'.json" "'+src+'" /Fe:"D:\\temp\\net\\net-'+role+'.exe" /Fo:"D:\\temp\\net\\net-'+role+'.obj" /link /DYNAMICBASE /FIXED:NO /NXCOMPAT /INCREMENTAL:NO')
        files['dependencies-'+role+'.json']=json.dumps({'Version':'1.2','Data':{'Source':src,'Includes':[header]+([local_header] if role=='child' else [])}}).encode()
    meta={'schema':'pw-original-windows-child-network-msvc/1','architecture':'x64','project':project,'run_id':'123','run_attempt':'1',**hashes,'headers':{header:{'bytes':50,'sha256':'c'*64},local_header:contract.record(header_bytes)},'compile_commands':commands,'compiler':{'name':'MSVC cl.exe','file_version':'original-inert-test','sha256':'d'*64},'inspector':{'name':'MSVC dumpbin.exe','sha256':'e'*64},'files':{name:{**contract.record(files[name]),'machine':'AMD64','selector':i} for i,name in enumerate(contract.NAMES)},'reference':{'executed':True,'exit':0,'deadline_seconds':105,'stdout':contract.record(parent),'stderr':contract.record(b''),'role_logs':{n:contract.record(files[n]) for n in ('net-parent-11-100.log','net-child-21-200.log')}},'runtime_validated':False,'network_validated':False,'independent_log_validation':False,'child_presentation':False,'child_input':False,'import_policy_verified':False,'relocation_entries_verified':False}
    files['network-source.json']=json.dumps(meta).encode()
    return files,meta,project,hashes,validator


class ContractTests(unittest.TestCase):
    def setUp(self):self.setup_bundle()
    def setup_bundle(self,**options):self.files,self.meta,self.project,self.hashes,self.validator=make_bundle(**options)
    def check(self):
        self.files['network-source.json']=json.dumps(self.meta).encode();detail={}
        result=contract.validate_contents(self.files.__getitem__,set(self.files),self.project,'123','1',self.hashes,detail)
        self.assertEqual(result,self.meta);self.assertTrue(detail['import_policy_verified']);self.assertTrue(detail['independent_log_validation']);self.assertFalse(detail['network_validated']);return detail
    def refuse(self):
        with self.assertRaises((ValueError,TypeError,KeyError,IndexError,UnicodeError)):self.check()
    def pe_edit(self,role,offset,fmt,value):
        name='net-'+role+'.exe';data=bytearray(self.files[name]);struct.pack_into(fmt,data,offset,value);self.files[name]=bytes(data);self.meta['files'][name].update(contract.record(data))
    def log_edit(self,role,old,new):
        name='net-'+role+('-11-100.log' if role=='parent' else '-21-200.log');self.files[name]=self.files[name].replace(old.encode(),new.encode());self.meta['reference']['role_logs'][name]=contract.record(self.files[name])
    def transform_child(self,transform):
        name='net-child-21-200.log';self.files[name]=transform(self.files[name]);self.meta['reference']['role_logs'][name]=contract.record(self.files[name])
    def test_actual_recipe_command_template(self):
        recipe_path=PROPOSAL/'build_windows_child_network.ps1'
        if not recipe_path.is_file():recipe_path=PROPOSAL/'tools/build_windows_child_network.ps1'
        recipe=recipe_path.read_text();match=re.search(r"\$command = '([^']+)' -f",recipe)
        self.assertIsNotNone(match)
        for selector,role in enumerate(('parent','child')):
            command=match[1].format(r'C:\VS\VC\Auxiliary\Build\vcvars64.bat',r'C:\VS\VC\Tools\MSVC\14\bin\Hostx64\x64\cl.exe',selector,r'D:\a\repo\tests\fixtures\windows_child_network.c','D:\\temp\\net\\net-'+role+'.exe','D:\\temp\\net\\net-'+role+'.obj','D:\\temp\\net\\dependencies-'+role+'.json')
            self.assertEqual(command,self.meta['compile_commands'][role])
        self.assertIn('& python $validatorPath --directory $Out --repo $ProjectRoot --report',recipe)
        self.assertIn("if ($LASTEXITCODE -ne 0) { throw 'Independent original network PE/log inspection failed.' }",recipe)
    def test_valid_byte_only(self):self.check()
    def test_optional_fqdn_error(self):self.setup_bundle(fqdn_code=11002);self.assertFalse(self.check()['observed']['fqdn']['success'])
    def test_optional_dns_module_absent(self):self.setup_bundle(dns='missing');self.check()
    def test_optional_directory_absent(self):self.setup_bundle(dns='directory');self.check()
    def test_optional_export_missing(self):self.setup_bundle(dns='export');self.check()
    def test_optional_config_success(self):self.setup_bundle(config_code=0);self.check()
    def test_optional_numeric_dns_error(self):
        self.log_edit('child','code=0 record_present=1','code=50 record_present=0');self.assertFalse(self.check()['observed']['dnsapi']['numeric']['success'])
    def test_optional_fqdn_negative_code(self):self.setup_bundle(fqdn_code=-1);self.check()
    def test_case_equivalent_header_path(self):
        name='dependencies-child.json';data=json.loads(self.files[name]);data['Data']['Includes'][1]=data['Data']['Includes'][1].upper();self.files[name]=json.dumps(data).encode();self.check()
    def test_duplicate_header_alias(self):
        name=r'D:\a\repo\tests\fixtures\windows_child_network_contract.h';self.meta['headers'][name.upper()]=self.meta['headers'][name];self.refuse()
    def test_config_false_untouched_success(self):self.setup_bundle(config_code=0);self.log_edit('child','untouched=0','untouched=1');self.refuse()
    def test_dns_directory_impossible_length(self):self.setup_bundle(dns='directory');self.log_edit('child','returned_length=0','returned_length=20');self.refuse()
    def test_unload_after_absent_module(self):
        self.setup_bundle(dns='missing');self.transform_child(lambda b:b.replace(b'PW_CHILD_NET role=child stage=wsa_cleanup',log_line('child','dnsapi_unload',result=1,error=0,prior_status=0).encode()+b'PW_CHILD_NET role=child stage=wsa_cleanup'));self.refuse()
    def test_legacy_headless_aslr_policy(self):self.pe_edit('parent',0x98+70,'<H',0x8120);self.refuse()
    def test_numeric_windows_refusal(self):self.setup_bundle(refusal=11001);self.check()
    def test_valid_filesystem_and_copy(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'repo';out=Path(temp)/'out';out.mkdir()
            for name,data in self.files.items():(out/name).write_bytes(data)
            for name,leaf in [(contract.SOURCE,'windows_child_network.c'),(contract.RECIPE,'build_windows_child_network.ps1'),(contract.VALIDATOR,'windows_child_network_contract.py'),(contract.HEADER,'windows_child_network_contract.h')]:
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(self.files[leaf])
            contract.validate_pair(out,self.project,root,'123','1');contract.verify_pair_copy(out,self.meta)
            (out/'net-child.exe').write_bytes(b'wrong')
            with self.assertRaises(ValueError):contract.verify_pair_copy(out,self.meta)
    def test_link_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'real').write_bytes(b'x');(root/'link').symlink_to(root/'real')
            with self.assertRaises(ValueError):contract.regular(root/'link',100)
    def test_truncated_pe(self):self.files['net-child.exe']=self.files['net-child.exe'][:-1];self.meta['files']['net-child.exe'].update(contract.record(self.files['net-child.exe']));self.refuse()
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
        ilt=struct.unpack_from('<I',self.files['net-parent.exe'],0x400)[0];self.pe_edit('parent',0x400+ilt-0x2000,'<Q',1<<63|1);self.refuse()
    def test_partial_hint(self):
        ilt=struct.unpack_from('<I',self.files['net-parent.exe'],0x400)[0];self.pe_edit('parent',0x400+ilt-0x2000,'<Q',0x5fff);self.refuse()
    def test_delay_import(self):self.pe_edit('parent',0x98+112+13*8,'<I',0x2000);self.refuse()
    def test_no_actual_relocation(self):self.pe_edit('parent',0x4408,'<H',0);self.refuse()
    def test_duplicate_relocation(self):self.pe_edit('parent',0x440a,'<H',0xa020);self.refuse()
    def test_wrong_relocation_type(self):self.pe_edit('parent',0x4408,'<H',0x3020);self.refuse()
    def test_bad_relocation_block(self):self.pe_edit('parent',0x4404,'<I',10);self.refuse()
    def test_bad_relocation_target(self):self.pe_edit('parent',0x4408,'<H',0xafff);self.refuse()
    def test_overlapping_sections(self):self.pe_edit('parent',0x98+240+40+12,'<I',0x1000);self.refuse()
    def test_extra_role_image(self):self.files['net-other.exe']=make_pe('parent');self.refuse()
    def test_case_alias(self):self.files['NET-PARENT.EXE']=make_pe('parent');self.refuse()
    def test_unsafe_name(self):self.files['../net-parent.exe']=b'x';self.refuse()
    def test_missing_source_copy(self):del self.files['windows_child_network.c'];self.refuse()
    def test_changed_recipe_copy(self):self.files['build_windows_child_network.ps1']+=b'changed';self.refuse()
    def test_changed_validator_copy(self):self.files['windows_child_network_contract.py']+=b'changed';self.refuse()
    def test_changed_header_copy(self):self.files['windows_child_network_contract.h']+=b'changed';self.refuse()
    def test_changed_consumed_header(self):self.meta['headers'][r'D:\a\repo\tests\fixtures\windows_child_network_contract.h']['sha256']='0'*64;self.refuse()
    def test_missing_consumed_contract(self):
        name='dependencies-child.json';data=json.loads(self.files[name]);data['Data']['Includes']=data['Data']['Includes'][:1];self.files[name]=json.dumps(data).encode();self.refuse()
    def test_wrong_project(self):self.meta['project']={'commit':'f'*40,'tree':'b'*40};self.refuse()
    def test_wrong_run(self):self.meta['run_id']='124';self.refuse()
    def test_wrong_attempt(self):self.meta['run_attempt']='2';self.refuse()
    def test_no_reference(self):self.meta['reference']['executed']=False;self.refuse()
    def test_failed_external_exit(self):self.meta['reference']['exit']=37;self.refuse()
    def test_overclaimed_network(self):self.meta['network_validated']=True;self.refuse()
    def test_overclaimed_runtime(self):self.meta['runtime_validated']=True;self.refuse()
    def test_wrong_selector(self):self.meta['files']['net-child.exe']['selector']=0;self.refuse()
    def test_boolean_selector(self):self.meta['files']['net-child.exe']['selector']=True;self.refuse()
    def test_swapped_images(self):
        self.files['net-parent.exe'],self.files['net-child.exe']=self.files['net-child.exe'],self.files['net-parent.exe']
        for name in contract.NAMES:self.meta['files'][name].update(contract.record(self.files[name]))
        self.refuse()
    def test_changed_flags(self):self.meta['compile_commands']['child']=self.meta['compile_commands']['child'].replace('/DYNAMICBASE','/DYNAMICBASE:NO');self.refuse()
    def test_changed_selector(self):self.meta['compile_commands']['child']=self.meta['compile_commands']['child'].replace('PW_NET_CHILD=1','PW_NET_CHILD=0');self.refuse()
    def test_appended_argument(self):self.meta['compile_commands']['child']+=' /FORCE';self.refuse()
    def test_changed_source(self):self.meta['compile_commands']['child']=self.meta['compile_commands']['child'].replace('windows_child_network.c','other.c');self.refuse()
    def test_no_headers(self):self.meta['headers']={};self.refuse()
    def test_unconsumed_header(self):self.meta['headers'][r'C:\SDK\unused.h']={'bytes':1,'sha256':'f'*64};self.refuse()
    def test_dependency_source(self):
        data=json.loads(self.files['dependencies-child.json']);data['Data']['Source']=r'C:\other.c';self.files['dependencies-child.json']=json.dumps(data).encode();self.refuse()
    def test_dependency_module(self):
        data=json.loads(self.files['dependencies-child.json']);data['Data']['ImportedModules']=['other'];self.files['dependencies-child.json']=json.dumps(data).encode();self.refuse()
    def test_duplicate_json(self):
        self.files['network-source.json']=b'{"a":1,"a":2}'
        with self.assertRaises(ValueError):contract.validate_contents(self.files.__getitem__,set(self.files),self.project,'123','1',self.hashes)
    def test_duplicate_field(self):self.log_edit('child','shape_valid=1','shape_valid=1 shape_valid=1');self.refuse()
    def test_extra_field(self):self.log_edit('child','shape_valid=1','shape_valid=1 ignored=1');self.refuse()
    def test_changed_main_tid(self):self.log_edit('child','stage=socket_create pid=21 tid=22','stage=socket_create pid=21 tid=23');self.refuse()
    def test_wrong_child_pid(self):self.log_edit('parent','child_pid=21','child_pid=99');self.refuse()
    def test_wrong_child_tid(self):self.log_edit('parent','child_tid=22','child_tid=99');self.refuse()
    def test_numeric_unrelated_refusal(self):self.setup_bundle(refusal=10093);self.refuse()
    def test_numeric_empty_success(self):self.log_edit('child','code=0 count=1 shape_valid=1 optional=0','code=0 count=0 shape_valid=1 optional=0');self.refuse()
    def test_numeric_malformed(self):self.log_edit('child','shape_valid=1 optional=0','shape_valid=0 optional=0');self.refuse()
    def test_numeric_nonzero_success(self):self.log_edit('child','code=0 count=1','code=11002 count=1');self.refuse()
    def test_fqdn_error_result(self):self.setup_bundle(fqdn_code=11002);self.log_edit('child','code=11002 count=0','code=11002 count=1');self.refuse()
    def test_fqdn_false_success(self):self.setup_bundle(fqdn_code=11002);self.log_edit('child','optional=1 success=0','optional=1 success=1');self.refuse()
    def test_fqdn_late(self):self.log_edit('child','elapsed_ms=2','elapsed_ms=45000');self.refuse()
    def test_fqdn_repeated(self):self.transform_child(lambda b:b.replace(next(x for x in b.splitlines(True) if b'stage=resolve_attempt ' in x and b'case=example.com.' in x),next(x for x in b.splitlines(True) if b'stage=resolve_attempt ' in x and b'case=example.com.' in x)*2));self.refuse()
    def test_reordered_stages(self):
        def swap(data):
            lines=data.splitlines(True);lines[3],lines[4]=lines[4],lines[3];return b''.join(lines)
        self.transform_child(swap);self.refuse()
    def test_missing_cleanup(self):self.transform_child(lambda b:b''.join(x for x in b.splitlines(True) if b'stage=wsa_cleanup ' not in x));self.refuse()
    def test_unload_failure(self):self.log_edit('child','stage=dnsapi_unload pid=21 tid=22 result=1','stage=dnsapi_unload pid=21 tid=22 result=0');self.refuse()
    def test_cleanup_failure(self):self.log_edit('child','stage=network_cleanup pid=21 tid=22 status=0','stage=network_cleanup pid=21 tid=22 status=17');self.refuse()
    def test_dns_malformed(self):self.log_edit('child','record_present=1 shape_valid=1','record_present=0 shape_valid=1');self.refuse()
    def test_config_error_success_claim(self):self.log_edit('child','server_config_available=0','server_config_available=1');self.refuse()
    def test_config_short_buffer(self):self.setup_bundle(config_code=0);self.log_edit('child','returned_bytes=8','returned_bytes=3');self.refuse()
    def test_config_excessive_count(self):self.setup_bundle(config_code=0);self.log_edit('child','count=1 shape_valid=1 untouched=0','count=64 shape_valid=1 untouched=0');self.refuse()
    def test_missing_export_unload(self):self.setup_bundle(dns='export');self.transform_child(lambda b:b''.join(x for x in b.splitlines(True) if b'stage=dnsapi_unload ' not in x));self.refuse()
    def test_unrelated_export(self):self.setup_bundle(dns='export');self.log_edit('child','name=DnsQueryConfig','name=WSAStartup');self.refuse()
    def test_extra_optional_query(self):
        self.transform_child(lambda b:b.replace(next(x for x in b.splitlines(True) if b'stage=dnsapi_numeric ' in x),next(x for x in b.splitlines(True) if b'stage=dnsapi_numeric ' in x)*2));self.refuse()
    def test_wrong_observed_exit(self):self.log_edit('parent','observed_code=37','observed_code=0');self.refuse()
    def test_no_exit_query(self):self.log_edit('parent','query_ok=1','query_ok=0');self.refuse()
    def test_final_close_claim(self):self.log_edit('child','final_log_close=pending','final_log_close=complete');self.refuse()
    def test_extra_role_log(self):self.files['net-child-21-201.log']=self.files['net-child-21-200.log'];self.refuse()
    def test_role_log_hash_changed(self):self.files['net-child-21-200.log']+=b'x';self.refuse()
    def test_nonempty_stderr(self):self.files['reference.stderr.log']=b'error';self.meta['reference']['stderr']=contract.record(b'error');self.refuse()
    def test_unbounded_pid(self):self.log_edit('child','pid=21','pid=4294967296');self.refuse()


if __name__=='__main__':unittest.main()
