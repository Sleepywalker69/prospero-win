#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Data-only title producer controls. No compiler, SELF or PE is executed."""
import ast
import copy
import os
import subprocess
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import build_wine_service_child as b
import prepare_windows_child_prefix as prefix
import build_owned_helper as owned_helper

class TitleInputs(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)/'repo';self.root.mkdir();self.build=Path(self.temp.name)/'build';self.build.mkdir();self.service=Path(self.temp.name)/'service';self.service.mkdir();self.fixture=Path(self.temp.name)/'fixture';self.fixture.mkdir();self.user=Path(self.temp.name)/'user';self.user.mkdir();self.sdk=Path(self.temp.name)/'sdk';self.sdk.mkdir();self.title=Path(self.temp.name)/'foundation';(self.title/'tooling').mkdir(parents=True)
  for name in ['tests/fixtures/windows_child_process.c','tools/build_windows_child_fixture.ps1','tools/build_native.sh','tools/windows_child_user_contract.py',*b.TITLE_USER_SOURCES]:
   p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('inert input '+name+'\n')
  self.project={'commit':'a'*40,'tree':'b'*40};self.manifest={'project':self.project};(self.service/'native-wine-child-build.json').write_text(json.dumps(self.manifest))
  self.pair={'project':self.project,'run_id':'123','run_attempt':'2','source_sha256':b.sha(self.root/'tests/fixtures/windows_child_process.c'),'recipe_sha256':b.sha(self.root/'tools/build_windows_child_fixture.ps1'),'files':{n:{'bytes':123,'sha256':'c'*64} for n in ['parent.exe','child.exe']}}
  self.user_pair={'project':self.project,'run_id':'123','run_attempt':'2','files':{'user-parent.exe':{'bytes':234,'sha256':'d'*64,'machine':'AMD64','selector':0},'user-child.exe':{'bytes':235,'sha256':'e'*64,'machine':'AMD64','selector':1}}};(self.user/'user-source.json').write_text(json.dumps(self.user_pair))
  p=patch.object(owned_helper,'validate_owned_helper',return_value={'elf':{'sha256':'ab'*32}});p.start();self.addCleanup(p.stop)
  self.calls=[]
  def validate(directory,project,root,run,attempt,details=None):
   self.calls.append((directory,project,root,run,attempt));return copy.deepcopy(self.user_pair)
  self.user_module=types.SimpleNamespace(__file__=str(self.root/'tools/windows_child_user_contract.py'),validate_pair=validate)
  p=patch.object(prefix,'validate_pair',side_effect=lambda directory,project:copy.deepcopy(self.pair));p.start();self.addCleanup(p.stop)
  p=patch.dict(sys.modules,{'windows_child_user_contract':self.user_module});p.start();self.addCleanup(p.stop)
 def inputs(self,enabled=True,run='123',attempt='2'):
  return b.title_input_contract(self.root,self.service,self.fixture,self.user if enabled else None,run,attempt)
 def test_disabled_keeps_original_record_and_does_not_validate_user(self):
  record,header,pair,user=self.inputs(False,None,None)
  self.assertEqual(set(record),{'schema','project','mode','define','fixture_child_sha256','build_script_sha256','service_manifest_sha256'})
  self.assertIn('PW_WINE_USER_PROFILE_ENABLED 0\n',header);self.assertNotIn('PW_WINE_USER_CHILD_SHA256',header);self.assertFalse(self.calls);self.assertIsNone(user)
 def test_enabled_binds_distinct_child_raw_reference_and_external_run(self):
  record,header,pair,user=self.inputs();self.assertTrue(record['user_enabled']);self.assertEqual(record['user_child_sha256'],'e'*64);self.assertEqual(record['user_reference_sha256'],b.sha(self.user/'user-source.json'));self.assertIn('PW_WINE_USER_PROFILE_ENABLED 1\n',header);self.assertIn('PW_WINE_USER_CHILD_SHA256 "'+'e'*64+'"\n',header);self.assertEqual(self.calls[-1],(self.user,self.project,self.root,'123','2'));self.assertEqual(pair,self.pair)
 def test_missing_or_wrong_external_original_run_refused_before_user_validator(self):
  for run,attempt in [(None,'2'),('123',None),('0','2'),('123','0'),('124','2'),('123','1')]:
   with self.subTest(run=run,attempt=attempt),self.assertRaises(ValueError):self.inputs(run=run,attempt=attempt)
  self.assertFalse(self.calls)
 def test_original_source_recipe_always_required(self):
  for field in ['source_sha256','recipe_sha256']:
   old=self.pair[field];self.pair[field]='0'*64
   for enabled in [False,True]:
    with self.assertRaises(ValueError):self.inputs(enabled)
   self.pair[field]=old
 def test_user_wrong_project_run_attempt_and_loaded_module_refused(self):
  for field,value in [('project',{'commit':'f'*40,'tree':'b'*40}),('run_id','124'),('run_attempt','1')]:
   old=self.user_pair[field];self.user_pair[field]=value
   with self.assertRaises(ValueError):self.inputs()
   self.user_pair[field]=old
  self.user_module.__file__=str(self.root/'wrong.py')
  with self.assertRaisesRegex(ValueError,'another project'):self.inputs()
 def test_changed_raw_reference_changes_input_binding(self):
  a=self.inputs()[0];p=self.user/'user-source.json';p.write_text(p.read_text()+'\n');z=self.inputs()[0];self.assertNotEqual(a['user_reference_sha256'],z['user_reference_sha256'])
 def test_compiled_user_digest_is_exact_standalone_read_only(self):
  def image(data,flags=4):return types.SimpleNamespace(data=data,programs=[(1,flags,0,0x1000,0,len(data))],offset=lambda address,size,required:address-0x1000)
  digest='e'*64;record=self.inputs()[0]
  self.assertEqual(b.user_title_identity(image(b'\0'+digest.encode()+b'\0'),record,self.user_pair)['addresses'],[0x1001])
  for data,flags,enabled in [(b'old\0',4,True),(b'x'+digest.encode()+b'\0',4,True),(digest.encode()+b'\0',6,True),(digest.encode()+b'\0',4,False)]:
   with self.assertRaises(ValueError):b.user_title_identity(image(data,flags),dict(record,user_enabled=enabled),self.user_pair)
 def compile_record(self,enabled=True):
  wrapper=self.title/'tooling/prospero-clang18';wrapper.write_text('inert compiler wrapper; never executed\n');compiler=['env','PS5_PAYLOAD_SDK='+str(self.sdk),'sh',str(wrapper)];flags=['-O2','-DPW_LAPY_HELPER_SHA256="'+'ab'*32+'"','-DPW_WINE_CHILD_FIXTURE_MODE=1','-DPW_WINE_USER_PROFILE_ENABLED='+str(int(enabled))];units=[n for n in b.TITLE_USER_SOURCES if n.endswith('.c')]
  for n in units:
   p=self.build/'obj'/(n.replace('/','_')+'.o');p.parent.mkdir(exist_ok=True);p.write_bytes(b'inert object '+n.encode())
  record=b.title_compile_record(self.root,self.build,self.project,compiler,flags,units);(self.build/'wine-child-title-compile.json').write_text(json.dumps(record));return record,wrapper
 def check_compile(self,enabled):return b.verify_title_compile_record(self.root,self.build,self.project,enabled,self.sdk,self.title)
 def test_actual_compile_record_binds_flags_source_object_wrapper(self):
  record,wrapper=self.compile_record();
  with patch.object(b,'WRAPPER_SHA',b.sha(wrapper)):
   self.assertTrue(self.check_compile(True)['user_enabled']);self.assertFalse(self.check_compile(True)['source_to_binary_reproducibility_verified'])
   with self.assertRaises(ValueError):self.check_compile(False)
   for n in [self.root/'native/pw_wine_child_title.h',self.build/'obj/native_pw_wine_child_title.c.o',wrapper]:
    raw=n.read_bytes();n.write_bytes(raw+b'changed')
    with self.assertRaises(ValueError):self.check_compile(True)
    n.write_bytes(raw)
 def test_compile_record_rejects_conflicting_flags_and_missing_functions(self):
  record,wrapper=self.compile_record();p=self.build/'wine-child-title-compile.json'
  with patch.object(b,'WRAPPER_SHA',b.sha(wrapper)):
   for flag in ['-DPW_LAPY_HELPER_SHA256="'+'cd'*32+'"','-UPW_LAPY_HELPER_SHA256','-DPW_WINE_USER_PROFILE_ENABLED=0','-UPW_WINE_USER_PROFILE_ENABLED','-include','-D']:
    wrong=copy.deepcopy(record);wrong['common_flags'].append(flag);p.write_text(json.dumps(wrong))
    with self.assertRaises(ValueError):self.check_compile(True)
   wrong=copy.deepcopy(record);wrong['sources'].pop('native/pw_wine_child_title.c');p.write_text(json.dumps(wrong))
   with self.assertRaises(ValueError):self.check_compile(True)
 def test_worker_metadata_declares_exact_four_compiled_capabilities(self):
  tree=ast.parse((ROOT/'tools/build_wine_service_child.py').read_text())
  function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='inputs')
  result=next(n.value for n in function.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='result' for t in n.targets))
  value=next(v for k,v in zip(result.keys,result.values) if isinstance(k,ast.Constant) and k.value=='candidate_capabilities')
  self.assertEqual(ast.literal_eval(value),[
   {'mode':1,'prefix':'windows-child-fixture-v1','guest_machine':'AMD64','backend':'native-amd64','runtime_validated':False},
   {'mode':2,'prefix':'battlenet-experimental-v1','guest_machine':'I386','backend':'wowprospero','runtime_validated':False},
   {'mode':3,'prefix':'windows-child-user-v1','guest_machine':'AMD64','backend':'native-amd64','runtime_validated':False},
   {'mode':4,'prefix':'windows-child-net-v1','guest_machine':'AMD64','backend':'native-amd64','runtime_validated':False}])
 def test_actual_user_function_mapping_refuses_old_only_missing_or_changed_code(self):
  class Image:
   def __init__(self):
    self.data=b'CODE'+b'\0'*124+b.TITLE_MARKER.encode()+b'\0'
    self.programs=[(1,5,0,0x1000,0,4),(1,4,128,0x2000,0,len(self.data)-128)]
   def offset(self,address,size,flags):
    for _,actual,off,virtual,_,extent in self.programs:
     if actual&flags==flags and virtual<=address and address-virtual+size<=extent:return off+address-virtual
    raise ValueError('not a mapped segment')
  linked,recovered=Image(),Image()
  symbols=lambda names:'\n'.join(f'{i}: 0000000000001000 4 FUNC GLOBAL DEFAULT 1 {name}' for i,name in enumerate(names,1))
  self.assertEqual(set(b.check_route(linked,recovered,symbols(b.TITLE_USER_FUNCTIONS),b.TITLE_USER_FUNCTIONS)['functions']),set(b.TITLE_USER_FUNCTIONS))
  for names in [b.TITLE_FUNCTIONS,b.TITLE_USER_FUNCTIONS[:1],b.TITLE_USER_FUNCTIONS+b.TITLE_USER_FUNCTIONS[:1]]:
   with self.assertRaises(ValueError):b.check_route(linked,recovered,symbols(names),b.TITLE_USER_FUNCTIONS)
  recovered.data=b'FAIL'+recovered.data[4:]
  with self.assertRaises(ValueError):b.check_route(linked,recovered,symbols(b.TITLE_USER_FUNCTIONS),b.TITLE_USER_FUNCTIONS)
 def test_actual_shell_routes_optional_reference_and_run_without_execution(self):
  native=(ROOT/'tools/build_native.sh').read_text()
  command=native.index('    python3 "$root/tools/build_wine_service_child.py" --check-title')
  start=native.rfind('if [[ $wine_child_fixture == 1 ]]; then',0,command)
  end=native.index('\nfi',command)+3
  shell='python3() { printf "%s\\0" "$@" > "$CAPTURE"; }\n'+native[start:end]
  with tempfile.TemporaryDirectory(prefix='USER title argv ') as directory:
   temp=Path(directory);capture=temp/'args'
   env=dict(os.environ,root=str(ROOT),build=str(temp/'build'),dist=str(temp/'app'),sdk=str(temp/'sdk'),llvm_bindir=str(temp/'llvm'),PW_WINE_CHILD_RUNTIME=str(temp/'runtime'),PW_WINE_CHILD_FOUNDATION=str(temp/'foundation'),PW_WINDOWS_CHILD_FIXTURE_DIR=str(temp/'original reference'),PW_NATIVE_SDK_SOURCE_ARCHIVE=str(temp/'source.tar.gz'),CAPTURE=str(capture),wine_child_fixture='1')
   for enabled in ('0','1'):
    args=dict(env,wine_user_enabled=enabled,wine_child_user=str(temp/'USER reference'),GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='2')
    subprocess.run(['bash','-euc',shell],env=args,check=True,capture_output=True,timeout=10)
    values=capture.read_bytes().split(b'\0')[:-1]
    values=[v.decode() for v in values]
    self.assertEqual(values[values.index('--fixture')+1],env['PW_WINDOWS_CHILD_FIXTURE_DIR'])
    self.assertEqual('--user-fixture' in values,enabled=='1')
    if enabled=='1':
     self.assertEqual(values[values.index('--user-fixture')+1],args['wine_child_user'])
     self.assertEqual(values[values.index('--run-id')+1],'123');self.assertEqual(values[values.index('--run-attempt')+1],'2')
   capture.unlink()
   subprocess.run(['bash','-euc',shell],env=dict(env,wine_child_fixture='0'),check=True,capture_output=True,timeout=10)
   self.assertFalse(capture.exists())
 def test_report_explicitly_binds_raw_compile_receipt(self):
  source=(ROOT/'tools/build_wine_service_child.py').read_text();tree=ast.parse(source)
  function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='check_title')
  report=next(n.value for n in function.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='report' for t in n.targets))
  pairs={k.value:v for k,v in zip(report.keys,report.values) if isinstance(k,ast.Constant)}
  self.assertEqual(ast.dump(pairs['title_compile_receipt']),ast.dump(ast.parse("record(build / 'wine-child-title-compile.json')",mode='eval').body))
 def test_enabled_source_flow_and_preserved_original_reference(self):
  native=(ROOT/'tools/build_native.sh').read_text();source=(ROOT/'tools/build_wine_service_child.py').read_text()
  self.assertIn('PW_WINDOWS_CHILD_FIXTURE_DIR:?',native);self.assertIn('PW_WINDOWS_CHILD_USER_DIR:-',native);self.assertIn('user_title_args+=(--user-fixture',native);self.assertIn('--run-id "$GITHUB_RUN_ID" --run-attempt "$GITHUB_RUN_ATTEMPT"',native);self.assertIn('-DPW_WINE_USER_PROFILE_ENABLED="$wine_user_enabled"',native);self.assertIn('"${#cc[@]}" "${#common[@]}" "${cc[@]}" "${common[@]}" "${sources[@]}"',native)
  self.assertLess(source.index('title_profiles_input_contract(root, args.service_work'),source.index('fixture_identity = fixture_title_identity'))
  self.assertIn("'user_reference_sha256': title_inputs.get('user_reference_sha256')",source)

if __name__=='__main__':unittest.main()
