#!/usr/bin/env python3
"""Inert optional network title joins. Reference validator/API and target objects are mocks."""
import copy,hashlib,json,os,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'tests'))
import build_wine_service_child as b
import test_wine_user_title_build as old

class NetworkTitle(unittest.TestCase):
 def setUp(self):
  self.f=old.TitleInputs();self.f.setUp();self.addCleanup(self.f.doCleanups)
  f=self.f;self.network=f.temp and Path(f.temp.name)/'network';self.network.mkdir();self.calls=[]
  for n in ('tools/windows_child_network_contract.py','tests/fixtures/windows_child_network_contract.h'):
   p=f.root/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('inert '+n+'\n')
  self.pair={'project':f.project,'run_id':'123','run_attempt':'2','header_sha256':b.sha(f.root/'tests/fixtures/windows_child_network_contract.h'),
   'files':{'net-parent.exe':{'bytes':100,'sha256':'7'*64,'machine':'AMD64','selector':0},'net-child.exe':{'bytes':101,'sha256':'8'*64,'machine':'AMD64','selector':1}}}
  (self.network/'network-source.json').write_text(json.dumps(self.pair))
  def validate(directory,project,root,run,attempt,details=None):self.calls.append((directory,project,root,run,attempt));return copy.deepcopy(self.pair)
  self.module=types.SimpleNamespace(__file__=str(f.root/'tools/windows_child_network_contract.py'),validate_pair=validate)
  p=patch.dict(sys.modules,{'windows_child_network_contract':self.module});p.start();self.addCleanup(p.stop)
 def inputs(self,network=True,user=False,run='123',attempt='2'):
  f=self.f;return b.title_profiles_input_contract(f.root,f.service,f.fixture,f.user if user else None,run,attempt,self.network if network else None)
 def test_disabled_wrapper_preserves_existing_four_outputs_and_no_network_hash(self):
  for user in (False,True):
   result=self.inputs(False,user);self.assertEqual(result[:4],self.f.inputs(user));self.assertIsNone(result[4]);self.assertNotIn('network_enabled',result[0]);self.assertNotIn('PW_WINE_NET',result[1])
  self.assertFalse(self.calls)
 def test_enabled_network_only_and_with_user_keep_independent_original_joins(self):
  for user in (False,True):
   record,header,leaf,upair,npair=self.inputs(True,user);self.assertIs(record['network_enabled'],True);self.assertEqual(record['network_child_sha256'],'8'*64);self.assertEqual(record['network_reference_sha256'],b.sha(self.network/'network-source.json'));self.assertEqual(record['network_header_sha256'],self.pair['header_sha256']);self.assertEqual(npair,self.pair);self.assertEqual(upair is not None,user)
   self.assertIn('#define PW_WINE_NET_PROFILE_ENABLED 1\n',header);self.assertIn('"'+'8'*64+'"\n',header);self.assertEqual(leaf,self.f.pair)
   self.assertEqual(self.calls[-1],(self.network,self.f.project,self.f.root,'123','2'))
 def test_missing_or_stale_external_run_refuses_before_network_callback(self):
  for run,attempt in [(None,'2'),('123',None),('0','2'),('124','2'),('123','1')]:
   with self.assertRaises(ValueError):self.inputs(run=run,attempt=attempt)
  self.assertFalse(self.calls)
 def test_original_source_recipe_and_user_refusals_still_block_network(self):
  for key in ('source_sha256','recipe_sha256'):
   old=self.f.pair[key];self.f.pair[key]='f'*64
   with self.assertRaises(ValueError):self.inputs()
   self.f.pair[key]=old
  self.f.user_pair['run_attempt']='1'
  with self.assertRaises(ValueError):self.inputs(True,True)
  self.assertFalse(self.calls)
 def test_network_wrong_project_run_header_or_loaded_module_refused(self):
  for field,value in [('project',{'commit':'f'*40,'tree':'b'*40}),('run_id','124'),('run_attempt','1'),('header_sha256','f'*64)]:
   old=self.pair[field];self.pair[field]=value
   with self.assertRaises(ValueError):self.inputs()
   self.pair[field]=old
  self.module.__file__=str(self.f.root/'elsewhere.py')
  with self.assertRaises(ValueError):self.inputs()
 def test_raw_original_receipt_reserialization_changes_exact_input_hash(self):
  before=self.inputs()[0];p=self.network/'network-source.json';p.write_text(p.read_text()+'\n');after=self.inputs()[0];self.assertNotEqual(before['network_reference_sha256'],after['network_reference_sha256'])
 def test_actual_standalone_readonly_network_digest_and_disabled_refusal(self):
  def image(data,flags=4):return types.SimpleNamespace(data=data,programs=[(1,flags,0,0x1000,0,len(data))],offset=lambda address,size,required:address-0x1000)
  record=self.inputs()[0];digest='8'*64
  self.assertEqual(b.network_title_identity(image(b'\0'+digest.encode()+b'\0'),record,self.pair)['addresses'],[0x1001])
  for content,flags,enabled in [(b'old\0',4,True),(b'x'+digest.encode()+b'\0',4,True),(digest.encode()+b'\0',6,True),(digest.encode()+b'\0',4,False)]:
   with self.assertRaises(ValueError):b.network_title_identity(image(content,flags),dict(record,network_enabled=enabled),self.pair)
 def test_compile_record_network_flag_exact_default_off_and_source_receipt_preserved(self):
  record,wrapper=self.f.compile_record(False);path=self.f.build/'wine-child-title-compile.json'
  def check(enabled):
   with patch.object(b,'WRAPPER_SHA',b.sha(wrapper)):return b.verify_title_compile_record(self.f.root,self.f.build,self.f.project,False,self.f.sdk,self.f.title,enabled)
  result=check(False);self.assertIs(result['network_enabled'],False);self.assertIsNone(result['network_hash_source'])
  with self.assertRaises(ValueError):check(True)
  record['common_flags'].append('-DPW_WINE_NET_PROFILE_ENABLED=1')
  # Rebuild the recorded argv using the actual producer function after synthetic object setup.
  record=b.title_compile_record(self.f.root,self.f.build,self.f.project,record['compiler_argv'],record['common_flags'],list(record['sources']));path.write_text(json.dumps(record))
  self.assertIs(check(True)['network_enabled'],True)
  with self.assertRaises(ValueError):check(False)
  for flag in ('-DPW_WINE_NET_PROFILE_ENABLED=0','-UPW_WINE_NET_PROFILE_ENABLED','-DPW_WINE_NET_CHILD_SHA256=bad','-UPW_WINE_NET_CHILD_SHA256'):
   wrong=copy.deepcopy(record);wrong['common_flags'].append(flag);path.write_text(json.dumps(wrong))
   with self.assertRaises(ValueError):check(True)
 def test_exact_shell_argument_combinations_and_space_preservation(self):
  text=(ROOT/'tools/build_native.sh').read_text();call=text.index('    python3 "$root/tools/build_wine_service_child.py" --check-title');start=text.rfind('if [[ $wine_child_fixture == 1 ]]; then',0,call);end=text.index('\nfi',call)+3
  shell='python3() { printf "%s\\0" "$@" > "$CAPTURE"; }\n'+text[start:end]
  with tempfile.TemporaryDirectory(prefix='network title args ') as directory:
   temp=Path(directory);capture=temp/'capture';env=dict(os.environ,root=str(ROOT),build=str(temp/'build'),dist=str(temp/'dist'),sdk=str(temp/'sdk'),llvm_bindir=str(temp/'llvm'),PW_WINE_CHILD_RUNTIME=str(temp/'runtime'),PW_WINE_CHILD_FOUNDATION=str(temp/'foundation'),PW_WINDOWS_CHILD_FIXTURE_DIR=str(temp/'leaf ref'),PW_NATIVE_SDK_SOURCE_ARCHIVE=str(temp/'sdk source.tar.gz'),CAPTURE=str(capture),wine_child_fixture='1',GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='2',wine_child_user=str(temp/'USER ref'),wine_child_network=str(temp/'network ref'))
   for user in (0,1):
    for net in (0,1):
     subprocess.run(['bash','-euc',shell],env=dict(env,wine_user_enabled=str(user),wine_network_enabled=str(net)),capture_output=True,check=True,timeout=10);args=[v.decode() for v in capture.read_bytes().split(b'\0')[:-1]]
     self.assertEqual('--user-fixture' in args,bool(user));self.assertEqual('--network-fixture' in args,bool(net));self.assertEqual(args.count('--run-id'),int(bool(user or net)))
     if net:self.assertEqual(args[args.index('--network-fixture')+1],env['wine_child_network'])
 def test_profile_compiler_and_input_flow_is_before_compile_and_replayed_after(self):
  text=(ROOT/'tools/build_native.sh').read_text();self.assertIn('PW_WINDOWS_CHILD_NETWORK_DIR:-',text);self.assertIn('title_profiles_input_contract',text);self.assertIn('common+=(-DPW_WINE_NET_PROFILE_ENABLED=1)',text)
  self.assertLess(text.index('title_profiles_input_contract'),text.index('for source in "${sources[@]}"'))
  code=(ROOT/'tools/build_wine_service_child.py').read_text();self.assertGreaterEqual(code.count('title_profiles_input_contract(root, args.service_work'),2);self.assertIn("'network_route': network_route",code);self.assertIn("'title_compile_receipt': record(build / 'wine-child-title-compile.json')",code)

if __name__=='__main__':unittest.main(verbosity=2)
