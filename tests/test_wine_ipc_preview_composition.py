#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Actual source/build-contract controls; no PS5 build or execution."""
import copy
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'tests'))
import build_wine_service_child as build
import test_wine_ipc_title_build as ipc_tests

MESSAGE='separate matched cohorts'
class CompositionControls(unittest.TestCase):
 def fixture(self):
  f=ipc_tests.IpcTitleControls();f.setUp();self.addCleanup(f.doCleanups);return f
 def test_input_contract_all_option_combinations(self):
  helper=self.fixture();f=helper.fixture
  for ui,ipc in [(False,False),(True,False),(False,True),(True,True)]:
   with self.subTest(ui=ui,ipc=ipc):
    f.manifest['child_ui']=build.child_ui_contract(ui)
    (f.service/'native-wine-child-build.json').write_text(json.dumps(f.manifest))
    helper.calls.clear()
    if ui and ipc:
     with self.assertRaisesRegex(ValueError,MESSAGE):helper.inputs(ipc)
     self.assertFalse(helper.calls)
    else:
     record,header,*_=helper.inputs(ipc)
     self.assertEqual(record['child_ui'],build.child_ui_contract(ui))
     self.assertEqual(record.get('ipc_enabled',False),ipc)
     self.assertEqual('PW_WINE_IPC_PROFILE_ENABLED 1' in header,ipc)
     self.assertEqual(bool(helper.calls),ipc)
 def test_compile_receipts_refuse_crossed_flags_all_combinations(self):
  helper=self.fixture();f=helper.fixture;record,wrapper=f.compile_record(False)
  receipt=f.build/'wine-child-title-compile.json'
  with patch.object(build,'WRAPPER_SHA',build.sha(wrapper)):
   for actual_ui,actual_ipc in [(False,False),(True,False),(False,True),(True,True)]:
    flags=record['common_flags']+(['-DPW_WINE_CHILD_UI_ENABLED=1'] if actual_ui else [])+(['-DPW_WINE_IPC_PROFILE_ENABLED=1'] if actual_ipc else [])
    receipt.write_text(json.dumps(build.title_compile_record(f.root,f.build,f.project,record['compiler_argv'],flags,list(record['sources']))))
    for claimed_ui,claimed_ipc in [(False,False),(True,False),(False,True),(True,True)]:
     with self.subTest(actual=(actual_ui,actual_ipc),claimed=(claimed_ui,claimed_ipc)):
      def verify():return build.verify_title_compile_record(f.root,f.build,f.project,False,f.sdk,f.title,False,claimed_ui,ipc_enabled=claimed_ipc)
      if (actual_ui,actual_ipc)==(claimed_ui,claimed_ipc) and not(actual_ui and actual_ipc):
       result=verify();self.assertEqual(result['child_ui']['enabled'],actual_ui);self.assertEqual(result['ipc_enabled'],actual_ipc)
      else:
       with self.assertRaises(ValueError):verify()
   # IPC must be named explicitly, not misread as the existing UI positional parameter.
   with self.assertRaises(TypeError):build.verify_title_compile_record(f.root,f.build,f.project,False,f.sdk,f.title,False,False,True)
 def test_worker_and_title_direct_entries_refuse_before_io(self):
  args=types.SimpleNamespace(child_ui=True,ipc_fixture=Path('/inert-missing-ipc'))
  for function in [lambda:build.inputs(args,None),lambda:build.build(args),lambda:build.check_title(args)]:
   with self.assertRaisesRegex(ValueError,MESSAGE):function()
 def test_actual_native_builder_refuses_before_output_or_foundation(self):
  env=dict(os.environ,PW_WINE_CHILD_FIXTURE_MODE='1',PW_OUTPUT_SUFFIX='-windows-child-fixture',PW_NATIVE_CHILD_PROBE='0',PW_WINE_CHILD_UI_ENABLED='1',PW_WINDOWS_CHROMIUM_IPC_DIR='/inert-missing-ipc',GITHUB_RUN_ID='',GITHUB_RUN_ATTEMPT='')
  result=subprocess.run(['bash',str(ROOT/'tools/build_native.sh')],env=env,capture_output=True,text=True,timeout=10)
  self.assertEqual(result.returncode,2,result.stderr);self.assertIn(MESSAGE,result.stderr)
 def test_actual_builder_preflight_all_sixteen_option_combinations(self):
  text=(ROOT/'tools/build_native.sh').read_text()
  preflight=text[text.index('wine_child_fixture=${'):text.index('[[ $native_mode ==')]
  for ui in (0,1):
   for ipc in (0,1):
    for user in (0,1):
     for network in (0,1):
      with self.subTest(ui=ui,ipc=ipc,user=user,network=network):
       env=dict(os.environ,native_child_probe='0',output_suffix='-windows-child-fixture',PW_WINE_CHILD_FIXTURE_MODE='1',
        PW_WINE_CHILD_UI_ENABLED=str(ui),PW_WINDOWS_CHROMIUM_IPC_DIR='/inert-ipc' if ipc else '',
        PW_WINDOWS_CHILD_USER_DIR='/inert-user' if user else '',PW_WINDOWS_CHILD_NETWORK_DIR='/inert-network' if network else '',
        GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='2')
       result=subprocess.run(['bash','-euc',preflight],env=env,capture_output=True,text=True,timeout=10)
       self.assertEqual(result.returncode,2 if ui and ipc else 0,result.stderr)
       if ui and ipc:self.assertIn(MESSAGE,result.stderr)
 def test_worker_cli_refuses_before_output_creation(self):
  with tempfile.TemporaryDirectory(prefix='pw-ipc-ui-cli-') as directory:
   out=Path(directory)/'must-not-exist'
   cmd=[sys.executable,str(ROOT/'tools/build_wine_service_child.py'),'--child-ui','--ipc-fixture','/missing-ipc','--sdk','/missing-sdk','--foundation','/missing-foundation','--runtime','/missing-runtime','--llvm-bindir','/missing-llvm','--out',str(out)]
   result=subprocess.run(cmd,capture_output=True,text=True,timeout=10)
   self.assertNotEqual(result.returncode,0);self.assertIn(MESSAGE,result.stderr);self.assertFalse(out.exists())
 def test_real_title_and_worker_compile_mode_matrix(self):
  cc=shlex.split(os.environ.get('CC','cc'))
  with tempfile.TemporaryDirectory(prefix='pw-ipc-ui-syntax-') as directory:
   (Path(directory)/'wine-child-title-config.h').write_text('#define PW_WINE_FIXTURE_CHILD_SHA256 "'+'0'*64+'"\n#define PW_WINE_USER_PROFILE_ENABLED 0\n')
   common=[*cc,'-std=c11','-D_DEFAULT_SOURCE','-Wall','-Wextra','-Werror','-Wno-enum-compare','-pthread','-fsyntax-only','-DPW_WINE_CHILD_FIXTURE_MODE=1','-I'+directory,'-iquote',str(ROOT/'tests/wine_child_fixture'),'-iquote',str(ROOT/'tests/wine_child_title_fixture')]
   for ui,ipc in [(0,0),(1,0),(0,1),(1,1),(2,0),(0,2)]:
    for source in ['native/pw_wine_child_main.c','native/pw_wine_child_title.c','native/pw_wine_child_bootstrap.c']:
     with self.subTest(ui=ui,ipc=ipc,source=source):
      result=subprocess.run([*common,'-DPW_WINE_CHILD_UI_ENABLED='+str(ui),'-DPW_WINE_CHILD_UI_COHORT='+str(ui),'-DPW_WINE_IPC_PROFILE_ENABLED='+str(ipc),str(ROOT/source)],capture_output=True,text=True,timeout=30)
      self.assertEqual(result.returncode==0,ui in (0,1) and ipc in (0,1) and not(ui and ipc),result.stderr)
if __name__=='__main__':unittest.main()
