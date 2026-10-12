#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Inert title/argv/compiler provenance tests; no target compiler or execution."""
import copy
import json
import os
from pathlib import Path
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
import test_wine_user_title_build as original


class IpcTitleControls(unittest.TestCase):
    def setUp(self):
        self.fixture=original.TitleInputs();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        f=self.fixture;self.bundle=Path(f.temp.name)/'ipc';self.bundle.mkdir();self.calls=[]
        path=f.root/'tools/windows_chromium_ipc_contract.py';path.write_text('inert validator identity')
        self.cohort={'project':f.project,'run_id':'123','run_attempt':'2','admitted_architecture':'x64',
            'references':{'x64':{'image':{'sha256':'7'*64}},'x86':{'image':{'sha256':'8'*64}}}}
        def validate(directory,project,root,run,attempt):
            self.calls.append((directory,project,root,run,attempt));return copy.deepcopy(self.cohort)
        self.module=types.SimpleNamespace(__file__=str(path),validate_bundle=validate)
        patcher=patch.dict(sys.modules,{'windows_chromium_ipc_contract':self.module});patcher.start();self.addCleanup(patcher.stop)
    def inputs(self,enabled=True,run='123',attempt='2'):
        f=self.fixture
        return build.title_profiles_input_contract(f.root,f.service,f.fixture,None,run,attempt,None,self.bundle if enabled else None)
    def test_off_preserves_original_outputs_and_never_opens_ipc(self):
        result=self.inputs(False,None,None)
        self.assertEqual(result[:4],self.fixture.inputs(False,None,None));self.assertIsNone(result[4])
        self.assertNotIn('ipc_enabled',result[0]);self.assertNotIn('PW_WINE_IPC_',result[1]);self.assertFalse(self.calls)
    def test_on_binds_x64_digest_and_both_reference_architectures(self):
        record,header,*rest=self.inputs()
        self.assertTrue(record['ipc_enabled']);self.assertEqual(record['ipc_reference'],self.cohort)
        self.assertEqual(record['ipc_child_sha256'],'7'*64)
        self.assertIn('#define PW_WINE_IPC_PROFILE_ENABLED 1\n',header)
        self.assertIn('#define PW_WINE_IPC_CHILD_SHA256 "'+'7'*64+'"\n',header)
        self.assertNotIn('8'*64,header)
        self.assertEqual(self.calls[-1],(self.bundle,self.fixture.project,self.fixture.root,'123','2'))
    def test_external_run_and_exact_project_are_not_taken_from_receipt(self):
        for run,attempt in [(None,'2'),('123',None),('124','2'),('123','1')]:
            with self.subTest(run=run,attempt=attempt),self.assertRaises(ValueError):self.inputs(run=run,attempt=attempt)
        self.assertFalse(self.calls)
        for field,value in [('project',{'commit':'f'*40,'tree':'b'*40}),('run_id','124'),('run_attempt','1'),('admitted_architecture','x86')]:
            saved=self.cohort[field];self.cohort[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.inputs()
            self.cohort[field]=saved
        self.module.__file__=str(self.fixture.root/'other.py')
        with self.assertRaises(ValueError):self.inputs()
    def test_exact_compile_flags_generated_hash_only_and_header_binding(self):
        f=self.fixture;record,wrapper=f.compile_record(False);path=f.build/'wine-child-title-compile.json'
        def check(enabled):
            with patch.object(build,'WRAPPER_SHA',build.sha(wrapper)):
                return build.verify_title_compile_record(f.root,f.build,f.project,False,f.sdk,f.title,False,ipc_enabled=enabled)
        self.assertFalse(check(False)['ipc_enabled'])
        with self.assertRaises(ValueError):check(True)
        record['common_flags'].append('-DPW_WINE_IPC_PROFILE_ENABLED=1')
        record=build.title_compile_record(f.root,f.build,f.project,record['compiler_argv'],record['common_flags'],list(record['sources']))
        path.write_text(json.dumps(record));self.assertTrue(check(True)['ipc_enabled'])
        with self.assertRaises(ValueError):check(False)
        for flag in ('-DPW_WINE_IPC_PROFILE_ENABLED=0','-UPW_WINE_IPC_PROFILE_ENABLED','-DPW_WINE_IPC_CHILD_SHA256=bad','-UPW_WINE_IPC_CHILD_SHA256'):
            changed=copy.deepcopy(record);changed['common_flags'].append(flag);path.write_text(json.dumps(changed))
            with self.subTest(flag=flag),self.assertRaises(ValueError):check(True)
        path.write_text(json.dumps(record));(f.root/'native/pw_wine_ipc_profile.h').write_text('changed exact mapping')
        with self.assertRaises(ValueError):check(True)
    def test_shell_replays_each_optional_profile_combination_exactly(self):
        text=(ROOT/'tools/build_native.sh').read_text();call=text.index('    python3 "$root/tools/build_wine_service_child.py" --check-title')
        start=text.rfind('if [[ $wine_child_fixture == 1 ]]; then',0,call);end=text.index('\nfi',call)+3
        shell='python3() { printf "%s\\0" "$@" > "$CAPTURE"; }\n'+text[start:end]
        with tempfile.TemporaryDirectory(prefix='IPC title args ') as directory:
            temp=Path(directory);capture=temp/'capture'
            env=dict(os.environ,root=str(ROOT),build=str(temp/'build'),dist=str(temp/'dist'),sdk=str(temp/'sdk'),
                llvm_bindir=str(temp/'llvm'),PW_WINE_CHILD_RUNTIME=str(temp/'runtime'),PW_WINE_CHILD_FOUNDATION=str(temp/'foundation'),
                PW_WINDOWS_CHILD_FIXTURE_DIR=str(temp/'leaf ref'),PW_NATIVE_SDK_SOURCE_ARCHIVE=str(temp/'sdk source.tar.gz'),
                CAPTURE=str(capture),wine_child_fixture='1',GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='2',
                wine_child_user=str(temp/'USER ref'),wine_child_network=str(temp/'network ref'),wine_child_ipc=str(temp/'IPC ref'))
            for user in (0,1):
                for network in (0,1):
                    for ipc in (0,1):
                        subprocess.run(['bash','-euc',shell],env=dict(env,wine_user_enabled=str(user),wine_network_enabled=str(network),
                            wine_ipc_enabled=str(ipc)),capture_output=True,check=True,timeout=10)
                        args=[v.decode() for v in capture.read_bytes().split(b'\0')[:-1]]
                        self.assertEqual('--user-fixture' in args,bool(user));self.assertEqual('--network-fixture' in args,bool(network))
                        self.assertEqual('--ipc-fixture' in args,bool(ipc));self.assertEqual(args.count('--run-id'),int(bool(user or network or ipc)))
                        if ipc:self.assertEqual(args[args.index('--ipc-fixture')+1],env['wine_child_ipc'])


if __name__=='__main__':unittest.main()
