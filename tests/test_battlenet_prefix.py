#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Fresh-prefix admission and profile controls; no Wine/vendor program runs."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import prepare_windows_child_prefix as prefix

class BattlePrefix(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='pw-battle-prefix-controls-')
        self.addCleanup(self.temporary.cleanup);self.root=Path(self.temporary.name)
        self.repo=Path(os.environ.get('PW_PREFIX_TEST_REPO',ROOT))

    def test_profile_uses_existing_native_parser_and_translator(self):
        text=prefix.battle_profile(self.repo)
        profile=self.root/'battle.profile';profile.write_text(text)
        source=self.root/'reader.c';source.write_text(r'''
#include "pw_game_profile.h"
#include <stdio.h>
#include <string.h>
int main(int argc,char **argv) {
    unsigned char bytes[8192]; size_t length; PwGameProfile p;
    if(argc!=2)return 1;
    FILE *f=fopen(argv[1],"rb"); if(!f)return 2;
    length=fread(bytes,1,sizeof bytes,f);fclose(f);
    if(length==sizeof bytes || pw_game_profile_parse(bytes,length,&p)!=PW_OK)return 3;
    if(strcmp(p.app.id,"battlenet-experimental-v1") || strcmp(p.app.prefix,"battlenet-experimental-v1") ||
       strcmp(p.app.executable,"C:\\installer\\Battle.net-Setup.exe") ||
       strcmp(p.app.working_directory,"C:\\installer") || strcmp(p.app.runtime,"wine-wow64") ||
       p.app.architecture!=PW_APP_ARCH_PE32 || p.app.graphics!=PW_APP_GRAPHICS_AUTO ||
       p.app.arguments[0] || p.runtime.cpu!=PW_GAME_CPU_TRANSLATOR || pw_game_cpu_native(&p))return 4;
    return 0;
}
''')
        compiler=shutil.which('cc');self.assertIsNotNone(compiler)
        command=[compiler,'-std=c11','-Wall','-Wextra','-Werror','-I'+str(self.repo/'src'),'-I'+str(self.repo/'include'),
                 str(source),str(self.repo/'src/pw_game_profile.c'),str(self.repo/'src/pw_app_profile.c'),'-o',str(self.root/'reader')]
        subprocess.run(command,check=True,capture_output=True,text=True)
        subprocess.run([str(self.root/'reader'),str(profile)],check=True,capture_output=True)
        self.assertNotIn('arguments =',text)

    def test_recipe_separates_owned_slots_and_contains_no_vendor_bytes(self):
        ordinary,battle=prefix.recipe(),prefix.recipe(True)
        self.assertNotEqual(ordinary['game_slug'],battle['game_slug'])
        self.assertEqual(battle['script']['game']['exe'],'drive_c/installer/Battle.net-Setup.exe')
        self.assertFalse(battle['script']['wine']['dxvk'])
        self.assertNotIn('files',battle);self.assertNotIn('installer',battle['script'])

    def runtime_fixture(self,abi=None,selector=None):
        cpu=self.root/'cpu';cpu.mkdir();(cpu/'cpu-build.json').write_text('{}')
        dll=cpu/'wowprospero.dll';dll.write_bytes(b'owned CPU PE bytes')
        cohort=self.root/'cohort.json';cohort.write_text(json.dumps({'ps5_source':{'source':'bound'}}))
        wine=self.root/'wine';wine.mkdir()
        (wine/'report.json').write_text(json.dumps({'service_fixture':selector if selector is not None else
                                                   {'enabled':True,'unix_define':'PW_WINE_SERVICE_FIXTURE=1','abi':1,'runtime_validated':False}}))
        record={'inputs':{'project':{'commit':'a'*40,'tree':'b'*40}}}
        abi=abi if abi is not None else {'wow64':{'abi':1,'runtime_validated':False}}
        tools={'check_private_dispatch_abi':types.SimpleNamespace(check_build=mock.Mock(return_value=abi)),
               'private_dispatch_wow64':types.SimpleNamespace(mapped_pe=mock.Mock())}
        patches=[mock.patch.object(prefix,'host_identity',return_value=({'project':record['inputs']['project']},self.root)),
                 mock.patch.object(prefix,'verify_source_snapshot'),mock.patch.object(prefix,'patched_pe_set'),
                 mock.patch.object(prefix,'cpu_inputs',return_value={}),
                 mock.patch.object(prefix,'verify_cpu',return_value=(record,dll)),
                 mock.patch.object(prefix,'load_tool',side_effect=lambda root,name:tools[name])]
        for item in patches:item.start();self.addCleanup(item.stop)
        args=(self.repo,self.root,wine,cohort,cpu,self.root)
        return args,tools,record

    def test_capability_gate_requires_actual_new_checker_and_cpu(self):
        args,tools,record=self.runtime_fixture()
        result=prefix.check_battlenet_runtime(*args)
        self.assertFalse(result['runtime_validated'])
        self.assertEqual(result['cpu'],record)
        self.assertEqual(result['translator_pe']['sha256'],prefix.sha(self.root/'cpu/wowprospero.dll'))
        self.assertTrue(tools['check_private_dispatch_abi'].check_build.call_args.kwargs['require_wow64'])
        tools['private_dispatch_wow64'].mapped_pe.assert_called_once_with(b'owned CPU PE bytes',0x8664)

    def test_old_abi_or_runtime_success_label_refused(self):
        args,tools,_=self.runtime_fixture(abi={'mode':1})
        with self.assertRaisesRegex(ValueError,'translated-I386'):prefix.check_battlenet_runtime(*args)
        tools['check_private_dispatch_abi'].check_build.return_value={'wow64':{'abi':1,'runtime_validated':True}}
        with self.assertRaisesRegex(ValueError,'translated-I386'):prefix.check_battlenet_runtime(*args)

    def test_service_selector_and_mixed_cpu_project_refused(self):
        args,tools,record=self.runtime_fixture(selector={'enabled':False})
        with self.assertRaisesRegex(ValueError,'service build selector'):prefix.check_battlenet_runtime(*args)
        (self.root/'wine/report.json').write_text(json.dumps({'service_fixture':{'enabled':True,'unix_define':'PW_WINE_SERVICE_FIXTURE=1','abi':1,'runtime_validated':False}}))
        accepted={'enabled':True,'unix_define':'PW_WINE_SERVICE_FIXTURE=1','abi':1,'runtime_validated':False}
        for change in ({'abi':0},{'runtime_validated':True},{'unix_define':'wrong'}):
            (self.root/'wine/report.json').write_text(json.dumps({'service_fixture':{**accepted,**change}}))
            with self.assertRaisesRegex(ValueError,'service build selector'):prefix.check_battlenet_runtime(*args)
        (self.root/'wine/report.json').write_text(json.dumps({'service_fixture':accepted}))
        record['inputs']['project']={'commit':'c'*40,'tree':'d'*40}
        with self.assertRaisesRegex(ValueError,'CPU and runtime'):prefix.check_battlenet_runtime(*args)

if __name__=='__main__':unittest.main(verbosity=2)
