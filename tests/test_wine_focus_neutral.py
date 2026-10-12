#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Compile-only focus selection, exact source/mode mismatch and native entry proof."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import wine_focus_neutral as focus
import build_wine_service_child as child
import wine_creation_abi as creation
import package_windows_child_fixture as package


def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--sanitize',default='');p.add_argument('--preview',action='store_true');a=p.parse_args()
    a.out.mkdir(parents=True,exist_ok=False);rows=[]
    env=dict(os.environ,ASAN_OPTIONS='detect_leaks=0:abort_on_error=1')
    def run(label,args,expected=0):
        x=subprocess.run(list(map(str,args)),capture_output=True,text=True,env=env,timeout=120)
        (a.out/(label+'.log')).write_text(x.stdout+x.stderr);rows.append(dict(label=label,argv=list(map(str,args)),exit=x.returncode,expected=expected))
        (a.out/'RESULT.json').write_text(json.dumps(rows,indent=2)+'\n')
        if (x.returncode==0)!=(expected==0):raise AssertionError((label,x.returncode,x.stdout,x.stderr))
        if expected>0:assert x.returncode==expected,(label,x.returncode)
    def bad(fn):
        try:fn()
        except ValueError:return
        raise AssertionError('malformed cohort accepted')
    # Selector rejection occurs before source/dependency/output mutation.
    for label,script,overrides,expected in [
        ('native-bad-mode','build_native.sh',{'PW_WINE_FOCUS_NEUTRAL':'2'},2),
        ('native-no-child','build_native.sh',{'PW_WINE_FOCUS_NEUTRAL':'1','PW_WINE_CHILD_FIXTURE_MODE':'0'},2),
        ('native-bad-output','build_native.sh',{'PW_WINE_FOCUS_NEUTRAL':'1','PW_WINE_CHILD_FIXTURE_MODE':'1','PW_OUTPUT_SUFFIX':'-wrong'},2),
        ('wine-bad-mode','build_wine_ps5.sh',{'PW_WINE_FOCUS_NEUTRAL':'2'},1),
        ('wine-no-fixture','build_wine_ps5.sh',{'PW_WINE_FOCUS_NEUTRAL':'1','PW_WINE_SERVICE_FIXTURE':'0'},1),
        ('wine-manual-mode','build_wine_ps5.sh',{'PW_WINE_FOCUS_NEUTRAL':'0','CFLAGS':'-DPW_FOCUS_BUILD_MODE=2'},1)]:
        command=['env',*[(key+'='+value) for key,value in overrides.items()], 'bash' if script=='build_native.sh' else 'sh',ROOT/'tools'/script]
        run(label,command,expected)
    c=focus.contract(ROOT);assert focus.checked(c)==c and c==focus.contract(ROOT)
    for k,v in [('mode',2),('protocol',962),('input_enabled',True),('native_entry_enabled',True),('provider_enabled',True),('package_enabled',True),('source_sha256','0'*64),('mode',True)]:
        t=copy.deepcopy(c);t[k]=v;bad(lambda:focus.checked(t))
    (a.out/'wine').mkdir();(a.out/'wine/pw_focus_build.h').write_text(focus.header(c))
    header=(ROOT/'tests/wine_child_fixture/wine-child-build.h').read_text().replace('PROTOCOL 962','PROTOCOL 963')
    (a.out/'wine-child-build.h').write_text('#define PW_WINE_CHILD_UI_COHORT '+str(int(a.preview))+'\n#define PW_WINE_CHILD_FOCUS_NEUTRAL 1\n'+header)
    (a.out/'wine-child-title-config.h').write_text('#define PW_WINE_FIXTURE_CHILD_SHA256 "'+'a'*64+'"\n')
    for runtime,worker in [({'focus_neutral':c},{}),({}, {'focus_neutral':c}),({'creation':{'protocol':963}},{}),({}, {'runtime':{'creation_protocol':963}})]:
        bad(lambda:package.refuse_focus_package(runtime,worker))
    package.refuse_focus_package({'creation':{'protocol':962}},{'runtime':{'creation_protocol':962}})
    base=['cc','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-D_DEFAULT_SOURCE','-I'+str(a.out),'-I'+str(ROOT/'include'),'-I'+str(ROOT/'src'),'-I'+str(ROOT/'native')]
    if a.sanitize:base+=['-fsanitize='+a.sanitize,'-fno-sanitize-recover=all','-fno-omit-frame-pointer']
    neutral=base+['-DPW_WINE_FOCUS_NEUTRAL=1']
    exe=a.out/'sink';run('compile-sink',neutral+['-pthread',ROOT/'tests/test_pw_wine_focus_neutral_sink.c','-o',exe]);run('sink',[exe])
    exe=a.out/'sink-default';run('compile-sink-default',[v for v in base if v!='-D_DEFAULT_SOURCE']+['-pthread',ROOT/'tests/test_pw_wine_sink.c',ROOT/'wine/ps5/pw_wine_sink.c','-o',exe]);run('sink-default',[exe])
    # Complete real native translation units, not extracted entry branches.
    # Every undefined external is renamed to an inert trap in this object only.
    # Host libc used by this driver is not interposed. The first trapped call
    # would exit99. Both entries must return78 without calling any boundary.
    for original_role,source,selected in [(role,path,mode) for role,path in [('root','native/wine64_main.c'),('child','native/pw_wine_child_main.c')] for mode in (1,0)]:
        role=original_role+('_neutral' if selected else '_default')
        selected_header=('#define PW_WINE_CHILD_FOCUS_NEUTRAL 1\n'+header) if selected else header.replace('PROTOCOL 963','PROTOCOL 962')
        (a.out/'wine-child-build.h').write_text('#define PW_WINE_CHILD_UI_COHORT '+str(int(a.preview))+'\n'+selected_header)
        obj=a.out/(role+'.o'); entry='focus_'+role+'_entry'
        flags=(neutral if selected else base)+['-Wno-enum-compare','-DPW_WINE64_SECONDS=1','-DPW_WINE_CHILD_FIXTURE_MODE=1','-DPW_WINE_CHILD_UI_ENABLED='+str(int(a.preview)),'-Dmain='+entry]+(['-I'+str(ROOT/'tests/wine_child_fixture')] if original_role=='child' else [])
        # Address sanitizer registration constructors need their real runtime;
        # the entry/trap proof uses strict/UBSan objects; sink covers ASan.
        flags=[v for v in flags if not v.startswith('-fsanitize=address')]
        run('compile-'+role,flags+['-c',ROOT/source,'-o',obj])
        undefined=subprocess.check_output(['nm','-u',str(obj)],text=True)
        symbols=sorted(set(line.split()[-1] for line in undefined.splitlines())-{'_GLOBAL_OFFSET_TABLE_'})
        assert 'clock_gettime' in symbols or original_role=='child'
        mapping=a.out/(role+'-rename');mapping.write_text(''.join(s+' focus_trap_'+s+'\n' for s in symbols))
        renamed=a.out/(role+'-renamed.o');run('rename-'+role,['objcopy','--redefine-syms='+str(mapping),obj,renamed])
        asm=a.out/(role+'-traps.S');asm.write_text('.text\n'+''.join('.globl focus_trap_'+s+'\nfocus_trap_'+s+': jmp focus_test_effect\n' for s in symbols)+'.section .note.GNU-stack,"",@progbits\n')
        driver=a.out/(role+'-driver.c');driver.write_text('''#include <stdlib.h>
void focus_test_effect(void){_Exit(99);}
extern int ENTRY(int,char **);
int main(void){char *args[]={"/app0/eboot.bin","path=/data/prospero-win/prefixes/windows-child-fixture-v1/drive_c/child.exe",0};
if(ENTRY(2,args)!=78)return 1;args[1]="profile=battlenet-experimental-v1";if(ENTRY(2,args)!=78)return 2;
args[1]="profile=focus963";if(ENTRY(2,args)!=78)return 3;return ENTRY(0,0)==78?0:4;}
'''.replace('ENTRY',entry))
        exe=a.out/(role+'-entry');run('link-'+role,['cc','-no-pie',renamed,asm,driver,'-o',exe]);run('entry-'+role,[exe],0 if selected else 99)
    # A 962 child header cannot compile in selected963, or vice versa.
    compile_child=neutral+['-DPW_WINE_CHILD_UI_ENABLED='+str(int(a.preview))]+['-I'+str(ROOT/'tests/wine_child_fixture'),'-fsyntax-only',ROOT/'native/pw_wine_child_main.c']
    (a.out/'wine-child-build.h').write_text('#define PW_WINE_CHILD_UI_COHORT '+str(int(a.preview))+'\n'+header) # absent focus marker
    run('reject-missing-child-focus',compile_child,1)
    (a.out/'wine-child-build.h').write_text('#define PW_WINE_CHILD_UI_COHORT '+str(int(a.preview))+'\n#define PW_WINE_CHILD_FOCUS_NEUTRAL 1\n'+header.replace('PROTOCOL 963','PROTOCOL 962'))
    run('reject-child962-neutral963',compile_child,1)
    (a.out/'wine-child-build.h').write_text('#define PW_WINE_CHILD_UI_COHORT '+str(int(a.preview))+'\n#define PW_WINE_CHILD_FOCUS_NEUTRAL 1\n'+header)
    run('reject-child963-default962',base+['-DPW_WINE_CHILD_UI_ENABLED='+str(int(a.preview)),'-I'+str(ROOT/'tests/wine_child_fixture'),'-fsyntax-only',ROOT/'native/pw_wine_child_main.c'],1)
    # Inherited generic parser is not changed by any optional patch.
    for name in focus.OPTIONAL:
        assert 'diff --git a/server/request.c' not in (ROOT/'wine/focus-neutral'/name).read_text()
    print('neutral source, sink and complete native-entry checks passed;',len(rows),'individually checked commands')
if __name__=='__main__':main()
