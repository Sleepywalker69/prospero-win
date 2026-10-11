#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Run isolated actual-native-source mocks; no Wine/PE/console execution."""
import argparse,hashlib,json,pathlib,shutil,subprocess,sys
sys.dont_write_bytecode=True
H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
p=argparse.ArgumentParser();p.add_argument('--project',type=pathlib.Path,required=True);p.add_argument('--out',type=pathlib.Path,required=True);p.add_argument('--cc',default='gcc');p.add_argument('--ubsan',action='store_true');p.add_argument('--baseline',action='store_true');p.add_argument('--only',default='title,disabled,wire,installer,owner,bootstrap,main');a=p.parse_args();a.project=a.project.resolve();a.out.mkdir(parents=True,exist_ok=False);cc=pathlib.Path(shutil.which(a.cc)).resolve()
r={'scope':'Actual native source with inert native/platform/transport boundaries, no target execution','compiler':{'path':str(cc),'sha256':H(cc),'version':subprocess.check_output([str(cc),'--version'],text=True).splitlines()[0]},'runner_sha256':H(pathlib.Path(__file__)),'commands':[]};bad=False
for name in a.only.split(','):
 f=a.project/'tests'/('test_wine_user_'+name+'.c');binary=a.out/name;deps=a.out/(name+'.d');flags=['-std=c11','-D_DEFAULT_SOURCE','-Wall','-Wextra','-Werror','-O1','-ffunction-sections','-fdata-sections','-Wl,--gc-sections','-I'+str(a.project/'native'),'-I'+str(a.project/'wine/ps5'),'-I'+str(a.project/'tests/wine_child_title_fixture')]
 if name in ['wire','bootstrap','main']:flags+=['-I'+str(a.project/'tests/wine_child_fixture')]
 if name=='title':flags+=['-DPW_WINE_USER_PROFILE_ENABLED=1']
 if a.ubsan:flags+=['-fsanitize=undefined','-fno-sanitize-recover=all']
 extra=[]
 if name in ['wire','bootstrap','main']:extra=[a.project/'native/pw_native_child_protocol.c']
 if name in ['bootstrap','main']:extra += [a.project/'native/pw_wine_child_bootstrap.c',a.project/'src/pw_wine_start.c',a.project/'wine/ps5/pw_wine_prx.c']
 for stage,argv in [('dependencies',[str(cc),*flags,'-M',str(f),*map(str,extra)]),('compile',[str(cc),*flags,str(f),*map(str,extra),'-o',str(binary.resolve())]),('run',[str(binary.resolve())]+(['baseline'] if a.baseline else []))]:
  run=subprocess.run(argv,capture_output=True,timeout=40);log=a.out/(name+'-'+stage+'.log');log.write_bytes(run.stdout+run.stderr);r['commands'].append({'name':name,'stage':stage,'argv':argv,'exit':run.returncode,'log_sha256':H(log)});print(name,stage,run.returncode,((run.stdout+run.stderr).decode()[-1700:] if stage!='dependencies' else ''),flush=True)
  if stage=='dependencies' and not run.returncode:
   paths=[]
   for line in run.stdout.decode().replace('\\\n',' ').splitlines():
    if ':' in line:paths.extend(line.split(':',1)[1].split())
   r.setdefault('compile_inputs',{})[name]={str(pathlib.Path(x).resolve()):H(pathlib.Path(x)) for x in paths}
  if run.returncode:bad=True;break
 if binary.exists():r.setdefault('binaries',{})[name]=H(binary)
r['success']=not bad;(a.out/'RESULT.json').write_text(json.dumps(r,indent=2)+'\n');raise SystemExit(int(bad))
