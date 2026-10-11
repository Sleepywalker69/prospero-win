#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Compile exact retained function bodies with inert mocks and real Wine types."""
import argparse,hashlib,json,pathlib,re,shutil,subprocess
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def function(text,signature):
 start=text.index(signature);begin=text.index('{',start);depth=0;mode='code';i=begin
 while i<len(text):
  c=text[i];n=text[i:i+2]
  if mode=='code':
   if n=='/*':mode='comment';i+=2;continue
   if n=='//':mode='line';i+=2;continue
   if c in ('"',"'"):mode=c
   elif c=='{':depth+=1
   elif c=='}':
    depth-=1
    if depth==0:return text[start:i+1]+'\n'
  elif mode=='comment':
   if n=='*/':mode='code';i+=2;continue
  elif mode=='line':
   if c=='\n':mode='code'
  elif c=='\\':i+=2;continue
  elif c==mode:mode='code'
  i+=1
 raise ValueError(signature)
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--wine-source',type=pathlib.Path,required=True);ap.add_argument('--fixtures',type=pathlib.Path,required=True);ap.add_argument('--out',type=pathlib.Path,required=True);ap.add_argument('--case',choices=['all','matrix','guards'],default='all');ap.add_argument('--ubsan',action='store_true');ap.add_argument('--cc',default='cc',help='host C compiler executable (default: cc)');a=ap.parse_args()
 source=a.wine_source/'dlls/win32u/ps5drv.c';headers=a.wine_source/'include';fixture=a.fixtures/'ps5_extended_keys.c'
 if not source.is_file() or not (headers/'winuser.h').is_file() or not fixture.is_file():ap.error('require composed ps5drv.c, real Wine headers and ps5_extended_keys.c fixture')
 compiler=shutil.which(a.cc)
 if not compiler:ap.error('selected C compiler is unavailable: '+a.cc)
 a.out.mkdir(parents=True,exist_ok=False)
 text=source.read_text();body='';
 if 'static BOOL is_extended_key(' in text:body+=function(text,'static BOOL is_extended_key(')
 body+=function(text,'static BOOL ps5_ProcessEvents(')
 declarations=re.search(r'struct ps5_input\n\{.*?\n\};\n\nenum \{ PS5_MAX_WINDOWS = 64, PS5_INPUT_BATCH = 64 \};',text,re.S).group()
 generated=a.out/'control.c';generated.write_text(fixture.read_text().replace('/* ACTUAL_FUNCTIONS */',body).replace('/* ACTUAL_INPUT_DECLARATIONS */',declarations))
 cc=pathlib.Path(compiler).resolve();binary=a.out/'control';receipt={'scope':'Exact extracted source bodies with inert input/USER/pthread/pipe boundaries; no Wine, target or third-party executable execution','source':{'path':str(source.resolve()),'sha256':sha(source)},'fixture_sha256':sha(fixture),'runner_sha256':sha(pathlib.Path(__file__)),'generated_sha256':sha(generated),'extracted_body_sha256':hashlib.sha256(body.encode()).hexdigest(),'compiler':{'path':str(cc),'sha256':sha(cc),'version':subprocess.check_output([str(cc),'--version'],text=True).splitlines()[0]},'commands':[]}
 flags=['-std=gnu11','-D_GNU_SOURCE','-D__WINESRC__','-fshort-wchar','-O1','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-I'+str(headers.resolve())]
 if a.ubsan:flags+=['-fsanitize=undefined','-fno-sanitize-recover=all']
 cmds=[('dependencies',[str(cc),*flags,'-M',str(generated.resolve())]),('compile',[str(cc),*flags,str(generated.resolve()),'-o',str(binary.resolve())]),('run',[str(binary.resolve()),a.case])]
 rc=0
 for name,argv in cmds:
  r=subprocess.run(argv,capture_output=True);log=a.out/(name+'.log');log.write_bytes(r.stdout+r.stderr);receipt['commands'].append({'label':name,'argv':argv,'exit':r.returncode,'log':log.name,'sha256':sha(log)});print(name,r.returncode,(r.stdout+r.stderr).decode()[-1000:]);rc=r.returncode
  if name=='dependencies' and not rc:
   files=r.stdout.decode().replace('\\\n',' ').split(':',1)[1].split();receipt['compile_inputs']={str(pathlib.Path(f).resolve()):sha(pathlib.Path(f)) for f in files}
  if rc:break
 if binary.exists():receipt['control_binary_sha256']=sha(binary)
 receipt['exit']=rc;(a.out/'RESULT.json').write_text(json.dumps(receipt,indent=2)+'\n');return rc
if __name__=='__main__':raise SystemExit(main())
