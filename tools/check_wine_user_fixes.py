#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Compile exact USER bodies with inert boundaries; never load Wine or a PE."""
import argparse,hashlib,json,os,re,shutil,subprocess,sys
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent

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
    raise ValueError('unterminated function '+signature)
def h(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--cc',default=os.environ.get('CC','cc'));ap.add_argument('--wine-source','--source',dest='source',type=Path,required=True);ap.add_argument('--context',type=Path);ap.add_argument('--wine-headers',type=Path);ap.add_argument('--fixtures',type=Path);ap.add_argument('--out',type=Path,required=True);ap.add_argument('--ubsan',action='store_true');ap.add_argument('--only',choices=['all','wake','desktop'],default='all');ap.add_argument('--case',default='all',choices=['all','wake-empty','wake-guards','wake-normal','desktop-root','desktop-cache','desktop-partial','desktop-switch','desktop-geometry','desktop-other','desktop-nonps5']);a=ap.parse_args()
    if a.only!='all' and a.case!='all' and not a.case.startswith(a.only):ap.error('--only and --case select different suites')
    a.context=a.context or a.source;a.wine_headers=a.wine_headers or a.source/'include';a.fixtures=a.fixtures or HERE.parent/'tests/fixtures/wine_user_fixes'
    compiler=shutil.which(a.cc)
    if not compiler:ap.error('compiler not found: '+a.cc)
    a.out.mkdir(parents=True,exist_ok=False)
    sources={n:a.source/'dlls/win32u'/n for n in ('ps5drv.c','winstation.c','window.c','ntuser_private.h','win32u_private.h')};sources['message.c']=a.context/'dlls/win32u/message.c'
    snap=a.out/'source';snap.mkdir()
    for n,p in sources.items():(snap/n).write_bytes(p.read_bytes())
    receipt={'scope':'Exact extracted function bodies, real Wine type headers where used, mocked USER/server/input/queue boundaries; no Wine/native/PE execution','sources':{str(p.resolve()):h(p) for p in sources.values()},'runner_sha256':h(Path(__file__)),'commands':[]}
    receipt['compiler']={'requested':a.cc,'path':str(Path(compiler).resolve()),'sha256':h(Path(compiler).resolve()),'version':subprocess.check_output([compiler,'--version'],text=True).splitlines()[0]}
    code={k:p.read_text() for k,p in sources.items()};new='void cache_thread_desktop_windows(' in code['winstation.c']
    wake='\n'.join(function(code[f],s) for f,s in [('ps5drv.c','static BOOL ps5_ProcessEvents('),('message.c','static BOOL process_driver_events(')])
    if 'static BOOL is_extended_key(' in code['ps5drv.c']:wake=function(code['ps5drv.c'],'static BOOL is_extended_key(')+wake
    desktop=[]
    if new:desktop.append(function(code['winstation.c'],'void cache_thread_desktop_windows('))
    desktop.append(function(code['winstation.c'],'HWND get_desktop_window(void)'))
    desktop.extend(function(code['window.c'],s) for s in ('BOOL is_desktop_window(', 'WND *get_win_ptr(', 'static HWND *list_window_parents(', 'HWND WINAPI NtUserGetAncestor(', 'static RECT get_client_surface_rects('))
    desktop.append(function(code['winstation.c'],'BOOL WINAPI NtUserSetThreadDesktop('))
    failed=False
    for name,body in [('wake',wake),('desktop','\n'.join(desktop))]:
        if a.only not in ('all',name) or (a.case!='all' and not a.case.startswith(name)):continue
        fixture=a.fixtures/(name+'.c');receipt.setdefault('fixtures',{})[fixture.name]=h(fixture)
        source=a.out/(name+'.c');text=fixture.read_text().replace('/* ACTUAL_FUNCTIONS */',body).replace('/* HAS_CACHE */','#define HAS_CACHE '+str(int(new)))
        if name=='wake':
            declaration=function(code['ps5drv.c'],'struct ps5_input\n')+';\n';batch=re.findall(r'enum \{ PS5_MAX_WINDOWS = [0-9]+, PS5_INPUT_BATCH = [0-9]+ \};',code['ps5drv.c']);assert len(batch)==1
            text=text.replace('/* INPUT_DECLARATIONS */',declaration+batch[0])
            if 'static pthread_mutex_t input_lock' in code['ps5drv.c']:text='#define HAS_WINDOW_SWITCHER 1\n'+text
        source.write_text(text)
        binary=a.out/name;flags=['-std=gnu11','-D_GNU_SOURCE','-D__WINESRC__','-fshort-wchar','-O0','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-unused-function','-Wno-unused-but-set-variable','-Wno-missing-field-initializers','-Wno-format','-I'+str(a.wine_headers.resolve())]
        if a.case=='desktop-nonps5':flags+=['-DOMIT_PS5_DRIVER=1']
        if a.ubsan:flags+=['-fsanitize=undefined','-fno-sanitize-recover=all']
        dependency=a.out/(name+'.d')
        flags+=['-MMD','-MF',str(dependency.resolve())]
        commands=[('compile-'+name,[compiler,*flags,str(source.resolve()),'-o',str(binary.resolve())]),('run-'+name,[str(binary.resolve()),a.case])]
        for label,argv in commands:
            r=subprocess.run(argv,capture_output=True,timeout=30);log=a.out/(label+'.log');log.write_bytes(r.stdout+r.stderr);receipt['commands'].append({'label':label,'argv':argv,'exit':r.returncode,'log':log.name,'log_sha256':h(log)});print(label,r.returncode,(r.stdout+r.stderr).decode()[-1200:]);
            if r.returncode:failed=True;break
        if dependency.exists():
            deptext=dependency.read_text().replace('\\\n',' ');deps=deptext.split(':',1)[1].split();receipt.setdefault('dependencies',{})[name]={str(Path(x).resolve()):h(Path(x)) for x in deps}
        receipt.setdefault('generated',{})[name]={'source_sha256':h(source),'binary_sha256':h(binary) if binary.exists() else None}
    receipt['success']=not failed
    (a.out/'RESULT.json').write_text(json.dumps(receipt,indent=2)+'\n');return int(failed)
if __name__=='__main__':raise SystemExit(main())
