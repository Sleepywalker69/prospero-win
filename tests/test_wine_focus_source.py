#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Source-index verification and actual optional patch/marker attachment proof."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import wine_focus_neutral as focus


def source_inputs(wine_source,host_config):
    """Absent optional inputs skip archive bodies, never the index controls."""
    if wine_source is None and host_config is None:return False
    if wine_source is None or host_config is None:raise ValueError('focus source controls require both --wine-source and --host-config')
    if not host_config.is_file():raise ValueError('configured focus host config is missing or invalid')
    for path in ('server/main.c','include/wine/server_protocol.h','dlls/ntdll/unix/server.c'):
        if not (wine_source/path).is_file():raise ValueError('configured focus Wine source is missing or invalid: '+path)
    return True


def main():
    p=argparse.ArgumentParser();p.add_argument('--wine-source',type=Path);p.add_argument('--host-config',type=Path);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    try:with_source=source_inputs(a.wine_source,a.host_config)
    except ValueError as error:p.error(str(error))
    a.out=a.out.resolve();a.out.mkdir(parents=True,exist_ok=False);rows=[]
    def run(label,args,expected=0,**kw):
        x=subprocess.run(list(map(str,args)),capture_output=True,text=True,timeout=120,**kw)
        (a.out/(label+'.log')).write_text(x.stdout+x.stderr);rows.append(dict(label=label,argv=list(map(str,args)),exit=x.returncode,expected=expected));(a.out/'RESULT.json').write_text(json.dumps(rows,indent=2)+'\n')
        if (x.returncode==0)!=(expected==0):raise AssertionError((label,x.returncode,x.stderr))
        return x.stdout.strip()
    # An inert local Git history proves exact default-index replay independently
    # of the archive subset below. Only this test temporarily substitutes its pin.
    repo=a.out/'index-repo';source=a.out/'index-source';(repo/'wine/patches').mkdir(parents=True);source.mkdir()
    run('index-init',['git','init','-q',source]);(source/'a').write_text('old\n');run('index-add',['git','-C',source,'add','.'])
    run('index-commit',['git','-C',source,'-c','user.name=Proof','-c','user.email=proof@example.invalid','commit','-qm','inert fixture'])
    pin=run('index-head',['git','-C',source,'rev-parse','HEAD']);(source/'a').write_text('new\n');diff=run('index-diff',['git','-C',source,'diff']);(repo/'wine/patches/0001.patch').write_text(diff+'\n');run('index-select',['git','-C',source,'add','.'])
    with patch.object(focus,'WINE_COMMIT',pin):
        focus.verify_default_source(repo,source)
        (source/'a').write_text('dirty\n')
        try:focus.verify_default_source(repo,source)
        except ValueError:pass
        else:raise AssertionError('dirty source accepted')
        (source/'a').write_text('new\n');(source/'untracked').write_text('extra')
        try:focus.verify_default_source(repo,source)
        except ValueError:pass
        else:raise AssertionError('untracked source accepted')
        (source/'untracked').unlink();(source/'a').write_text('different index\n');run('index-change',['git','-C',source,'add','.'])
        try:focus.verify_default_source(repo,source)
        except ValueError:pass
        else:raise AssertionError('wrong default patch index accepted')
    try:focus.verify_default_source(repo,source)
    except ValueError:pass
    else:raise AssertionError('wrong Git pin accepted')
    if not with_source:
        (a.out/'SOURCE-BOUNDARY.json').write_text(json.dumps({'index_controls':'passed','archive_controls':'skipped: optional Wine source and host config not configured','target_compile':False},indent=2)+'\n')
        print(len(rows),'index commands passed; archive full-TU controls skipped: set FOCUS_WINE_SOURCE and FOCUS_HOST_CONFIG')
        return
    # Actual pinned archive bodies are scoped to server/include/ntdll; these
    # hashes disclose that boundary rather than claiming a full upstream clone.
    tree=a.out/'composed';original={}
    for directory in ('server','include','dlls/ntdll/unix'):
        src=a.wine_source/directory;shutil.copytree(src,tree/directory)
        original.update({str(p.relative_to(a.wine_source)):hashlib.sha256(p.read_bytes()).hexdigest() for p in src.rglob('*') if p.is_file()})
    for src in (a.wine_source/'dlls/ntdll').glob('*.h'):shutil.copyfile(src,tree/'dlls/ntdll'/src.name)
    run('source-init',['git','init','-q',tree]);run('source-add',['git','-C',tree,'add','.'])
    for i,pt in enumerate(sorted((ROOT/'wine/patches').glob('*.patch'))):
        run('default-'+str(i),['git','-C',tree,'apply','--index','--include=server/*','--include=include/*','--include=dlls/ntdll/unix/*',pt])
    # No full original Git checkout is available here. The real index verifier
    # was exercised above; bypass it only inside this host fixture to exercise
    # the actual staging function and all actual optional Git applications.
    with patch.object(focus,'verify_default_source',lambda *_:None):c=focus.stage(ROOT,tree,a.out/'focus-neutral.json')
    (a.out/'SOURCE-BOUNDARY.json').write_text(json.dumps({'original':original,'scope':'archive server/include/ntdll subset','staging_git_pin':'mocked only for subset staging; real index verifier tested independently','target_compile':False},indent=2)+'\n')
    shutil.copyfile(a.host_config,tree/'config.h')
    base=['cc','-std=gnu11','-D_GNU_SOURCE','-D__WINESRC__','-fshort-wchar','-fsyntax-only','-Werror','-I'+str(tree),'-I'+str(tree/'include'),'-I'+str(tree/'server'),'-DWINE_INPROCESS_SERVER','-DPW_WINE_SERVICE_FIXTURE','-DPW_FOCUS_SERVER_ADAPTER','-DPW_FOCUS_SERVER_REQUESTS']
    for unit in ('main','thread','process','queue','window','winstation','user','creation','pw_focus_core','pw_focus_requests'):
        run('syntax-server-'+unit,base+[tree/'server'/(unit+'.c')])
    run('syntax-ntdll',base+['-DWINE_UNIX_LIB','-DHAVE_SYS_UIO_H','-DHAVE_SYS_UN_H','-I'+str(tree/'dlls/ntdll'),'-I'+str(tree/'dlls/ntdll/unix'),tree/'dlls/ntdll/unix/server.c'])
    # Compile and execute the exact composed ntdll comparison helper. The
    # eleven marker callback bodies stand in for dynamic module resolution.
    values=list(focus.markers(c).values());names=list(focus.markers(c));test=a.out/'cohort.c'
    test.write_text('''#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "wine/pw_focus_build.h"
#include "wine/pw_focus_cohort.h"
static unsigned values[]={VALUES};static unsigned index_,missing=99,calls;
static const char *const names[]={NAMES};
static unsigned marker(void){return values[index_];}
static void *lookup(void *module,const char *name){assert(module==(void*)1);calls++;
for(index_=0;index_<11;index_++)if(!strcmp(name,names[index_]))return index_==missing?0:(void*)marker;
assert(0);return 0;}
int main(void){assert(pw_focus_cohort_matches((void*)1,lookup)&&calls==11);
for(unsigned i=0;i<11;i++){values[i]^=1;assert(!pw_focus_cohort_matches((void*)1,lookup));values[i]^=1;
missing=i;assert(!pw_focus_cohort_matches((void*)1,lookup));missing=99;}
assert(!pw_focus_cohort_matches(0,lookup)&&!pw_focus_cohort_matches((void*)1,0));puts("cohort: eleven exact markers and all missing/mismatched positions refused");}
'''.replace('VALUES',','.join(str(x)+'u' for x in values)).replace('NAMES',','.join('"'+x+'"' for x in names)))
    exe=a.out/'cohort';run('compile-cohort',['cc','-std=gnu11','-Wall','-Wextra','-Werror','-fsanitize=undefined','-fno-sanitize-recover=all','-I'+str(tree/'include'),test,'-o',exe]);run('cohort',[exe])
    nt=(tree/'dlls/ntdll/unix/server.c').read_text();entry=nt[nt.index('if (!(module = dlopen( module_path'):]
    assert entry.index('pw_focus_cohort_matches')<entry.index('install_server_fatal_sink')<entry.index('connect_server( nls_dir )')
    assert 'pw_wineserver_focus_install' not in nt # no permissive provider forwarding
    # Exact new mismatch branch + inherited caller/fixture-socket/fatal bodies.
    # Only module lookup, logging, allocation frees, OS calls and process exit
    # are fixtures. This proves the native failure callback is NOT omitted.
    block=nt[nt.index('    if (!pw_focus_cohort_matches'):nt.index('    install_server_fatal_sink( module );')]
    caller=nt[nt.index('    s = connect_inprocess_server();'):nt.index('    return s;',nt.index('    s = connect_inprocess_server();'))+len('    return s;')]
    fatal=nt[nt.index('static void fatal_error( const char *err, ... )\n{'):]
    fatal=fatal[:fatal.index('\n}\n')+3]
    unit=a.out/'failure.c'
    unit.write_text('''#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include "wine/pw_focus_build.h"
#include "wine/pw_focus_cohort.h"
#include "pw_wine_fixture_socket.c"
static jmp_buf end;static int frees,sinks,closes,restores,exits,logs;
static void fail_sink(void *context,const PwWineFixtureSocketResult *r){assert(context==(void*)2&&r->api==PW_WF_SOCKET_ARGUMENT&&r->status==-1);sinks++;}
static void *lookup(void *module,const char *name){(void)module;(void)name;return 0;}
static void free_fixture(void *p){assert(p==(void*)3||p==(void*)4||p==(void*)5);frees++;}
static void exit_fixture(int status){assert(status==1);exits++;longjmp(end,1);}
static int fchdir_fixture(int fd){assert(fd==8);restores++;return 0;}
static int close_fixture(int fd){assert(fd==-1);closes++;return -1;}
static void wine_vprint_stderr(const char *prefix,const char *fmt,va_list args){(void)prefix;(void)fmt;(void)args;logs++;}
#define exit exit_fixture
FATAL
#undef exit
static int connect_inprocess_server(void){void *module=(void*)1,*dir=(void*)3,*module_path=(void*)4,*nls_dir=(void*)5;
#define dlsym lookup
#define free free_fixture
#if 1
BLOCK
#undef free
#undef dlsym
assert(0);return -2;}
static int caller(void){int s,initial_cwd=8;
#define PW_WINE_SERVICE_FIXTURE 1
#define fchdir fchdir_fixture
#define close close_fixture
CALLER
#undef close
#undef fchdir
}
int main(void){assert(!pw_wine_fixture_socket_set_sink(fail_sink,(void*)2));if(!setjmp(end)){caller();assert(0);}
assert(frees==3&&sinks==1&&closes==1&&restores==1&&exits==1&&logs==1);puts("mismatch: inherited native socket-failure callback then startup exit1; no settlement");}
'''.replace('FATAL',fatal).replace('BLOCK',block).replace('CALLER',caller))
    exe=a.out/'failure';run('compile-failure',['cc','-std=gnu11','-Wall','-Wextra','-Werror','-fsanitize=undefined','-fno-sanitize-recover=all','-I'+str(tree/'include'),'-I'+str(ROOT/'wine/ps5'),unit,'-o',exe]);run('failure',[exe])
    print(len(rows),'commands passed with individual statuses; source fixture boundaries recorded')
if __name__=='__main__':main()
