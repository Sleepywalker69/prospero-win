#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Actual title routing and environment ordering, using inert host boundaries."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def function(source, signature):
    begin = source.index(signature)
    brace = source.index('{', begin)
    depth = 1
    for end in range(brace + 1, len(source)):
        depth += (source[end] == '{') - (source[end] == '}')
        if not depth:
            return source[begin:end + 1]
    raise AssertionError(signature)


def preprocess(mode, include):
    return subprocess.check_output([os.environ.get('CC', 'cc'), '-E', '-P',
        '-DPW_WINE_CHILD_FIXTURE_MODE=' + str(mode), '-I' + str(include),
        '-Iinclude', '-Isrc', '-Inative', 'native/wine64_main.c'], cwd=ROOT, text=True)


class WineChildIntegration(unittest.TestCase):
    def test_preprocessed_profile_and_every_exit_route(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'wine-child-title-config.h').write_text('#define PW_WINE_FIXTURE_CHILD_SHA256 "' + 'a'*64 + '"\n')
            ordinary = preprocess(0, path)
            source = preprocess(1, path)
            self.assertNotIn('pw_wine_child_title_prepare', ordinary)
            self.assertNotIn('child_hold_for_release', ordinary)
            restart = function(source, 'static void restart_title(')
            self.assertLess(restart.index('pw_wine_child_title_restart_ready'), restart.index('sceSystemServiceLoadExec'))
            catalog = function(source, 'static int open_library(')
            self.assertLess(catalog.index('pw_wine_child_title_profile'), catalog.index('catalog[catalog_count] ='))
            main = function(source, 'int main(')
            self.assertLess(main.index('selection_refused'), main.index('pw_wine_start_load'))
            self.assertLess(main.index('child_environment('), main.index('pw_wine_start_load'))
            self.assertLess(main.index('pw_wine_child_title_prepare('), main.index('pw_wine_child_title_install('))
            self.assertLess(main.index('pw_wine_child_title_install('), main.index('pw_wine_start_run('))
            self.assertIn('child_profile == 1 ? "' + 'a'*64 + '" :', main)
            timeout = main[main.index('if (close_requested &&'):]
            self.assertLess(timeout.index('pw_wine_child_title_restart_ready'), timeout.index('"close-timeout"'))
            self.assertLess(main.index('child_hold_for_release('), main.rindex('_exit(1)'))
            on_exit = function(source, 'static void on_exit_report(')
            self.assertLess(on_exit.index('child_hold_for_release'), on_exit.index('restart_title'))
            self.assertIn('pw_wine_child_title_cancel();', main)

    def test_actual_environment_failures_prevent_load(self):
        source = (ROOT / 'native/wine64_main.c').read_text()
        helper = function(source, 'static int child_environment(')
        begin = source.index('    status = child_environment(&start, &config, &ops);')
        end = source.index('    PS5LOG_LOG("PW_WINE64 load status=', begin)
        sequence = source[begin:end].replace('#endif', '')
        program = r'''
#include <assert.h>
#include <stddef.h>
#include <string.h>
#include "pw_wine_start.h"
#define PW_OK 0
#define PW_ERR_STATE -7
static int calls, fail_at, loads;
static const char *names[]={"base","WINE_PRX_DIR","WINE_PS5_SERVER_DIRECT","WINE_PS5_MUTEX_FAST","WINE_PS5_MUTEX_SHARED","WINE_PS5_SYNC_SHARED","WINE_PS5_SCHED"};
static int set_env(const char *name,const char *value) {
 assert(!strcmp(name,names[calls]));
 assert(!strcmp(value,calls==1?"/fixed/runtime":calls?"0":"base"));
 return ++calls==fail_at?-9:0;
}
int pw_wine_start_environment(PwWineStart *a,const PwWineStartConfig *b,const PwWineStartOps *c)
{(void)a;(void)b;return c->set_env("base","base");}
int pw_wine_start_load(PwWineStart *a,const PwWineStartConfig *b,const PwWineStartOps *c)
{(void)a;(void)b;(void)c;assert(calls==7);++loads;return 0;}
#define pw_diagnostics_log_local(...) ((void)0)
''' + helper + '\nint main(void){for(fail_at=0;fail_at<=7;fail_at++){\n' + r'''
 PwWineStart start={0};PwWineStartConfig config={0};PwWineStartOps ops={0};int status;
 config.ntdll_dir="/fixed/runtime";ops.set_env=set_env;calls=loads=0;
''' + sequence + r'''
 assert(loads==(fail_at==0));assert((status==0)==(fail_at==0));
 }return 0;}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'test.c').write_text(program)
            subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-I' + str(ROOT / 'src'), str(path/'test.c'), '-o', str(path/'test')], check=True)
            subprocess.run([str(path/'test')], check=True)


    def test_profile_override_and_malformed_fields(self):
        repo = ROOT
        s=(repo/'native/wine64_main.c').read_text(); t=(repo/'native/pw_wine_child_title.c').read_text()
        a=s.index('    child_profile = pw_wine_child_title_profile(game);');b=s.index('\n#endif',a)
        body=s[a:b]
        prefix=r'''
        #include <assert.h>
        #include <stdint.h>
        #include <stdio.h>
        #include <string.h>
        #include "pw_game_profile.h"
        #include "pw_wine_launch.h"
        static unsigned checks,restarts;
        #define CHECK(x) do { ++checks; assert(x); } while(0)
        static PwWineLaunch launch;
        static const char pw_wine_child_title_marker[]="fixture";
        static void log_mock(const char *s,...) {(void)s;}
        #define pw_diagnostics_log_local log_mock
        static void restart_title(const PwWineApp *app,uint32_t cycle,const char *why) {(void)app;(void)cycle;(void)why;restarts++;}
        '''
        code=prefix+function(t,'static int equal_field(')+'\n#define EQUAL(o, field, value) equal_field((o)->field,sizeof((o)->field),(value))\n'+function(t,'unsigned pw_wine_child_title_profile(')+'\nstatic int selection(const PwGameProfile *game) { unsigned child_profile;\n'+body+'\nreturn 0; }\n'
        code+=r'''
        static PwGameProfile profile(unsigned mode) {
         PwGameProfile p={0};strcpy(p.app.runtime,"wine-wow64");
         if(mode==1){strcpy(p.app.id,"windows-child-fixture-v1");strcpy(p.app.prefix,p.app.id);strcpy(p.app.executable,"C:\\windows-child-fixture\\parent.exe");strcpy(p.app.working_directory,"C:\\windows-child-fixture");p.app.architecture=PW_APP_ARCH_PE64;p.runtime.cpu=PW_GAME_CPU_DEFAULT;}
         else {strcpy(p.app.id,"battlenet-experimental-v1");strcpy(p.app.prefix,p.app.id);strcpy(p.app.executable,"C:\\installer\\Battle.net-Setup.exe");strcpy(p.app.working_directory,"C:\\installer");p.app.architecture=PW_APP_ARCH_PE32;p.runtime.cpu=PW_GAME_CPU_TRANSLATOR;}
         return p;
        }
        int main(int argc,char **argv) {
         int override_only=argc==2&&!strcmp(argv[1],"override");
         for(unsigned mode=1;mode<=2;mode++) {
          PwGameProfile good=profile(mode),p;PwWineApp app={good.app.id,"name","detail",good.app.executable};
          char argument[256];snprintf(argument,sizeof argument,"profile=%s",app.id);
          char *args[]={argument};CHECK(!pw_wine_launch_parse(1,args,&app,1,&launch));CHECK(!selection(&good));
          if(!override_only){
        #define BAD(change) do { p=good; change; restarts=0; CHECK(selection(&p)==1);CHECK(restarts==1); } while(0)
           BAD(p.app.prefix[0]='X');BAD(p.app.executable[3]='X');BAD(p.app.working_directory[3]='X');
           BAD(p.app.runtime[0]='X');BAD(p.app.arguments[0]='X');BAD(p.app.dll_overrides[0]='X');
           BAD(p.app.startup_command_id=1);BAD(p.app.graphics=PW_APP_GRAPHICS_DXVK);
           BAD(p.app.architecture=0);BAD(p.runtime.cpu=PW_GAME_CPU_NATIVE);BAD(p.runtime.shared_input=1);
           BAD(p.runtime.thread_scheduling=1);BAD(p.runtime.fast_clock=1);BAD(p.debug_env_count=1);
           BAD(memset(p.app.executable,'X',sizeof p.app.executable));BAD(memset(p.app.prefix,'X',sizeof p.app.prefix));
        #undef BAD
          }
          char *other[]={argument,"path=C:\\other.exe"};CHECK(!pw_wine_launch_parse(2,other,&app,1,&launch));
          CHECK(launch.app==&app&&!strcmp(launch.executable,"C:\\other.exe"));
          restarts=0;int rc=selection(&good);fprintf(stderr,"profile=%u overridden_root=%s selection_result=%d restarts=%u\n",mode,launch.executable,rc,restarts);CHECK(rc==1&&restarts==1);
         }
         printf("Actual profile/parser/caller selection: %u checks passed\n",checks);return 0;
        }
        '''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'test.c').write_text(code)
            subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-I' + str(ROOT / 'src'), '-I' + str(ROOT / 'include'), str(path / 'test.c'),
                            str(ROOT / 'src' / 'pw_wine_launch.c'), '-o', str(path / 'test')], check=True)
            subprocess.run([str(path / 'test')], check=True)


    def test_real_environment_before_constructor(self):
        repo = ROOT
        s=(repo/'native/wine64_main.c').read_text()
        a=s.index('    status = child_environment(&start, &config, &ops);');b=s.index('    PS5LOG_LOG("PW_WINE64 load status=',a)
        sequence=s[a:b].replace('#endif','')
        code=r'''
        #include <assert.h>
        #include <stdint.h>
        #include <stdio.h>
        #include <string.h>
        #include "pw_wine_start.h"
        #include "prospero_win.h"
        static unsigned checks,calls,loads,constructors,adopts,fail_at;
        static int fail_result;
        #define CHECK(x) do { ++checks; assert(x); } while(0)
        static struct { char name[64],value[128]; } env[32];
        static unsigned env_count;
        static const char *get(const char *name) { for(unsigned i=0;i<env_count;i++)if(!strcmp(name,env[i].name))return env[i].value;return "UNSET"; }
        static int set(const char *name,const char *value) {
         calls++;if(calls==fail_at)return fail_result;
         unsigned i;for(i=0;i<env_count;i++)if(!strcmp(name,env[i].name))break;
         CHECK(i<32&&strlen(name)<64&&strlen(value)<128);strcpy(env[i].name,name);strcpy(env[i].value,value);if(i==env_count)env_count++;return 0;
        }
        static void check_env(void) {
         CHECK(!strcmp(get("WINEPREFIX"),"/fixed/prefix"));CHECK(!strcmp(get("WINELOADERNOEXEC"),"1"));
         CHECK(!strcmp(get("WINE_PS5_NTDLL_DIR"),"/fixed/runtime"));CHECK(!strcmp(get("WINE_PRX_DIR"),"/fixed/runtime"));
         const char *names[]={"WINE_PS5_SERVER_DIRECT","WINE_PS5_MUTEX_FAST","WINE_PS5_MUTEX_SHARED","WINE_PS5_SYNC_SHARED","WINE_PS5_SCHED"};
         for(unsigned i=0;i<5;i++)CHECK(!strcmp(get(names[i]),"0"));
        }
        static void wine_main(int argc,char **argv) {(void)argc;(void)argv;CHECK(0);}
        static int constructor(size_t argc,const void *args) {CHECK(!argc&&!args);check_env();constructors++;return 0;}
        static void *adopt(const char *path,int32_t module) {CHECK(!strcmp(path,"/fixed/runtime/ntdll.prx")&&module==42);adopts++;return env;}
        static int32_t load(const char *path,size_t argc,const void *args,uint32_t flags,const void *option,int *result) {
         CHECK(!strcmp(path,"/fixed/runtime/ntdll.prx")&&!argc&&!args&&!flags&&!option&&result);check_env();loads++;return 42;
        }
        static int info(int32_t module,void *p) {CHECK(module==42&&p);return 0;}
        int pw_prx_parse_module_info(const void *p,char name[PW_PRX_MAX_NAME],PwPrxSegment segments[PW_PRX_MAX_SEGMENTS],uint32_t *count) {(void)name;CHECK(p&&segments&&count);*count=0;return 0;}
        int pw_prx_find_descriptor(const PwPrxSegment *s,uint32_t count,const PwPrxDescriptor **d) {static PwPrxDescriptor descriptor;CHECK(s&&!count&&d);*d=&descriptor;return 0;}
        const void *pw_prx_lookup(const PwPrxDescriptor *d,const char *name) {CHECK(d&&name);if(!strcmp(name,"__wine_main"))return (void*)wine_main;if(!strcmp(name,"module_start"))return (void*)constructor;if(!strcmp(name,"pw_wine_dl_adopt"))return (void*)adopt;return NULL;}
        #define pw_diagnostics_log_local(...) ((void)0)
        '''+function(s,'static int child_environment(')+r'''
        int main(void) {
         const PwWineStartEnv extra[]={ {"WINE_PRX_DIR","/wrong"},{"WINE_PS5_SERVER_DIRECT","1"},{"WINE_PS5_MUTEX_SHARED","1"} };
         for(unsigned sign=0;sign<2;sign++)for(fail_at=0;fail_at<=12;fail_at++) {
          PwWineStart start={0};PwWineStartConfig config={.ntdll_path="/fixed/runtime/ntdll.prx",.ntdll_dir="/fixed/runtime",.prefix="/fixed/prefix",.extra_env=extra,.extra_env_count=3};
          PwWineStartOps ops={.load_start=load,.module_info=info,.set_env=set};int status;
          calls=loads=constructors=adopts=env_count=0;fail_result=sign?19:-19;
        '''+sequence+r'''
          CHECK((status==0)==!fail_at);CHECK(loads==!fail_at&&constructors==!fail_at&&adopts==!fail_at);
          CHECK(calls==(fail_at?fail_at:12));
         }
         printf("Actual caller + start environment/load + mock constructor: %u checks passed\n",checks);return 0;
        }
        '''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'test.c').write_text(code)
            subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-I' + str(ROOT / 'src'), '-I' + str(ROOT / 'include'), str(path / 'test.c'),
                            str(ROOT / 'src' / 'pw_wine_start.c'), '-o', str(path / 'test')], check=True)
            subprocess.run([str(path / 'test')], check=True)


    def test_actual_restart_and_completion_holds(self):
        repo = ROOT
        s=(repo/'native/wine64_main.c').read_text()
        timeout=function(s,'        if (close_requested && now - close_requested >=')
        a=s.index('    PS5LOG_LOG("PW_WINE64 done status=');tail=s[a:s.rindex('\n}')]
        code=r'''
        #include <assert.h>
        #include <stdint.h>
        #include <stddef.h>
        #include <stdio.h>
        #include <string.h>
        #include <setjmp.h>
        #include "pw_wine_start.h"
        #include "prospero_win.h"
        #define PW_WINE_CHILD_FIXTURE_MODE 1
        #define PW_SANDBOX_APP0 "/sandbox"
        #define PW_WINE64_TICK_US 10000
        #define PW_WINE64_CLOSE_WAIT_S 5
        #define PW_PRESENT_SCALE_FIT 1
        static unsigned checks,execs,closes,resumes,cancels,ticks,sleeps,presents,exits,ready,ready_after,stop_after,alive;
        static unsigned display_closed,sink_calls;static uint64_t clock_value;
        static PwWineLaunch launch;
        static jmp_buf limit;
        #define CHECK(x) do{checks++;assert(x);}while(0)
        typedef struct { int unused; } PwVideoOutPs5;
        typedef struct { int unused; } PwPresentFrame;
        typedef struct { int unused; } Loading;
        static void log_mock(const char *s,...) {(void)s;}
        #define PS5LOG_LOG log_mock
        #define pw_diagnostics_log_local log_mock
        static int pw_wine_child_title_restart_ready(void) {return ready;}
        static void pw_wine_child_title_cancel(void) {cancels++;}
        static void pw_diagnostics_close(const char *s) {CHECK(s);closes++;}
        static void pw_diagnostics_resume(void) {resumes++;}
        static int sceSystemServiceLoadExec(const char *s,char **args) {CHECK(ready&&s&&args);execs++;return -1;}
        static uint64_t now_ns(void) {return clock_value++;}
        static void pw_diagnostics_tick(uint64_t now) {(void)now;ticks++;}
        static const PwPresentFrame *loading_frame(Loading *l,uint64_t now,uint64_t start,PwPresentFrame *f) {(void)now;(void)start;CHECK(l&&f);return f;}
        static int pw_videoout_ps5_present_scaled(PwVideoOutPs5 *v,const PwPresentFrame *f,int scale,int zero) {CHECK(v&&f&&scale==PW_PRESENT_SCALE_FIT&&!zero&&!display_closed);presents++;return 0;}
        static int usleep(unsigned delay) {CHECK(delay==PW_WINE64_TICK_US);sleeps++;if(ready_after&&sleeps==ready_after)ready=1;if(stop_after&&sleeps==stop_after)longjmp(limit,1);return 0;}
        static void fake_exit(int code) {CHECK(code==1&&ready);exits++;longjmp(limit,2);}
        #define _exit fake_exit
        '''+function(s,'static void restart_title(')+'\n'+function(s,'static void child_hold_for_release(')+'\n'+function(s,'static void on_exit_report(')+r'''
        static void completion(int status,int video_status) {PwWineStart start={0};PwVideoOutPs5 video={0};const char *child_hold_reason="pre-guest-provider-install-failed";(void)child_hold_reason;
        '''+tail+r'''
        }
        static void timeout_loop(void) {
         uint64_t close_requested=1,now=6000000001ULL;
         for(unsigned i=0;i<4;i++) {
        '''+timeout+r'''
          alive++;
         }
        }
        static void reset(void) {execs=closes=resumes=cancels=ticks=sleeps=presents=exits=ready=ready_after=stop_after=alive=display_closed=0;}
        int main(int argc,char **argv) {
         if(argc==2&&!strcmp(argv[1],"timeout")){reset();timeout_loop();fprintf(stderr,"held timeout alive=%u execs=%u\n",alive,execs);CHECK(alive==4&&!execs);return 0;}
         PwVideoOutPs5 video={0};
         reset();restart_title(NULL,0,"held");CHECK(!execs&&!closes&&!resumes);
         reset();ready=1;restart_title(NULL,0,"released");CHECK(execs==2&&closes==2&&resumes==2);
         reset();ready=1;child_hold_for_release(&video,"unused");CHECK(!cancels&&!ticks&&!sleeps);
         reset();ready_after=3;child_hold_for_release(&video,"held");CHECK(cancels==1&&ticks==3&&sleeps==3&&presents==3&&!execs);
         reset();ready_after=2;display_closed=1;child_hold_for_release(&video,"closed");CHECK(cancels==1&&ticks==2&&!presents);
         reset();ready_after=2;child_hold_for_release(NULL,"no-video");CHECK(cancels==1&&ticks==2&&!presents);
         reset();stop_after=4;if(!setjmp(limit))on_exit_report();CHECK(cancels==1&&ticks==4&&!execs&&!closes&&!exits);
         reset();ready_after=3;on_exit_report();CHECK(cancels==1&&ticks==3&&execs==2&&closes==3&&resumes==2);
         for(int status=-1;status<=0;status++) {
          reset();stop_after=4;if(!setjmp(limit))completion(status,PW_OK);CHECK(cancels==1&&ticks==4&&!execs&&!closes&&!exits);
          reset();ready_after=2;if(!setjmp(limit))completion(status,PW_OK);CHECK(cancels==1&&ticks==2&&exits==1&&execs==(status?2u:0u));
         }
         reset();timeout_loop();CHECK(alive==4&&!execs&&!closes);
         reset();ready=1;timeout_loop();CHECK(!alive&&execs==2&&closes==2);
         printf("Actual extracted caller lifetime functions/regions: %u checks passed\n",checks);return 0;
        }
        '''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'test.c').write_text(code)
            subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-I' + str(ROOT / 'src'), '-I' + str(ROOT / 'include'), str(path / 'test.c'),
                            str(ROOT / 'src' / 'pw_wine_launch.c'), '-o', str(path / 'test')], check=True)
            subprocess.run([str(path / 'test')], check=True)


if __name__ == '__main__':
    unittest.main()
