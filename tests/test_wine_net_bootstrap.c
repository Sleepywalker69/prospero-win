/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define main legacy_bootstrap_main
#include "test_pw_wine_child_bootstrap.c"
#undef main
static unsigned net_checks,desktop_seen,view_seen,directories;
static int path_error,late_env;
#define T(x) do{++net_checks;assert(x);}while(0)
static const char uprefix[]="/data/prospero-win/prefixes/windows-child-net-v1";
static const char ucwd[]="/data/prospero-win/prefixes/windows-child-net-v1/drive_c/windows-child-net";
static const char uimage[]="C:\\windows-child-net\\net-child.exe";
static void net_main(int argc,char **argv){T(argc==2&&!strcmp(argv[1],uimage)&&!argv[2]);}
static int net_directory(void*c,const char*p){T(c==&m&&(!strcmp(p,uprefix)||!strcmp(p,ucwd)));directories++;return path_error;}
static int net_cwd(const char*p){T(!strcmp(p,ucwd));m.cwds++;return m.cwd_fail;}
static int net_env(const char *name,const char *value)
{
 T(!m.loads);m.envs++;
 if(!strcmp(name,"HOME")||!strcmp(name,"WINEPREFIX"))T(!strcmp(value,uprefix));
 if(!strcmp(name,"WINESERVERSOCKET"))T(!strcmp(value,"9"));
 if(!strcmp(name,"WINE_PRX_DIR"))T(!strcmp(value,PW_WINE_CHILD_RUNTIME));
 if(!strcmp(name,"WINE_PS5_DESKTOP")){desktop_seen++;T(0);}
 if(!strcmp(name,"WINE_PS5_VIEW")){view_seen++;T(0);}
 if(!strcmp(name,"WINE_PS5_SERVER_DIRECT")||!strcmp(name,"WINE_PS5_SCHED")||!strcmp(name,"WINE_PS5_MUTEX_SHARED")||!strcmp(name,"WINE_PS5_SYNC_SHARED"))T(!strcmp(value,"0"));
 if(late_env&&m.envs==16)m.now=500;
 return m.env_fail==m.envs?-3:0;
}
static int32_t net_load(const char*p,size_t n,const void*a,uint32_t flags,const void*o,int*r)
{T(m.envs==16&&desktop_seen==0&&view_seen==0&&!strcmp(p,PW_WINE_CHILD_RUNTIME "/ntdll.prx")&&!n&&!a&&!flags&&!o);*r=0;m.loads++;return m.load_fail?-9:7;}
static void net_reset(void)
{reset();m.profile=4;m.machine=0x8664;desktop_seen=view_seen=directories=0;path_error=late_env=0;ops.directory=net_directory;ops.wine.set_env=net_env;ops.wine.load_start=net_load;module.d.exports[0].address=(void*)net_main;module.d.exports[4].address=(void*)net_cwd;}
int main(int argc,char **argv)
{
 net_reset();if(argc==2&&!strcmp(argv[1],"baseline")){T(prepare()&&!m.loads&&!m.envs);puts("mode4 bootstrap: expected prefeature refusal");return 0;}
 T(!prepare()&&b.prepared&&!b.started&&m.loads==1&&m.starts==1&&m.adopts==1&&directories==2);
 T(!strcmp(b.config.prefix,uprefix)&&!strcmp(b.argv[1],uimage)&&b.config.extra_env_count==13);T(m.bindings==1&&m.cwds==1&&m.sinks==1);
 T(!pw_wine_child_bootstrap_start(&b,&io,&ops)&&b.started&&m.threads==1);m.entry(m.arg);T(pw_wine_child_bootstrap_start(&b,&io,&ops));
 for(int n=1;n<=16;n++){net_reset();m.env_fail=n;T(prepare()&&!m.loads&&!m.threads);}
 net_reset();m.machine=0x14c;T(prepare()&&!m.envs&&!m.loads);net_reset();m.profile=5;T(prepare()&&!m.envs&&!m.loads);
 net_reset();path_error=1;T(prepare()&&!m.envs&&!m.loads);net_reset();m.wrong_path=1;T(prepare()&&!m.envs&&!m.loads);
 net_reset();m.cancel=1;T(prepare()&&!m.envs&&!m.loads);net_reset();late_env=1;T(prepare()&&!m.loads&&!m.threads&&io.stage_end==500);
 net_reset();strcpy(module.names[9],"translated-capability-not-required");T(!prepare());
 for(unsigned i=0;i<EXPORTS;i++){if(i==9)continue;net_reset();strcpy(module.names[i],"missing");T(prepare()&&!m.threads);}
 net_reset();m.abi=0;T(prepare()&&!m.bindings);net_reset();m.cwd_fail=-1;T(prepare()&&!m.bindings);net_reset();m.register_fail=-1;T(prepare()&&!m.threads);
 net_reset();T(!prepare());m.thread_fail=-7;T(pw_wine_child_bootstrap_start(&b,&io,&ops)&&!b.started);
 T(!legacy_bootstrap_main());printf("mode4 bootstrap: %u additive assertions; legacy modes retained with unknown5 sentinel\n",net_checks);return 0;
}
