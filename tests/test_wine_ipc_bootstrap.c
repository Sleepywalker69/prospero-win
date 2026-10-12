/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define main legacy_bootstrap_main
#include "test_pw_wine_child_bootstrap.c"
#undef main
#include "../wine/ps5/pw_wine_fixture_provider.c"
static unsigned ipc_checks,desktop_seen,view_seen,directories;
static int path_error,late_env;
#define T(x) do{++ipc_checks;assert(x);}while(0)
static unsigned ipc_mode=16;
#define uprefix PW_WINE_IPC_PREFIX
#define ucwd (pw_wine_ipc_profile(ipc_mode)->native_cwd)
#define uimage (pw_wine_ipc_profile(ipc_mode)->image)
static void ipc_main(int argc,char **argv){T(argc==2&&!strcmp(argv[1],uimage)&&!argv[2]);}
static int ipc_directory(void*c,const char*p){T(c==&m&&(!strcmp(p,uprefix)||!strcmp(p,ucwd)));directories++;return path_error;}
static int ipc_cwd(const char*p){T(!strcmp(p,ucwd));m.cwds++;return m.cwd_fail;}
static int ipc_env(const char *name,const char *value)
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
static int32_t ipc_load(const char*p,size_t n,const void*a,uint32_t flags,const void*o,int*r)
{T(m.envs==16&&desktop_seen==0&&view_seen==0&&!strcmp(p,PW_WINE_CHILD_RUNTIME "/ntdll.prx")&&!n&&!a&&!flags&&!o);*r=0;m.loads++;return m.load_fail?-9:7;}
static void ipc_reset(void)
{reset();atomic_store(&ready,0);atomic_store(&process_role,0);atomic_store(&creation_ready,0);atomic_store(&child_ready,0);m.profile=ipc_mode;m.machine=0x8664;desktop_seen=view_seen=directories=0;path_error=late_env=0;ops.directory=ipc_directory;ops.wine.set_env=ipc_env;ops.wine.load_start=ipc_load;module.d.exports[0].address=(void*)ipc_main;module.d.exports[4].address=(void*)ipc_cwd;module.d.exports[12].address=(void*)pw_wine_creation_child_install;}
#ifdef PW_IPC_BOOTSTRAP_BRIDGE
int ipc_bootstrap_suite_main(void)
#else
int main(void)
#endif
{
 for(ipc_mode=16;ipc_mode<=23;++ipc_mode){ipc_reset();T(!prepare());T(directories==2&&!desktop_seen&&!view_seen);T(pw_wine_creation_child_get()&&pw_wine_creation_child_get()->profile==ipc_mode&&!pw_wine_fixture_get()&&!pw_wine_creation_get());T(!pw_wine_child_bootstrap_start(&b,&io,&ops));
  ipc_reset();m.machine=0x14c;T(prepare()&&!m.loads);ipc_reset();path_error=-1;T(prepare()&&!m.loads);
 }
 T(!legacy_bootstrap_main());printf("IPC bootstrap: %u mocked assertions; exact selected paths and old profiles\n",ipc_checks);return 0;
}
