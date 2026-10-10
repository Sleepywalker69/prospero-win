/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Native main compiled directly with every external boundary mocked. */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "wine_child_data_bridge.h"
static int fake_pause(const struct timespec*,struct timespec*);
static int fake_clock(clockid_t,struct timespec*),fake_open(const char*,int,...),fake_stat(const char*,struct stat*);
static int fake_fstat(int,struct stat*),fake_close(int),fake_setenv(const char*,const char*,int);
static ssize_t fake_read(int,void*,size_t),fake_write(int,const void*,size_t);
static pid_t fake_pid(void),fake_ppid(void);
static void fake_exit(int) __attribute__((noreturn));
static int fake_attr_init(pthread_attr_t*),fake_attr_stack(pthread_attr_t*,size_t),fake_attr_destroy(pthread_attr_t*);
static int fake_thread_create(pthread_t*,const pthread_attr_t*,void*(*)(void*),void*);
static int fake_trylock(pthread_mutex_t*),fake_unlock(pthread_mutex_t*);
static int32_t fake_load(const char*,size_t,const void*,uint32_t,const void*,int*);
static int fake_info(int32_t,void*),fake_register(long,pthread_t),fake_kill(pid_t,long,int);
static void fake_unregister(long);
static int fake_validate(PwNativeChildIo*,int,PwWineChildWireResult*);
static int fake_send(int,const PwWineChildFrame*,int,PwWineChildWireResult*);
static int fake_same(const PwWineChildFrame*,const PwWineChildFrame*);
static int fake_receive(PwNativeChildIo*,int,uint32_t,PwWineChildFrame*,int*,PwWineChildWireResult*);
static int fake_step(PwNativeChildIo*,int,uint32_t,PwWineChildFrame*,int*,PwWineChildWireResult*);
static void fake_wire_close(int*,PwWineChildWireResult*);
#define nanosleep fake_pause
#define clock_gettime fake_clock
#define open fake_open
#define stat(...) fake_stat(__VA_ARGS__)
#define fstat fake_fstat
#define close fake_close
#define read fake_read
#define write fake_write
#define setenv fake_setenv
#define getpid fake_pid
#define getppid fake_ppid
#define _exit fake_exit
#define pthread_attr_init fake_attr_init
#define pthread_attr_setstacksize fake_attr_stack
#define pthread_attr_destroy fake_attr_destroy
#define pthread_create fake_thread_create
#define pthread_mutex_trylock fake_trylock
#define pthread_mutex_unlock fake_unlock
#define sceKernelLoadStartModule fake_load
#define sceKernelGetModuleInfo fake_info
#define pw_wine_thread_register fake_register
#define pw_wine_thread_unregister fake_unregister
#define pw_wine_thread_kill fake_kill
#define pw_wine_child_wire_validate fake_validate
#define pw_wine_child_wire_try_send fake_send
#define pw_wine_child_wire_same_session fake_same
#define pw_wine_child_wire_receive fake_receive
#define pw_wine_child_wire_receive_step fake_step
#define pw_wine_child_wire_close fake_wire_close
#define main child_main
#include "../native/pw_wine_child_main.c"
#undef main
#undef stat
#undef fstat
#undef open
#undef close
#undef read
#undef write
#undef setenv
#undef nanosleep
#undef clock_gettime
#undef getpid
#undef getppid
#undef _exit
#undef pthread_attr_init
#undef pthread_attr_setstacksize
#undef pthread_attr_destroy
#undef pthread_create
#undef pthread_mutex_trylock
#undef pthread_mutex_unlock
#undef pw_wine_child_bootstrap_prepare
#undef pw_wine_child_bootstrap_start
static DiagnosticCase scenario;
static DiagnosticResult *result;
static PwWineChildFrame input;
static struct {
    uint64_t ms;int battle;int prepare_rc,start_rc,start_owns,wrong_session,kill_rc,log_fail;
    int sends,steps,closes,closed[20],kills,prepares,starts,exit_code,query_failure,send_rc,idle_timeout,bad_sequence;
    int envs,loads,stats,probe_stats,fstats;
    char data_marker[512];unsigned data_marker_count;
    int writes,trylock_rc,unlock_rc,write_short;char last_write[512];
    int attr_init_rc,attr_stack_rc,attr_destroy_rc,thread_rc,thread_calls,reads,bad_hash;
    PwWineChildFrame frames[8];
}m;
static jmp_buf done;
static int fake_pause(const struct timespec *p,struct timespec *r){assert(p&&p->tv_sec==1&&!p->tv_nsec&&!r);result->parked=1;longjmp(done,1);}
static int fake_clock(clockid_t id,struct timespec*t){assert(id==CLOCK_MONOTONIC);t->tv_sec=(time_t)(m.ms/1000);t->tv_nsec=(long)((m.ms%1000)*1000000);return 0;}
static pid_t fake_pid(void){return 600;}static pid_t fake_ppid(void){return 53;}
static void fake_exit(int code){m.exit_code=code;longjmp(done,1);}
static int fake_open(const char*p,int flags,...)
{
    if(strstr(p,"/logs/wine-child-")){
        assert((flags&(O_EXCL|O_CREAT|O_NOFOLLOW|O_NONBLOCK))==(O_EXCL|O_CREAT|O_NOFOLLOW|O_NONBLOCK));
        va_list a;va_start(a,flags);assert(va_arg(a,int)==0600);va_end(a);
        if(scenario.which==CASE_LOG){if(scenario.expire_open)m.ms=31000;errno=EACCES;return -1;}return 5;
    }
    assert(flags&O_NOFOLLOW);
    if(scenario.which==CASE_RUNTIME_OPEN){errno=strstr(p,"/mnt/sandbox/")?ENOENT:EACCES;return -1;}
    if(strstr(p,"/mnt/sandbox/")){errno=ENOENT;return -1;}return 9;
}
static int external_cancel(void *unused){(void)unused;return 1;}
static int fake_stat(const char*p,struct stat*s)
{
    assert(p&&p[0]=='/');m.stats++;memset(s,0,sizeof(*s));s->st_mode=S_IFDIR;
    if(!strcmp(p,"/data")){
        m.probe_stats++;
        if(scenario.expire_probe)m.ms=301000;
        if(scenario.cancel_probe)child_io.cancelled=external_cancel;
        errno=ERANGE;
        if(scenario.probe==1){errno=ENOTDIR;return -1;}
        if(scenario.probe==2)s->st_mode=S_IFREG;
        if(scenario.probe==3)return 7;
        return 0;
    }
    if(scenario.transport_guard==1)wire_result.status=PW_WC_OS;
    if(scenario.transport_guard==2)wire_result.delivery_uncertain=1;
    if(scenario.transport_guard==3)wire_result.ownership_uncertain=1;
    if(scenario.transport_guard==4)wire_result.cleanup_failed=1;
    int cwd=strstr(p,"/drive_c")!=NULL;
    if(scenario.which==CASE_PATH_BUDGET)m.ms=31000;
    if((!cwd&&scenario.which==CASE_PREFIX)||(cwd&&scenario.which==CASE_CWD)){errno=cwd?ENOENT:EACCES;return -1;}
    if(!cwd&&scenario.which==CASE_PREFIX_TYPE)s->st_mode=S_IFREG;
    errno=ERANGE;return 0;
}
static int fake_fstat(int fd,struct stat*s)
{
 assert(fd==9);m.fstats++;memset(s,0,sizeof(*s));s->st_mode=S_IFREG;s->st_size=3;s->st_ino=1;errno=ERANGE;
 if(scenario.which==CASE_RUNTIME_STAT){errno=EIO;return -1;}
 if(scenario.which==CASE_RUNTIME_TYPE)s->st_mode=S_IFDIR;
 if(scenario.which==CASE_RUNTIME_SIZE)s->st_size=0;
 if(scenario.which==CASE_RUNTIME_CHANGED&&m.fstats>1)s->st_ino=2;
 return 0;
}
static ssize_t fake_read(int fd,void*p,size_t n){assert(fd==9);if(scenario.which==CASE_RUNTIME_READ){errno=EIO;return -1;}if(m.reads++){if(scenario.which==CASE_RUNTIME_EXTRA){errno=EIO;return -1;}return 0;}assert(n==3);memcpy(p,scenario.which==CASE_RUNTIME_HASH?"abd":"abc",3);return 3;}
static ssize_t fake_write(int fd,const void*p,size_t n){assert(fd==5&&p&&n<=65536);m.writes++;if(scenario.which==CASE_LOG_HEADER){errno=EIO;return -1;}errno=EINTR;size_t take=n<sizeof(m.last_write)-1?n:sizeof(m.last_write)-1;memcpy(m.last_write,p,take);m.last_write[take]=0;if(strstr(m.last_write,"PW_WINE_CHILD_DATA ")==m.last_write){strcpy(m.data_marker,m.last_write);m.data_marker_count++;if(scenario.which==CASE_DATA_MARKER){errno=ENOSPC;return -1;}}if(scenario.log_after_path&&strstr(m.last_write,"stage=1 status=-1")){errno=ENOSPC;return -1;}return m.write_short?(ssize_t)n-1:(ssize_t)n;}
static int fake_close(int fd){assert(m.closes<20);m.closed[m.closes++]=fd;errno=EBADF;return scenario.cleanup_error||(fd==9&&scenario.which==CASE_RUNTIME_CLOSE)?-1:0;}
static int fake_setenv(const char*a,const char*b,int c){(void)a;(void)b;assert(c==1);m.envs++;return 0;}
static int fake_attr_init(pthread_attr_t*a){(void)a;return m.attr_init_rc;}
static int fake_attr_stack(pthread_attr_t*a,size_t n){(void)a;assert(n==(16u<<20));return m.attr_stack_rc;}
static int fake_attr_destroy(pthread_attr_t*a){(void)a;return m.attr_destroy_rc;}
static int fake_thread_create(pthread_t*t,const pthread_attr_t*a,void*(*f)(void*),void*p){(void)t;(void)a;(void)f;assert(!p);m.thread_calls++;return m.thread_rc;}
static int fake_trylock(pthread_mutex_t*p){assert(p==&log_lock);return m.trylock_rc;}static int fake_unlock(pthread_mutex_t*p){assert(p==&log_lock);return m.unlock_rc;}
enum{EXPORTS=10};
_Alignas(PW_PRX_ALIGN) static struct{struct{uint64_t magic;uint32_t version,count;PwPrxExport exports[EXPORTS];}d;char names[EXPORTS][64];}module;
static void mock_wine_main(int argc,char **argv){assert(argc==2&&argv);}
static int module_start(size_t n,const void *p){assert(!n&&!p);return 0;}
static void *adopt(const char*p,int32_t h){assert(strstr(p,"ntdll.prx")&&h==7);return &module;}
static unsigned abi(void){return 1;}
static int cwd(const char*p){assert(p&&strstr(p,"drive_c"));return 0;}
static void set_sink(void(*fn)(const char*,size_t)){assert(fn==output);}
static int threads(int(*add)(long,pthread_t),void(*remove)(long)){assert(add&&remove);return 0;}
static int install_socket_sink(PwWineFixtureSocketSink fn,void*context){assert(fn==socket_failure_sink&&context==&active_session);return 0;}
static int socket_failed(PwWineFixtureSocketResult *r){(void)r;return 0;}
static int32_t fake_load(const char*p,size_t n,const void*a,uint32_t f,const void*o,int*r)
{
 assert(m.envs==16&&p&&strstr(p,"ntdll.prx")&&!n&&!a&&!f&&!o);*r=0;m.loads++;
 const char *names[]={"__wine_main","module_start","pw_wine_dl_adopt","__wine_ps5_private_dispatch_abi","pw_cwd_set","__wine_ps5_set_output_sink","pw_wine_fixture_local_threads","pw_wine_fixture_socket_set_sink","pw_wine_fixture_socket_failure","__wine_ps5_private_dispatch_wow64_abi"};
 const void *functions[]={(void*)mock_wine_main,(void*)module_start,(void*)adopt,(void*)abi,(void*)cwd,(void*)set_sink,(void*)threads,(void*)install_socket_sink,(void*)socket_failed,(void*)abi};
 memset(&module,0,sizeof(module));module.d.magic=PW_PRX_MAGIC;module.d.version=PW_PRX_VERSION;module.d.count=EXPORTS;
 for(unsigned i=0;i<EXPORTS;i++){strcpy(module.names[i],names[i]);module.d.exports[i]=(PwPrxExport){module.names[i],functions[i]};}
 return 7;
}
static int fake_info(int32_t h,void *buffer)
{
 assert(h==7);unsigned char*p=buffer;uint64_t address;uint32_t bytes,prot=1,count=2;
 uintptr_t low=(uintptr_t)mock_wine_main,high=low;
 for(unsigned i=0;i<EXPORTS;i++){uintptr_t fn=(uintptr_t)module.d.exports[i].address;if(fn<low)low=fn;if(fn>high)high=fn;}
 address=(uintptr_t)&module;bytes=sizeof(module);memcpy(p+0x108,&address,8);memcpy(p+0x110,&bytes,4);memcpy(p+0x114,&prot,4);
 address=low;bytes=(uint32_t)(high-low+64);memcpy(p+0x118,&address,8);memcpy(p+0x120,&bytes,4);memcpy(p+0x124,&prot,4);memcpy(p+0x148,&count,4);return 0;
}
static int fake_register(long id,pthread_t t){(void)id;(void)t;return 0;}static void fake_unregister(long id){(void)id;}
static int fake_kill(pid_t pid,long tid,int sig){assert(pid==600&&tid==123&&sig==30);m.kills++;if(m.kill_rc)errno=3;return m.kill_rc;}
static PwWineChildFrame session(void){return input;}
static int fake_validate(PwNativeChildIo*i,int fd,PwWineChildWireResult*r){assert(i==&child_io&&fd==3&&r==&wire_result);return 0;}
static int fake_send(int fd,const PwWineChildFrame*f,int right,PwWineChildWireResult*r)
{
    assert(fd==3&&right==-1&&r&&m.sends<8);
    unsigned char bytes[PW_WC_WIRE_BYTES];PwWineChildFrame decoded;
    assert(!pw_wine_child_wire_encode(bytes,f));assert(!pw_wine_child_wire_decode(&decoded,bytes));
    m.frames[m.sends++]=decoded;
    if(f->kind==PW_WC_FAILURE||f->kind==PW_WC_BOOTSTRAP_ACK)memcpy(result->bytes,bytes,sizeof(bytes));
    errno=EINTR;return m.send_rc;
}
static int fake_same(const PwWineChildFrame*a,const PwWineChildFrame*b)
{return a->generation==b->generation&&a->child_pid==b->child_pid&&a->parent_pid==b->parent_pid&&a->wine_pid==b->wine_pid;}
static int fake_receive(PwNativeChildIo*i,int fd,uint32_t k,PwWineChildFrame*f,int*right,PwWineChildWireResult*r)
{assert(i==&child_io&&fd==3&&k==PW_WC_KIND(PW_WC_BOOTSTRAP)&&r==&wire_result);unsigned char bytes[PW_WC_WIRE_BYTES];assert(!pw_wine_child_wire_encode(bytes,&input));assert(!pw_wine_child_wire_decode(f,bytes));*right=72;return PW_WC_RECORD;}
static int fake_step(PwNativeChildIo*i,int fd,uint32_t k,PwWineChildFrame*f,int*right,PwWineChildWireResult*r)
{assert(i==&child_io&&fd==3&&k==PW_WC_KIND(PW_WC_SIGNAL)&&*right==-1&&r==&wire_result);
 if(scenario.which==CASE_SUCCESS)return PW_WC_CHANNEL_CLOSED;
 if(m.idle_timeout){unsigned left;m.ms+=10000;return pw_native_child_remaining(i,&left)?PW_WC_ERROR:PW_WC_IDLE;}
 if(m.steps++)return PW_WC_CHANNEL_CLOSED;
 *f=session();f->kind=PW_WC_SIGNAL;f->sequence=m.bad_sequence?3:2;f->signal=30;f->target_tid=123;return PW_WC_RECORD;}
static void fake_wire_close(int*fd,PwWineChildWireResult*r){(void)r;if(*fd>=0){fake_close(*fd);*fd=-1;}}
static void reset(void)
{memset(&m,0,sizeof(m));m.ms=100;m.start_owns=1;memset(&bootstrap,0,sizeof(bootstrap));memset(&wire_result,0,sizeof(wire_result));
 memset(&child_io,0,sizeof(child_io));memset(&active_session,0,sizeof(active_session));log_fd=-1;log_bytes=0;log_loss_marker=0;atomic_store(&log_dropped_records,0);atomic_store(&log_dropped_bytes,0);atomic_store(&log_counts_incomplete,0);atomic_store(&runtime_failure,0);atomic_store(&socket_failure_attempted,0);atomic_flag_clear(&send_claim);}
static void run(void){if(!setjmp(done))child_main(0,NULL);}
static unsigned closed(int fd){unsigned n=0;for(int i=0;i<m.closes;i++)n+=m.closed[i]==fd;return n;}


void diagnostic_child_run(const PwWineChildFrame *request,const DiagnosticCase *test,DiagnosticResult *out)
{
    reset();memset(&bootstrap_failure,0,sizeof(bootstrap_failure));memset(&data_readiness,0,sizeof(data_readiness));scenario=*test;input=*request;result=out;memset(out,0,sizeof(*out));
    m.ms=1000;data_adapter_fixture_reset(&m.ms,(unsigned)test->data_mode);m.battle=input.profile==PW_WC_PROFILE_BATTLENET;
    run();out->exit_code=m.exit_code;out->sends=m.sends;out->stats=m.stats;out->probe_stats=m.probe_stats;
    strcpy(out->data_marker,m.data_marker);out->data_marker_count=m.data_marker_count;out->data=data_readiness;data_adapter_fixture_counts(&out->data_calls,&out->data_clones,&out->data_sends);
    out->envs=m.envs;out->loads=m.loads;out->threads=m.thread_calls;out->stage=bootstrap.stage;
    out->api=bootstrap_failure.api;out->raw=bootstrap_failure.raw;out->error=bootstrap_failure.error;out->errno_valid=bootstrap_failure.errno_valid;
    out->auxiliary=bootstrap_failure.auxiliary;out->detail=bootstrap_failure.detail;
    out->stage_end=child_io.stage_end;out->total_end=child_io.total_end;
    for(int fd=0;fd<128;fd++)out->closes[fd]=(int)closed(fd);
    if(m.sends)out->hello=m.frames[0];
    if(m.sends>1)out->failure=m.frames[1];
}
