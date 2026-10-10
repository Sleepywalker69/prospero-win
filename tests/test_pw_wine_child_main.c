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
#include "../native/pw_wine_child_bootstrap.h"
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
static int fake_prepare(PwWineChildBootstrap*,PwNativeChildIo*,int,const char*,unsigned,uint32_t,uint32_t,const PwWineChildBootstrapOps*);
static int fake_start(PwWineChildBootstrap*,PwNativeChildIo*,const PwWineChildBootstrapOps*);
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
#define pw_wine_child_bootstrap_prepare fake_prepare
#define pw_wine_child_bootstrap_start fake_start
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
static struct {
    uint64_t ms;int battle;int prepare_rc,start_rc,start_owns,wrong_session,kill_rc,log_fail;
    int sends,steps,closes,closed[20],kills,prepares,starts,exit_code,query_failure,send_rc,idle_timeout,bad_sequence;
    int writes,trylock_rc,unlock_rc,write_short;char last_write[512];
    int log_error,data_error,data_nondir,data_stats,close_error,open_mask,alias_open;
    int stat_error,read_error;
    int attr_init_rc,attr_stack_rc,attr_destroy_rc,thread_rc,thread_calls,reads,bad_hash;
    PwWineChildFrame frames[8];
}m;
static jmp_buf done;
static int fake_clock(clockid_t id,struct timespec*t){assert(id==CLOCK_MONOTONIC);t->tv_sec=(time_t)(m.ms/1000);t->tv_nsec=(long)((m.ms%1000)*1000000);return 0;}
static pid_t fake_pid(void){return 600;}static pid_t fake_ppid(void){return 53;}
static void fake_exit(int code){m.exit_code=code;longjmp(done,1);}
static int fake_open(const char*p,int flags,...)
{
    if(strstr(p,"/logs/wine-child-")){assert(flags&(O_EXCL|O_CREAT));va_list a;va_start(a,flags);assert(va_arg(a,int)==0600);va_end(a);if(m.log_fail){errno=m.log_error;return -1;}return 5;}
    assert(flags&O_NOFOLLOW);int alias=strstr(p,"/mnt/sandbox/")!=NULL;
    if((alias&&!m.alias_open)||(m.open_mask&(1<<alias))){errno=alias?ENOENT:EACCES;return -1;}
    m.reads=0;return 9;
}
static int fake_stat(const char*p,struct stat*s)
{assert(p&&p[0]=='/');if(!strcmp(p,"/data")){m.data_stats++;if(m.data_error){errno=m.data_error;return -1;}}
 memset(s,0,sizeof(*s));s->st_mode=m.data_nondir?S_IFREG:S_IFDIR;return 0;}
static int fake_fstat(int fd,struct stat*s){assert(fd==9);if(m.stat_error){errno=m.stat_error;return -1;}memset(s,0,sizeof(*s));s->st_mode=S_IFREG;s->st_size=3;s->st_ino=1;return 0;}
static ssize_t fake_read(int fd,void*p,size_t n){assert(fd==9);if(m.read_error){errno=m.read_error;return -1;}if(m.reads++)return 0;assert(n==3);memcpy(p,m.bad_hash?"abd":"abc",3);return 3;}
static ssize_t fake_write(int fd,const void*p,size_t n){assert(fd==5&&p&&n<=65536);m.writes++;size_t take=n<sizeof(m.last_write)-1?n:sizeof(m.last_write)-1;memcpy(m.last_write,p,take);m.last_write[take]=0;return m.write_short?(ssize_t)n-1:(ssize_t)n;}
static int fake_close(int fd){assert(m.closes<20);m.closed[m.closes++]=fd;if(m.close_error){errno=m.close_error;return -1;}return 0;}
static int fake_setenv(const char*a,const char*b,int c){(void)a;(void)b;assert(c==1);return 0;}
static int fake_attr_init(pthread_attr_t*a){(void)a;return m.attr_init_rc;}
static int fake_attr_stack(pthread_attr_t*a,size_t n){(void)a;assert(n==(16u<<20));return m.attr_stack_rc;}
static int fake_attr_destroy(pthread_attr_t*a){(void)a;return m.attr_destroy_rc;}
static int fake_thread_create(pthread_t*t,const pthread_attr_t*a,void*(*f)(void*),void*p){(void)t;(void)a;(void)f;assert(!p);m.thread_calls++;return m.thread_rc;}
static int fake_trylock(pthread_mutex_t*p){assert(p==&log_lock);return m.trylock_rc;}static int fake_unlock(pthread_mutex_t*p){assert(p==&log_lock);return m.unlock_rc;}
static int32_t fake_load(const char*p,size_t n,const void*a,uint32_t f,const void*o,int*r){(void)p;(void)n;(void)a;(void)f;(void)o;(void)r;return 0;}
static int fake_info(int32_t h,void*p){(void)h;(void)p;return 0;}
static int fake_register(long id,pthread_t t){(void)id;(void)t;return 0;}static void fake_unregister(long id){(void)id;}
static int fake_kill(pid_t pid,long tid,int sig){assert(pid==600&&tid==123&&sig==30);m.kills++;if(m.kill_rc)errno=3;return m.kill_rc;}
static PwWineChildFrame session(void)
{PwWineChildFrame f={.kind=PW_WC_BOOTSTRAP,.sequence=1,.parent_pid=599,.child_pid=600,.child_ppid=53,.wine_pid=20,.wine_tid=24,.generation=1,.profile=PW_WC_PROFILE_FIXTURE,.machine=PW_WC_MACHINE_AMD64};
 if(m.battle){f.profile=PW_WC_PROFILE_BATTLENET;f.machine=PW_WC_MACHINE_I386;}
 memcpy(f.build_id,PW_WINE_CHILD_BUILD_ID,41);return f;}
static int fake_validate(PwNativeChildIo*i,int fd,PwWineChildWireResult*r){assert(i==&child_io&&fd==3&&r==&wire_result);return 0;}
static int fake_send(int fd,const PwWineChildFrame*f,int right,PwWineChildWireResult*r)
{assert(fd==3&&right==-1&&r&&m.sends<8);m.frames[m.sends++]=*f;return m.send_rc;}
static int fake_same(const PwWineChildFrame*a,const PwWineChildFrame*b)
{return a->generation==b->generation&&a->child_pid==b->child_pid&&a->parent_pid==b->parent_pid&&a->wine_pid==b->wine_pid;}
static int fake_receive(PwNativeChildIo*i,int fd,uint32_t k,PwWineChildFrame*f,int*right,PwWineChildWireResult*r)
{assert(i==&child_io&&fd==3&&k==PW_WC_KIND(PW_WC_BOOTSTRAP)&&r==&wire_result);*f=session();if(m.wrong_session)f->child_pid=601;*right=9;return PW_WC_RECORD;}
static int fake_step(PwNativeChildIo*i,int fd,uint32_t k,PwWineChildFrame*f,int*right,PwWineChildWireResult*r)
{assert(i==&child_io&&fd==3&&k==PW_WC_KIND(PW_WC_SIGNAL)&&*right==-1&&r==&wire_result);
 if(m.idle_timeout){unsigned left;m.ms+=10000;return pw_native_child_remaining(i,&left)?PW_WC_ERROR:PW_WC_IDLE;}
 if(m.steps++)return PW_WC_CHANNEL_CLOSED;
 *f=session();f->kind=PW_WC_SIGNAL;f->sequence=m.bad_sequence?3:2;f->signal=30;f->target_tid=123;return PW_WC_RECORD;}
static void fake_wire_close(int*fd,PwWineChildWireResult*r){(void)r;if(*fd>=0){fake_close(*fd);*fd=-1;}}
static int query(PwWineFixtureSocketResult*r)
{if(!m.query_failure)return 0;*r=(PwWineFixtureSocketResult){.status=-1,.api=5,.raw_result=0,.returned_length=4,.returned_value=0};return 1;}
static int fake_prepare(PwWineChildBootstrap*b,PwNativeChildIo*i,int fd,const char*h,unsigned abi,uint32_t profile,uint32_t machine,const PwWineChildBootstrapOps*o)
{assert(i==&child_io&&fd==9&&!strcmp(h,PW_WINE_CHILD_NTDLL_SHA256)&&abi==1&&profile==(m.battle?PW_WC_PROFILE_BATTLENET:PW_WC_PROFILE_FIXTURE)&&machine==(m.battle?PW_WC_MACHINE_I386:PW_WC_MACHINE_AMD64)&&o->socket_sink==socket_failure_sink&&o->context==&active_session);
 m.prepares++;b->stage=PW_WCB_PREPARED;b->socket_failure=query;return m.prepare_rc;}
static int fake_start(PwWineChildBootstrap*b,PwNativeChildIo*i,const PwWineChildBootstrapOps*o)
{assert(i==&child_io&&o);m.starts++;b->started=m.start_owns;return m.start_rc;}
static void reset(void)
{memset(&m,0,sizeof(m));m.ms=100;m.start_owns=1;memset(&bootstrap,0,sizeof(bootstrap));memset(&wire_result,0,sizeof(wire_result));
 memset(&bootstrap_failure,0,sizeof(bootstrap_failure));
 memset(&child_io,0,sizeof(child_io));memset(&active_session,0,sizeof(active_session));log_fd=-1;log_bytes=0;log_loss_marker=0;atomic_store(&log_dropped_records,0);atomic_store(&log_dropped_bytes,0);atomic_store(&log_counts_incomplete,0);atomic_store(&runtime_failure,0);atomic_store(&socket_failure_attempted,0);atomic_flag_clear(&send_claim);}
static void run(void){if(!setjmp(done))child_main(0,NULL);}
static unsigned closed(int fd){unsigned n=0;for(int i=0;i<m.closes;i++)n+=m.closed[i]==fd;return n;}
static void dummy(void*p){(void)p;}
static int external_cancel(void*p){(void)p;return 1;}
int main(void)
{
    reset();run();assert(m.exit_code==17&&m.prepares==1&&m.starts==1&&m.sends==3&&m.kills==1);
    assert(m.frames[0].kind==PW_WC_HELLO&&m.frames[1].kind==PW_WC_BOOTSTRAP_ACK&&m.frames[2].kind==PW_WC_SIGNAL_ACK);
    assert(!closed(9)&&!closed(3)&&!closed(5)&&child_io.total_end==60100&&child_io.stage_end==60100);
    reset();m.wrong_session=1;run();assert(m.exit_code==13&&closed(9)==1&&!m.prepares);
    reset();m.log_fail=1;run();assert(m.exit_code==14&&closed(9)==1&&!m.prepares&&m.frames[1].kind==PW_WC_FAILURE&&!m.frames[1].errno_valid);
    reset();m.prepare_rc=-1;run();assert(m.exit_code==14&&closed(9)==1&&!m.starts);
    reset();m.start_rc=-1;m.start_owns=0;run();assert(m.exit_code==16&&closed(9)==1);
    reset();m.start_rc=-1;run();assert(m.exit_code==16&&!closed(9));
    /* The installed callback context remains valid after run_child returns. */
    assert(active_session.generation==1&&active_session.child_pid==600);
    reset();m.kill_rc=-1;run();assert(m.exit_code==20&&m.frames[2].status==-1&&m.frames[2].native_error==3);
    reset();m.query_failure=1;run();assert(m.exit_code==21&&m.frames[2].kind==PW_WC_FAILURE&&m.frames[2].failure_api==5&&m.frames[2].returned_length==4);
    reset();m.idle_timeout=1;run();assert(m.exit_code==17&&m.ms==60100&&!m.kills&&m.sends==2);
    reset();m.battle=1;m.idle_timeout=1;run();assert(m.exit_code==17&&m.ms==300100&&child_io.total_end==300100&&!m.kills&&m.sends==2);
    reset();m.bad_sequence=1;run();assert(m.exit_code==18&&!m.kills);
    reset();PwWineChildFrame f=session();PwWineFixtureSocketResult failure={.status=-1,.api=4,.raw_result=-1,.native_error=13,.errno_valid=1};
    socket_failure_sink(&f,&failure);socket_failure_sink(&f,&failure);assert(m.sends==1&&m.frames[0].errno_valid&&m.frames[0].native_error==13);
    reset();m.send_rc=-1;socket_failure_sink(&f,&failure);socket_failure_sink(&f,&failure);assert(m.sends==1);
    reset();atomic_flag_test_and_set(&send_claim);socket_failure_sink(&f,&failure);assert(!m.sends&&!atomic_load(&socket_failure_attempted));
    atomic_flag_clear(&send_claim);socket_failure_sink(&f,&failure);assert(m.sends==1);
    reset();assert(!start_thread(dummy,NULL,16u<<20)&&m.thread_calls==1);
    reset();m.attr_init_rc=2;assert(start_thread(dummy,NULL,16u<<20)==2&&!m.thread_calls);
    reset();m.attr_stack_rc=3;assert(start_thread(dummy,NULL,16u<<20)==3&&!m.thread_calls);
    reset();m.thread_rc=4;assert(start_thread(dummy,NULL,16u<<20)==4);
    reset();m.attr_destroy_rc=5;assert(!start_thread(dummy,NULL,16u<<20)&&atomic_load(&runtime_failure)==3);
    reset();child_io=(PwNativeChildIo){.clock_ms=clock_ms,.ready=1,.last_clock=100,.stage_end=1000,.total_end=2000};char path[256];
    assert(!runtime(NULL,PW_WINE_CHILD_NTDLL_SHA256,path,sizeof(path))&&!strcmp(path,PW_WINE_CHILD_RUNTIME)&&closed(9)==1);
    reset();child_io=(PwNativeChildIo){.clock_ms=clock_ms,.ready=1,.last_clock=100,.stage_end=1000,.total_end=2000};m.bad_hash=1;
    assert(runtime(NULL,PW_WINE_CHILD_NTDLL_SHA256,path,sizeof(path))&&closed(9)==1);
    reset();active_session.profile=PW_WC_PROFILE_BATTLENET;log_fd=5;m.trylock_rc=EBUSY;output("abc",3);
    assert(!atomic_load(&runtime_failure)&&atomic_load(&log_dropped_records)==1&&atomic_load(&log_dropped_bytes)==3&&!m.writes);
    m.trylock_rc=0;report_log_loss();assert(log_loss_marker&&m.writes==1&&strstr(m.last_write,"incomplete=1 snapshot=1"));
    report_log_loss();assert(m.writes==1&&log_bytes<=65536);
    reset();active_session.profile=PW_WC_PROFILE_BATTLENET;log_fd=5;log_bytes=65536-512;output("abc",3);
    assert(!atomic_load(&runtime_failure)&&atomic_load(&log_dropped_bytes)==3&&log_loss_marker&&log_bytes<=65536);
    output("abc",3);assert(!atomic_load(&runtime_failure)&&atomic_load(&log_dropped_records)==2&&m.writes==1);
    reset();active_session.profile=PW_WC_PROFILE_FIXTURE;log_fd=5;m.trylock_rc=EBUSY;output("abc",3);assert(atomic_load(&runtime_failure));
    reset();active_session.profile=PW_WC_PROFILE_FIXTURE;log_fd=5;log_bytes=65536;output("abc",3);assert(atomic_load(&runtime_failure));
    reset();active_session.profile=PW_WC_PROFILE_BATTLENET;log_fd=5;m.write_short=1;output("abc",3);assert(atomic_load(&runtime_failure));
    reset();active_session.profile=PW_WC_PROFILE_BATTLENET;log_fd=5;dropped_log(3);m.write_short=1;output("abc",3);
    assert(atomic_load(&runtime_failure)&&m.writes==1&&!log_loss_marker);report_log_loss();assert(m.writes==1);
    reset();active_session.profile=PW_WC_PROFILE_BATTLENET;log_fd=5;m.unlock_rc=1;output("abc",3);assert(atomic_load(&runtime_failure));
    reset();active_session.profile=PW_WC_PROFILE_BATTLENET;log_fd=5;m.trylock_rc=EINVAL;output("abc",3);assert(atomic_load(&runtime_failure));
    reset();m.battle=1;m.log_fail=1;run();assert(m.exit_code==14&&!m.starts);
    reset();m.battle=1;m.trylock_rc=EBUSY;run();assert(m.exit_code==14&&!m.starts); /* missing initial header */
    reset();active_session.profile=PW_WC_PROFILE_BATTLENET;atomic_store(&log_dropped_bytes,ULLONG_MAX-1);dropped_log(3);
    assert(atomic_load(&log_dropped_bytes)==ULLONG_MAX&&atomic_load(&log_counts_incomplete));
    /* Native errors are captured before the /data probe and descriptor cleanup. */
    reset();m.log_fail=1;m.log_error=EACCES;m.data_error=ENOENT;m.close_error=EBADF;run();
    assert(m.exit_code==14&&m.sends==2&&!m.prepares&&!m.starts&&m.data_stats==1);
    assert(m.frames[1].failure_api==PW_WC_DIAG_LOG_OPEN&&m.frames[1].failure_raw==-1);
    assert(m.frames[1].errno_valid&&m.frames[1].native_error==EACCES);
    assert(m.frames[1].returned_length==PW_WC_DATA_STAT_FAILED&&m.frames[1].returned_value==ENOENT);
    assert(closed(9)==1&&closed(3)==1&&!closed(5));
    reset();m.log_fail=1;m.log_error=EEXIST;run();
    assert(m.frames[1].native_error==EEXIST&&m.frames[1].returned_length==PW_WC_DATA_DIRECTORY&&!m.frames[1].returned_value);
    reset();m.log_fail=1;m.data_nondir=1;run();
    assert(!m.frames[1].errno_valid&&!m.frames[1].native_error&&m.frames[1].returned_length==PW_WC_DATA_NOT_DIRECTORY);
    for(unsigned operation=0;operation<4;operation++){
        reset();child_io=(PwNativeChildIo){.clock_ms=clock_ms,.ready=1,.last_clock=100,.stage_end=1000,.total_end=2000};
        if(operation==0)m.open_mask=3;
        if(operation==1){m.stat_error=EACCES;m.close_error=EBADF;}
        if(operation==2){m.read_error=EIO;m.close_error=EBADF;}
        if(operation==3)m.close_error=EBADF;
        assert(runtime(NULL,PW_WINE_CHILD_NTDLL_SHA256,path,sizeof(path))==-1);
        const unsigned apis[]={PW_WC_DIAG_RUNTIME_OPEN,PW_WC_DIAG_RUNTIME_STAT,PW_WC_DIAG_RUNTIME_READ,PW_WC_DIAG_RUNTIME_CLOSE};
        const int errors[]={EACCES,EACCES,EIO,EBADF};
        assert(bootstrap_failure.api==apis[operation]&&bootstrap_failure.raw==-1);
        assert(bootstrap_failure.errno_valid&&bootstrap_failure.error==errors[operation]&&!bootstrap_failure.auxiliary);
        assert(closed(9)==(operation?1:0));
    }
    /* A permitted unreadable alias must not poison successful selection. */
    reset();child_io=(PwNativeChildIo){.clock_ms=clock_ms,.ready=1,.last_clock=100,.stage_end=1000,.total_end=2000};
    m.open_mask=1;m.alias_open=1;
    assert(!runtime(NULL,PW_WINE_CHILD_NTDLL_SHA256,path,sizeof(path))&&!strcmp(path,PW_WINE_CHILD_RUNTIME_ALIAS));
    assert(!bootstrap_failure.api&&closed(9)==1);
    /* The sole final pre-Wine failure report can survive its own failed logger,
     * but cannot bypass transport errors, external cancellation or the clock. */
    reset();m.write_short=1;run();
    assert(m.exit_code==14&&m.sends==2&&m.frames[1].kind==PW_WC_FAILURE);
    assert(m.frames[1].failure_api==PW_WC_DIAG_LOG_HEADER&&!m.starts&&closed(9)==1&&closed(5)==1&&closed(3)==1);
    for(unsigned guard=0;guard<9;guard++){
        reset();child_io=(PwNativeChildIo){.clock_ms=clock_ms,.cancelled=cancelled,.ready=1,.last_clock=100,.stage_end=1000,.total_end=2000};
        PwWineChildFrame failed=session();failed.kind=PW_WC_FAILURE;failed.status=-1;
        atomic_store(&runtime_failure,1);
        if(guard==0)bootstrap.started=1;
        if(guard==1)wire_result.status=PW_WC_OS;
        if(guard==2)wire_result.delivery_uncertain=1;
        if(guard==3)wire_result.ownership_uncertain=1;
        if(guard==4)wire_result.cleanup_failed=1;
        if(guard==5)child_io.cancelled=external_cancel;
        if(guard==6)m.ms=1000;
        if(guard==7)child_io.last_clock=101;
        if(guard==8)atomic_flag_test_and_set(&send_claim);
        assert(send_bootstrap_failure(&failed)==-1&&!m.sends);
    }
    reset();child_io=(PwNativeChildIo){.clock_ms=clock_ms,.cancelled=cancelled,.ready=1,.last_clock=99,.stage_end=1000,.total_end=2000};
    PwWineChildFrame failed=session();failed.kind=PW_WC_FAILURE;failed.status=-1;atomic_store(&runtime_failure,1);
    assert(!send_bootstrap_failure(&failed)&&m.sends==1&&child_io.last_clock==100&&atomic_load(&runtime_failure)==1);
    puts("wine child main: all mocked lifecycle controls passed");return 0;
}
