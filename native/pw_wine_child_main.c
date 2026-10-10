/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Headless application main, linked with the unchanged foundation app_crt.
 * No payload CRT, helper, graphics setup or root-title restart hook. */
#define _POSIX_C_SOURCE 200809L
#include "pw_wine_child_bootstrap.h"
#include "../wine/ps5/pw_wine_threads.h"
#include "wine-child-build.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

int32_t sceKernelLoadStartModule(const char *,size_t,const void *,uint32_t,const void *,int *);
int sceKernelGetModuleInfo(int32_t,void *);
_Static_assert(sizeof(PW_WINE_CHILD_BUILD_ID)==41,"worker build ID shape");
_Static_assert(sizeof(PW_WINE_CHILD_NTDLL_SHA256)==65,"ntdll hash shape");
_Static_assert(PW_WINE_CHILD_PRIVATE_DISPATCH_ABI==1,"private dispatcher cohort");
_Static_assert(PW_WINE_CHILD_WOW64_ABI==1,"checked translated I386 cohort");
static PwNativeChildIo child_io;
static PwWineChildWireResult wire_result;
static PwWineChildBootstrap bootstrap;
/* Registered callbacks can outlive run_child's stack on a failure path. */
static PwWineChildFrame active_session;
static int log_fd=-1;
static size_t log_bytes;
static atomic_ullong log_dropped_records,log_dropped_bytes;
static atomic_uint log_counts_incomplete;
static unsigned log_loss_marker;
_Static_assert(ATOMIC_LLONG_LOCK_FREE==2,"bounded log counters must be lock-free");
static atomic_int runtime_failure;
static atomic_uint socket_failure_attempted;
static atomic_flag send_claim=ATOMIC_FLAG_INIT;
static pthread_mutex_t log_lock=PTHREAD_MUTEX_INITIALIZER;
static struct {void(*entry)(void*);void *arg;} thread_start;
/* Only the pre-Wine main thread writes this snapshot. Copy errno at the failed
 * native call, before observers, budget checks or once-only cleanup run. */
static struct {
    uint32_t api, auxiliary, errno_valid;
    int32_t raw, error, detail;
} bootstrap_failure;
static int boot_failure(unsigned api,int32_t raw,int error,unsigned auxiliary,int32_t detail)
{
    if(!bootstrap_failure.api){
        bootstrap_failure.api=api;bootstrap_failure.raw=raw;
        bootstrap_failure.errno_valid=error>0;bootstrap_failure.error=error>0?error:0;
        bootstrap_failure.auxiliary=auxiliary;bootstrap_failure.detail=detail;
    }
    return -1;
}
static int clock_ms(void *unused,uint64_t *out)
{
    struct timespec t;(void)unused;
    if(clock_gettime(CLOCK_MONOTONIC,&t)||t.tv_sec<0||t.tv_nsec<0||t.tv_nsec>=1000000000||
       (uint64_t)t.tv_sec>UINT64_MAX/1000)return -1;
    uint64_t whole=(uint64_t)t.tv_sec*1000,part=(uint64_t)t.tv_nsec/1000000;
    if(whole>UINT64_MAX-part)return -1;
    *out=whole+part;return 0;
}
static int cancelled(void *unused){(void)unused;return atomic_load(&runtime_failure)!=0;}
static int within_budget(void){unsigned n;return pw_native_child_remaining(&child_io,&n);}
static int boot_budget(void)
{
    return within_budget()?boot_failure(PW_WC_DIAG_BUDGET,-1,0,0,0):0;
}
static int send_record(const PwWineChildFrame *f)
{
    if(within_budget())return -1;
    if(atomic_flag_test_and_set(&send_claim)){atomic_store(&runtime_failure,4);return -1;}
    int rc=pw_wine_child_wire_try_send(3,f,-1,&wire_result);
    atomic_flag_clear(&send_claim);
    if(!rc&&within_budget()){wire_result.delivery_uncertain=1;return -1;}
    return rc;
}
static int send_bootstrap_failure(const PwWineChildFrame *f)
{
    /* A failed local logger must not hide a pre-Wine failure on fd3. This is
     * one final nonblocking attempt, never a retry after transport ambiguity.
     * Keep any other cancellation callback and the original clock history. */
    if(!f||f->kind!=PW_WC_FAILURE||bootstrap.started||wire_result.status||wire_result.delivery_uncertain||
       wire_result.ownership_uncertain||wire_result.cleanup_failed)return -1;
    PwNativeChildIo io=child_io;unsigned left;
    if(io.cancelled==cancelled)io.cancelled=NULL;
    int rc=pw_native_child_remaining(&io,&left);
    child_io.last_clock=io.last_clock;
    if(rc||atomic_flag_test_and_set(&send_claim))return -1;
    rc=pw_wine_child_wire_try_send(3,f,-1,&wire_result);
    atomic_flag_clear(&send_claim);
    if(!rc&&pw_native_child_remaining(&io,&left)){wire_result.delivery_uncertain=1;rc=-1;}
    child_io.last_clock=io.last_clock;
    return rc;
}
static void socket_failure_sink(void *context,const PwWineFixtureSocketResult *failure)
{
    /* Called from inside Wine: no clocks, wait, logger or server operation.
     * No second send after partial/ambiguous delivery. Query is backup only
     * when a concurrent writer prevented any attempt. */
    const PwWineChildFrame *session=context;
    if(!session||!failure||atomic_load(&socket_failure_attempted))return;
    if(atomic_flag_test_and_set(&send_claim))return;
    unsigned expected=0;
    if(atomic_compare_exchange_strong(&socket_failure_attempted,&expected,1)){
        PwWineChildFrame f=*session;PwWineChildWireResult local={0};
        f.kind=PW_WC_FAILURE;f.status=-PW_WCB_SOCKET;
        f.failure_api=(uint32_t)failure->api;f.failure_raw=failure->raw_result;
        f.returned_length=failure->returned_length;f.returned_value=failure->returned_value;
        f.errno_valid=(uint32_t)(failure->errno_valid!=0);f.native_error=f.errno_valid?failure->native_error:0;
        (void)pw_wine_child_wire_try_send(3,&f,-1,&local);
    }
    atomic_flag_clear(&send_claim);
}
static int directory(void *unused,const char *path)
{
    struct stat st;(void)unused;
    unsigned which=!strcmp(path,PW_WINE_CHILD_PREFIX)||!strcmp(path,PW_WINE_CHILD_BATTLENET_PREFIX)?
                   PW_WC_DIRECTORY_PREFIX:PW_WC_DIRECTORY_CWD;
    if(boot_budget())return -1;
    errno=0;int rc=stat(path,&st),error=rc<0?errno:0;
    if(rc)return boot_failure(PW_WC_DIAG_DIRECTORY_STAT,rc,error,which,0);
    if(!S_ISDIR(st.st_mode))return boot_failure(PW_WC_DIAG_DIRECTORY_TYPE,0,0,which,0);
    return boot_budget();
}
static int runtime(void *unused,const char *hash,char *out,size_t size)
{
    static const char *const roots[]={PW_WINE_CHILD_RUNTIME,PW_WINE_CHILD_RUNTIME_ALIAS};
    int found=0,first_open_raw=0,first_open_error=0;unsigned first_open_index=0;(void)unused;
    for(unsigned i=0;i<2;i++){
        char path[272],actual[65];struct stat before,after;
        if(boot_budget())return -1;
        int n=snprintf(path,sizeof(path),"%s/ntdll.prx",roots[i]);
        if(n<=0||(size_t)n>=sizeof(path))return boot_failure(PW_WC_DIAG_RUNTIME_PATH,n,0,i,0);
        errno=0;int fd=open(path,O_RDONLY|O_NOFOLLOW|O_NONBLOCK),open_error=fd<0?errno:0;
        if(fd<0){
            /* An unreadable alias is permitted by the existing selection
             * contract. Publish it only if neither candidate can be opened. */
            if(!first_open_raw){first_open_raw=fd;first_open_error=open_error;first_open_index=i;}
            continue;
        }
        int error=0;
        errno=0;int rc=fstat(fd,&before),native_error=rc<0?errno:0;
        if(rc)error=boot_failure(PW_WC_DIAG_RUNTIME_STAT,rc,native_error,i,0);
        else if(!S_ISREG(before.st_mode))error=boot_failure(PW_WC_DIAG_RUNTIME_TYPE,0,0,i,0);
        else if(before.st_size<=0||(uint64_t)before.st_size>128u*1024u*1024u)
            error=boot_failure(PW_WC_DIAG_RUNTIME_SIZE,0,0,i,0);
        PwWineChildHash state;pw_wine_child_hash_init(&state);uint64_t count=0;
        while(!error&&count<(uint64_t)before.st_size){unsigned char bytes[4096];
            size_t wanted=(uint64_t)before.st_size-count;if(wanted>sizeof(bytes))wanted=sizeof(bytes);
            if(boot_budget()){error=-1;break;}
            errno=0;ssize_t got=read(fd,bytes,wanted);native_error=got<0?errno:0;
            if(got<=0||(size_t)got>wanted){error=boot_failure(PW_WC_DIAG_RUNTIME_READ,(int32_t)got,native_error,i,0);break;}
            if(pw_wine_child_hash_update(&state,bytes,(size_t)got)){
                error=boot_failure(PW_WC_DIAG_RUNTIME_HASH,-1,0,i,0);break;}
            count+=(uint64_t)got;if(boot_budget())error=-1;
        }
        if(!error){unsigned char extra;
            errno=0;ssize_t got=read(fd,&extra,1);native_error=got<0?errno:0;
            if(got!=0)error=boot_failure(PW_WC_DIAG_RUNTIME_EXTRA_READ,(int32_t)got,native_error,i,0);
            if(!error){
                errno=0;rc=fstat(fd,&after);native_error=rc<0?errno:0;
                if(rc)error=boot_failure(PW_WC_DIAG_RUNTIME_STAT,rc,native_error,i,0);
                else if(before.st_dev!=after.st_dev||before.st_ino!=after.st_ino||before.st_size!=after.st_size)
                    error=boot_failure(PW_WC_DIAG_RUNTIME_CHANGED,0,0,i,0);
            }
        }
        if(!error){pw_wine_child_hash_final(&state,actual);
            if(strcmp(actual,hash))error=boot_failure(PW_WC_DIAG_RUNTIME_HASH,-1,0,i,0);}
        /* Close once; a later close failure cannot replace the first error. */
        errno=0;rc=close(fd);native_error=rc<0?errno:0;
        if(rc)error=boot_failure(PW_WC_DIAG_RUNTIME_CLOSE,rc,native_error,i,0);
        if(boot_budget()||error)return -1;
        if(!found){
            if(strlen(roots[i])>=size)return boot_failure(PW_WC_DIAG_RUNTIME_PATH,-1,0,i,0);
            strcpy(out,roots[i]);found=1;
        }
    }
    return found?0:boot_failure(PW_WC_DIAG_RUNTIME_OPEN,first_open_raw,first_open_error,first_open_index,0);
}
static int set_env(const char *name,const char *value){return setenv(name,value,1);}
static void add_log_loss(atomic_ullong *counter,unsigned long long amount)
{
    unsigned long long old=atomic_load(counter);
    for(unsigned attempt=0;attempt<8;attempt++){
        unsigned long long next=amount>ULLONG_MAX-old?ULLONG_MAX:old+amount;
        int overflow=amount>ULLONG_MAX-old;
        if(atomic_compare_exchange_weak(counter,&old,next)){if(overflow)atomic_store(&log_counts_incomplete,1);return;}
    }
    atomic_store(&log_counts_incomplete,1); /* lower-bound snapshots after contention */
}
static void dropped_log(size_t size)
{
    add_log_loss(&log_dropped_records,1);
    add_log_loss(&log_dropped_bytes,(unsigned long long)size);
}
/* Caller owns log_lock. Never calls output recursively. Counter values are
 * snapshots/lower bounds; an abrupt Wine exit may preempt a later snapshot. */
static void log_loss_locked(void)
{
    if(atomic_load(&runtime_failure)||log_loss_marker||(!atomic_load(&log_dropped_records)&&!atomic_load(&log_counts_incomplete)))return;
    char line[256];
    int n=snprintf(line,sizeof(line),"PW_WINE_CHILD_LOG incomplete=1 snapshot=1 dropped_records=%llu dropped_bytes=%llu counts_incomplete=%u\n",
        atomic_load(&log_dropped_records),atomic_load(&log_dropped_bytes),atomic_load(&log_counts_incomplete));
    if(n<=0||(size_t)n>=sizeof(line)||log_fd<0||log_bytes>65536-(size_t)n){atomic_store(&runtime_failure,1);return;}
    ssize_t rc=write(log_fd,line,(size_t)n);
    if(rc!=n){atomic_store(&runtime_failure,1);return;}
    log_bytes+=(size_t)n;log_loss_marker=1;
}
static void report_log_loss(void)
{
    if(active_session.profile!=PW_WC_PROFILE_BATTLENET||atomic_load(&runtime_failure)||
       (!atomic_load(&log_dropped_records)&&!atomic_load(&log_counts_incomplete)))return;
    int lock=pthread_mutex_trylock(&log_lock);
    if(lock){if(lock!=EBUSY)atomic_store(&runtime_failure,1);return;}
    log_loss_locked();
    if(pthread_mutex_unlock(&log_lock))atomic_store(&runtime_failure,1);
}
static void output(const char *text,size_t size)
{
    /* No stdout/fd0 setup. A contended vendor logger drops bounded diagnostics
     * rather than terminating the client. Real write/lock-release errors stay
     * failures. Reserve room for an explicit loss snapshot inside the64KiB cap. */
    if(!text||!size||atomic_load(&runtime_failure))return;
    int vendor=active_session.profile==PW_WC_PROFILE_BATTLENET;
    int lock=pthread_mutex_trylock(&log_lock);
    if(lock){
        if(vendor&&lock==EBUSY)dropped_log(size);else atomic_store(&runtime_failure,1);
        return;
    }
    size_t limit=vendor?65536-512:65536;
    if(log_fd<0)atomic_store(&runtime_failure,1);
    else if(log_bytes>limit||size>limit-log_bytes){
        if(vendor)dropped_log(size);else atomic_store(&runtime_failure,1);
    }
    else {ssize_t rc=write(log_fd,text,size);
        if(rc<0||(size_t)rc!=size)atomic_store(&runtime_failure,1);
        else log_bytes+=size;}
    if(vendor)log_loss_locked();
    if(pthread_mutex_unlock(&log_lock))atomic_store(&runtime_failure,1);
}
static void record(void *unused,unsigned stage,int status)
{
    char line[160];(void)unused;
    if(stage==PW_WCB_PATHS&&status)boot_failure(PW_WC_DIAG_PATHS_CONTROL,status,0,0,0);
    int n=snprintf(line,sizeof(line),"PW_WINE_CHILD_BOOT stage=%u status=%d\n",stage,status);
    if(n>0&&(size_t)n<sizeof(line))output(line,(size_t)n);
}
static void *trampoline(void *unused)
{
    (void)unused;thread_start.entry(thread_start.arg);
    atomic_store(&runtime_failure,2);return NULL;
}
static int start_thread(void(*entry)(void*),void *arg,size_t stack)
{
    pthread_attr_t attr;pthread_t thread;
    int rc=pthread_attr_init(&attr);if(rc)return rc;
    rc=pthread_attr_setstacksize(&attr,stack);
    if(rc){(void)pthread_attr_destroy(&attr);return rc;}
    thread_start.entry=entry;thread_start.arg=arg;
    rc=pthread_create(&thread,&attr,trampoline,NULL);
    int destroyed=pthread_attr_destroy(&attr);
    if(rc)return rc;
    /* Wine may already own the received fd; do not report no-start merely
     * because later attribute cleanup failed. The supervisor exits instead. */
    if(destroyed)atomic_store(&runtime_failure,3);
    return 0;
}
/* Diagnostic only, after a failed log open. No helper/grant, directory
 * creation, alternate path, retry or wait. Preserve the primary open error. */
static void observe_data(void)
{
    if(within_budget()){bootstrap_failure.auxiliary=PW_WC_DATA_BUDGET;return;}
    struct stat st;errno=0;int rc=stat("/data",&st),error=rc<0?errno:0;
    if(rc<0){bootstrap_failure.auxiliary=PW_WC_DATA_STAT_FAILED;bootstrap_failure.detail=error>0?error:0;}
    else if(rc){bootstrap_failure.auxiliary=PW_WC_DATA_UNEXPECTED;bootstrap_failure.detail=rc;}
    else bootstrap_failure.auxiliary=S_ISDIR(st.st_mode)?PW_WC_DATA_DIRECTORY:PW_WC_DATA_NOT_DIRECTORY;
}
static int open_log(const PwWineChildFrame *session)
{
    char path[256],line[256];
    int n=snprintf(path,sizeof(path),"/data/prospero-win/logs/wine-child-%s-%u-%llu.log",
                   PW_WINE_CHILD_BUILD_ID,session->child_pid,(unsigned long long)session->generation);
    if(n<=0||(size_t)n>=sizeof(path))return boot_failure(PW_WC_DIAG_LOG_PATH,n,0,0,0);
    errno=0;log_fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_NONBLOCK,0600);
    int error=log_fd<0?errno:0;
    if(log_fd<0){boot_failure(PW_WC_DIAG_LOG_OPEN,log_fd,error,0,0);observe_data();return -1;}
    n=snprintf(line,sizeof(line),"PW_WINE_CHILD build=%s generation=%llu native_pid=%u native_ppid=%u wine_pid=%u wine_tid=%u profile=%u machine=%04x\n",
       PW_WINE_CHILD_BUILD_ID,(unsigned long long)session->generation,session->child_pid,
       session->child_ppid,session->wine_pid,session->wine_tid,session->profile,session->machine);
    if(n<=0||(size_t)n>=sizeof(line))return boot_failure(PW_WC_DIAG_LOG_HEADER,n,0,0,0);
    size_t before=log_bytes;output(line,(size_t)n);
    if(log_bytes-before!=(size_t)n)return boot_failure(PW_WC_DIAG_LOG_HEADER,-1,0,0,0); /* mandatory header */
    if(session->profile==PW_WC_PROFILE_BATTLENET){
        static const char policy[]="PW_WINE_CHILD_LOG completeness=not_guaranteed quota=65536 loss_policy=nonfatal snapshot_counters=lower_bounds\n";
        before=log_bytes;output(policy,sizeof(policy)-1);
        if(log_bytes-before!=sizeof(policy)-1)return boot_failure(PW_WC_DIAG_LOG_HEADER,-1,0,0,0);
    }
    return atomic_load(&runtime_failure)?-1:0;
}
static int run_child(void)
{
    uint64_t begun;int fd=-1;
    if(clock_ms(NULL,&begun)||begun>UINT64_MAX-PW_WC_BATTLENET_LIFETIME_MS)return 10;
    child_io=(PwNativeChildIo){.clock_ms=clock_ms,.cancelled=cancelled,.ready=1,
        .last_clock=begun,.stage_end=begun+PW_WC_STARTUP_MS,.total_end=begun+PW_WC_BATTLENET_LIFETIME_MS};
    PwWineChildFrame hello={.kind=PW_WC_HELLO,.child_pid=(uint32_t)getpid(),.child_ppid=(uint32_t)getppid()};
    memcpy(hello.build_id,PW_WINE_CHILD_BUILD_ID,41);
    if(pw_wine_child_wire_validate(&child_io,3,&wire_result)||
       send_record(&hello))return 11;
    PwWineChildFrame *session=&active_session;
    int received=pw_wine_child_wire_receive(&child_io,3,PW_WC_KIND(PW_WC_BOOTSTRAP),session,&fd,&wire_result);
    if(received!=PW_WC_RECORD)return 12;
    if(session->child_pid!=hello.child_pid||session->child_ppid!=hello.child_ppid||
       memcmp(session->build_id,hello.build_id,41)){
        pw_wine_child_wire_close(&fd,&wire_result);return 13;}
    child_io.total_end=begun+(session->profile==PW_WC_PROFILE_FIXTURE?PW_WC_LIFETIME_MS:PW_WC_BATTLENET_LIFETIME_MS);
    const PwWineChildBootstrapOps ops={.context=session,.wine={sceKernelLoadStartModule,sceKernelGetModuleInfo,set_env,start_thread},
        .runtime=runtime,.directory=directory,.register_thread=pw_wine_thread_register,
        .unregister_thread=pw_wine_thread_unregister,.output=output,.socket_sink=socket_failure_sink,.record=record};
    int rc=open_log(session);
    if(!rc)rc=pw_wine_child_bootstrap_prepare(&bootstrap,&child_io,fd,PW_WINE_CHILD_NTDLL_SHA256,
                                             PW_WINE_CHILD_PRIVATE_DISPATCH_ABI,session->profile,session->machine,&ops);
    PwWineChildFrame reply=*session;
    if(rc){reply.kind=PW_WC_FAILURE;reply.status=-(int)(bootstrap.stage?bootstrap.stage:1);
        reply.failure_api=bootstrap_failure.api;reply.failure_raw=bootstrap_failure.raw;
        reply.native_error=bootstrap_failure.error;reply.errno_valid=bootstrap_failure.errno_valid;
        reply.returned_length=bootstrap_failure.auxiliary;reply.returned_value=bootstrap_failure.detail;
        (void)send_bootstrap_failure(&reply);
        pw_wine_child_wire_close(&fd,&wire_result);return 14;}
    reply.kind=PW_WC_BOOTSTRAP_ACK;
    if(send_record(&reply)){
        pw_wine_child_wire_close(&fd,&wire_result);return 15;}
    rc=pw_wine_child_bootstrap_start(&bootstrap,&child_io,&ops);
    if(bootstrap.started)fd=-1; /* only ntdll now owns the transferred stream */
    if(rc){pw_wine_child_wire_close(&fd,&wire_result);return 16;}
    child_io.stage_end=child_io.total_end; /* original lifetime, never renewed */
    uint32_t sequence=2;
    for(;;){PwWineChildFrame request;int unexpected=-1;PwWineFixtureSocketResult failure;
        report_log_loss();
        if(bootstrap.socket_failure(&failure)){socket_failure_sink(session,&failure);return 21;}
        rc=pw_wine_child_wire_receive_step(&child_io,3,PW_WC_KIND(PW_WC_SIGNAL),&request,&unexpected,&wire_result);
        if(rc==PW_WC_IDLE)continue;
        if(rc!=PW_WC_RECORD)return 17;
        if(!pw_wine_child_wire_same_session(session,&request)||request.sequence!=sequence||
           request.target_tid>LONG_MAX)return 18;
        errno=0;int sent=pw_wine_thread_kill((pid_t)session->child_pid,(long)request.target_tid,request.signal);
        int error=sent<0?errno:0;
        request.kind=PW_WC_SIGNAL_ACK;request.status=sent? -1:0;request.native_error=sent?(error>0?error:EIO):0;
        if(send_record(&request))return 19;
        if(sent||sequence==UINT32_MAX)return 20;
        sequence++;
    }
}
int main(int argc,char **argv)
{
    (void)argc;(void)argv;int result=run_child();
    /* After starting Wine another thread may be sending a failure or writing
     * its sink. Do not close/reuse those descriptors beneath a live callback;
     * finite whole-process teardown settles them. Before that, this is the
     * only thread and owns the once-only explicit closes. */
    if(!bootstrap.started){
        if(log_fd>=0){int owned=log_fd;log_fd=-1;(void)close(owned);}
        (void)close(3);
    }
    _exit(result); /* a finite supervisor failure, never Windows success */
}
