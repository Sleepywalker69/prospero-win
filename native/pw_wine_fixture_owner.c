/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _POSIX_C_SOURCE 200809L
#include "pw_wine_fixture_owner.h"
#include "pw_wine_child_bootstrap.h"
#include "pw_wine_child_wire.h"
#include "pw_wine_child_data.h"
#if PW_WINE_CHILD_UI_ENABLED
#include "pw_wine_child_ui_runtime.h"
#endif
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

int sceSystemServiceGetAppStatus(void *);
int sceSystemServiceGetLocalProcessStatusList(void *,unsigned,unsigned *);
int sceSystemServiceAddLocalProcess(int,const char *,const char *const *,const void *);
int sceSystemServiceKillLocalProcess(int,int);
enum { WF_OK=0, WF_BAD=0xc0000001u, WF_UNSUPPORTED=0xc00000bbu,
       WF_TIMEOUT=0xc00000b5u, WF_CANCELLED=0xc0000120u };
enum { API_CLOCK=1,API_IMAGE,API_CLOSE,API_APP,API_LIST,API_PAIR,API_ADD,
       API_DUP,API_HANDOFF,API_SIGNAL,API_KILL,API_WINE,API_SOCKET };
enum { G_EMPTY,G_ADMITTED,G_BOUND,G_LAUNCH,G_STARTING,G_RUNNING,G_SETTLING,G_RETIRED,G_UNCERTAIN,G_REQUESTED,G_SUBMITTING,G_HELPER_DRAIN,G_CLEANUP };
#define CANARY UINT32_C(0x4a357bc1)
typedef struct { int32_t id;char name[32]; } ServiceEntry;
typedef struct { uint32_t size;int32_t fd,crash;uint32_t other[15]; } ServiceOptions;
_Static_assert(sizeof(ServiceEntry)==36 && sizeof(ServiceOptions)==72,"service ABI");
static const char *const helpers[]={"/app0/native-wine-child.self","/mnt/sandbox/PPSA99995_000/app0/native-wine-child.self"};

typedef struct Generation {
    atomic_uint state,released,startup_done,startup_success,cleanup_requested,identity_ready,launch_failed;
    atomic_uint startup_status,pending_signal,signal_sequence,signal_ack,signal_failure;
    atomic_flag send_claim;
    atomic_uint origin_dead,remote_lease,abandoned,request_status;
    PwWineCreationRequest creation;
    unsigned depth,start_phase,progress_stage,helper_cancel_attempted,startup_stop_reported;
    uint64_t generation,started,startup_end,end,last_clock,next_list,helper_recovery_end;
    uint32_t caller_pid,caller_tid,wine_pid,wine_tid,machine;
    int stream_fd,control_fd,passed_fd,service_id,baseline[PW_WFO_LIST_CAP];
    unsigned baseline_count,launch_possible,hello,ack,listed,absent,kill_called,closed,list_calls,close_pending,missing_reported;
    unsigned helper_possible; /* cleared only by an exact positive settlement certificate */
    int kill_result;
    PwWineChildFrame session,signal;
    PwNativeChildIo io;
    struct PwWineFixtureOwner *owner;
    PwWineChildWireResult wire,helper_drain_wire;
    ServiceOptions options;
    const char *arguments[2];
#if PW_WINE_CHILD_UI_ENABLED
    PwWineChildUiOwner ui;
    unsigned ui_retirement_reported;
#endif
} Generation;
struct PwWineFixtureOwner {
    PwWineFixtureOwnerConfig config;
    Generation generations[PW_WFO_MAX_GENERATIONS];
    atomic_uint initialized,cancelled,blocked,uncertain,admission_claim,count;
    atomic_uint failure_state,root_done,root_result,release_ready,admission_closed,active_callbacks,root_detach_state;
    pthread_mutex_t clock_lock;
    unsigned failure_api,failure_reported;int64_t failure_raw;int failure_errno;
    uint64_t started,end,last_clock;
    int app_id,helper_index;
    uint32_t root_pid,root_tid;
    unsigned creation_enabled;
};
#if PW_WINE_CHILD_UI_ENABLED
static void retire_ui(PwWineFixtureOwner *,Generation *);
#endif
static void failure(PwWineFixtureOwner *o,unsigned api,int64_t raw,int error,int uncertain)
{
    unsigned expected=0;
    atomic_store(&o->blocked,1);
    if(uncertain)atomic_store(&o->uncertain,1);
    if(atomic_compare_exchange_strong(&o->failure_state,&expected,1)){
        o->failure_api=api;o->failure_raw=raw;o->failure_errno=error;
        atomic_store_explicit(&o->failure_state,2,memory_order_release);
    }
}
static int sample_clock(PwWineFixtureOwner *o,uint64_t *value)
{
    uint64_t t=0;int bad=0;
    if(pthread_mutex_lock(&o->clock_lock)){failure(o,API_CLOCK,-1,0,0);return -1;}
    if(o->config.clock_ms(o->config.context,&t)||t<o->last_clock)bad=1;
    else o->last_clock=t;
    if(pthread_mutex_unlock(&o->clock_lock))bad=1;
    if(bad){failure(o,API_CLOCK,-1,0,0);return -1;}
    *value=t;return 0;
}
static int clock_now(PwWineFixtureOwner *o,uint64_t end,uint64_t *value,int cleanup)
{
    uint64_t t;
    if(sample_clock(o,&t))return -1;
    if(t>=end){failure(o,API_CLOCK,0,0,0);return -1;}
    if(!cleanup&&(atomic_load(&o->cancelled)||o->config.cancelled(o->config.context))){
        atomic_store(&o->cancelled,1);failure(o,API_CLOCK,0,0,0);return -1;
    }
    *value=t;return 0;
}
static void close_slot(PwWineFixtureOwner *o,int *slot)
{
    if(*slot<0)return;
    int fd=*slot;*slot=-1;int rc=close(fd),error=rc<0?errno:0;
    if(rc)failure(o,API_CLOSE,rc,error,1);
}
static Generation *find(PwWineFixtureOwner *o,uint64_t id)
{
    unsigned count=atomic_load_explicit(&o->count,memory_order_acquire);
    for(unsigned i=0;i<count&&i<PW_WFO_MAX_GENERATIONS;i++)
        if(o->generations[i].generation==id)return &o->generations[i];
    return NULL;
}
static int pause_client(PwWineFixtureOwner *o,uint64_t end,uint64_t *last)
{
    uint64_t now;
    if(atomic_load(&o->root_done)||clock_now(o,end,&now,0)||now<*last){failure(o,API_CLOCK,0,0,0);return -1;}
    *last=now;struct timespec delay={0,10000000};
    if(nanosleep(&delay,NULL)){failure(o,API_CLOCK,-1,errno,0);return -1;}
    return 0;
}
static int check_image_path(PwWineFixtureOwner *o,const char *path)
{
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_NONBLOCK);
    if(fd<0){failure(o,API_IMAGE,-1,errno,0);return -1;}
    struct stat st;int rc=fstat(fd,&st),err=rc<0?errno:0;
    if(rc||!S_ISREG(st.st_mode)||st.st_size<=0||st.st_size>64*1024*1024){
        failure(o,API_IMAGE,rc,err,0);close_slot(o,&fd);return -1;
    }
    PwWineChildHash hash;pw_wine_child_hash_init(&hash);uint64_t count=0,now;
    unsigned char bytes[4096];
    while(count<(uint64_t)st.st_size){
        if(clock_now(o,o->end,&now,0)){close_slot(o,&fd);return -1;}
        ssize_t got=read(fd,bytes,sizeof(bytes));err=got<0?errno:0;
        if(got<=0||(uint64_t)got>(uint64_t)st.st_size-count||pw_wine_child_hash_update(&hash,bytes,(size_t)got)){
            failure(o,API_IMAGE,got,err,0);close_slot(o,&fd);return -1;
        }
        count+=(uint64_t)got;
    }
    ssize_t extra=read(fd,bytes,1);err=extra<0?errno:0;
    char hex[65];pw_wine_child_hash_final(&hash,hex);close_slot(o,&fd);
    if(extra||strcmp(hex,o->config.child_sha256)){failure(o,API_IMAGE,extra,err,0);return -1;}
    return atomic_load(&o->blocked)?-1:0;
}
static int check_image(PwWineFixtureOwner *o)
{return check_image_path(o,o->config.child_unix_path);}
static int admitted_path(PwWineFixtureOwner *o,const char *path,uint32_t machine)
{
    if(!path)return 0;
    const PwWineIpcProfile *ipc=pw_wine_ipc_profile(o->config.profile);
    if(ipc)return PW_WINE_IPC_PROFILE_ENABLED&&machine==PW_WINE_FIXTURE_AMD64&&
        (!strcmp(path,ipc->native_image)||!strcmp(path,ipc->native_alias));
    if(o->config.profile==1){
        static const char alias[]="/data/prospero-win/prefixes/windows-child-fixture-v1/dosdevices/c:/windows-child-fixture/child.exe";
        return machine==PW_WINE_FIXTURE_AMD64&&
            (!strcmp(path,o->config.child_unix_path)||!strcmp(path,alias));
    }
    if(o->config.profile==3){
        static const char alias[]="/data/prospero-win/prefixes/windows-child-user-v1/dosdevices/c:/windows-child-user/user-child.exe";
        return machine==PW_WINE_FIXTURE_AMD64&&
            (!strcmp(path,o->config.child_unix_path)||!strcmp(path,alias));
    }
    if(o->config.profile==4){
        static const char alias[]="/data/prospero-win/prefixes/windows-child-net-v1/dosdevices/c:/windows-child-net/net-child.exe";
        return machine==PW_WINE_FIXTURE_AMD64&&
            (!strcmp(path,o->config.child_unix_path)||!strcmp(path,alias));
    }
    if(o->config.profile!=2||
       (machine!=PW_WINE_FIXTURE_AMD64&&machine!=PW_WINE_FIXTURE_I386))return 0;
    static const char drive[]="/data/prospero-win/prefixes/battlenet-experimental-v1/drive_c/";
    static const char alias[]="/data/prospero-win/prefixes/battlenet-experimental-v1/dosdevices/c:/";
    const char *relative=NULL;
    if(!strncmp(path,drive,sizeof(drive)-1))relative=path+sizeof(drive)-1;
    else if(!strncmp(path,alias,sizeof(alias)-1))relative=path+sizeof(alias)-1;
    if(!relative||!*relative)return 0;
    /* No parent traversal, empty components or device paths. Wine's already
     * successful image lookup/serialized startup remains the authority. */
    for(const char *at=relative;*at;){
        const char *end=strchr(at,'/');size_t n=end?(size_t)(end-at):strlen(at);
        if(!n||(n==1&&at[0]=='.')||(n==2&&at[0]=='.'&&at[1]=='.')||memchr(at,'\\',n))return 0;
        if(!end)break;
        at=end+1;if(!*at)return 0;
    }
    const char *name=strrchr(relative,'/');name=name?name+1:relative;
    /* Prefix construction must finish before this mode. Bootstrap helpers
     * cannot consume the first caller/generation intended for the selected PE. */
    return strcmp(name,"wineboot.exe")&&strcmp(name,"winedevice.exe");
}
static uint32_t admit(void *context,uint32_t pid,uint32_t tid,uint32_t machine,const char *path,uint64_t *out)
{
    PwWineFixtureOwner *o=context;unsigned zero=0;uint64_t now,last;
    if(!out||!pid||!tid||!admitted_path(o,path,machine))return WF_UNSUPPORTED;
    if(!atomic_compare_exchange_strong(&o->admission_claim,&zero,1))return WF_UNSUPPORTED;
    uint32_t status=WF_BAD;
    if(atomic_load(&o->admission_closed)||atomic_load(&o->root_done)||clock_now(o,o->end-PW_WFO_CLEANUP_MS,&last,0))goto done;
    while(!atomic_load_explicit(&o->initialized,memory_order_acquire)){
        if(atomic_load(&o->blocked)||pause_client(o,o->end-PW_WFO_CLEANUP_MS,&last))goto done;
    }
    unsigned count=atomic_load_explicit(&o->count,memory_order_acquire);
    const PwWineIpcProfile *ipc=pw_wine_ipc_profile(o->config.profile);
    unsigned cap=ipc?ipc->direct_children:o->config.profile==1?3:(o->config.profile==3||o->config.profile==4)?1:PW_WFO_MAX_GENERATIONS;
    if(count>=cap||(o->root_pid&&o->root_pid!=pid))goto done;
    for(unsigned i=0;i<count;i++)
        if(o->generations[i].caller_tid==tid&&atomic_load(&o->generations[i].state)==G_ADMITTED)goto done;
    if(count&&o->config.profile==1){
        Generation *previous=&o->generations[count-1];
        while(atomic_load_explicit(&previous->state,memory_order_acquire)!=G_RETIRED){
            if(atomic_load(&o->blocked)||pause_client(o,o->end-PW_WFO_CLEANUP_MS,&last))goto done;
        }
    }
    if(atomic_load(&o->blocked)||(ipc?check_image_path(o,path):((o->config.profile==1||o->config.profile==3||o->config.profile==4)&&check_image(o)))||
       clock_now(o,o->end-PW_WFO_CLEANUP_MS,&now,0)||atomic_load(&o->root_done))goto done;
    Generation *g=&o->generations[count];
    g->generation=(o->config.session&~UINT64_C(31))+(uint64_t)count+1;
    g->caller_pid=pid;g->caller_tid=tid;g->machine=machine;g->depth=1;g->started=g->last_clock=now;
    uint64_t limit=o->end-PW_WFO_CLEANUP_MS;
    unsigned lifetime=(ipc||o->config.profile==1)?PW_WFO_CHILD_MS:o->config.profile==3?PW_WFO_USER_CHILD_MS:o->config.profile==4?PW_WFO_NET_CHILD_MS:PW_WFO_VENDOR_CHILD_MS;
    g->startup_end=limit-now<PW_WFO_STARTUP_MS?limit:now+PW_WFO_STARTUP_MS;
    g->end=limit-now<lifetime?limit:now+lifetime;
    o->root_pid=pid;
    atomic_store_explicit(&g->state,G_ADMITTED,memory_order_release);
    atomic_store_explicit(&o->count,count+1,memory_order_release);
    *out=g->generation;status=WF_OK;
 done:atomic_store(&o->admission_claim,0);return status;
}
static uint32_t bind_process(void *context,uint32_t pid,uint32_t tid,uint32_t child,uint64_t *out)
{
    PwWineFixtureOwner *o=context;unsigned count=atomic_load_explicit(&o->count,memory_order_acquire);
    if(!out||!child||!count||atomic_load(&o->blocked)||atomic_load(&o->root_done))return WF_BAD;
    Generation *g=NULL;
    for(unsigned i=0;i<count;i++){
        Generation *candidate=&o->generations[i];
        if(atomic_load_explicit(&candidate->state,memory_order_acquire)==G_ADMITTED&&
           pid==candidate->caller_pid&&tid==candidate->caller_tid){
            if(g)return WF_BAD;
            g=candidate;
        }
    }
    if(!g)return WF_BAD;
    g->wine_pid=child;*out=g->generation;atomic_store_explicit(&g->state,G_BOUND,memory_order_release);return WF_OK;
}
static void release_process(void *context,uint64_t id,uint32_t pid)
{
    PwWineFixtureOwner *o=context;Generation *g=find(o,id);
    if(!g||g->wine_pid!=pid||atomic_exchange(&g->released,1))failure(o,API_WINE,pid,0,1);
}
static uint32_t remaining(void *context,uint64_t id)
{
    PwWineFixtureOwner *o=context;Generation *g=find(o,id);uint64_t now;
    if(!g||atomic_load(&g->origin_dead)||atomic_load(&o->blocked)||atomic_load(&o->root_done)||clock_now(o,g->startup_end,&now,0))return 0;
    uint64_t n=g->startup_end-now;return n>PW_WFO_STARTUP_MS?0:(uint32_t)n;
}
static uint32_t spawn(void *context,uint64_t id,int borrowed,uint32_t pid,uint32_t tid)
{
    PwWineFixtureOwner *o=context;Generation *g=find(o,id);uint64_t last;
    if(!g||g->wine_pid!=pid||!tid||atomic_load_explicit(&g->state,memory_order_acquire)!=G_BOUND||!remaining(o,id))return WF_BAD;
    int fd=dup(borrowed),error=fd<0?errno:0;
    if(fd<0){failure(o,API_DUP,fd,error,0);return WF_BAD;}
    PwWineFixtureSocketResult prepared;
    if(pw_wine_fixture_socket_prepare(fd,PW_WF_SOCKET_CLOEXEC,&prepared)){
        pw_wine_fixture_owner_socket_failure(o,&prepared);close_slot(o,&fd);return WF_BAD;
    }
    if(!remaining(o,id)){close_slot(o,&fd);return WF_TIMEOUT;}
    g->stream_fd=fd;g->wine_tid=tid;last=g->started;
    atomic_store_explicit(&g->state,G_LAUNCH,memory_order_release);
    while(atomic_load_explicit(&g->state,memory_order_acquire)!=G_RUNNING){
        if(atomic_load(&o->blocked)||pause_client(o,g->startup_end,&last)){
            atomic_store(&g->cleanup_requested,1);
            if(atomic_load(&o->cancelled))return WF_CANCELLED;
            return atomic_load_explicit(&g->launch_failed,memory_order_acquire)?WF_BAD:WF_TIMEOUT;
        }
    }
    return remaining(o,id)?WF_OK:WF_TIMEOUT;
}
static void startup_result(void *context,uint64_t id,uint32_t success,uint32_t status)
{
    PwWineFixtureOwner *o=context;Generation *g=find(o,id);
    unsigned empty=0;
    if(!g||!atomic_compare_exchange_strong(&g->startup_done,&empty,1)){failure(o,API_WINE,status,0,1);return;}
    atomic_store(&g->startup_success,success);atomic_store(&g->startup_status,status);
    atomic_store_explicit(&g->startup_done,2,memory_order_release);
    if(!success||status){failure(o,API_WINE,status,0,0);atomic_store(&g->cleanup_requested,1);}
}
static int signal_request(void *context,uint64_t id,uint32_t pid,int32_t native,int64_t tid,int32_t signal)
{
    PwWineFixtureOwner *o=context;Generation *g=find(o,id);
    if(!g||atomic_load_explicit(&g->state,memory_order_acquire)!=G_RUNNING||
       g->wine_pid!=pid||native!=(int32_t)g->session.child_pid||tid<=0||atomic_load(&o->blocked)||
       atomic_load(&o->cancelled)||(signal!=PW_WC_SIGNAL_QUIT&&signal!=PW_WC_SIGNAL_USR1))return PW_WF_SIGNAL_FAILED;
    if(atomic_flag_test_and_set_explicit(&g->send_claim,memory_order_acquire))return PW_WF_SIGNAL_FAILED;
    int result=PW_WF_SIGNAL_FAILED;
    if(atomic_load_explicit(&g->state,memory_order_acquire)==G_RUNNING&&g->control_fd>=0&&!atomic_load(&g->pending_signal)){
        PwWineChildFrame frame=g->session;frame.kind=PW_WC_SIGNAL;
        frame.sequence=atomic_fetch_add(&g->signal_sequence,1)+2;frame.target_tid=tid;frame.signal=signal;
        if(frame.sequence<=17){
            g->signal=frame;atomic_store_explicit(&g->pending_signal,1,memory_order_release);
            PwWineChildWireResult wire={0};
            if(!pw_wine_child_wire_try_send(g->control_fd,&frame,-1,&wire))result=PW_WF_SIGNAL_QUEUED;
            else {failure(o,API_SIGNAL,wire.raw_result,wire.native_error,wire.ownership_uncertain);atomic_store(&g->cleanup_requested,1);}
        }
    }
    atomic_flag_clear_explicit(&g->send_claim,memory_order_release);
    if(result!=PW_WF_SIGNAL_QUEUED){failure(o,API_SIGNAL,signal,0,0);atomic_store(&g->cleanup_requested,1);}
    return result;
}
static uint32_t process_state(void *context,uint64_t id,uint32_t pid,int32_t native,uint32_t cleanup)
{
    PwWineFixtureOwner *o=context;Generation *g=find(o,id);
    if(!g||g->wine_pid!=pid||(native>0&&atomic_load_explicit(&g->identity_ready,memory_order_acquire)&&native!=(int32_t)g->session.child_pid)){
        failure(o,API_WINE,native,0,1);return PW_WF_OWNED_UNCERTAIN;
    }
    if(cleanup)atomic_store(&g->cleanup_requested,1);
    unsigned state=atomic_load_explicit(&g->state,memory_order_acquire);
    return state==G_RETIRED?PW_WF_OWNED_RETIRED:state==G_UNCERTAIN?PW_WF_OWNED_UNCERTAIN:PW_WF_OWNED_ACTIVE;
}
static uint32_t root_exit(void *context,uint32_t status)
{
    PwWineFixtureOwner *o=context;unsigned expected=0;
    if(atomic_compare_exchange_strong(&o->root_done,&expected,1)){
        atomic_store(&o->root_result,status);
        atomic_store_explicit(&o->root_done,2,memory_order_release);
    }
    expected=0;
    if(!atomic_compare_exchange_strong(&o->admission_claim,&expected,1))return 0;
    if(!o->creation_enabled||o->config.profile!=2)
        atomic_store_explicit(&o->admission_closed,1,memory_order_release);
    unsigned ready=atomic_load_explicit(&o->release_ready,memory_order_acquire)==2;
    atomic_store(&o->admission_claim,0);
    return ready;
}
/* One atomic closed-bit/count gate seals callback entry from exactly zero.
 * Records/modules remain alive until native process exit; late calls cannot
 * acquire leases or manufacture a result for an already retired generation. */
#define CALLBACKS_CLOSED (1u<<31)
static int callback_enter(PwWineFixtureOwner *o)
{
    unsigned value=atomic_load_explicit(&o->active_callbacks,memory_order_acquire);
    for(unsigned attempt=0;attempt<8;attempt++){
        if(value&CALLBACKS_CLOSED||value==CALLBACKS_CLOSED-1)return 0;
        if(atomic_compare_exchange_weak_explicit(&o->active_callbacks,&value,value+1,
                                                memory_order_acq_rel,memory_order_acquire))return 1;
    }
    return 0;
}
static uint32_t counted_admit(void *context,uint32_t a,uint32_t b,uint32_t c,const char *d,uint64_t *e)
{
    PwWineFixtureOwner *o=context;
    if(!callback_enter(o))return WF_UNSUPPORTED;
    uint32_t result=admit(context,a,b,c,d,e);
    atomic_fetch_sub_explicit(&o->active_callbacks,1,memory_order_release);
    return result;
}
static uint32_t counted_bind_process(void *context,uint32_t a,uint32_t b,uint32_t c,uint64_t *d)
{
    PwWineFixtureOwner *o=context;
    if(!callback_enter(o))return WF_BAD;
    uint32_t result=bind_process(context,a,b,c,d);
    atomic_fetch_sub_explicit(&o->active_callbacks,1,memory_order_release);
    return result;
}
static void counted_release_process(void *context,uint64_t a,uint32_t b)
{
    PwWineFixtureOwner *o=context;
    if(!callback_enter(o))return;
    release_process(context,a,b);
    atomic_fetch_sub_explicit(&o->active_callbacks,1,memory_order_release);
}
static uint32_t counted_spawn(void *context,uint64_t a,int b,uint32_t c,uint32_t d)
{
    PwWineFixtureOwner *o=context;
    if(!callback_enter(o))return WF_CANCELLED;
    uint32_t result=spawn(context,a,b,c,d);
    atomic_fetch_sub_explicit(&o->active_callbacks,1,memory_order_release);
    return result;
}
static uint32_t counted_remaining(void *context,uint64_t a)
{
    PwWineFixtureOwner *o=context;
    if(!callback_enter(o))return 0;
    uint32_t result=remaining(context,a);
    atomic_fetch_sub_explicit(&o->active_callbacks,1,memory_order_release);
    return result;
}
static void counted_startup_result(void *context,uint64_t a,uint32_t b,uint32_t c)
{
    PwWineFixtureOwner *o=context;
    if(!callback_enter(o))return;
    startup_result(context,a,b,c);
    atomic_fetch_sub_explicit(&o->active_callbacks,1,memory_order_release);
}
static int counted_signal_request(void *context,uint64_t a,uint32_t b,int32_t c,int64_t d,int32_t e)
{
    PwWineFixtureOwner *o=context;
    if(!callback_enter(o))return PW_WF_SIGNAL_FAILED;
    int result=signal_request(context,a,b,c,d,e);
    atomic_fetch_sub_explicit(&o->active_callbacks,1,memory_order_release);
    return result;
}
static uint32_t counted_process_state(void *context,uint64_t a,uint32_t b,int32_t c,uint32_t d)
{
    PwWineFixtureOwner *o=context;
    if(!callback_enter(o))return PW_WF_OWNED_UNCERTAIN;
    uint32_t result=process_state(context,a,b,c,d);
    atomic_fetch_sub_explicit(&o->active_callbacks,1,memory_order_release);
    return result;
}
static void root_detached(void *context,uint32_t success,int32_t raw,int32_t error)
{
    PwWineFixtureOwner *o=context;unsigned empty=0;
    if(!atomic_compare_exchange_strong(&o->root_detach_state,&empty,success?1u:2u)){
        failure(o,API_WINE,raw,error,1);return;
    }
    if(!success)failure(o,API_WINE,raw,error,1);
}
/* These callbacks execute on the serialized Wine server. They only perform
 * bounded copies, comparisons and atomic publication, never native I/O/waits. */
static uint32_t creation_prepare(void *context,const PwWineCreationRequest *q,uint64_t *out)
{
    PwWineFixtureOwner *o=context;unsigned claim=0;uint32_t result=WF_UNSUPPORTED;
    if(!q||!out||!callback_enter(o))return result;
    if(!o->creation_enabled||o->config.profile!=2||!q->origin||!q->lease||!q->key||
       !q->caller_pid||!q->caller_tid||!q->image_bytes||q->image_bytes>PW_WINE_CREATION_IMAGE_BYTES||
       (q->image_bytes&1)||q->path_bytes<2||q->path_bytes>PW_WINE_CREATION_PATH_BYTES||
       q->path[q->path_bytes-1]||memchr(q->path,0,q->path_bytes-1)||
       q->now<o->started||q->deadline<=q->now||q->deadline-q->now>PW_WFO_STARTUP_MS||
       atomic_load(&o->blocked)||atomic_load(&o->cancelled)||atomic_load(&o->admission_closed))goto done;
    if(!atomic_compare_exchange_strong(&o->admission_claim,&claim,1))goto done;
    Generation *origin=find(o,q->origin);unsigned count=atomic_load_explicit(&o->count,memory_order_acquire);
    unsigned origin_state=origin?atomic_load_explicit(&origin->state,memory_order_acquire):G_EMPTY;
    if(!origin||!atomic_load_explicit(&origin->identity_ready,memory_order_acquire)||
       origin->wine_pid!=q->caller_pid||origin->depth>=2||atomic_load(&origin->origin_dead)||
       (origin_state!=G_RUNNING&&origin_state!=G_STARTING)||count>=PW_WFO_MAX_GENERATIONS||
       q->now>=o->end-PW_WFO_CLEANUP_MS||atomic_load(&o->admission_closed))goto unlock;
    for(unsigned i=0;i<count;i++)if(o->generations[i].creation.lease==q->lease)goto unlock;
    Generation *g=&o->generations[count];g->creation=*q;g->depth=origin->depth+1;
    g->generation=(o->config.session&~UINT64_C(31))+(uint64_t)count+1;
    g->caller_pid=q->caller_pid;g->caller_tid=q->caller_tid;g->machine=q->machine;
    g->started=g->last_clock=q->now;
    uint64_t limit=o->end-PW_WFO_CLEANUP_MS;
    g->startup_end=q->deadline<limit?q->deadline:limit;
    g->end=limit-q->now<PW_WFO_VENDOR_CHILD_MS?limit:q->now+PW_WFO_VENDOR_CHILD_MS;
    atomic_store(&g->remote_lease,1);
    atomic_store_explicit(&g->state,G_REQUESTED,memory_order_release);
    atomic_store_explicit(&o->count,count+1,memory_order_release);
    *out=g->generation;result=WF_OK;
 unlock:atomic_store(&o->admission_claim,0);
 done:atomic_fetch_sub_explicit(&o->active_callbacks,1,memory_order_release);return result;
}
static Generation *creation_find(PwWineFixtureOwner *o,uint64_t id,uint64_t lease)
{
    Generation *g=find(o,id);
    return g&&lease&&g->creation.lease==lease?g:NULL;
}
static int creation_origin_live(PwWineFixtureOwner *o,Generation *g)
{
    Generation *origin=g?find(o,g->creation.origin):NULL;
    if(!origin||atomic_load(&origin->origin_dead)||atomic_load(&origin->cleanup_requested))return 0;
    unsigned state=atomic_load_explicit(&origin->state,memory_order_acquire);
    return state==G_RUNNING||state==G_STARTING;
}
static uint32_t creation_budget(PwWineFixtureOwner *o,Generation *g,uint64_t now)
{
    if(atomic_load(&o->cancelled))return WF_CANCELLED;
    if(!g)return WF_BAD;
    /* The launch flag is independently published; failure metadata may still
     * be owned by another writer and is not needed to classify this result. */
    if(atomic_load_explicit(&g->launch_failed,memory_order_acquire))return WF_BAD;
    if(now<g->started)return WF_BAD;
    if(now>=g->startup_end)return WF_TIMEOUT;
    if(!creation_origin_live(o,g)||atomic_load(&g->abandoned)||
       atomic_load(&o->blocked)||atomic_load(&o->admission_closed))return WF_BAD;
    return WF_OK;
}
static uint32_t creation_query(void *context,uint64_t id,uint64_t lease,uint64_t now,PwWineCreationStatus *out)
{
    PwWineFixtureOwner *o=context;uint32_t result=WF_BAD;
    if(!out||!callback_enter(o))return result;
    Generation *g=creation_find(o,id,lease);
    if(!g)goto done;
    out->deadline=g->startup_end;out->status=atomic_load(&g->request_status);
    unsigned state=atomic_load_explicit(&g->state,memory_order_acquire);
    out->phase=state==G_REQUESTED?PW_WCR_PENDING:state==G_ADMITTED?PW_WCR_ADMITTED:
        state==G_BOUND?PW_WCR_BOUND:(state==G_LAUNCH||state==G_STARTING||state==G_SUBMITTING)?PW_WCR_SUBMITTED:
        (state==G_RUNNING||(state==G_RETIRED&&g->ack))?PW_WCR_BOOTSTRAPPED:PW_WCR_FAILED;
    uint32_t refusal=creation_budget(o,g,now);
    if(refusal){out->phase=PW_WCR_FAILED;if(refusal==WF_CANCELLED||!out->status)out->status=refusal;}
    if(out->phase==PW_WCR_FAILED&&!out->status)out->status=WF_BAD;
    result=WF_OK;
 done:atomic_fetch_sub_explicit(&o->active_callbacks,1,memory_order_release);return result;
}
static uint32_t creation_bind(void *context,uint64_t id,uint64_t lease,uint64_t now,
                              uint32_t pid,uint32_t machine,const void *image,uint32_t bytes)
{
    PwWineFixtureOwner *o=context;uint32_t result=WF_BAD;unsigned expected=G_ADMITTED;
    if(!callback_enter(o))return result;
    Generation *g=creation_find(o,id,lease);
    if(!pid||!image||creation_budget(o,g,now)||g->machine!=machine||g->creation.image_bytes!=bytes||
       memcmp(g->creation.image,image,bytes)||
       !atomic_compare_exchange_strong(&g->state,&expected,G_SUBMITTING))goto done;
    g->wine_pid=pid;atomic_store_explicit(&g->state,G_BOUND,memory_order_release);result=WF_OK;
 done:atomic_fetch_sub_explicit(&o->active_callbacks,1,memory_order_release);return result;
}
static uint32_t creation_submit(void *context,uint64_t id,uint64_t lease,uint64_t now,
                                uint32_t pid,uint32_t tid,int *stream)
{
    PwWineFixtureOwner *o=context;uint32_t result=WF_BAD;unsigned expected=G_BOUND;
    if(!stream||*stream<0||!callback_enter(o))return result;
    Generation *g=creation_find(o,id,lease);
    if(!tid||creation_budget(o,g,now)||g->wine_pid!=pid||
       !atomic_compare_exchange_strong(&g->state,&expected,G_SUBMITTING))goto done;
    g->stream_fd=*stream;*stream=-1;g->wine_tid=tid;
    atomic_store_explicit(&g->state,G_LAUNCH,memory_order_release);result=WF_OK;
 done:atomic_fetch_sub_explicit(&o->active_callbacks,1,memory_order_release);return result;
}
static uint32_t creation_result(void *context,uint64_t id,uint64_t lease,uint32_t success,uint32_t status)
{
    PwWineFixtureOwner *o=context;uint32_t result=WF_BAD;
    if(!callback_enter(o))return result;
    Generation *g=creation_find(o,id,lease);unsigned expected=1;
    if(g&&atomic_compare_exchange_strong(&g->remote_lease,&expected,2)){
        startup_result(o,id,success,status);atomic_store_explicit(&g->remote_lease,0,memory_order_release);result=WF_OK;
    }
    atomic_fetch_sub_explicit(&o->active_callbacks,1,memory_order_release);return result;
}
static void creation_abandon(void *context,uint64_t id,uint64_t lease)
{
    PwWineFixtureOwner *o=context;if(!callback_enter(o))return;
    Generation *g=creation_find(o,id,lease);unsigned expected=1;
    if(g&&atomic_compare_exchange_strong(&g->remote_lease,&expected,0)){
        atomic_store(&g->abandoned,1);atomic_store(&g->cleanup_requested,1);
    }
    atomic_fetch_sub_explicit(&o->active_callbacks,1,memory_order_release);
}
static void creation_transport_failure(void *context,uint64_t id,uint64_t lease,int32_t raw,int32_t error)
{
    PwWineFixtureOwner *o=context;if(!callback_enter(o))return;
    Generation *g=creation_find(o,id,lease);
    failure(o,API_HANDOFF,raw,error,1);
    if(g)atomic_store_explicit(&g->state,G_UNCERTAIN,memory_order_release);
    atomic_fetch_sub_explicit(&o->active_callbacks,1,memory_order_release);
}
static void creation_origin_dead(void *context,uint64_t id,uint32_t pid)
{
    PwWineFixtureOwner *o=context;if(!callback_enter(o))return;
    Generation *g=find(o,id);
    if(g&&g->wine_pid==pid)atomic_store_explicit(&g->origin_dead,1,memory_order_release);
    else failure(o,API_WINE,pid,0,1);
    atomic_fetch_sub_explicit(&o->active_callbacks,1,memory_order_release);
}
static uint32_t creation_join(void *context,uint64_t id,uint32_t pid,uint32_t tid,int32_t native)
{
    PwWineFixtureOwner *o=context;uint32_t result=WF_BAD;
    if(!callback_enter(o))return result;
    Generation *g=find(o,id);
    if(g&&atomic_load_explicit(&g->identity_ready,memory_order_acquire)&&
       pid==g->wine_pid&&tid==g->wine_tid&&native>0&&native==(int32_t)g->session.child_pid&&
       !atomic_load(&g->origin_dead)&&!atomic_load(&o->blocked)&&!atomic_load(&o->cancelled)&&
       (atomic_load(&g->state)==G_STARTING||atomic_load(&g->state)==G_RUNNING))result=WF_OK;
    atomic_fetch_sub_explicit(&o->active_callbacks,1,memory_order_release);return result;
}
int pw_wine_fixture_owner_creation(PwWineFixtureOwner *o,PwWineCreationProvider *out)
{
    if(!o||!out||o->creation_enabled)return -1;
    o->creation_enabled=1;
    *out=(PwWineCreationProvider){PW_WINE_CREATION_ABI,sizeof(*out),o,creation_prepare,creation_query,
        creation_bind,creation_submit,creation_result,creation_abandon,creation_transport_failure,creation_origin_dead,creation_join};
    return 0;
}
unsigned pw_wine_fixture_owner_bytes(void){return sizeof(PwWineFixtureOwner);}
int pw_wine_fixture_owner_init(void *storage,unsigned bytes,const PwWineFixtureOwnerConfig *c,PwWineFixtureProvider *out)
{
    const PwWineIpcProfile *ipc=c?pw_wine_ipc_profile(c->profile):NULL;
    if(!storage||bytes!=sizeof(PwWineFixtureOwner)||!c||!out||!c->session||c->session>UINT64_MAX-32||(c->profile!=1&&c->profile!=2&&c->profile!=3&&c->profile!=4&&!ipc)||
       (ipc&&(!PW_WINE_IPC_PROFILE_ENABLED||!c->child_unix_path||strcmp(c->child_unix_path,ipc->native_image)||
              !c->child_sha256||strlen(c->child_sha256)!=64))||
       (c->profile==1&&(!c->child_unix_path||strcmp(c->child_unix_path,"/data/prospero-win/prefixes/windows-child-fixture-v1/drive_c/windows-child-fixture/child.exe")||
                       !c->child_sha256||strlen(c->child_sha256)!=64))||
       (c->profile==3&&(!c->child_unix_path||strcmp(c->child_unix_path,PW_WINE_CHILD_USER_CWD "/user-child.exe")||
                       !c->child_sha256||strlen(c->child_sha256)!=64))||
       (c->profile==4&&(!c->child_unix_path||strcmp(c->child_unix_path,PW_WINE_CHILD_NET_CWD "/net-child.exe")||
                       !c->child_sha256||strlen(c->child_sha256)!=64))||!c->build_id||strlen(c->build_id)!=40||
       !c->helper_image||!c->helper_bytes||c->helper_bytes>16*1024*1024||!c->clock_ms||!c->cancelled||!c->record)return -1;
    if(c->profile==3||c->profile==4||ipc)for(unsigned i=0;i<64;i++)
        if(!((c->child_sha256[i]>='0'&&c->child_sha256[i]<='9')||
             (c->child_sha256[i]>='a'&&c->child_sha256[i]<='f')))return -1;
#if PW_WINE_CHILD_UI_ENABLED
    if(!c->ui_frame||!c->ui_retired)return -1;
#endif
    PwWineFixtureOwner *o=storage;memset(o,0,sizeof(*o));o->config=*c;o->helper_index=-1;
    for(unsigned i=0;i<PW_WFO_MAX_GENERATIONS;i++){
        o->generations[i].stream_fd=o->generations[i].control_fd=o->generations[i].passed_fd=-1;
        atomic_flag_clear(&o->generations[i].send_claim);o->generations[i].owner=o;
    }
    if(pthread_mutex_init(&o->clock_lock,NULL))return -1;
    uint64_t now;if(c->clock_ms(c->context,&now)||now>UINT64_MAX-PW_WFO_VENDOR_MS)return -1;
    o->started=o->last_clock=now;o->end=now+((ipc||c->profile==1)?PW_WFO_ATTEMPT_MS:c->profile==3?PW_WFO_USER_MS:c->profile==4?PW_WFO_NET_MS:PW_WFO_VENDOR_MS);
    /* IPC root and worker are the same selected alias. Check the root before
     * publishing callbacks or entering any guest, even for cap-zero cases. */
    if(ipc&&check_image(o))return -1;
    *out=(PwWineFixtureProvider){PW_WINE_FIXTURE_ABI,sizeof(*out),o,counted_admit,counted_bind_process,counted_release_process,
                                 counted_spawn,counted_remaining,counted_startup_result,counted_signal_request,counted_process_state,root_exit,root_detached};
    return 0;
}
void pw_wine_fixture_owner_cancel(PwWineFixtureOwner *o){if(o)atomic_store(&o->cancelled,1);}
void pw_wine_fixture_owner_socket_failure(void *context,const PwWineFixtureSocketResult *r)
{
    PwWineFixtureOwner *o=context;if(o&&r)failure(o,API_SOCKET,r->api,r->errno_valid?r->native_error:0,0);
}

static void record(PwWineFixtureOwner *o,const char *event,Generation *g,int64_t a,int64_t b,int64_t c)
{ o->config.record(o->config.context,event,g?g->generation:0,a,b,c); }
/* Only the supervisor emits; callback paths merely publish immutable data. */
static void record_failure(PwWineFixtureOwner *o)
{
    if(!o->failure_reported&&atomic_load_explicit(&o->failure_state,memory_order_acquire)==2){
        o->failure_reported=1;
        record(o,"first_failure",NULL,o->failure_api,o->failure_raw,o->failure_errno);
    }
}
#if PW_WINE_CHILD_UI_ENABLED
static int ui_frame(void *context,const void *pixels,uint32_t width,uint32_t height,uint32_t stride)
{
    Generation *g=context;
    return g->owner->config.ui_frame(g->owner->config.context,g->ui.rx.identity,pixels,width,height,stride);
}
static void retire_ui(PwWineFixtureOwner *o,Generation *g)
{
    if(!g->ui.initialized)return;
    (void)pw_wine_child_ui_owner_retire(&g->ui);
    if(!g->ui_retirement_reported){
        g->ui_retirement_reported=1;o->config.ui_retired(o->config.context,g->ui.rx.identity);
        record(o,"ui_retired",g,g->ui.close_uncertain,0,0);
    }
    /* Close ambiguity prevents owner reuse, but does not request helper Kill
     * or mark the Wine/control channel failed. UI has an independent lifetime. */
    if(g->ui.close_uncertain)atomic_store(&o->uncertain,1);
}
#endif
static void uncertain(PwWineFixtureOwner *o,Generation *g,unsigned api,int64_t raw,int error)
{
    failure(o,api,raw,error,1);
#if PW_WINE_CHILD_UI_ENABLED
    retire_ui(o,g);
#endif
    atomic_store_explicit(&g->state,G_UNCERTAIN,memory_order_release);
}
/* Only the supervisor closes this slot. A server callback may own the send
 * lease; never wait for it under a Wine lock, and never close while it sends. */
static int close_control(PwWineFixtureOwner *o,Generation *g)
{
    if(atomic_flag_test_and_set_explicit(&g->send_claim,memory_order_acquire))return 0;
    close_slot(o,&g->control_fd);
    atomic_flag_clear_explicit(&g->send_claim,memory_order_release);
    return 1;
}
static void helper_hold(PwWineFixtureOwner *o,Generation *g)
{
#if PW_WINE_CHILD_UI_ENABLED
    retire_ui(o,g);
#endif
    atomic_store(&o->blocked,1);atomic_store(&o->uncertain,1);
    unsigned previous=atomic_exchange_explicit(&g->state,G_UNCERTAIN,memory_order_acq_rel);
    if(previous!=G_UNCERTAIN)
        record(o,"helper_unsettled",g,g->session.child_pid,g->service_id,g->wire.status);
}
static void retire(PwWineFixtureOwner *o,Generation *g)
{
#if PW_WINE_CHILD_UI_ENABLED
    retire_ui(o,g);
#endif
    /* Absence, channel closure and Stop are not helper-settlement evidence. */
    if(g->helper_possible){helper_hold(o,g);return;}
    atomic_store_explicit(&g->state,G_SETTLING,memory_order_release);
    close_slot(o,&g->stream_fd);close_slot(o,&g->passed_fd);
    if(!close_control(o,g)){g->close_pending=1;return;}
    g->closed=1;g->close_pending=0;
    if(atomic_load(&o->uncertain)){
        atomic_store_explicit(&g->state,G_UNCERTAIN,memory_order_release);return;
    }
    if(!g->wine_pid)atomic_store(&g->released,1);
    atomic_store_explicit(&g->state,G_RETIRED,memory_order_release);
    record(o,"retired",g,g->service_id,g->hello,g->kill_called);
}
static int helper_preflight(PwWineFixtureOwner *o)
{
    for(unsigned i=0;i<2;i++){
        uint64_t now;
        if(clock_now(o,o->end-PW_WFO_CLEANUP_MS,&now,0))return -1;
        int fd=open(helpers[i],O_RDONLY|O_NOFOLLOW|O_NONBLOCK),error=fd<0?errno:0;
        record(o,"helper_open",NULL,i,fd>=0,error);
        if(fd<0)continue;
        struct stat st;int rc=fstat(fd,&st);error=rc<0?errno:0;
        if(rc||!S_ISREG(st.st_mode)||st.st_size!=(off_t)o->config.helper_bytes){
            failure(o,API_IMAGE,rc,error,0);close_slot(o,&fd);return -1;
        }
        size_t at=0;
        while(at<o->config.helper_bytes){
            unsigned char bytes[2048];size_t want=o->config.helper_bytes-at;
            if(want>sizeof(bytes))want=sizeof(bytes);
            if(clock_now(o,o->end-PW_WFO_CLEANUP_MS,&now,0)){close_slot(o,&fd);return -1;}
            ssize_t got=read(fd,bytes,want);error=got<0?errno:0;
            if(got<=0||(size_t)got>want||memcmp(bytes,o->config.helper_image+at,(size_t)got)){
                failure(o,API_IMAGE,got,error,0);close_slot(o,&fd);return -1;
            }
            at+=(size_t)got;
        }
        unsigned char extra;ssize_t got=read(fd,&extra,1);error=got<0?errno:0;
        close_slot(o,&fd);
        if(got||atomic_load(&o->blocked)){failure(o,API_IMAGE,got,error,0);return -1;}
        record(o,"helper_match",NULL,i,(int64_t)at,1);
        if(o->helper_index<0)o->helper_index=(int)i;
    }
    if(o->helper_index<0){failure(o,API_IMAGE,-1,0,0);return -1;}
    struct {uint32_t before,words[4],after;} data={CANARY,{0},CANARY};
    uint64_t now;if(clock_now(o,o->end-PW_WFO_CLEANUP_MS,&now,0))return -1;
    int rc=sceSystemServiceGetAppStatus(data.words);
    record(o,"app",NULL,rc,data.words[0],data.before==CANARY&&data.after==CANARY);
    if(rc||data.before!=CANARY||data.after!=CANARY||!data.words[0]||data.words[0]>INT_MAX){
        failure(o,API_APP,rc?rc:(int64_t)data.words[0],0,0);return -1;
    }
    o->app_id=(int)data.words[0];
    return clock_now(o,o->end-PW_WFO_CLEANUP_MS,&now,0);
}
/* A complete list is only a service-ID observation, never native wait/reap. */
static int service_list(PwWineFixtureOwner *o,Generation *g,int baseline)
{
    struct {uint32_t before;ServiceEntry entries[PW_WFO_LIST_CAP];uint32_t after;} data;
    memset(&data,0,sizeof(data));data.before=data.after=CANARY;
    unsigned count=UINT_MAX;uint64_t now;
    if(g->list_calls>=4096||clock_now(o,o->end,&now,!baseline))return -1;
    int rc=sceSystemServiceGetLocalProcessStatusList(data.entries,PW_WFO_LIST_CAP,&count);
    g->list_calls++;
    /* Reserve one observable entry before dispatch. A full post-launch list
     * is ambiguous; do not create that state from an already saturated
     * baseline. Concurrent external additions still fail closed below. */
    if(rc||data.before!=CANARY||data.after!=CANARY||count>=PW_WFO_LIST_CAP||
       (baseline&&count>=PW_WFO_LIST_CAP-1)){
        failure(o,API_LIST,rc?rc:(int64_t)count,0,!baseline);return -1;
    }
    int present=0;
    for(unsigned i=0;i<count;i++){
        if(data.entries[i].id<=0){failure(o,API_LIST,data.entries[i].id,0,!baseline);return -1;}
        for(unsigned j=0;j<i;j++)if(data.entries[i].id==data.entries[j].id){
            failure(o,API_LIST,data.entries[i].id,0,!baseline);return -1;
        }
        if(baseline)g->baseline[i]=data.entries[i].id;
        else if(data.entries[i].id==g->service_id)present=1;
    }
    if(clock_now(o,o->end,&now,!baseline))return -1;
    if(baseline)g->baseline_count=count;
    else if(present){if(!g->listed)record(o,"listed",g,g->service_id,1,0);g->listed=1;}
    else {g->absent=1;record(o,"absent",g,g->service_id,g->hello,0);}
    return present;
}
static int io_clock(void *context,uint64_t *value)
{ Generation *g=context;return sample_clock(g->owner,value); }
static int io_cancel(void *context)
{
    Generation *g=context;PwWineFixtureOwner *o=g->owner;
    return (atomic_load(&o->root_done)&&!g->creation.lease&&
            atomic_load_explicit(&g->state,memory_order_acquire)!=G_RUNNING)||
           atomic_load(&o->blocked)||atomic_load(&o->cancelled)||
           atomic_load(&g->cleanup_requested)||o->config.cancelled(o->config.context);
}
static int budget(PwWineFixtureOwner *o,Generation *g,int startup)
{
    uint64_t now;
    return (startup&&(atomic_load(&g->origin_dead)||(atomic_load(&o->root_done)&&!g->creation.lease)))||
           atomic_load(&o->blocked)||atomic_load(&g->cleanup_requested)||
           clock_now(o,startup?g->startup_end:g->end,&now,0);
}
static void wire_failure(PwWineFixtureOwner *o,Generation *g)
{
    failure(o,API_HANDOFF,g->wire.raw_result,g->wire.errno_valid?g->wire.native_error:0,
            g->wire.ownership_uncertain||g->wire.cleanup_failed);
    record(o,"wire_failure",g,g->wire.api,g->wire.raw_result,g->wire.native_error);
    record(o,"wire_phase",g,g->start_phase,g->progress_stage,g->wire.status);
    record(o,"wire_receive",g,g->wire.received_bytes,g->wire.poll_revents,g->wire.message_flags);
    record(o,"wire_channel",g,g->wire.channel_zero_observed,g->wire.hangup_observed,(int64_t)g->wire.control_bytes);
    atomic_store(&g->cleanup_requested,1);
}
/* A failure is not Windows success. Only an affirmative, identity-bound
 * client certificate can narrow the conservative pre-BOOTSTRAP helper latch.
 * Missing bits, EOF, stage absence and timeout are never such a certificate. */
static int helper_failure_certificate(PwWineFixtureOwner *o,Generation *g,const PwWineChildFrame *f)
{
    if(!g->helper_possible||!g->hello||g->start_phase!=3||f->kind!=PW_WC_FAILURE||
       f->sequence!=1||f->status>=0||!pw_wine_child_wire_same_session(&g->session,f))return 0;
    unsigned flags=f->returned_length>>PW_WCD_STATE_SHIFT;
    unsigned known=PW_WCD_POSSIBLE|PW_WCD_TERMINAL|PW_WCD_DATA_BEFORE|PW_WCD_DATA_AFTER|
        PW_WCD_LSTAT_BEFORE|PW_WCD_LSTAT_AFTER|PW_WCD_NO_DISPATCH|PW_WCD_SETTLED_FAILURE;
    if(flags&~known)return 0;
    int unused=(flags&PW_WCD_NO_DISPATCH)&&!(flags&(PW_WCD_POSSIBLE|PW_WCD_TERMINAL|PW_WCD_SETTLED_FAILURE));
    int settled=(flags&PW_WCD_SETTLED_FAILURE)&&!(flags&PW_WCD_NO_DISPATCH)&&
        (flags&PW_WCD_TERMINAL);
    if(!unused&&!settled)return 0;
    g->helper_possible=0;
    record(o,unused?"helper_not_dispatched":"helper_terminal_failure",g,
           g->session.child_pid,g->service_id,flags);
    atomic_store(&g->cleanup_requested,1);
    atomic_store_explicit(&g->state,G_CLEANUP,memory_order_release);
    return 1;
}
static void start_generation_attempt(PwWineFixtureOwner *o,Generation *g)
{
    int async=o->creation_enabled&&o->config.profile==2;
    int rc,received=-1;
    if(g->start_phase==0){
    if(budget(o,g,1)||service_list(o,g,1)<0){retire(o,g);return;}
    int pair[2]={-1,-1};rc=socketpair(AF_UNIX,SOCK_SEQPACKET,0,pair);int error=rc<0?errno:0;
    record(o,"pair",g,rc,pair[0],pair[1]);
    if(rc){
        if(rc>0||pair[0]!=-1||pair[1]!=-1)uncertain(o,g,API_PAIR,rc,error);
        else {failure(o,API_PAIR,rc,error,0);retire(o,g);}
        return;
    }
    g->control_fd=pair[0];g->passed_fd=pair[1];
    if(pair[0]<0||pair[1]<0||pair[0]==pair[1]){
        if(pair[0]==pair[1])g->passed_fd=-1;
        uncertain(o,g,API_PAIR,0,0);close_slot(o,&g->passed_fd);close_control(o,g);close_slot(o,&g->stream_fd);return;
    }
    g->helper_recovery_end=g->end-g->startup_end<PW_WINE_CHILD_CLEANUP_MS?
        g->end:g->startup_end+PW_WINE_CHILD_CLEANUP_MS;
    g->io=(PwNativeChildIo){.context=g,.clock_ms=io_clock,.cancelled=io_cancel,
        .total_end=g->end,.stage_end=g->startup_end,.last_clock=g->started,.ready=1};
    if(budget(o,g,1)||pw_wine_child_wire_validate(&g->io,g->control_fd,&g->wire)){
        wire_failure(o,g);retire(o,g);return;
    }
    memset(&g->options,0,sizeof(g->options));g->options.size=sizeof(g->options);
    g->options.fd=g->passed_fd;g->options.other[0]=UINT32_MAX;
    uint64_t preload=UINT64_C(0x8000000000000002);memcpy(&g->options.other[3],&preload,sizeof(preload));
    /* The parent read alias may change after elevation. Keep the service call
     * on the demonstrated app-relative path instead of passing that read alias. */
    g->arguments[0]=helpers[0];g->arguments[1]=NULL;
    if(budget(o,g,1)){retire(o,g);return;}
    /* Persist intent before dispatch. The call's synchronous duration is not
     * established by the protocol deadline; a late return is still owned. */
    g->launch_possible=1;atomic_store_explicit(&g->state,G_STARTING,memory_order_release);
    record(o,"launch_possible",g,o->app_id,o->helper_index,0);
    record(o,"launch_path",g,o->helper_index,0,0);
    if(budget(o,g,1)){g->launch_possible=0;retire(o,g);return;}
    rc=sceSystemServiceAddLocalProcess(o->app_id,helpers[0],g->arguments,&g->options);
    record(o,"launch_return",g,rc,o->app_id,0);
    if(rc<=0){
        atomic_store_explicit(&g->launch_failed,1,memory_order_release);
        uncertain(o,g,API_ADD,rc,0);close_slot(o,&g->passed_fd);
        close_slot(o,&g->stream_fd);close_control(o,g);return;
    }
    close_slot(o,&g->passed_fd);
    for(unsigned i=0;i<g->baseline_count;i++)if(g->baseline[i]==rc){
        uncertain(o,g,API_ADD,rc,0);close_slot(o,&g->stream_fd);close_control(o,g);return;
    }
    unsigned count=atomic_load_explicit(&o->count,memory_order_acquire);
    for(unsigned i=0;i<count;i++)if(&o->generations[i]!=g&&o->generations[i].service_id==rc){
        uncertain(o,g,API_ADD,rc,0);close_slot(o,&g->stream_fd);close_control(o,g);return;
    }
    g->service_id=rc;g->start_phase=1;
    if(async)return;
    }
    if(budget(o,g,1)){atomic_store(&g->cleanup_requested,1);return;}
    if(g->start_phase==1){
    PwWineChildFrame hello;
    rc=async?pw_wine_child_wire_receive_nowait(&g->io,g->control_fd,PW_WC_KIND(PW_WC_HELLO),&hello,&received,&g->wire):
             pw_wine_child_wire_receive(&g->io,g->control_fd,PW_WC_KIND(PW_WC_HELLO),&hello,&received,&g->wire);
    if(rc==PW_WC_IDLE)return;
    if(rc!=PW_WC_RECORD||received>=0){close_slot(o,&received);wire_failure(o,g);return;}
    if(hello.generation||hello.sequence||!hello.child_pid||!hello.child_ppid||
       hello.child_pid==(uint32_t)getpid()||strcmp(hello.build_id,o->config.build_id)){
        /* Emit only fixed mismatch bits, never an untrusted payload/build ID. */
        unsigned mismatch=(hello.generation?1u:0u)|(hello.sequence?2u:0u)|
            (!hello.child_pid?4u:0u)|(!hello.child_ppid?8u:0u)|
            (hello.child_pid==(uint32_t)getpid()?16u:0u)|
            (strcmp(hello.build_id,o->config.build_id)?32u:0u);
        record(o,"hello_refused",g,mismatch,0,0);
        failure(o,API_HANDOFF,hello.child_pid,0,0);atomic_store(&g->cleanup_requested,1);return;
    }
    g->session=hello;g->session.kind=PW_WC_BOOTSTRAP;g->session.sequence=1;
    g->session.generation=g->generation;g->session.parent_pid=(uint32_t)getpid();
    g->session.wine_pid=g->wine_pid;g->session.wine_tid=g->wine_tid;
    g->session.profile=o->config.profile;g->session.machine=g->machine;
    g->hello=1;atomic_store_explicit(&g->identity_ready,1,memory_order_release);
    record(o,"hello",g,hello.child_pid,hello.child_ppid,g->service_id);
#if PW_WINE_CHILD_UI_ENABLED
    PwWineChildUiIdentity id={o->config.session,g->generation,g->session.child_pid};
    if(pw_wine_child_ui_owner_init(&g->ui,id,ui_frame,g)){
        retire_ui(o,g);failure(o,API_PAIR,-1,0,g->ui.close_uncertain);
        atomic_store(&g->cleanup_requested,1);return;
    }
    record(o,"ui_pair_owned",g,g->session.child_pid,PW_WCU_MAX_BYTES,0);
#endif
    g->start_phase=2;
    if(async)return;
    }
    if(g->start_phase==2){
    if(budget(o,g,1)){atomic_store(&g->cleanup_requested,1);return;}
    /* This matching child may dispatch the fixed PID-targeted data helper as
     * soon as BOOTSTRAP arrives. Latch before even a possibly partial send. */
    if(!g->helper_possible){
        g->helper_possible=1;
        record(o,"helper_possible",g,g->session.child_pid,g->service_id,0);
    }
#if PW_WINE_CHILD_UI_ENABLED
    rc=pw_wine_child_ui_owner_send(&g->ui,&g->io,g->control_fd,&g->session,o->config.session,g->stream_fd);
    if(rc==PW_WC_IDLE)return;
    g->wire=g->ui.handoff.result;
    if(g->ui.close_uncertain){g->wire.cleanup_failed=g->wire.ownership_uncertain=1;
        g->wire.status=PW_WC_OS;g->wire.api=PW_WC_API_CLOSE;g->wire.raw_result=-1;}
    rc=rc==PW_WC_RECORD?0:-1;
#else
    if(async){
        rc=pw_wine_child_wire_send_step(&g->io,g->control_fd,&g->session,g->stream_fd,&g->wire);
        if(rc==PW_WC_IDLE)return;
        rc=rc==PW_WC_RECORD?0:-1;
    }else rc=pw_wine_child_wire_send(&g->io,g->control_fd,&g->session,g->stream_fd,&g->wire);
#endif
    close_slot(o,&g->stream_fd);
    if(rc){wire_failure(o,g);return;}
    g->start_phase=3;
    record(o,"bootstrap_sent",g,g->session.profile,g->session.machine,0);
    if(async)return;
    }
    /* Bounded diagnostics share the original startup budget and transport.
     * Only a matching ACK below can settle helper ownership. */
    for(;;){
    /* The normal startup budget still gates work. Once a terminal record is
     * queued, however, its post-recv budget check must not discard it merely
     * because cancellation or the startup deadline raced the read. Use the
     * precomputed cleanup-only observation window, without renewing either. */
    if(budget(o,g,1)||io_cancel(g)){atomic_store(&g->cleanup_requested,1);return;}
    PwNativeChildIo receive_io=g->io;
    receive_io.cancelled=NULL;receive_io.stage_end=g->helper_recovery_end;
    PwWineChildFrame ack;
    rc=pw_wine_child_wire_receive_nowait(&receive_io,g->control_fd,
        PW_WC_KIND(PW_WC_BOOTSTRAP_ACK)|PW_WC_KIND(PW_WC_FAILURE)|PW_WC_KIND(PW_WC_PROGRESS),
        &ack,&received,&g->wire);
    g->io.last_clock=receive_io.last_clock;
    if(rc==PW_WC_IDLE)return;
    if(rc!=PW_WC_RECORD||received>=0){close_slot(o,&received);wire_failure(o,g);return;}
    if(!pw_wine_child_wire_same_session(&g->session,&ack)||ack.sequence!=1){
        /* Do not attribute diagnostic payload from a different generation or
         * process to this child, even when the frame itself decoded. */
        record(o,"bootstrap_refused",g,ack.kind,ack.sequence,ack.status);
        g->wire.status=PW_WC_PROTOCOL;g->wire.api=PW_WC_API_RECEIVE;
        failure(o,API_HANDOFF,ack.status,0,0);atomic_store(&g->cleanup_requested,1);return;
    }
    if(ack.kind==PW_WC_PROGRESS){
        if(ack.failure_api<=g->progress_stage||ack.failure_api>PW_WC_PROGRESS_LAST){
            record(o,"progress_refused",g,ack.failure_api,g->progress_stage,0);
            g->wire.status=PW_WC_PROTOCOL;g->wire.api=PW_WC_API_RECEIVE;
            failure(o,API_HANDOFF,ack.failure_api,0,0);atomic_store(&g->cleanup_requested,1);return;
        }
        g->progress_stage=ack.failure_api;
        record(o,"bootstrap_progress",g,ack.failure_api,0,0);
        if(async)return;
        continue;
    }
    if(ack.kind!=PW_WC_BOOTSTRAP_ACK||ack.status){
        (void)helper_failure_certificate(o,g,&ack);
        record(o,"bootstrap_failure",g,ack.failure_api,ack.failure_raw,ack.native_error);
        record(o,"bootstrap_failure_value",g,ack.returned_length,ack.returned_value,ack.errno_valid);
        failure(o,API_HANDOFF,ack.status,ack.errno_valid?ack.native_error:0,0);atomic_store(&g->cleanup_requested,1);return;
    }
    /* ACK also certifies terminal helper success (or preexisting data), the
     * full settle and actual bootstrap readiness in this exact child build. */
    g->helper_possible=0;
    if(budget(o,g,1)){atomic_store(&g->cleanup_requested,1);
        atomic_store_explicit(&g->state,G_CLEANUP,memory_order_release);return;}
    g->ack=1;g->start_phase=4;g->io.stage_end=g->end;
    atomic_store_explicit(&g->state,G_RUNNING,memory_order_release);
    record(o,"bootstrap_ready",g,g->wine_pid,g->wine_tid,0);
    return;
    }
}
static void start_generation(PwWineFixtureOwner *o,Generation *g)
{
    start_generation_attempt(o,g);
    /* One bounded observation of interrupted startup, before cleanup policy.
     * This is neither a child exit reason nor helper settlement evidence. */
    if(!g->ack&&!g->startup_stop_reported&&
       (g->wire.status||atomic_load(&g->cleanup_requested)||atomic_load(&o->blocked)||
        atomic_load(&o->cancelled)||atomic_load(&g->state)==G_UNCERTAIN)){
        g->startup_stop_reported=1;
        record(o,"bootstrap_stopped",g,g->start_phase,g->progress_stage,g->helper_possible);
        record(o,"bootstrap_stop_control",g,g->wire.status,g->wire.api,g->wire.raw_result);
    }
    if(g->helper_possible&&(g->wire.status||atomic_load(&g->cleanup_requested)||atomic_load(&o->blocked)||
                           atomic_load(&o->cancelled)||atomic_load(&g->state)==G_UNCERTAIN)){
        /* A cancellation or pure budget refusal leaves transport usable for
         * one cleanup-only exchange. Actual wire/ownership ambiguity does not. */
        int budget_only=g->wire.status==PW_WC_BUDGET&&g->wire.api==PW_WC_API_CLOCK;
        if(g->start_phase==3&&(!g->wire.status||budget_only)&&
           !g->wire.delivery_uncertain&&!g->wire.ownership_uncertain&&!g->wire.cleanup_failed&&
           !g->wire.channel_zero_observed&&!g->wire.hangup_observed){
            atomic_store(&o->blocked,1);atomic_store(&g->cleanup_requested,1);
            atomic_store_explicit(&g->state,G_HELPER_DRAIN,memory_order_release);
            record(o,"helper_cleanup_begin",g,g->session.child_pid,g->service_id,
                   (int64_t)g->helper_recovery_end);
        }else helper_hold(o,g);
    }
}
static void drain_helper(PwWineFixtureOwner *o,Generation *g)
{
    uint64_t now;
    if(!g->helper_possible||g->control_fd<0||sample_clock(o,&now)||now>=g->helper_recovery_end){
        record(o,"helper_cleanup_unproved",g,g->session.child_pid,g->service_id,0);
        helper_hold(o,g);return;
    }
    PwNativeChildIo io=g->io;
    io.cancelled=NULL;io.stage_end=g->helper_recovery_end;
    /* Observe an already queued certificate before attempting cancellation.
     * The child may have sent its final receipt and closed: a redundant send
     * failure must not hide stronger same-session settlement evidence. Valid
     * progress is strictly increasing over a finite stage range, so draining
     * it cannot renew the deadline or create an unbounded receive loop. */
    for(;;){
    PwWineChildFrame frame;int received=-1;
    int rc=pw_wine_child_wire_receive_nowait(&io,g->control_fd,
        PW_WC_KIND(PW_WC_FAILURE)|PW_WC_KIND(PW_WC_BOOTSTRAP_ACK)|PW_WC_KIND(PW_WC_PROGRESS),
        &frame,&received,&g->helper_drain_wire);
    g->io.last_clock=io.last_clock;
    if(rc==PW_WC_IDLE)goto request_cancel;
    if(rc!=PW_WC_RECORD||received>=0||frame.sequence!=1||
       !pw_wine_child_wire_same_session(&g->session,&frame)){
        close_slot(o,&received);record(o,"helper_cleanup_unproved",g,rc,
            g->helper_drain_wire.api,g->helper_drain_wire.raw_result);helper_hold(o,g);return;
    }
    if(frame.kind==PW_WC_PROGRESS){
        if(frame.failure_api<=g->progress_stage||frame.failure_api>PW_WC_PROGRESS_LAST){helper_hold(o,g);return;}
        g->progress_stage=frame.failure_api;record(o,"bootstrap_progress",g,frame.failure_api,0,0);
        continue;
    }
    if(frame.kind==PW_WC_FAILURE){
        record(o,"bootstrap_failure",g,frame.failure_api,frame.failure_raw,frame.native_error);
        record(o,"bootstrap_failure_value",g,frame.returned_length,frame.returned_value,frame.errno_valid);
        failure(o,API_HANDOFF,frame.status,frame.errno_valid?frame.native_error:0,0);
        if(!helper_failure_certificate(o,g,&frame))helper_hold(o,g);
        return;
    }
    /* A racing exact ACK still certifies helper settlement, but cancellation
     * has already made this guest attempt fail. Never publish G_RUNNING/ack. */
    g->helper_possible=0;atomic_store(&g->cleanup_requested,1);
    atomic_store_explicit(&g->state,G_CLEANUP,memory_order_release);
    record(o,"helper_ack_after_cancel",g,g->session.child_pid,g->service_id,0);
    return;
    }
request_cancel:
    if(!g->helper_cancel_attempted){
        if(sample_clock(o,&now)||now>=g->helper_recovery_end){helper_hold(o,g);return;}
        if(atomic_flag_test_and_set_explicit(&g->send_claim,memory_order_acquire))return;
        g->helper_cancel_attempted=1;
        PwWineChildFrame cancel=g->session;cancel.kind=PW_WC_CANCEL;
        int sent=pw_wine_child_wire_try_send(g->control_fd,&cancel,-1,&g->helper_drain_wire);
        atomic_flag_clear_explicit(&g->send_claim,memory_order_release);
        record(o,"helper_cancel_sent",g,sent,g->service_id,0);
        if(sent)helper_hold(o,g); /* Never retry uncertain cancellation delivery. */
    }
}
static void observe_control(PwWineFixtureOwner *o,Generation *g)
{
    if(g->control_fd<0)return;
    PwWineChildFrame frame;int right=-1;
    int rc=o->creation_enabled&&o->config.profile==2?
        pw_wine_child_wire_receive_nowait(&g->io,g->control_fd,
            PW_WC_KIND(PW_WC_SIGNAL_ACK)|PW_WC_KIND(PW_WC_FAILURE),&frame,&right,&g->wire):
        pw_wine_child_wire_receive_step(&g->io,g->control_fd,
            PW_WC_KIND(PW_WC_SIGNAL_ACK)|PW_WC_KIND(PW_WC_FAILURE),&frame,&right,&g->wire);
    if(rc==PW_WC_IDLE)return;
    if(rc==PW_WC_CHANNEL_CLOSED){record(o,"channel_zero_hup",g,1,1,0);g->close_pending=1;return;}
    if(rc!=PW_WC_RECORD||right>=0){close_slot(o,&right);wire_failure(o,g);return;}
    if(!pw_wine_child_wire_same_session(&g->session,&frame)){
        failure(o,API_HANDOFF,frame.sequence,0,0);atomic_store(&g->cleanup_requested,1);return;
    }
    if(frame.kind==PW_WC_FAILURE){
        record(o,"child_failure",g,frame.failure_api,frame.failure_raw,frame.native_error);
        record(o,"child_failure_value",g,frame.returned_length,frame.returned_value,frame.errno_valid);
        failure(o,API_HANDOFF,frame.status,frame.errno_valid?frame.native_error:0,0);
        atomic_store(&g->cleanup_requested,1);return;
    }
    if(!atomic_load_explicit(&g->pending_signal,memory_order_acquire)||
       frame.sequence!=g->signal.sequence||frame.target_tid!=g->signal.target_tid||frame.signal!=g->signal.signal){
        failure(o,API_SIGNAL,frame.sequence,0,0);atomic_store(&g->cleanup_requested,1);return;
    }
    record(o,"signal_ack",g,frame.target_tid,frame.status,frame.native_error);
    atomic_store(&g->signal_ack,frame.sequence);atomic_store(&g->pending_signal,0);
    if(frame.status){failure(o,API_SIGNAL,frame.status,frame.native_error,0);atomic_store(&g->cleanup_requested,1);}
}
static void supervise(PwWineFixtureOwner *o,Generation *g)
{
    unsigned state=atomic_load_explicit(&g->state,memory_order_acquire);
    if(g->creation.lease&&atomic_load_explicit(&g->abandoned,memory_order_acquire)&&
       !atomic_load_explicit(&g->remote_lease,memory_order_acquire)&&
       atomic_load_explicit(&g->startup_done,memory_order_acquire)!=2&&!g->missing_reported){
        g->missing_reported=1;
        record(o,"startup_result_missing",g,g->caller_pid,g->caller_tid,(int64_t)g->creation.lease);
        failure(o,API_WINE,0,0,0);
    }
    if(state==G_RETIRED)return;
    if(state==G_HELPER_DRAIN){
        drain_helper(o,g);state=atomic_load_explicit(&g->state,memory_order_acquire);
        if(state==G_HELPER_DRAIN||state==G_UNCERTAIN)return;
    }
#if PW_WINE_CHILD_UI_ENABLED
    if(state==G_UNCERTAIN)retire_ui(o,g);
#endif
    if(state==G_UNCERTAIN){close_slot(o,&g->stream_fd);close_slot(o,&g->passed_fd);close_control(o,g);return;}
    if(state==G_SETTLING||g->absent){retire(o,g);return;}
    if(g->close_pending)close_control(o,g);
    /* Bounded server submissions are progressed here, never under its lock.
     * G_SUBMITTING is a publication lease: the supervisor cannot close a slot
     * while bind/submit is writing identity or moving descriptor ownership. */
    if(state==G_SUBMITTING)return;
    if(g->creation.lease&&(state==G_REQUESTED||state==G_ADMITTED||state==G_BOUND)){
        uint64_t now=0;
        uint32_t refused=sample_clock(o,&now)?WF_BAD:creation_budget(o,g,now);
        if(!refused&&(atomic_load(&g->cleanup_requested)||!admitted_path(o,g->creation.path,g->machine)))refused=WF_BAD;
        if(refused){
            unsigned expected=state;
            if(atomic_compare_exchange_strong(&g->state,&expected,G_SETTLING)){
                atomic_store(&g->request_status,atomic_load(&o->cancelled)?WF_CANCELLED:refused);
                retire(o,g);
            }
            return;
        }
        if(state==G_REQUESTED){
            Generation *origin=find(o,g->creation.origin);
            /* A valid first join can beat parent-side ACK observation. Wait
             * without extending the request deadline or clearing helper hold. */
            if(atomic_load_explicit(&origin->state,memory_order_acquire)!=G_RUNNING)return;
            unsigned expected=G_REQUESTED;
            atomic_compare_exchange_strong_explicit(&g->state,&expected,G_ADMITTED,
                                                    memory_order_release,memory_order_relaxed);
        }
        return;
    }
    if(state==G_ADMITTED||state==G_BOUND){
        if(atomic_load(&o->root_done)&&!atomic_load_explicit(&o->active_callbacks,memory_order_acquire)){
            if(atomic_load_explicit(&g->startup_done,memory_order_acquire)!=2){
                g->missing_reported=1;record(o,"startup_result_missing",g,g->caller_pid,g->caller_tid,0);
                failure(o,API_WINE,0,0,0);
            }
            retire(o,g);
        }
        else if(atomic_load_explicit(&g->startup_done,memory_order_acquire)==2&&!atomic_load(&g->startup_success))retire(o,g);
        return;
    }
    if(state==G_LAUNCH||state==G_STARTING){start_generation(o,g);state=atomic_load_explicit(&g->state,memory_order_acquire);}
    if(state==G_RETIRED||state==G_UNCERTAIN||state==G_HELPER_DRAIN)return;
    uint64_t now;
    if(sample_clock(o,&now)){uncertain(o,g,API_CLOCK,-1,0);return;}
    if(!g->creation.lease&&atomic_load(&o->root_done)&&atomic_load_explicit(&g->startup_done,memory_order_acquire)!=2){
        if(!g->missing_reported){g->missing_reported=1;record(o,"startup_result_missing",g,g->caller_pid,g->caller_tid,0);}
        failure(o,API_WINE,0,0,0);atomic_store(&g->cleanup_requested,1);
    }
    if(now>=g->end||atomic_load(&o->cancelled)||atomic_load(&o->blocked)||o->config.cancelled(o->config.context)){
        atomic_store(&g->cleanup_requested,1);
        if(now>=g->end)failure(o,API_CLOCK,0,0,0);
    }
    if(g->helper_possible){
        /* Keep pumping other generations, but never list/retire/Kill a child
         * while its helper may still be applying to this native PID. */
        if(atomic_load(&g->cleanup_requested)||atomic_load(&o->cancelled)||atomic_load(&o->blocked))helper_hold(o,g);
        return;
    }
#if PW_WINE_CHILD_UI_ENABLED
    if(state==G_RUNNING&&!atomic_load(&g->cleanup_requested)&&!g->ui.retired){
        if(pw_wine_child_ui_owner_pump(&g->ui)<0)retire_ui(o,g);
    }
    if(atomic_load(&g->cleanup_requested))retire_ui(o,g);
#endif
    if(state==G_RUNNING&&!atomic_load(&g->cleanup_requested))observe_control(o,g);
    if(now<g->next_list)return;
    g->next_list=now>UINT64_MAX-100?UINT64_MAX:now+100;
    if(g->service_id<=0){uncertain(o,g,API_ADD,g->service_id,0);return;}
    int present=service_list(o,g,0);
    if(present<0){uncertain(o,g,API_LIST,-1,0);close_slot(o,&g->stream_fd);close_control(o,g);return;}
    if(!present){
        /* A complete absence before identity handoff is still ambiguous
         * asynchronous startup. Never recycle or target this ID again. */
        if(!g->hello){uncertain(o,g,API_LIST,0,0);close_slot(o,&g->stream_fd);close_control(o,g);return;}
        retire(o,g);return;
    }
    if(atomic_load(&g->cleanup_requested)&&!g->kill_called){
        if(g->helper_possible){helper_hold(o,g);return;}
        if(clock_now(o,o->end,&now,1)){uncertain(o,g,API_CLOCK,0,0);return;}
        record(o,"kill_possible",g,o->app_id,g->service_id,0);
        if(clock_now(o,o->end,&now,1)){uncertain(o,g,API_CLOCK,0,0);return;}
        if(g->helper_possible){helper_hold(o,g);return;}
        g->kill_called=1;
        g->kill_result=sceSystemServiceKillLocalProcess(o->app_id,g->service_id);
        record(o,"kill_return",g,g->kill_result,g->service_id,0);
        failure(o,API_KILL,g->kill_result,0,g->kill_result!=0);
        if(g->kill_result){atomic_store_explicit(&g->state,G_UNCERTAIN,memory_order_release);return;}
        close_slot(o,&g->stream_fd);close_control(o,g);
    }
}
int pw_wine_fixture_owner_pump(PwWineFixtureOwner *o)
{
    if(!o)return -1;
    if(!atomic_load_explicit(&o->initialized,memory_order_acquire)){
        int rc=helper_preflight(o);
        atomic_store_explicit(&o->initialized,1,memory_order_release);
        record(o,"preflight",NULL,rc,o->helper_index,o->app_id);
    }
    unsigned count=atomic_load_explicit(&o->count,memory_order_acquire);
    for(unsigned i=0;i<count;i++)supervise(o,&o->generations[i]);
    if(atomic_load_explicit(&o->root_done,memory_order_acquire)==2&&
       (atomic_load(&o->admission_closed)||(o->creation_enabled&&o->config.profile==2))){
        unsigned zero=0;
        if(atomic_compare_exchange_strong(&o->admission_claim,&zero,1)){
            int idle=!atomic_load_explicit(&o->active_callbacks,memory_order_acquire);
            int ready=!atomic_load(&o->uncertain)&&idle&&atomic_load_explicit(&o->root_detach_state,memory_order_acquire)==1;
            count=atomic_load_explicit(&o->count,memory_order_acquire);
            for(unsigned i=0;i<count;i++){
                Generation *g=&o->generations[i];
                if(idle&&(!g->creation.lease||atomic_load_explicit(&g->abandoned,memory_order_acquire))&&
                   atomic_load_explicit(&g->startup_done,memory_order_acquire)!=2&&!g->missing_reported){
                    g->missing_reported=1;
                    record(o,"startup_result_missing",g,g->caller_pid,g->caller_tid,0);
                    failure(o,API_WINE,0,0,0);
                }
                if(atomic_load_explicit(&g->state,memory_order_acquire)!=G_RETIRED||
                   atomic_load_explicit(&g->remote_lease,memory_order_acquire))ready=0;
            }
            unsigned open=0;
            if(ready&&!atomic_load(&o->release_ready)&&
               atomic_compare_exchange_strong_explicit(&o->active_callbacks,&open,CALLBACKS_CLOSED,
                                                       memory_order_acq_rel,memory_order_acquire)){
                /* A callback could have completed between the preliminary
                 * snapshot and this successful seal. Re-read its publications
                 * after no further callback may enter. Never reopen on failure. */
                ready=!atomic_load_explicit(&o->uncertain,memory_order_acquire)&&
                      atomic_load_explicit(&o->root_detach_state,memory_order_acquire)==1;
                for(unsigned i=0;i<count;i++){
                    Generation *g=&o->generations[i];
                    if(atomic_load_explicit(&g->state,memory_order_acquire)!=G_RETIRED||
                       atomic_load_explicit(&g->remote_lease,memory_order_acquire))ready=0;
                    /* Abandonment may have published after the earlier scan
                     * but before this seal. Preserve its missing-result fact. */
                    if(g->creation.lease&&atomic_load(&g->abandoned)&&
                       atomic_load_explicit(&g->startup_done,memory_order_acquire)!=2&&!g->missing_reported){
                        g->missing_reported=1;
                        record(o,"startup_result_missing",g,g->caller_pid,g->caller_tid,(int64_t)g->creation.lease);
                        failure(o,API_WINE,0,0,0);
                    }
                }
                if(!ready){atomic_store(&o->admission_claim,0);record_failure(o);return -1;}
                atomic_store_explicit(&o->admission_closed,1,memory_order_release);
                atomic_store(&o->release_ready,1);
                record_failure(o);
                record(o,"root_release_safe",NULL,atomic_load(&o->root_result),atomic_load(&o->blocked),count);
                atomic_store_explicit(&o->release_ready,2,memory_order_release);
            }
            atomic_store(&o->admission_claim,0);
        }
    }
    record_failure(o);
    if(atomic_load_explicit(&o->failure_state,memory_order_acquire)==2)
        return -1;
    return 0;
}
int pw_wine_fixture_owner_root_result(PwWineFixtureOwner *o,uint64_t session,unsigned result)
{ return !o||session!=o->config.session?-1:(int)root_exit(o,result); }
int pw_wine_fixture_owner_release_ready(const PwWineFixtureOwner *o)
{ return o?(atomic_load_explicit(&o->release_ready,memory_order_acquire)==2):0; }
