/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Actual owner C. Every OS, service and transport boundary is mocked. */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#ifndef AF_UNIX
#define AF_UNIX 1 /* Target API mock only; every socketpair call is replaced. */
#endif
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
static unsigned checks;
#define CHECK(c) do{++checks;assert(c);}while(0)
static int mock_open(const char *,int,...);
static int mock_fstat(int,struct stat *);
static ssize_t mock_read(int,void *,size_t);
static int mock_close(int);
static int mock_dup(int);
static int mock_socketpair(int,int,int,int *);
static int mock_nanosleep(const struct timespec *,struct timespec *);
static pid_t mock_getpid(void);
static int mock_mutex_init(pthread_mutex_t *,const pthread_mutexattr_t *);
static int mock_mutex_lock(pthread_mutex_t *);
static int mock_mutex_unlock(pthread_mutex_t *);
#define open mock_open
#define fstat mock_fstat
#define read mock_read
#define close mock_close
#define dup mock_dup
#define socketpair mock_socketpair
#define nanosleep mock_nanosleep
#define getpid mock_getpid
#define pthread_mutex_init mock_mutex_init
#define pthread_mutex_lock mock_mutex_lock
#define pthread_mutex_unlock mock_mutex_unlock
static unsigned force_weak_failure,weak_calls;
static void before_seal(atomic_uint *,unsigned);
static int intercepted_cas(atomic_uint *p,unsigned *expected,unsigned desired,memory_order success,memory_order failure)
{before_seal(p,desired);return atomic_compare_exchange_strong_explicit(p,expected,desired,success,failure);}
static int intercepted_weak(atomic_uint *p,unsigned *expected,unsigned desired,memory_order success,memory_order failure)
{if(force_weak_failure){weak_calls++;return 0;}return atomic_compare_exchange_weak_explicit(p,expected,desired,success,failure);}
#undef atomic_compare_exchange_strong_explicit
#undef atomic_compare_exchange_weak_explicit
#define atomic_compare_exchange_strong_explicit intercepted_cas
#define atomic_compare_exchange_weak_explicit intercepted_weak
#define pw_wine_child_wire_validate owner_wire_validate
#define pw_wine_child_wire_send owner_wire_send
#define pw_wine_child_wire_try_send owner_wire_try_send
#define pw_wine_child_wire_same_session owner_wire_same_session
#define pw_wine_child_wire_receive owner_wire_receive
#define pw_wine_child_wire_receive_step owner_wire_receive_step
#include "../native/pw_wine_fixture_owner.c"
#undef pw_wine_child_wire_validate
#undef pw_wine_child_wire_send
#undef pw_wine_child_wire_try_send
#undef pw_wine_child_wire_same_session
#undef pw_wine_child_wire_receive
#undef pw_wine_child_wire_receive_step
#include "bootstrap_diagnostic_bridge.h"
int pw_wine_child_wire_same_session(const PwWineChildFrame*,const PwWineChildFrame*);
static DiagnosticCase scenario;
static DiagnosticResult child_result;
static int corrupt_generation;
#undef atomic_compare_exchange_strong_explicit
#undef atomic_compare_exchange_weak_explicit
#undef pthread_mutex_unlock
#undef pthread_mutex_lock
#undef pthread_mutex_init
#undef getpid
#undef nanosleep
#undef socketpair
#undef dup
#undef close
#undef read
#undef fstat
#undef open
static struct {
    uint64_t now;
    int cancelled,clock_error,mutex_error,mutex_locked,open_error,stat_error,read_error,close_error;
    int dup_error,prepare_error,pair_rc,pair_a,pair_b,app_rc,app_id,app_canary;
    int list_rc,list_unwritten,list_canary,list_count,list_ids[16],add_result,kill_result;
    int validate_error,send_error,receive_error,ack_bad,sleep_action,hash_bad;
    unsigned opens,reads,closes[128],dups,pairs,adds,kills,sends,receives,validations,records,sleeps,lists,apps,missing_result;
    unsigned opened[128],positions[128],next_fd,stage_receive;
    int root_during_clock,inject_seal,publication_samples;
    unsigned first_failures,first_index,release_index,inside_callback,reenter_failure;
    int64_t first_api,first_raw,first_errno;
    int extra_right,wire_uncertain,auto_present,prepare_cancel,prepare_expire;
    int record_action,step_result,root_during_send,wire_cancelled;
    int add_cancel,add_partial_failure;
    int helper_open_error[2],helper_mismatch[2],fd_helper[128];
    unsigned helper_matches,launch_paths,boot_failures,boot_values;int64_t boot_api,boot_raw,boot_errno,boot_aux1,boot_aux2,boot_valid;
    int64_t launch_read_index,launch_service_index;
    const char *record_event;
    PwWineChildFrame sent;
} m;
static PwWineFixtureOwner owner;
static PwWineFixtureProvider provider;
static uint32_t report_root_exit(void *context,uint32_t status)
{
    uint32_t result=provider.root_exit(context,status);
    if(!atomic_load(&owner.root_detach_state))provider.root_detached(context,1,0,0);
    return result;
}
static void before_seal(atomic_uint *slot,unsigned desired)
{
    if(slot==&owner.active_callbacks&&desired==CALLBACKS_CLOSED&&m.inject_seal){
        m.inject_seal=0;provider.release_process(&owner,UINT64_MAX,99);
    }
}
static const unsigned char helper_bytes[]={1,2,3,4};
static const char hash64[]="9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a";
static const char build40[]="0123456789012345678901234567890123456789";
static int clock_cb(void *c,uint64_t *out)
{
    CHECK(c==&m);*out=m.now;
    if(m.root_during_clock){m.root_during_clock=0;CHECK(!report_root_exit(provider.context,77));}
    return m.clock_error;
}
static int cancel_cb(void *c){CHECK(c==&m);return m.cancelled;}
static void record_cb(void *c,const char *event,uint64_t generation,int64_t a,int64_t b,int64_t d)
{
    CHECK(c==&m&&event);(void)generation;(void)a;(void)b;(void)d;m.records++;
    if(!strcmp(event,"first_failure")){
        CHECK(!m.inside_callback&&!m.first_failures);
        m.first_failures++;m.first_index=m.records;m.first_api=a;m.first_raw=b;m.first_errno=d;
        if(m.reenter_failure){PwWineFixtureSocketResult again={.api=999,.errno_valid=1,.native_error=ERANGE};m.reenter_failure=0;pw_wine_fixture_owner_socket_failure(&owner,&again);}
    }
    if(!strcmp(event,"bootstrap_failure")){m.boot_failures++;m.boot_api=a;m.boot_raw=b;m.boot_errno=d;}
    if(!strcmp(event,"bootstrap_failure_value")){m.boot_values++;m.boot_aux1=a;m.boot_aux2=b;m.boot_valid=d;}
    if(!strcmp(event,"helper_match"))m.helper_matches++;
    if(!strcmp(event,"launch_path")){m.launch_paths++;m.launch_read_index=a;m.launch_service_index=b;}
    if(!strcmp(event,"startup_result_missing"))m.missing_result++;
    if(!strcmp(event,"root_release_safe")){CHECK(!pw_wine_fixture_owner_release_ready(&owner));m.publication_samples++;m.release_index=m.records;}
    if(m.record_event&&!strcmp(event,m.record_event)){
        m.record_event=NULL;
        if(m.record_action==1)m.cancelled=1;
        else if(m.record_action==2)m.now=owner.end;
    }
}
static int mock_mutex_init(pthread_mutex_t *p,const pthread_mutexattr_t *a)
{CHECK(p==&owner.clock_lock&&!a);return m.mutex_error;}
static int mock_mutex_lock(pthread_mutex_t *p)
{CHECK(p==&owner.clock_lock&&!m.mutex_locked);if(m.mutex_error)return m.mutex_error;m.mutex_locked=1;return 0;}
static int mock_mutex_unlock(pthread_mutex_t *p)
{CHECK(p==&owner.clock_lock&&m.mutex_locked);m.mutex_locked=0;return m.mutex_error;}
static int mock_open(const char *path,int flags,...)
{
    CHECK(path&&(flags&O_NOFOLLOW)&&(flags&O_NONBLOCK));m.opens++;
    if(m.open_error){errno=EACCES;return -1;}
    int alias=-1;
    for(unsigned i=0;i<2;i++)if(!strcmp(path,helpers[i]))alias=(int)i;
    if(alias>=0&&m.helper_open_error[alias]){errno=m.helper_open_error[alias];return -1;}
    int fd=(int)m.next_fd++;CHECK(fd>=10&&fd<128);m.opened[fd]=1;m.fd_helper[fd]=alias+1;return fd;
}
static int mock_fstat(int fd,struct stat *st)
{CHECK(fd>=10&&fd<128&&m.opened[fd]);if(m.stat_error){errno=EIO;return -1;}memset(st,0,sizeof(*st));st->st_mode=S_IFREG;st->st_size=4;return 0;}
static ssize_t mock_read(int fd,void *out,size_t bytes)
{
    CHECK(fd>=10&&fd<128&&m.opened[fd]&&out&&bytes);m.reads++;
    if(m.read_error){errno=EIO;return -1;}
    size_t left=4-m.positions[fd];if(bytes>left)bytes=left;
    memcpy(out,helper_bytes+m.positions[fd],bytes);
    if(bytes&&m.fd_helper[fd]&&m.helper_mismatch[m.fd_helper[fd]-1])((unsigned char*)out)[0]^=1;
    m.positions[fd]+=(unsigned)bytes;return (ssize_t)bytes;
}
static int mock_close(int fd)
{CHECK(fd>=0&&fd<128);CHECK(!m.closes[fd]);m.closes[fd]++;errno=EBADF;return m.close_error;}
static int mock_dup(int fd)
{CHECK(fd==70);m.dups++;if(m.dup_error){errno=EACCES;return -1;}return 71;}
static int mock_socketpair(int domain,int type,int protocol,int *pair)
{CHECK(domain==AF_UNIX&&type==SOCK_SEQPACKET&&!protocol);CHECK(pair[0]==-1&&pair[1]==-1);m.pairs++;pair[0]=m.pair_a;pair[1]=m.pair_b;errno=EACCES;return m.pair_rc;}
static pid_t mock_getpid(void){return 599;}
static int mock_nanosleep(const struct timespec *delay,struct timespec *out)
{
    CHECK(delay->tv_sec==0&&delay->tv_nsec==10000000&&!out);m.sleeps++;m.now+=10;
    if(m.sleep_action==1)pw_wine_fixture_owner_pump(&owner);
    else if(m.sleep_action==2)atomic_store(&owner.generations[0].state,G_RETIRED);
    else if(m.sleep_action==3){m.now=owner.generations[0].startup_end;pw_wine_fixture_owner_pump(&owner);}
    else if(m.sleep_action==4)m.now=owner.generations[0].startup_end;
    else if(m.sleep_action==5){pw_wine_fixture_owner_cancel(&owner);pw_wine_fixture_owner_pump(&owner);}
    else m.cancelled=1;
    return 0;
}
int sceSystemServiceGetAppStatus(void *out)
{uint32_t *p=out;m.apps++;p[0]=(uint32_t)m.app_id;if(m.app_canary)p[4]=0;return m.app_rc;}
int sceSystemServiceGetLocalProcessStatusList(void *out,unsigned capacity,unsigned *count)
{
    CHECK(capacity==16&&*count==UINT_MAX);ServiceEntry *p=out;m.lists++;
    int n=m.auto_present&&m.adds?1:m.list_count;
    if(!m.list_unwritten)*count=(unsigned)n;
    for(int i=0;i<n&&i<16;i++)p[i].id=m.auto_present&&m.adds?900:m.list_ids[i];
    if(m.list_canary)((unsigned char*)out)[sizeof(ServiceEntry)*16]=0;
    return m.list_rc;
}
int sceSystemServiceAddLocalProcess(int app,const char *path,const char *const *args,const void *opaque)
{
    CHECK(app==8216&&!strcmp(path,helpers[0])&&args[0]==path&&!args[1]);
    const ServiceOptions *o=opaque;CHECK(o->size==72&&o->fd==81&&o->crash==0&&o->other[0]==UINT_MAX);
    uint64_t preload;memcpy(&preload,&o->other[3],8);CHECK(preload==UINT64_C(0x8000000000000002));
    CHECK(owner.generations[0].launch_possible&&atomic_load(&owner.generations[0].state)==G_STARTING);
    m.adds++;
    if(m.add_cancel)pw_wine_fixture_owner_cancel(&owner);
    if(m.add_partial_failure){
        /* Model an unrelated failure publisher paused at its claimed state.
         * These plain fields deliberately do not identify the service failure. */
        owner.failure_api=API_CLOCK;owner.failure_raw=123;owner.failure_errno=ERANGE;
        atomic_store(&owner.failure_state,1);
    }
    return m.add_result;
}
int sceSystemServiceKillLocalProcess(int app,int id)
{CHECK(app==8216&&id==900);m.kills++;return m.kill_result;}
int pw_wine_fixture_socket_prepare(int fd,unsigned flags,PwWineFixtureSocketResult *r)
{CHECK(fd==71&&flags==PW_WF_SOCKET_CLOEXEC);memset(r,0,sizeof(*r));if(m.prepare_cancel)m.cancelled=1;if(m.prepare_expire)m.now=owner.end;if(m.prepare_error){r->status=-1;r->api=3;r->errno_valid=1;r->native_error=EACCES;}return m.prepare_error;}
int owner_wire_validate(PwNativeChildIo *io,int fd,PwWineChildWireResult *r)
{CHECK(io&&fd==80);m.validations++;if(m.validate_error){r->status=1;r->raw_result=-1;}return m.validate_error;}
int owner_wire_send(PwNativeChildIo *io,int fd,const PwWineChildFrame *f,int right,PwWineChildWireResult *r)
{
    CHECK(io&&fd==80&&right==71&&f->kind==PW_WC_BOOTSTRAP);
    if(m.root_during_send){m.root_during_send=0;CHECK(!report_root_exit(&owner,77));m.wire_cancelled=io->cancelled(io->context);if(m.wire_cancelled){r->status=1;return -1;}}
    m.sent=*f;m.sends++;diagnostic_child_run(f,&scenario,&child_result);
    if(m.send_error){r->status=1;r->raw_result=-1;r->ownership_uncertain=m.wire_uncertain;}
    return m.send_error;
}
int owner_wire_try_send(int fd,const PwWineChildFrame *f,int right,PwWineChildWireResult *r)
{CHECK(fd==80&&right==-1&&f->kind==PW_WC_SIGNAL);m.sent=*f;m.sends++;(void)r;return m.send_error;}
int owner_wire_same_session(const PwWineChildFrame *a,const PwWineChildFrame *b)
{return pw_wine_child_wire_same_session(a,b);}
int owner_wire_receive(PwNativeChildIo *io,int fd,uint32_t kinds,PwWineChildFrame *out,int *right,PwWineChildWireResult *r)
{
    CHECK(io&&fd==80&&*right==-1);m.receives++;
    if(m.receive_error){r->status=1;r->raw_result=-1;return PW_WC_ERROR;}
    memset(out,0,sizeof(*out));
    if(kinds==PW_WC_KIND(PW_WC_HELLO)){out->kind=PW_WC_HELLO;out->child_pid=600;out->child_ppid=53;memcpy(out->build_id,build40,41);}
    else{if(child_result.sends<2){r->status=PW_WC_BUDGET;r->api=PW_WC_API_CLOCK;return PW_WC_ERROR;}
 CHECK(child_result.sends==2);CHECK(!pw_wine_child_wire_decode(out,child_result.bytes));CHECK(kinds&PW_WC_KIND(out->kind));
 if(corrupt_generation){unsigned char bytes[PW_WC_WIRE_BYTES];out->generation++;CHECK(!pw_wine_child_wire_encode(bytes,out));CHECK(!pw_wine_child_wire_decode(out,bytes));}}
    if(m.extra_right)*right=82;
    return PW_WC_RECORD;
}
int owner_wire_receive_step(PwNativeChildIo *io,int fd,uint32_t kinds,PwWineChildFrame *out,int *right,PwWineChildWireResult *r)
{CHECK(io&&fd==80&&kinds&&out&&*right==-1&&r);if(m.step_result==PW_WC_RECORD){*out=m.sent;out->kind=PW_WC_SIGNAL_ACK;}return m.step_result;}
static PwWineFixtureOwnerConfig config(unsigned profile)
{
    PwWineFixtureOwnerConfig c={.session=0x123400,.profile=profile,.child_unix_path="/data/prospero-win/prefixes/windows-child-fixture-v1/drive_c/windows-child-fixture/child.exe",.child_sha256=hash64,.helper_image=helper_bytes,.helper_bytes=4,.build_id=build40,.context=&m,.clock_ms=clock_cb,.cancelled=cancel_cb,.record=record_cb};return c;
}
static void reset(unsigned profile)
{
    memset(&m,0,sizeof(m));force_weak_failure=weak_calls=0;m.now=1000;m.next_fd=10;m.app_id=8216;m.pair_a=80;m.pair_b=81;m.add_result=900;m.auto_present=1;
    PwWineFixtureOwnerConfig c=config(profile);CHECK(!pw_wine_fixture_owner_init(&owner,sizeof(owner),&c,&provider));
}
static void preflight(void){CHECK(!pw_wine_fixture_owner_pump(&owner));CHECK(atomic_load(&owner.initialized)&&owner.app_id==8216&&owner.helper_index==0);}
static Generation *admitted(unsigned profile)
{
    reset(profile);preflight();uint64_t id=0;
    const char *path=profile==1?owner.config.child_unix_path:"/data/prospero-win/prefixes/battlenet-experimental-v1/drive_c/Battle.net/Agent.exe";
    CHECK(!provider.admit(provider.context,44,45,PW_WINE_FIXTURE_AMD64,path,&id));CHECK(id);
    Generation *g=find(&owner,id);CHECK(g&&g->caller_pid==44&&g->caller_tid==45);return g;
}
static Generation *bound(unsigned profile)
{Generation *g=admitted(profile);uint64_t id=0;CHECK(!provider.bind_process(provider.context,44,45,46,&id)&&id==g->generation);return g;}


static Generation *run_case(unsigned profile,int which,int probe,int cleanup)
{
    scenario=(DiagnosticCase){.which=which,.probe=probe,.cleanup_error=cleanup,.profile=(int)profile};
    Generation *g=bound(profile);g->stream_fd=71;g->wine_tid=47;
    if(profile==PW_WC_PROFILE_BATTLENET)g->machine=PW_WC_MACHINE_I386;
    atomic_store(&g->state,G_STARTING);start_generation(&owner,g);
    CHECK(child_result.exit_code==14&&child_result.closes[72]==1&&child_result.closes[3]==1);
    CHECK(!child_result.envs&&!child_result.loads&&!child_result.threads);
    CHECK(!g->ack&&atomic_load(&g->cleanup_requested)&&atomic_load(&g->state)!=G_RUNNING);
    CHECK(m.adds==1&&!m.kills&&g->service_id==900&&!pw_wine_fixture_owner_release_ready(&owner));
    CHECK(m.closes[81]==1&&m.closes[71]==1&&!m.closes[70]);
    CHECK(child_result.stage_end==31000&&child_result.total_end==(profile==1?61000:301000));
    return g;
}
static void check_failure(unsigned profile,int which,unsigned api,int raw,int error,unsigned aux,int detail,int cleanup)
{
    Generation *g=run_case(profile,which,0,cleanup);PwWineChildFrame *f=&child_result.failure;
    CHECK(child_result.sends==2&&child_result.hello.kind==PW_WC_HELLO&&f->kind==PW_WC_FAILURE);
    CHECK(f->status==-1&&f->failure_api==api&&f->failure_raw==raw);
    CHECK(f->errno_valid==(unsigned)(error!=0)&&f->native_error==error);
    CHECK(f->returned_length==aux&&f->returned_value==detail);
    CHECK(pw_wine_child_wire_same_session(f,&g->session)&&f->sequence==1);
    CHECK(m.boot_failures==1&&m.boot_values==1&&m.boot_api==api&&m.boot_raw==raw&&m.boot_errno==error);
    CHECK(m.boot_aux1==aux&&m.boot_aux2==detail&&m.boot_valid==(error!=0));
    CHECK(owner.failure_api==API_HANDOFF&&owner.failure_raw==-1&&owner.failure_errno==error);
    CHECK(child_result.stage==(which==CASE_LOG?PW_WCB_INITIAL:PW_WCB_PATHS));
    CHECK(child_result.probe_stats==(which==CASE_LOG));
    CHECK(child_result.closes[5]==(which!=CASE_LOG));
    CHECK(child_result.closes[9]==(which==CASE_RUNTIME_HASH||which==CASE_RUNTIME_READ||which==CASE_RUNTIME_STAT||which==CASE_RUNTIME_TYPE||which==CASE_RUNTIME_SIZE||which==CASE_RUNTIME_EXTRA||which==CASE_RUNTIME_CHANGED||which==CASE_RUNTIME_CLOSE));
    printf("profile=%u case=%d cleanup_error=%d api=%u raw=%d errno=%d stage=%u accepted failure only\n",profile,which,cleanup,api,raw,error,child_result.stage);
}
int main(int argc,char **argv)
{
    if(argc==2&&!strcmp(argv[1],"initial-red")){
        run_case(1,CASE_LOG,0,0);CHECK(child_result.failure.errno_valid==1&&child_result.failure.native_error==EACCES);return 0;
    }
    if(argc==2&&!strcmp(argv[1],"logger-red")){
        scenario=(DiagnosticCase){.which=CASE_PREFIX,.log_after_path=1};
        Generation *g=bound(1);g->stream_fd=71;g->wine_tid=47;atomic_store(&g->state,G_STARTING);start_generation(&owner,g);
        printf("PATHS original errno=%d local stage=%u sends=%d parent bootstrap records=%u\n",child_result.error,child_result.stage,child_result.sends,m.boot_failures);fflush(stdout);
        CHECK(child_result.sends==2&&child_result.failure.native_error==EACCES&&m.boot_errno==EACCES);return 0;
    }
    for(unsigned profile=1;profile<=2;profile++)for(int cleanup=0;cleanup<2;cleanup++){
        check_failure(profile,CASE_LOG,PW_WC_DIAG_LOG_OPEN,-1,EACCES,PW_WC_DATA_DIRECTORY,0,cleanup);
        check_failure(profile,CASE_PREFIX,PW_WC_DIAG_DIRECTORY_STAT,-1,EACCES,PW_WC_DIRECTORY_PREFIX,0,cleanup);
        check_failure(profile,CASE_CWD,PW_WC_DIAG_DIRECTORY_STAT,-1,ENOENT,PW_WC_DIRECTORY_CWD,0,cleanup);
        check_failure(profile,CASE_PREFIX_TYPE,PW_WC_DIAG_DIRECTORY_TYPE,0,0,PW_WC_DIRECTORY_PREFIX,0,cleanup);
        check_failure(profile,CASE_RUNTIME_OPEN,PW_WC_DIAG_RUNTIME_OPEN,-1,EACCES,0,0,cleanup);
        check_failure(profile,CASE_RUNTIME_HASH,PW_WC_DIAG_RUNTIME_HASH,-1,0,0,0,cleanup);
        check_failure(profile,CASE_RUNTIME_READ,PW_WC_DIAG_RUNTIME_READ,-1,EIO,0,0,cleanup);
        check_failure(profile,CASE_RUNTIME_STAT,PW_WC_DIAG_RUNTIME_STAT,-1,EIO,0,0,cleanup);
        check_failure(profile,CASE_RUNTIME_TYPE,PW_WC_DIAG_RUNTIME_TYPE,0,0,0,0,cleanup);
        check_failure(profile,CASE_RUNTIME_SIZE,PW_WC_DIAG_RUNTIME_SIZE,0,0,0,0,cleanup);
        check_failure(profile,CASE_RUNTIME_EXTRA,PW_WC_DIAG_RUNTIME_EXTRA_READ,-1,EIO,0,0,cleanup);
        check_failure(profile,CASE_RUNTIME_CHANGED,PW_WC_DIAG_RUNTIME_CHANGED,0,0,0,0,cleanup);
        check_failure(profile,CASE_RUNTIME_CLOSE,PW_WC_DIAG_RUNTIME_CLOSE,-1,EBADF,0,0,cleanup);
    }
    for(int probe=1;probe<=3;probe++){
        run_case(1,CASE_LOG,probe,1);PwWineChildFrame *f=&child_result.failure;
        CHECK(f->failure_api==PW_WC_DIAG_LOG_OPEN&&f->failure_raw==-1&&f->native_error==EACCES&&f->errno_valid==1);
        unsigned expected=probe==1?PW_WC_DATA_STAT_FAILED:probe==2?PW_WC_DATA_NOT_DIRECTORY:PW_WC_DATA_UNEXPECTED;
        int detail=probe==1?ENOTDIR:probe==3?7:0;
        CHECK(f->returned_length==expected&&f->returned_value==detail&&child_result.probe_stats==1);
        CHECK(m.boot_values==1&&m.boot_aux1==expected&&m.boot_aux2==detail&&m.boot_valid==1);
    }
    /* A valid wire failure from another generation is not attributed to ours. */
    corrupt_generation=1;run_case(1,CASE_LOG,0,0);corrupt_generation=0;
    CHECK(!m.boot_failures&&!m.boot_values&&owner.failure_errno==0);
    /* Timeout/Stop in the optional observation cannot reset or extend budget. */
    for(int action=1;action<=3;action++){
        scenario=(DiagnosticCase){.which=CASE_LOG,.expire_probe=action==1,.cancel_probe=action==2,.expire_open=action==3};
        Generation *g=bound(1);g->stream_fd=71;g->wine_tid=47;atomic_store(&g->state,G_STARTING);start_generation(&owner,g);
        CHECK(child_result.sends==1&&child_result.exit_code==14&&!g->ack);
        CHECK(child_result.api==PW_WC_DIAG_LOG_OPEN&&child_result.raw==-1&&child_result.error==EACCES&&child_result.errno_valid==1);
        CHECK(child_result.probe_stats==(action!=3)&&child_result.stage_end==31000&&child_result.total_end==61000);
        CHECK(child_result.closes[72]==1&&child_result.closes[3]==1&&!child_result.loads&&!child_result.threads);
    }
    run_case(1,CASE_PATH_BUDGET,0,0);CHECK(child_result.sends==1&&child_result.stage==PW_WCB_PATHS);
    CHECK(child_result.api==PW_WC_DIAG_BUDGET&&child_result.error==0&&!child_result.errno_valid);
    for(int fault=0;fault<=4;fault++){
        scenario=(DiagnosticCase){.which=CASE_PREFIX,.log_after_path=1,.transport_guard=fault};
        Generation *g=bound(1);g->stream_fd=71;g->wine_tid=47;atomic_store(&g->state,G_STARTING);start_generation(&owner,g);
        CHECK(child_result.api==PW_WC_DIAG_DIRECTORY_STAT&&child_result.error==EACCES&&child_result.errno_valid==1);
        CHECK(child_result.exit_code==14&&!g->ack&&!child_result.threads&&child_result.closes[72]==1&&child_result.closes[3]==1&&child_result.closes[5]==1);
        if(!fault){CHECK(child_result.sends==2&&child_result.failure.native_error==EACCES&&m.boot_errno==EACCES&&m.boot_values==1);}
        else {CHECK(child_result.sends==1&&!m.boot_failures&&!m.boot_values);}
    }
    run_case(1,CASE_LOG_HEADER,0,0);
    CHECK(child_result.stage==PW_WCB_INITIAL&&child_result.sends==2&&child_result.failure.failure_api==PW_WC_DIAG_LOG_HEADER);
    CHECK(child_result.failure.status==-1&&!child_result.failure.errno_valid&&!child_result.failure.native_error&&m.boot_values==1);
    printf("Actual child/main/bootstrap/codec/owner with mock platform boundaries: %u checks passed\n",checks);return 0;
}
