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
#include "../native/pw_wine_fixture_owner.c"
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
    const char *last_open_path;
    int root_during_clock,inject_seal,publication_samples;
    unsigned first_failures,first_index,release_index,inside_callback,reenter_failure;
    int64_t first_api,first_raw,first_errno;
    int extra_right,wire_uncertain,auto_present,prepare_cancel,prepare_expire;
    int record_action,step_result,root_during_send,wire_cancelled,async_idle;
    int add_cancel,add_partial_failure;
    int helper_open_error[2],helper_mismatch[2],fd_helper[128];
    unsigned helper_matches,launch_paths,hello_bad,hello_refused,bootstrap_sent,bootstrap_stopped,stop_control;
    int64_t hello_mismatch,stop_phase,stop_progress,stop_helper,stop_status,stop_api,stop_raw;
    int64_t launch_read_index,launch_service_index;
    const char *record_event;
    unsigned inject_progress, progress_auto, progress_stage, progress_mutation, progress_records, progress_mask_refused;
    unsigned failure_frame,failure_flags,failure_mutation,cancel_sends,receive_eof,cancel_send_error;
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
static const char hash64[]="0000000000000000000000000000000000000000000000000000000000000000";
static const char build40[]="1111111111111111111111111111111111111111";
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
    if(!strcmp(event,"bootstrap_progress"))m.progress_records++;
    if(!strcmp(event,"hello_refused")){m.hello_refused++;m.hello_mismatch=a;CHECK(!b&&!d);}
    if(!strcmp(event,"bootstrap_sent")){m.bootstrap_sent++;CHECK(a==owner.config.profile&&b==owner.generations[0].machine&&!d);}
    if(!strcmp(event,"bootstrap_stopped")){m.bootstrap_stopped++;m.stop_phase=a;m.stop_progress=b;m.stop_helper=d;}
    if(!strcmp(event,"bootstrap_stop_control")){m.stop_control++;m.stop_status=a;m.stop_api=b;m.stop_raw=d;}
    if(!strcmp(event,"first_failure")){
        CHECK(!m.inside_callback&&!m.first_failures);
        m.first_failures++;m.first_index=m.records;m.first_api=a;m.first_raw=b;m.first_errno=d;
        if(m.reenter_failure){PwWineFixtureSocketResult again={.api=999,.errno_valid=1,.native_error=ERANGE};m.reenter_failure=0;pw_wine_fixture_owner_socket_failure(&owner,&again);}
    }
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
    CHECK(path&&(flags&O_NOFOLLOW)&&(flags&O_NONBLOCK));m.opens++;m.last_open_path=path;
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
    Generation *launched=NULL;
    for(unsigned i=0;i<atomic_load(&owner.count);i++)if(opaque==&owner.generations[i].options)launched=&owner.generations[i];
    CHECK(launched&&launched->launch_possible&&atomic_load(&launched->state)==G_STARTING);
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
void pw_wine_child_hash_init(PwWineChildHash *h){memset(h,0,sizeof(*h));}
int pw_wine_child_hash_update(PwWineChildHash *h,const void *p,size_t n){CHECK(p&&n);h->bytes+=n;return 0;}
void pw_wine_child_hash_final(PwWineChildHash *h,char out[65]){CHECK(h->bytes==4);memcpy(out,hash64,65);if(m.hash_bad)out[0]='f';}
int pw_wine_child_wire_validate(PwNativeChildIo *io,int fd,PwWineChildWireResult *r)
{CHECK(io&&fd==80);m.validations++;if(m.validate_error){r->status=1;r->raw_result=-1;}return m.validate_error;}
int pw_wine_child_wire_send(PwNativeChildIo *io,int fd,const PwWineChildFrame *f,int right,PwWineChildWireResult *r)
{
    CHECK(io&&fd==80&&right==71&&f->kind==PW_WC_BOOTSTRAP);
    if(m.root_during_send){m.root_during_send=0;CHECK(!report_root_exit(&owner,77));m.wire_cancelled=io->cancelled(io->context);if(m.wire_cancelled){r->status=1;return -1;}}
    m.sent=*f;m.sends++;
    if(m.send_error){r->status=1;r->raw_result=-1;r->ownership_uncertain=m.wire_uncertain;}
    return m.send_error;
}
int pw_wine_child_wire_try_send(int fd,const PwWineChildFrame *f,int right,PwWineChildWireResult *r)
{CHECK(fd==80&&right==-1&&(f->kind==PW_WC_SIGNAL||f->kind==PW_WC_CANCEL));
 if(f->kind==PW_WC_CANCEL){m.cancel_sends++;if(m.cancel_send_error){r->status=PW_WC_OS;r->delivery_uncertain=1;return -1;}}
 m.sent=*f;m.sends++;return m.send_error;}
int pw_wine_child_wire_same_session(const PwWineChildFrame *a,const PwWineChildFrame *b)
{return a->generation==b->generation&&a->parent_pid==b->parent_pid&&a->child_pid==b->child_pid&&a->wine_pid==b->wine_pid&&a->wine_tid==b->wine_tid&&a->profile==b->profile&&a->machine==b->machine&&a->child_ppid==b->child_ppid&&!memcmp(a->build_id,b->build_id,41);}
static int progress_frame(uint32_t kinds,PwWineChildFrame *out,PwWineChildWireResult *r)
{
    if(!m.inject_progress)return 0;
    m.inject_progress--;
    if(!(kinds&PW_WC_KIND(PW_WC_PROGRESS))){m.progress_mask_refused++;r->status=PW_WC_PROTOCOL;r->api=PW_WC_API_RECEIVE;return PW_WC_ERROR;}
    *out=m.sent;out->kind=PW_WC_PROGRESS;out->failure_api=m.progress_stage;if(m.progress_auto)m.progress_stage++;
    if(m.progress_mutation==1)out->generation++;
    if(m.progress_mutation==2)out->child_pid++;
    if(m.progress_mutation==3)out->child_ppid++;
    if(m.progress_mutation==4)out->parent_pid++;
    if(m.progress_mutation==5)out->wine_pid++;
    if(m.progress_mutation==6)out->wine_tid++;
    if(m.progress_mutation==7)out->profile++;
    if(m.progress_mutation==8)out->machine++;
    if(m.progress_mutation==9)out->build_id[0]='f';
    if(m.progress_mutation==10)out->sequence++;
    return PW_WC_RECORD;
}

int pw_wine_child_wire_receive(PwNativeChildIo *io,int fd,uint32_t kinds,PwWineChildFrame *out,int *right,PwWineChildWireResult *r)
{
    CHECK(io&&fd==80&&*right==-1);m.receives++;
    if(m.receive_error){r->status=m.receive_error==2?PW_WC_PROTOCOL:1;
        r->api=PW_WC_API_RECEIVE;r->raw_result=m.receive_error==2?7:-1;return PW_WC_ERROR;}
    if(m.receive_eof){r->channel_zero_observed=r->hangup_observed=1;return PW_WC_CHANNEL_CLOSED;}
    if(m.inject_progress&&(kinds&PW_WC_KIND(PW_WC_BOOTSTRAP_ACK)))return progress_frame(kinds,out,r);
    if(m.failure_frame){
        m.failure_frame=0;CHECK(kinds&PW_WC_KIND(PW_WC_FAILURE));
        *out=m.sent;out->kind=PW_WC_FAILURE;out->status=-PW_WCB_DATA;
        out->failure_api=PW_WCD_CANCEL;out->returned_length=m.failure_flags<<PW_WCD_STATE_SHIFT;
        if(m.failure_mutation==1)out->generation++;
        if(m.failure_mutation==2)out->child_pid++;
        if(m.failure_mutation==3)out->child_ppid++;
        if(m.failure_mutation==4)out->parent_pid++;
        if(m.failure_mutation==5)out->wine_pid++;
        if(m.failure_mutation==6)out->wine_tid++;
        if(m.failure_mutation==7)out->profile++;
        if(m.failure_mutation==8)out->machine++;
        if(m.failure_mutation==9)out->build_id[0]='f';
        if(m.failure_mutation==10)out->sequence++;
        if(m.extra_right)*right=82;
        return PW_WC_RECORD;
    }
    memset(out,0,sizeof(*out));
    if(kinds==PW_WC_KIND(PW_WC_HELLO)){out->kind=PW_WC_HELLO;out->child_pid=600;out->child_ppid=53;memcpy(out->build_id,build40,41);if(m.hello_bad)out->build_id[0]='f';}
    else{*out=m.sent;out->kind=PW_WC_BOOTSTRAP_ACK;if(m.ack_bad)out->generation++;}
    if(m.extra_right)*right=82;
    return PW_WC_RECORD;
}
int pw_wine_child_wire_receive_step(PwNativeChildIo *io,int fd,uint32_t kinds,PwWineChildFrame *out,int *right,PwWineChildWireResult *r)
{CHECK(io&&fd==80&&kinds&&out&&*right==-1&&r);if(m.inject_progress)return progress_frame(kinds,out,r);if(m.step_result==PW_WC_RECORD){*out=m.sent;out->kind=PW_WC_SIGNAL_ACK;}return m.step_result;}
/* Legacy controls model transport; real zero-timeout ownership is separately
 * exercised by test_pw_wine_child_wire. No native service is executed. */
int pw_wine_child_wire_send_step(PwNativeChildIo *io,int fd,const PwWineChildFrame *f,int right,PwWineChildWireResult *r)
{return pw_wine_child_wire_send(io,fd,f,right,r)?PW_WC_ERROR:PW_WC_RECORD;}
int pw_wine_child_wire_receive_nowait(PwNativeChildIo *io,int fd,uint32_t kinds,PwWineChildFrame *out,int *right,PwWineChildWireResult *r)
{
    if(m.async_idle&&(kinds&PW_WC_KIND(PW_WC_BOOTSTRAP_ACK)))return PW_WC_IDLE;
    if(kinds&(PW_WC_KIND(PW_WC_HELLO)|PW_WC_KIND(PW_WC_BOOTSTRAP_ACK)))
        return pw_wine_child_wire_receive(io,fd,kinds,out,right,r);
    return pw_wine_child_wire_receive_step(io,fd,kinds,out,right,r);
}
#ifndef PW_WFO_UI_TEST_CONFIG
#define PW_WFO_UI_TEST_CONFIG
#endif
static PwWineFixtureOwnerConfig config(unsigned profile)
{
    PwWineFixtureOwnerConfig c={.session=0x123400,.profile=profile,.child_unix_path="/data/prospero-win/prefixes/windows-child-fixture-v1/drive_c/windows-child-fixture/child.exe",.child_sha256=hash64,.helper_image=helper_bytes,.helper_bytes=4,.build_id=build40,.context=&m,.clock_ms=clock_cb,.cancelled=cancel_cb,.record=record_cb PW_WFO_UI_TEST_CONFIG};return c;
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
static void release_deadlock(void)
{
    Generation *g=bound(1);atomic_store(&g->state,G_RETIRED);provider.startup_result(provider.context,g->generation,1,0);
    CHECK(!atomic_load(&g->released));CHECK(!report_root_exit(provider.context,77));
    pw_wine_fixture_owner_pump(&owner);
    printf("retired service with retained Windows handle: release_ready=%d released=%u\n",pw_wine_fixture_owner_release_ready(&owner),atomic_load(&g->released));fflush(stdout);
    CHECK(pw_wine_fixture_owner_release_ready(&owner)==1);
}
static void admission_tests(void)
{
    reset(2);preflight();
    const char *bad[]={NULL,"","/data/prospero-win/prefixes/other/drive_c/Agent.exe",
        "/data/prospero-win/prefixes/battlenet-experimental-v1/drive_c/",
        "/data/prospero-win/prefixes/battlenet-experimental-v1/drive_c/../Agent.exe",
        "/data/prospero-win/prefixes/battlenet-experimental-v1/drive_c/./Agent.exe",
        "/data/prospero-win/prefixes/battlenet-experimental-v1/drive_c/a//Agent.exe",
        "/data/prospero-win/prefixes/battlenet-experimental-v1/drive_c/a/",
        "/data/prospero-win/prefixes/battlenet-experimental-v1/drive_c/a\\Agent.exe",
        "/data/prospero-win/prefixes/battlenet-experimental-v1/drive_c/wineboot.exe",
        "/data/prospero-win/prefixes/battlenet-experimental-v1/drive_c/windows/winedevice.exe"};
    for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++){
        uint64_t out=UINT64_MAX;CHECK(provider.admit(&owner,44,45,PW_WINE_FIXTURE_AMD64,bad[i],&out)==WF_UNSUPPORTED);
        CHECK(out==UINT64_MAX&&!atomic_load(&owner.count)&&!m.adds&&!m.dups);
    }
    const char *vendor="/data/prospero-win/prefixes/battlenet-experimental-v1/drive_c/Agent.exe";
    uint64_t out=0;CHECK(provider.admit(&owner,44,45,0x1c4,vendor,&out)==WF_UNSUPPORTED);
    CHECK(!provider.admit(&owner,44,45,PW_WINE_FIXTURE_I386,vendor,&out));
    CHECK(owner.generations[0].machine==PW_WINE_FIXTURE_I386);
    uint64_t ignored=999;CHECK(provider.admit(&owner,44,45,PW_WINE_FIXTURE_AMD64,vendor,&ignored)!=0&&ignored==999);
    CHECK(provider.admit(&owner,46,47,PW_WINE_FIXTURE_AMD64,vendor,&ignored)!=0&&ignored==999);
    for(unsigned i=1;i<16;i++)CHECK(!provider.admit(&owner,44,45+i,PW_WINE_FIXTURE_AMD64,vendor,&out));
    CHECK(atomic_load(&owner.count)==16);CHECK(provider.admit(&owner,44,99,PW_WINE_FIXTURE_AMD64,vendor,&out)!=0);
    reset(1);preflight();out=99;
    CHECK(provider.admit(&owner,44,45,PW_WINE_FIXTURE_I386,owner.config.child_unix_path,&out)==WF_UNSUPPORTED&&out==99);
    m.hash_bad=1;CHECK(provider.admit(&owner,44,45,PW_WINE_FIXTURE_AMD64,owner.config.child_unix_path,&out)!=0);
    CHECK(!atomic_load(&owner.count)&&!m.adds&&atomic_load(&owner.blocked));
    reset(2);preflight();m.root_during_clock=1;out=99;
    CHECK(provider.admit(&owner,44,45,PW_WINE_FIXTURE_AMD64,vendor,&out)!=0);
    CHECK(out==99&&!atomic_load(&owner.count)&&!atomic_load(&owner.admission_claim));
    CHECK(!report_root_exit(&owner,77));pw_wine_fixture_owner_pump(&owner);
    CHECK(pw_wine_fixture_owner_release_ready(&owner));
}
static void callbacks_tests(void)
{
    Generation *g=admitted(2);uint64_t out=999;
    CHECK(provider.bind_process(&owner,44,46,47,&out)!=0&&out==999);
    CHECK(provider.bind_process(&owner,45,45,47,&out)!=0&&out==999);
    CHECK(!provider.bind_process(&owner,44,45,47,&out)&&out==g->generation);
    CHECK(provider.bind_process(&owner,44,45,48,&out)!=0&&g->wine_pid==47);
    CHECK(provider.startup_remaining_ms(&owner,g->generation)==30000);
    m.now=2000;CHECK(provider.startup_remaining_ms(&owner,g->generation)==29000);
    m.now=1500;CHECK(!provider.startup_remaining_ms(&owner,g->generation)&&atomic_load(&owner.blocked));
    g=bound(2);provider.startup_result(&owner,g->generation,1,0);
    CHECK(atomic_load(&g->startup_done)==2&&atomic_load(&g->startup_success)==1&&!atomic_load(&g->startup_status));
    provider.startup_result(&owner,g->generation,0,0xc1234567);
    CHECK(atomic_load(&owner.uncertain)&&atomic_load(&g->startup_success)==1&&!atomic_load(&g->startup_status));
    g=bound(2);provider.release_process(&owner,g->generation,46);CHECK(atomic_load(&g->released));
    provider.release_process(&owner,g->generation,46);CHECK(atomic_load(&owner.uncertain));
    g=bound(2);CHECK(provider.process_state(&owner,g->generation,46,-1,0)==PW_WF_OWNED_ACTIVE);
    atomic_store(&g->identity_ready,1);g->session.child_pid=600;
    CHECK(provider.process_state(&owner,g->generation,46,601,0)==PW_WF_OWNED_UNCERTAIN);
}
static void spawn_tests(void)
{
    Generation *g=bound(1);m.sleep_action=1;
    CHECK(!provider.spawn(&owner,g->generation,70,46,47));
    CHECK(m.dups==1&&m.pairs==1&&m.adds==1&&m.sends==1&&m.receives==2);
    CHECK(m.closes[71]==1&&m.closes[81]==1&&!m.closes[70]&&!m.closes[80]);
    CHECK(atomic_load(&g->state)==G_RUNNING&&g->hello&&g->ack&&!atomic_load(&g->startup_done));
    CHECK(m.sent.wine_pid==46&&m.sent.wine_tid==47&&m.sent.profile==1&&m.sent.machine==PW_WINE_FIXTURE_AMD64);
    provider.startup_result(&owner,g->generation,1,0);m.auto_present=0;m.now+=101;
    pw_wine_fixture_owner_pump(&owner);CHECK(atomic_load(&g->state)==G_RETIRED&&m.closes[80]==1&&!m.kills);
    CHECK(!report_root_exit(&owner,0));pw_wine_fixture_owner_pump(&owner);CHECK(report_root_exit(&owner,0));
    CHECK(!atomic_load(&g->released));
    for(unsigned phase=0;phase<6;phase++){
        g=bound(1);m.sleep_action=1;
        if(phase==0)m.dup_error=1;
        if(phase==1)m.prepare_error=1;
        if(phase==2){m.pair_rc=-1;m.pair_a=m.pair_b=-1;}
        if(phase==3)m.validate_error=1;
        if(phase==4)m.send_error=1;
        if(phase==5)m.ack_bad=1;
        CHECK(provider.spawn(&owner,g->generation,70,46,47)!=0);
        CHECK(!m.closes[70]&&m.adds==(phase>=4));
        CHECK(m.closes[71]==(phase!=0));
        CHECK(!atomic_load(&g->startup_done));
    }
    g=bound(1);m.prepare_error=1;m.close_error=-1;
    CHECK(provider.spawn(&owner,g->generation,70,46,47)!=0);
    CHECK(owner.failure_api==API_SOCKET&&owner.failure_errno==EACCES&&atomic_load(&owner.uncertain));
}
static void list_launch_tests(void)
{
    for(unsigned bad=0;bad<6;bad++){
        Generation *g=bound(2);g->stream_fd=71;g->wine_tid=47;atomic_store(&g->state,G_LAUNCH);
        if(bad==0)m.list_rc=-1;
        if(bad==1)m.list_unwritten=1;
        if(bad==2)m.list_count=16;
        if(bad==3){m.list_count=1;m.list_ids[0]=0;}
        if(bad==4){m.list_count=2;m.list_ids[0]=m.list_ids[1]=800;}
        if(bad==5)m.list_canary=1;
        pw_wine_fixture_owner_pump(&owner);
        CHECK(!m.pairs&&!m.adds&&!m.kills&&m.closes[71]==1);
    }
    for(unsigned bad=0;bad<4;bad++){
        Generation *g=bound(2);g->stream_fd=71;g->wine_tid=47;atomic_store(&g->state,G_LAUNCH);
        if(bad==0)m.add_result=0;
        if(bad==1)m.add_result=-7;
        if(bad==2){m.list_count=1;m.list_ids[0]=900;}
        if(bad==3){m.pair_rc=-1;m.pair_a=80;m.pair_b=81;}
        pw_wine_fixture_owner_pump(&owner);
        CHECK(atomic_load(&owner.uncertain)&&!m.kills);
        CHECK(m.adds==(bad!=3));if(bad==3)CHECK(!m.closes[80]&&!m.closes[81]);
    }
}
/* Headroom is a pre-dispatch policy, never a certificate for existing
 * services or helper transactions. All service boundaries remain mocked. */
static void list_headroom_tests(void)
{
    for(unsigned count=14;count<=16;count++){
        Generation *g=bound(2);PwWineCreationProvider creation;
        CHECK(!pw_wine_fixture_owner_creation(&owner,&creation));
        m.auto_present=0;m.list_count=(int)count;
        for(unsigned i=0;i<count;i++)m.list_ids[i]=800+(int)i;
        g->stream_fd=71;g->wine_tid=47;atomic_store(&g->state,G_LAUNCH);
        start_generation_attempt(&owner,g);
        if(count==14){
            CHECK(m.adds==1&&m.pairs==1&&g->service_id==900&&g->start_phase==1);
            CHECK(!atomic_load(&owner.blocked)&&!atomic_load(&owner.uncertain));
            CHECK(!m.closes[71]&&!m.closes[80]&&m.closes[81]==1);
            /* Our new entry fits at15. An unrelated concurrent addition
             * then makes the next16-entry observation ambiguous. */
            m.list_ids[14]=900;m.list_count=15;
            CHECK(service_list(&owner,g,0)==1&&!atomic_load(&owner.uncertain));
            m.list_ids[15]=901;m.list_count=16;
            CHECK(service_list(&owner,g,0)<0&&atomic_load(&owner.uncertain));
            CHECK(!m.kills&&!g->hello&&!g->ack&&!g->helper_possible);
            CHECK(!pw_wine_fixture_owner_release_ready(&owner));
        }else{
            CHECK(!m.adds&&!m.pairs&&!m.sends&&!m.receives&&!m.kills);
            CHECK(atomic_load(&g->state)==G_RETIRED&&!g->launch_possible&&!g->service_id);
            CHECK(m.closes[71]==1&&!m.closes[80]&&!m.closes[81]);
            CHECK(atomic_load(&owner.blocked)&&!atomic_load(&owner.uncertain));
            CHECK(owner.failure_api==API_LIST&&owner.failure_raw==(int64_t)count);
            CHECK(!g->hello&&!g->ack&&!g->helper_possible&&!atomic_load(&g->startup_success));
            CHECK(!pw_wine_fixture_owner_release_ready(&owner));
        }
        printf("service headroom: baseline=%u adds=%u uncertain=%u release=%d\n",count,m.adds,
               atomic_load(&owner.uncertain),pw_wine_fixture_owner_release_ready(&owner));
    }
    Generation *existing=bound(2);PwWineCreationProvider creation;
    CHECK(!pw_wine_fixture_owner_creation(&owner,&creation));
    existing->service_id=900;existing->hello=1;existing->helper_possible=1;
    existing->session.child_pid=600;atomic_store(&existing->identity_ready,1);
    atomic_store(&existing->state,G_STARTING);
    uint64_t id=0,bound_id=0;
    const char *path="/data/prospero-win/prefixes/battlenet-experimental-v1/drive_c/Agent.exe";
    CHECK(!provider.admit(&owner,44,48,PW_WINE_FIXTURE_AMD64,path,&id));
    CHECK(!provider.bind_process(&owner,44,48,49,&bound_id)&&bound_id==id);
    Generation *g=find(&owner,id);CHECK(g&&g!=existing);
    g->stream_fd=71;g->wine_tid=50;atomic_store(&g->state,G_LAUNCH);
    m.auto_present=0;m.list_count=15;m.list_ids[0]=900;
    for(unsigned i=1;i<15;i++)m.list_ids[i]=800+(int)i;
    start_generation_attempt(&owner,g);
    CHECK(!m.adds&&!m.pairs&&atomic_load(&g->state)==G_RETIRED);
    CHECK(existing->helper_possible&&atomic_load(&existing->state)==G_STARTING&&!existing->closed);
    CHECK(!existing->ack&&!atomic_load(&existing->startup_success)&&!atomic_load(&existing->released));
    CHECK(!pw_wine_fixture_owner_release_ready(&owner));
    CHECK(!report_root_exit(&owner,0));pw_wine_fixture_owner_pump(&owner);
    CHECK(existing->helper_possible&&atomic_load(&existing->state)==G_UNCERTAIN&&!m.kills);
    CHECK(!pw_wine_fixture_owner_release_ready(&owner)&&!atomic_load(&existing->released));
    puts("service headroom: saturated refusal preserves existing helper hold; no release or terminal success");
}

static void release_tests(void)
{
    release_deadlock();
    Generation *g=bound(2);atomic_store(&g->state,G_RETIRED);provider.startup_result(&owner,g->generation,0,0xc1234567);
    CHECK(!report_root_exit(&owner,1));pw_wine_fixture_owner_pump(&owner);
    CHECK(pw_wine_fixture_owner_release_ready(&owner)&&atomic_load(&owner.blocked));
    g=bound(2);atomic_store(&g->state,G_RETIRED);provider.startup_result(&owner,g->generation,1,0);
    atomic_store(&owner.active_callbacks,1);CHECK(!report_root_exit(&owner,0));pw_wine_fixture_owner_pump(&owner);
    CHECK(!pw_wine_fixture_owner_release_ready(&owner));atomic_store(&owner.active_callbacks,0);pw_wine_fixture_owner_pump(&owner);
    CHECK(pw_wine_fixture_owner_release_ready(&owner));
    g=bound(2);atomic_store(&g->state,G_RETIRED);CHECK(!report_root_exit(&owner,77));pw_wine_fixture_owner_pump(&owner);
    CHECK(pw_wine_fixture_owner_release_ready(&owner)&&!atomic_load(&g->startup_done));
    CHECK(pw_wine_fixture_owner_root_result(&owner,owner.config.session+1,0)==-1);
    g=bound(2);atomic_store(&g->state,G_RETIRED);provider.startup_result(&owner,g->generation,1,0);
    atomic_store(&owner.uncertain,1);CHECK(!report_root_exit(&owner,0));pw_wine_fixture_owner_pump(&owner);
    CHECK(!pw_wine_fixture_owner_release_ready(&owner));
}
static void stop_budget_tests(void)
{
    for(unsigned kind=0;kind<3;kind++){
        Generation *g=bound(1);if(kind)m.prepare_expire=1;else m.prepare_cancel=1;
        CHECK(provider.spawn(&owner,g->generation,70,46,47)!=0);
        CHECK(!m.adds&&!m.pairs&&m.closes[71]==1&&!m.closes[70]);
    }
    for(unsigned kind=1;kind<=2;kind++){
        Generation *g=bound(2);g->stream_fd=71;g->wine_tid=47;atomic_store(&g->state,G_LAUNCH);
        m.record_event="launch_possible";m.record_action=(int)kind;pw_wine_fixture_owner_pump(&owner);
        CHECK(!m.adds&&!m.kills&&!g->launch_possible&&m.closes[71]==1&&m.closes[80]==1&&m.closes[81]==1);
    }
    Generation *g=bound(2);g->stream_fd=71;g->wine_tid=47;atomic_store(&g->state,G_LAUNCH);
    m.record_event="launch_return";m.record_action=2;pw_wine_fixture_owner_pump(&owner);
    CHECK(m.adds==1&&!m.sends&&!m.kills&&g->service_id==900&&atomic_load(&owner.uncertain));
    g=bound(2);g->stream_fd=71;g->wine_tid=47;atomic_store(&g->state,G_LAUNCH);
    m.record_event="hello";m.record_action=1;pw_wine_fixture_owner_pump(&owner);
    CHECK(m.adds==1&&!m.sends&&m.kills==1&&g->kill_called&&atomic_load(&owner.blocked));
    g=bound(2);g->stream_fd=71;g->wine_tid=47;atomic_store(&g->state,G_LAUNCH);
    m.record_event="hello";m.record_action=1;
    /* Stop after launch is allowed to settle only this acquired service. */
    pw_wine_fixture_owner_pump(&owner);m.auto_present=0;m.now+=101;pw_wine_fixture_owner_pump(&owner);
    CHECK(m.kills==1&&atomic_load(&g->state)==G_RETIRED);
    provider.startup_result(&owner,g->generation,0,WF_CANCELLED);report_root_exit(&owner,1);
    pw_wine_fixture_owner_pump(&owner);CHECK(pw_wine_fixture_owner_release_ready(&owner)&&atomic_load(&owner.blocked));
}
static void signal_close_tests(void)
{
    Generation *g=bound(1);m.sleep_action=1;CHECK(!provider.spawn(&owner,g->generation,70,46,47));
    unsigned sends=m.sends;CHECK(provider.signal(&owner,g->generation+1,46,600,601,PW_WC_SIGNAL_QUIT)==PW_WF_SIGNAL_FAILED);
    CHECK(provider.signal(&owner,g->generation,46,601,601,PW_WC_SIGNAL_QUIT)==PW_WF_SIGNAL_FAILED&&m.sends==sends);
    CHECK(provider.signal(&owner,g->generation,46,600,601,PW_WC_SIGNAL_QUIT)==PW_WF_SIGNAL_QUEUED);
    CHECK(m.sends==sends+1&&atomic_load(&g->pending_signal)&&m.sent.sequence==2&&m.sent.target_tid==601);
    m.step_result=PW_WC_RECORD;pw_wine_fixture_owner_pump(&owner);
    CHECK(!atomic_load(&g->pending_signal)&&atomic_load(&g->signal_ack)==2&&!m.kills);
    m.now+=101;pw_wine_fixture_owner_pump(&owner);CHECK(atomic_load(&owner.blocked)&&m.kills==1);
    g=bound(2);g->control_fd=80;g->service_id=900;g->hello=1;atomic_store(&g->state,G_RUNNING);atomic_store(&g->cleanup_requested,1);
    atomic_flag_test_and_set(&g->send_claim);pw_wine_fixture_owner_pump(&owner);
    CHECK(g->absent&&atomic_load(&g->state)==G_SETTLING&&!m.closes[80]&&!m.kills&&m.lists==1);
    atomic_flag_clear(&g->send_claim);m.list_count=1;m.list_ids[0]=900;m.now+=101;
    pw_wine_fixture_owner_pump(&owner);
    CHECK(atomic_load(&g->state)==G_RETIRED&&m.closes[80]==1&&m.lists==1&&!m.kills);
    unsigned cases[][2]={{80,80},{80,UINT_MAX},{UINT_MAX,81}};
    for(unsigned i=0;i<3;i++){
        g=bound(2);g->stream_fd=71;g->wine_tid=47;atomic_store(&g->state,G_LAUNCH);
        m.pair_a=(int)cases[i][0];m.pair_b=(int)cases[i][1];pw_wine_fixture_owner_pump(&owner);
        CHECK(atomic_load(&owner.uncertain)&&!m.adds&&m.closes[71]==1);
        if(i!=2)CHECK(m.closes[80]==1);
        if(i==2)CHECK(m.closes[81]==1);
    }
}
static void retired_missing_result(void)
{
    Generation *g=bound(2);atomic_store(&g->state,G_RETIRED);CHECK(!report_root_exit(&owner,0));
    pw_wine_fixture_owner_pump(&owner);
    printf("retired missing startup result: release=%d blocked=%u missing_records=%u startup_done=%u\n",pw_wine_fixture_owner_release_ready(&owner),atomic_load(&owner.blocked),m.missing_result,atomic_load(&g->startup_done));fflush(stdout);
    CHECK(pw_wine_fixture_owner_release_ready(&owner)&&!atomic_load(&g->startup_done));
    CHECK(atomic_load(&owner.blocked)&&m.missing_result==1);
    pw_wine_fixture_owner_pump(&owner);CHECK(m.missing_result==1&&!atomic_load(&g->startup_done));
}
static void init_preflight_tests(void)
{
    for(unsigned bad=0;bad<16;bad++){
        reset(1);PwWineFixtureOwnerConfig c=config(1);PwWineFixtureProvider out,before;
        memset(&out,0xa5,sizeof(out));before=out;
        switch(bad){
        case 0:c.session=0;break;case 1:c.session=UINT64_MAX;break;case 2:c.profile=0;break;
        case 3:c.child_unix_path=NULL;break;case 4:c.child_unix_path="/unrelated/child.exe";break;
        case 5:c.child_sha256=NULL;break;case 6:c.child_sha256="short";break;
        case 7:c.build_id=NULL;break;case 8:c.build_id="short";break;
        case 9:c.helper_image=NULL;break;case 10:c.helper_bytes=0;break;
        case 11:c.helper_bytes=16*1024*1024+1;break;
        case 12:c.clock_ms=NULL;break;case 13:c.cancelled=NULL;break;case 14:c.record=NULL;break;
        default:c.profile=3;break;}
        CHECK(pw_wine_fixture_owner_init(&owner,sizeof(owner),&c,&out)==-1);
        CHECK(!memcmp(&out,&before,sizeof(out))&&!m.opens&&!m.adds);
    }
    for(unsigned bad=0;bad<8;bad++){
        reset(1);
        if(bad==0)m.open_error=1;
        if(bad==1)m.stat_error=1;
        if(bad==2)m.read_error=1;
        if(bad==3)m.close_error=-1;
        if(bad==4)m.app_rc=-7;
        if(bad==5)m.app_id=0;
        if(bad==6)m.app_id=-1;
        if(bad==7)m.app_canary=1;
        CHECK(pw_wine_fixture_owner_pump(&owner)==-1);
        CHECK(atomic_load(&owner.blocked)&&!m.adds&&!m.pairs);
    }
}
static void missing_caller_tests(void)
{
    for(unsigned bound_state=0;bound_state<2;bound_state++){
        Generation *g=bound_state?bound(2):admitted(2);uint64_t ignored=0;
        CHECK(!report_root_exit(&owner,77));
        CHECK(provider.bind_process(&owner,44,45,46,&ignored)!=0);
        CHECK(!provider.startup_remaining_ms(&owner,g->generation));
        CHECK(provider.spawn(&owner,g->generation,70,46,47)!=0&&!m.dups);
        pw_wine_fixture_owner_pump(&owner);
        CHECK(atomic_load(&g->state)==G_RETIRED&&!atomic_load(&g->startup_done));
        CHECK(pw_wine_fixture_owner_release_ready(&owner)&&atomic_load(&owner.blocked)&&m.missing_result==1);
    }
}
static void wire_root_closure(void)
{
    Generation *g=bound(1);m.sleep_action=1;m.root_during_send=1;
    CHECK(provider.spawn(&owner,g->generation,70,46,47)!=0);
    printf("root closed at wire cancellation sample: cancelled=%d modeled_transfers=%u adds=%u\n",m.wire_cancelled,m.sends,m.adds);fflush(stdout);
    CHECK(m.wire_cancelled==1&&m.sends==0&&m.adds==1);
}
static Generation *retired_for_detach(void)
{
    Generation *g=bound(2);atomic_store(&g->state,G_RETIRED);
    provider.startup_result(&owner,g->generation,1,0);return g;
}
static void detach_gate_tests(void)
{
    Generation *g=retired_for_detach();CHECK(!provider.root_exit(&owner,77));
    pw_wine_fixture_owner_pump(&owner);CHECK(!pw_wine_fixture_owner_release_ready(&owner));
    provider.root_detached(&owner,1,0,0);pw_wine_fixture_owner_pump(&owner);
    CHECK(pw_wine_fixture_owner_release_ready(&owner)&&m.publication_samples==1);
    CHECK(atomic_load(&owner.active_callbacks)==CALLBACKS_CLOSED);
    uint64_t output=99;unsigned sends=m.sends,adds=m.adds;
    CHECK(provider.admit(&owner,44,45,PW_WINE_FIXTURE_AMD64,owner.config.child_unix_path,&output)==WF_UNSUPPORTED&&output==99);
    CHECK(provider.bind_process(&owner,44,45,46,&output)==WF_BAD&&output==99);
    CHECK(provider.spawn(&owner,g->generation,70,46,47)==WF_CANCELLED);
    CHECK(!provider.startup_remaining_ms(&owner,g->generation));
    provider.startup_result(&owner,g->generation,0,UINT32_MAX);provider.release_process(&owner,UINT64_MAX,99);
    CHECK(provider.signal(&owner,g->generation,46,600,601,PW_WC_SIGNAL_QUIT)==PW_WF_SIGNAL_FAILED);
    CHECK(provider.process_state(&owner,g->generation,46,600,1)==PW_WF_OWNED_UNCERTAIN);
    CHECK(!atomic_load(&owner.uncertain)&&atomic_load(&g->startup_success)==1&&m.sends==sends&&m.adds==adds);
    retired_for_detach();CHECK(!provider.root_exit(&owner,0));provider.root_detached(&owner,0,-1,EACCES);
    pw_wine_fixture_owner_pump(&owner);CHECK(!pw_wine_fixture_owner_release_ready(&owner)&&atomic_load(&owner.uncertain));
    CHECK(owner.failure_raw==-1&&owner.failure_errno==EACCES);
    retired_for_detach();CHECK(!provider.root_exit(&owner,0));provider.root_detached(&owner,1,0,0);provider.root_detached(&owner,1,0,0);
    pw_wine_fixture_owner_pump(&owner);CHECK(!pw_wine_fixture_owner_release_ready(&owner)&&atomic_load(&owner.uncertain));
    retired_for_detach();force_weak_failure=1;
    CHECK(!provider.startup_remaining_ms(&owner,owner.generations[0].generation));
    CHECK(weak_calls==8&&!atomic_load(&owner.active_callbacks));force_weak_failure=0;
}
static void seal_race_test(void)
{
    retired_for_detach();CHECK(!report_root_exit(&owner,0));m.inject_seal=1;
    pw_wine_fixture_owner_pump(&owner);
    printf("callback before release seal: uncertainty=%u release=%d gate=%08x\n",atomic_load(&owner.uncertain),pw_wine_fixture_owner_release_ready(&owner),atomic_load(&owner.active_callbacks));fflush(stdout);
    CHECK(atomic_load(&owner.uncertain)&&!pw_wine_fixture_owner_release_ready(&owner));
    CHECK(atomic_load(&owner.active_callbacks)==CALLBACKS_CLOSED&&!m.publication_samples);
    CHECK(m.first_failures==1);
}
static void first_failure_tests(void)
{
    reset(2);preflight();CHECK(!m.first_failures);
    atomic_store(&owner.failure_state,1);owner.failure_api=API_SOCKET;owner.failure_raw=-7;owner.failure_errno=EACCES;
    pw_wine_fixture_owner_pump(&owner);CHECK(!m.first_failures&&!owner.failure_reported);
    atomic_store_explicit(&owner.failure_state,2,memory_order_release);pw_wine_fixture_owner_pump(&owner);
    CHECK(m.first_failures==1&&m.first_api==API_SOCKET&&m.first_raw==-7&&m.first_errno==EACCES);
    pw_wine_fixture_owner_pump(&owner);CHECK(m.first_failures==1);
    Generation *g=bound(2);m.inside_callback=1;
    provider.startup_result(&owner,g->generation,0,UINT32_C(0xc1234567));m.inside_callback=0;
    CHECK(!m.first_failures);pw_wine_fixture_owner_pump(&owner);
    CHECK(m.first_failures==1&&m.first_api==API_WINE&&m.first_raw==UINT32_C(0xc1234567)&&!m.first_errno);
    g=bound(2);m.prepare_error=1;m.close_error=-1;m.inside_callback=1;
    CHECK(provider.spawn(&owner,g->generation,70,46,47)!=0);m.inside_callback=0;
    CHECK(!m.first_failures&&owner.failure_api==API_SOCKET&&owner.failure_errno==EACCES);
    m.reenter_failure=1;pw_wine_fixture_owner_pump(&owner);
    CHECK(m.first_failures==1&&m.first_api==API_SOCKET&&m.first_raw==PW_WF_SOCKET_CLEX&&m.first_errno==EACCES);
    CHECK(owner.failure_api==API_SOCKET&&owner.failure_errno==EACCES);
    pw_wine_fixture_owner_pump(&owner);CHECK(m.first_failures==1);
    g=bound(2);atomic_store(&g->state,G_RETIRED);provider.startup_result(&owner,g->generation,0,77);
    report_root_exit(&owner,77);pw_wine_fixture_owner_pump(&owner);
    CHECK(m.first_failures==1&&m.first_index<m.release_index&&pw_wine_fixture_owner_release_ready(&owner));
}

/* These exercise the actual provider.spawn wait and actual supervisor pump.
 * Service/OS calls remain deterministic mocks, never console execution. */
static void launch_failure_tests(int close_fails)
{
    const int errors[]={-2147352574,-7,0};
    for(unsigned profile=1;profile<=2;profile++)for(unsigned i=0;i<sizeof(errors)/sizeof(errors[0]);i++){
        Generation *g=bound(profile);m.sleep_action=1;m.add_result=errors[i];
        m.close_error=close_fails?-1:0;
        uint64_t began=m.now;
        uint32_t status=provider.spawn(&owner,g->generation,70,46,47);
        printf("Add raw=%d close_error=%d status=%08x elapsed=%llu first_api=%u first_raw=%lld uncertain=%u\n",
               errors[i],m.close_error,status,(unsigned long long)(m.now-began),owner.failure_api,
               (long long)owner.failure_raw,atomic_load(&owner.uncertain));fflush(stdout);
        CHECK(m.now<g->startup_end&&m.now-began==10);
        CHECK(m.dups==1&&m.pairs==1&&m.adds==1&&!m.sends&&!m.receives&&!m.kills);
        CHECK(atomic_load(&g->state)==G_UNCERTAIN&&g->launch_possible&&!g->service_id);
        CHECK(atomic_load(&owner.blocked)&&atomic_load(&owner.uncertain));
        CHECK(g->stream_fd==-1&&g->passed_fd==-1&&g->control_fd==-1);
        CHECK(m.closes[71]==1&&m.closes[80]==1&&m.closes[81]==1&&!m.closes[70]);
        CHECK(atomic_load(&owner.failure_state)==2);
        /* Check the causal error before status so the combined failure has its own red. */
        CHECK(owner.failure_api==API_ADD&&owner.failure_raw==errors[i]&&!owner.failure_errno);
        CHECK(status==WF_BAD);
        CHECK(atomic_load(&g->cleanup_requested)&&!atomic_load(&g->startup_done));
        CHECK(m.first_failures==1&&m.first_api==API_ADD&&m.first_raw==errors[i]&&!m.first_errno);
        provider.startup_result(&owner,g->generation,0,status);
        CHECK(atomic_load(&g->startup_done)==2&&!atomic_load(&g->startup_success)&&atomic_load(&g->startup_status)==status);
        CHECK(owner.failure_api==API_ADD&&owner.failure_raw==errors[i]);
        unsigned lists=m.lists;
        for(unsigned n=0;n<3;n++)pw_wine_fixture_owner_pump(&owner);
        CHECK(provider.spawn(&owner,g->generation,70,46,47)==WF_BAD);
        uint64_t next=UINT64_MAX;
        CHECK(provider.admit(&owner,44,48,PW_WINE_FIXTURE_AMD64,
              profile==1?owner.config.child_unix_path:"/data/prospero-win/prefixes/battlenet-experimental-v1/drive_c/Agent.exe",&next)!=WF_OK);
        CHECK(next==UINT64_MAX&&atomic_load(&owner.count)==1);
        CHECK(!report_root_exit(&owner,status));pw_wine_fixture_owner_pump(&owner);
        CHECK(!pw_wine_fixture_owner_release_ready(&owner)&&atomic_load(&owner.uncertain));
        CHECK(m.dups==1&&m.pairs==1&&m.adds==1&&!m.kills&&m.lists==lists);
        CHECK(m.closes[71]==1&&m.closes[80]==1&&m.closes[81]==1&&!m.closes[70]);
        CHECK(m.first_failures==1);
    }
}
static void launch_wait_status_tests(void)
{
    for(unsigned action=3;action<=5;action++)for(unsigned profile=1;profile<=2;profile++){
        Generation *g=bound(profile);m.sleep_action=(int)action;
        uint32_t status=provider.spawn(&owner,g->generation,70,46,47);
        uint32_t expected=action==5?WF_CANCELLED:WF_TIMEOUT;
        printf("No launch: action=%u status=%08x expected=%08x first_api=%u now=%llu endpoint=%llu\n",
               action,status,expected,owner.failure_api,(unsigned long long)m.now,
               (unsigned long long)g->startup_end);fflush(stdout);
        CHECK(status==expected);
        CHECK(atomic_load(&owner.failure_state)==2&&owner.failure_api==API_CLOCK);
        CHECK(!atomic_load(&owner.uncertain)&&!g->launch_possible&&!g->service_id);
        CHECK(m.dups==1&&!m.adds&&!m.pairs&&!m.sends&&!m.receives&&!m.kills);
        CHECK(atomic_load(&g->cleanup_requested));
        pw_wine_fixture_owner_pump(&owner);
        CHECK(g->stream_fd==-1&&m.closes[71]==1&&!m.closes[70]);
        CHECK(atomic_load(&g->state)==G_RETIRED);
        CHECK(provider.spawn(&owner,g->generation,70,46,47)!=WF_OK&&!m.adds&&m.dups==1);
    }
}
static void launch_cancel_publication_tests(void)
{
    for(unsigned cancelled=0;cancelled<=1;cancelled++)for(unsigned partial=0;partial<=1;partial++){
        Generation *g=bound(1);m.sleep_action=1;m.add_result=-2147352574;
        m.add_cancel=(int)cancelled;m.add_partial_failure=(int)partial;
        uint32_t status=provider.spawn(&owner,g->generation,70,46,47);
        printf("Add publication: partial=%u cancel=%u status=%08x failure_state=%u\n",
               partial,cancelled,status,atomic_load(&owner.failure_state));fflush(stdout);
        CHECK(status==(cancelled?WF_CANCELLED:WF_BAD));
        CHECK(atomic_load(&owner.failure_state)==(partial?1u:2u));
        CHECK(m.adds==1&&!m.sends&&!m.receives&&!m.kills&&atomic_load(&owner.uncertain));
        CHECK(m.closes[71]==1&&m.closes[80]==1&&m.closes[81]==1&&!m.closes[70]);
        CHECK(atomic_load(&g->state)==G_UNCERTAIN&&!g->service_id&&g->launch_possible);
        if(partial){CHECK(!m.first_failures);CHECK(owner.failure_api==API_CLOCK&&owner.failure_raw==123);}
        else CHECK(owner.failure_api==API_ADD&&owner.failure_raw==m.add_result);
    }
}


static Generation *bound_read_alias(unsigned profile,unsigned absent_mask)
{
    reset(profile);
    for(unsigned i=0;i<2;i++)if(absent_mask&(1u<<i))m.helper_open_error[i]=ENOENT;
    CHECK(!pw_wine_fixture_owner_pump(&owner));
    CHECK(atomic_load(&owner.initialized)&&owner.helper_index==((absent_mask&1)?1:0));
    CHECK(m.helper_matches==(absent_mask?1u:2u));
    for(unsigned fd=10;fd<m.next_fd;fd++)CHECK(m.closes[fd]==1);
    uint64_t id=0;
    const char *path=profile==1?owner.config.child_unix_path:"/data/prospero-win/prefixes/battlenet-experimental-v1/drive_c/Agent.exe";
    CHECK(!provider.admit(&owner,44,45,PW_WINE_FIXTURE_AMD64,path,&id));
    CHECK(!provider.bind_process(&owner,44,45,46,&id));
    Generation *g=find(&owner,id);CHECK(g);return g;
}
static void helper_alias_tests(void)
{
    /* The mock gives parent reads and service dispatch distinct contracts.
     * This asserts the proposed fixed /app0 dispatch, not its firmware support. */
    for(unsigned profile=1;profile<=2;profile++)for(unsigned index=0;index<3;index++)for(unsigned rejected=0;rejected<=1;rejected++){
        const unsigned missing_order[]={1,0,2};unsigned missing=missing_order[index];
        Generation *g=bound_read_alias(profile,missing);m.sleep_action=1;
        if(rejected)m.add_result=-2147352574;
        uint32_t status=provider.spawn(&owner,g->generation,70,46,47);
        CHECK(status==(rejected?WF_BAD:WF_OK));
        CHECK(m.adds==1&&m.launch_paths==1);
        CHECK(m.launch_read_index==owner.helper_index&&m.launch_service_index==0);
        CHECK(g->arguments[0]==helpers[0]&&!strcmp(g->arguments[0],"/app0/native-wine-child.self"));
        if(rejected){
            for(unsigned n=0;n<3;n++)pw_wine_fixture_owner_pump(&owner);
            CHECK(provider.spawn(&owner,g->generation,70,46,47)==WF_BAD);
            CHECK(m.adds==1&&!m.kills&&!m.sends&&!m.receives);
            CHECK(atomic_load(&owner.uncertain)&&owner.failure_api==API_ADD);
            CHECK(m.closes[71]==1&&m.closes[80]==1&&m.closes[81]==1&&!m.closes[70]);
        }else CHECK(m.sends==1&&m.receives==2&&atomic_load(&g->state)==G_RUNNING);
    }
}
static void helper_identity_tests(void)
{
    for(unsigned bad=0;bad<4;bad++){
        reset(1);
        if(bad==0)m.helper_open_error[0]=m.helper_open_error[1]=ENOENT;
        if(bad==1){m.helper_open_error[0]=ENOENT;m.helper_mismatch[1]=1;}
        if(bad==2)m.helper_mismatch[0]=1; /* Other alias being valid is no escape. */
        if(bad==3)m.helper_mismatch[1]=1; /* Earlier valid alias does not excuse mismatch. */
        CHECK(pw_wine_fixture_owner_pump(&owner)!=0);
        CHECK(atomic_load(&owner.blocked)&&owner.failure_api==API_IMAGE);
        CHECK(!m.adds&&!m.pairs&&!m.dups&&!m.sends&&!m.receives&&!m.launch_paths);
        for(unsigned fd=10;fd<m.next_fd;fd++)CHECK(m.closes[fd]==1);
        uint64_t out=UINT64_MAX;
        CHECK(provider.admit(&owner,44,45,PW_WINE_FIXTURE_AMD64,owner.config.child_unix_path,&out)!=WF_OK);
        CHECK(out==UINT64_MAX&&!atomic_load(&owner.count));
    }
}
static void launch_path_callback_tests(void)
{
    for(unsigned action=1;action<=2;action++){
        Generation *g=bound_read_alias(1,1);m.sleep_action=1;
        m.record_event="launch_path";m.record_action=(int)action;
        uint32_t status=provider.spawn(&owner,g->generation,70,46,47);
        printf("launch_path callback: action=%u status=%08x adds=%u launch_possible=%u\n",
               action,status,m.adds,g->launch_possible);fflush(stdout);
        CHECK(m.launch_paths==1&&!m.adds&&!g->launch_possible&&!g->service_id);
        CHECK(status==(action==1?WF_CANCELLED:WF_TIMEOUT));
        CHECK(!m.sends&&!m.receives&&!m.kills&&!atomic_load(&owner.uncertain));
        CHECK(m.closes[71]==1&&m.closes[80]==1&&m.closes[81]==1&&!m.closes[70]);
        CHECK(atomic_load(&g->state)==G_RETIRED);
    }
}

static void creation_queue_tests(void)
{
    Generation *origin=bound(2);PwWineCreationProvider creation;
    CHECK(!pw_wine_fixture_owner_creation(&owner,&creation));
    origin->wine_tid=47;origin->session.child_pid=600;
    atomic_store_explicit(&origin->identity_ready,1,memory_order_release);
    atomic_store(&origin->state,G_STARTING);
    CHECK(!creation.join(&owner,origin->generation,46,47,600));
    PwWineCreationRequest q={.origin=origin->generation,.lease=1,.key=1,.now=m.now,.deadline=m.now+30000,
        .caller_pid=46,.caller_tid=47,.machine=PW_WINE_FIXTURE_AMD64,.image_bytes=2};
    q.image[0]='x';strcpy(q.path,"/data/prospero-win/prefixes/battlenet-experimental-v1/drive_c/Battle.net/Wow.exe");
    q.path_bytes=(uint32_t)strlen(q.path)+1;
    uint64_t id=0;unsigned opens=m.opens,lists=m.lists,sleeps=m.sleeps,adds=m.adds;
    CHECK(!creation.prepare(&owner,&q,&id)&&id!=origin->generation);
    CHECK(m.opens==opens&&m.lists==lists&&m.sleeps==sleeps&&m.adds==adds&&!m.mutex_locked);
    Generation *g=find(&owner,id);CHECK(g&&g->depth==2&&atomic_load(&g->remote_lease)==1);
    PwWineCreationStatus status;CHECK(!creation.query(&owner,id,1,m.now,&status)&&status.phase==PW_WCR_PENDING);
    /* The queue waits for supervisor-observed ACK, not merely the valid join. */
    supervise(&owner,g);CHECK(atomic_load(&g->state)==G_REQUESTED);
    origin->ack=1;atomic_store_explicit(&origin->state,G_RUNNING,memory_order_release);
    supervise(&owner,g);CHECK(atomic_load(&g->state)==G_ADMITTED);
    CHECK(!creation.query(&owner,id,1,m.now,&status)&&status.phase==PW_WCR_ADMITTED&&status.deadline==q.deadline);
    unsigned char wrong[2]={'y',0};
    CHECK(creation.bind(&owner,id,1,m.now,48,q.machine,wrong,2));
    CHECK(atomic_load(&g->state)==G_ADMITTED);
    CHECK(!creation.bind(&owner,id,1,m.now,48,q.machine,q.image,2));
    int stream=0;CHECK(!creation.submit(&owner,id,1,m.now,48,49,&stream)&&stream==-1);
    CHECK(g->stream_fd==0&&g->wine_tid==49&&atomic_load(&g->state)==G_LAUNCH);
    stream=72;CHECK(creation.submit(&owner,id,1,m.now,48,49,&stream)&&stream==72&&!m.closes[72]);
    CHECK(!report_root_exit(&owner,0)&&!atomic_load(&owner.admission_closed));
    uint64_t rejected=0;CHECK(provider.admit(&owner,44,55,q.machine,q.path,&rejected));
    q.lease=2;q.key=2;CHECK(!creation.prepare(&owner,&q,&rejected));
    Generation *pending=find(&owner,rejected);CHECK(pending&&atomic_load(&pending->state)==G_REQUESTED);
    q.origin=g->generation;q.caller_pid=48;q.caller_tid=49;q.lease=3;q.key=3;
    g->ack=1;atomic_store(&g->identity_ready,1);atomic_store(&g->state,G_RUNNING);
    CHECK(creation.prepare(&owner,&q,&rejected)); /* explicit depth 2 limit */
    creation.origin_dead(&owner,origin->generation,46);
    q.origin=origin->generation;q.caller_pid=46;q.caller_tid=47;
    CHECK(creation.prepare(&owner,&q,&rejected));
    creation.abandon(&owner,pending->generation,2);
    supervise(&owner,pending);
    CHECK(atomic_load(&pending->state)==G_RETIRED&&!atomic_load(&pending->remote_lease));
    CHECK(pending->missing_reported&&!atomic_load(&pending->startup_done));
    unsigned missing=m.missing_result;supervise(&owner,pending);CHECK(m.missing_result==missing);
    CHECK(!pw_wine_fixture_owner_release_ready(&owner));
}

static void creation_status_tests(void)
{
    for(unsigned scenario=0;scenario<12;scenario++){
        Generation *origin=bound(2);PwWineCreationProvider creation;
        CHECK(!pw_wine_fixture_owner_creation(&owner,&creation));
        origin->wine_tid=47;origin->ack=1;atomic_store(&origin->identity_ready,1);atomic_store(&origin->state,G_RUNNING);
        PwWineCreationRequest q={.origin=origin->generation,.lease=1,.key=1,.now=m.now,.deadline=m.now+30000,
            .caller_pid=46,.caller_tid=47,.machine=PW_WINE_FIXTURE_AMD64,.image_bytes=2};
        q.image[0]='x';strcpy(q.path,"/data/prospero-win/prefixes/battlenet-experimental-v1/drive_c/Wow.exe");
        q.path_bytes=(uint32_t)strlen(q.path)+1;uint64_t id=0;
        CHECK(!creation.prepare(&owner,&q,&id));Generation *g=find(&owner,id);CHECK(g);
        uint64_t now=m.now;uint32_t expected=WF_BAD;
        if(scenario<3){
            supervise(&owner,g);CHECK(atomic_load(&g->state)==G_ADMITTED);
            CHECK(!creation.bind(&owner,id,1,now,48,q.machine,q.image,2));
            int fd=71;CHECK(!creation.submit(&owner,id,1,now,48,49,&fd)&&fd==-1);
            m.add_result=scenario?-2147352574:0;m.add_partial_failure=scenario==1;m.add_cancel=scenario==2;
            supervise(&owner,g);CHECK(m.adds==1&&atomic_load(&g->launch_failed)&&!m.kills);
            if(scenario==2)expected=WF_CANCELLED;
            if(scenario==1)CHECK(atomic_load(&owner.failure_state)==1);
        }else if(scenario==3){pw_wine_fixture_owner_cancel(&owner);expected=WF_CANCELLED;}
        else if(scenario==4){now=g->startup_end;expected=WF_TIMEOUT;}
        else if(scenario==5)now=g->started-1;
        else if(scenario==6){atomic_store(&owner.blocked,1);atomic_store(&owner.failure_state,1);}
        else if(scenario==7)creation.origin_dead(&owner,origin->generation,46);
        else if(scenario==8)creation.abandon(&owner,id,1);
        else {
            if(scenario>=10)supervise(&owner,g);
            if(scenario==11)CHECK(!creation.bind(&owner,id,1,now,48,q.machine,q.image,2));
            now=m.now=g->startup_end;expected=WF_TIMEOUT;supervise(&owner,g);
            CHECK(atomic_load(&g->state)==G_RETIRED);
        }
        PwWineCreationStatus out;CHECK(!creation.query(&owner,id,1,now,&out)&&out.phase==PW_WCR_FAILED);
        printf("creation query scenario=%u status=%08x expected=%08x\n",scenario,out.status,expected);fflush(stdout);
        CHECK(out.status==expected);
    }
}

static void asynchronous_helper_hold(void)
{
    Generation *g=bound(2);PwWineCreationProvider creation;
    CHECK(!pw_wine_fixture_owner_creation(&owner,&creation));
    g->stream_fd=71;g->wine_tid=47;atomic_store(&g->state,G_LAUNCH);
    CHECK(!pw_wine_fixture_owner_pump(&owner));
    CHECK(g->start_phase==1&&m.adds==1&&!m.sends&&!m.receives);
    CHECK(!pw_wine_fixture_owner_pump(&owner));
    CHECK(g->start_phase==2&&g->hello&&!g->helper_possible);
    CHECK(!pw_wine_fixture_owner_pump(&owner));
    CHECK(g->start_phase==3&&g->helper_possible&&!g->ack&&m.sends==1);
    unsigned lists=m.lists;m.async_idle=1;m.auto_present=0;m.now+=101;
    CHECK(!pw_wine_fixture_owner_pump(&owner));
    CHECK(atomic_load(&g->state)==G_STARTING&&g->helper_possible&&m.lists==lists&&!m.kills);
    pw_wine_fixture_owner_cancel(&owner);
    pw_wine_fixture_owner_pump(&owner);
    CHECK(atomic_load(&g->state)==G_HELPER_DRAIN&&g->helper_possible&&m.lists==lists&&!m.kills);
    CHECK(!atomic_load(&owner.uncertain));
    m.now=g->helper_recovery_end;pw_wine_fixture_owner_pump(&owner);
    CHECK(atomic_load(&g->state)==G_UNCERTAIN);
    CHECK(atomic_load(&owner.uncertain)&&!pw_wine_fixture_owner_release_ready(&owner));
    retire(&owner,g);
    CHECK(atomic_load(&g->state)==G_UNCERTAIN&&!m.kills);
}
static Generation *progress_waiter(void)
{
    Generation *g=bound(2);PwWineCreationProvider creation;
    CHECK(!pw_wine_fixture_owner_creation(&owner,&creation));
    g->stream_fd=71;g->wine_tid=47;atomic_store(&g->state,G_LAUNCH);
    for(unsigned i=0;i<3;i++)CHECK(!pw_wine_fixture_owner_pump(&owner));
    CHECK(g->start_phase==3&&g->helper_possible&&!g->ack&&m.sends==1);
    return g;
}
static void progress_owner_tests(void)
{
    Generation *sync=bound(1);m.sleep_action=1;m.inject_progress=PW_WC_PROGRESS_LAST;m.progress_stage=1;m.progress_auto=1;
    CHECK(provider.spawn(&owner,sync->generation,70,46,47)==WF_OK);
    CHECK(sync->ack&&!sync->helper_possible&&m.progress_records==PW_WC_PROGRESS_LAST&&!m.inject_progress);

    Generation *g=progress_waiter();uint64_t stage_end=g->io.stage_end,total_end=g->io.total_end;
    for(unsigned stage=1;stage<=PW_WC_PROGRESS_LAST;stage++){
        m.inject_progress=1;m.progress_stage=stage;
        CHECK(!pw_wine_fixture_owner_pump(&owner));
        CHECK(atomic_load(&g->state)==G_STARTING&&g->helper_possible&&!g->ack&&!m.kills);
        CHECK(g->io.stage_end==stage_end&&g->io.total_end==total_end&&m.progress_records==stage);
    }
    CHECK(!pw_wine_fixture_owner_pump(&owner));
    CHECK(g->ack&&!g->helper_possible&&atomic_load(&g->state)==G_RUNNING);
    m.inject_progress=1;m.progress_stage=PW_WC_PROGRESS_LAST;
    pw_wine_fixture_owner_pump(&owner);
    CHECK(m.progress_mask_refused==1&&atomic_load(&owner.blocked));
    for(unsigned malformed=0;malformed<14;malformed++){
        g=progress_waiter();m.inject_progress=1;m.progress_stage=2;
        if(malformed<10)m.progress_mutation=malformed+1;
        if(malformed==10)m.progress_stage=0;
        if(malformed==11)m.progress_stage=PW_WC_PROGRESS_LAST+1;
        if(malformed>=12){CHECK(!pw_wine_fixture_owner_pump(&owner));m.inject_progress=1;m.progress_stage=malformed==12?2:1;}
        pw_wine_fixture_owner_pump(&owner);
        CHECK(atomic_load(&g->state)==G_UNCERTAIN&&g->helper_possible&&!g->ack&&!m.kills);
        CHECK(atomic_load(&owner.uncertain)&&!pw_wine_fixture_owner_release_ready(&owner));
    }
    g=progress_waiter();m.inject_progress=1;m.progress_stage=1;m.now=g->startup_end;
    pw_wine_fixture_owner_pump(&owner);
    CHECK(atomic_load(&g->state)==G_HELPER_DRAIN&&g->helper_possible&&!g->ack&&!m.kills&&!m.progress_records);
    CHECK(!atomic_load(&owner.uncertain));
    m.now=g->helper_recovery_end;pw_wine_fixture_owner_pump(&owner);
    CHECK(atomic_load(&g->state)==G_UNCERTAIN&&atomic_load(&owner.uncertain));
}

static void queued_terminal_before_cancel_tests(void)
{
    const unsigned proof[]={PW_WCD_NO_DISPATCH,
        PW_WCD_POSSIBLE|PW_WCD_TERMINAL|PW_WCD_SETTLED_FAILURE,
        PW_WCD_TERMINAL|PW_WCD_SETTLED_FAILURE};
    for(unsigned kind=0;kind<4;kind++)for(unsigned progress=0;progress<3;progress++){
        Generation *g=progress_waiter();uint64_t deadline=g->helper_recovery_end;
        pw_wine_fixture_owner_cancel(&owner);pw_wine_fixture_owner_pump(&owner);
        CHECK(atomic_load(&g->state)==G_HELPER_DRAIN);
        m.cancel_send_error=1; /* Model EPIPE if a redundant CANCEL is attempted. */
        m.inject_progress=progress==2?PW_WC_PROGRESS_LAST:progress;m.progress_stage=1;m.progress_auto=1;
        if(kind<3){m.failure_frame=1;m.failure_flags=proof[kind];}
        pw_wine_fixture_owner_pump(&owner);
        CHECK(!g->helper_possible&&!g->ack&&!atomic_load(&owner.uncertain));
        CHECK(atomic_load(&g->state)==G_CLEANUP&&m.cancel_sends==0);
        CHECK(g->helper_recovery_end==deadline&&!atomic_load(&g->startup_success));
    }
    for(unsigned bad=0;bad<12;bad++){
        Generation *g=progress_waiter();pw_wine_fixture_owner_cancel(&owner);
        pw_wine_fixture_owner_pump(&owner);m.cancel_send_error=1;
        m.failure_frame=1;m.failure_flags=proof[1];
        if(bad<10)m.failure_mutation=bad+1;
        if(bad==10)m.extra_right=1;
        if(bad==11)m.failure_flags=PW_WCD_TERMINAL;
        pw_wine_fixture_owner_pump(&owner);
        CHECK(g->helper_possible&&atomic_load(&g->state)==G_UNCERTAIN&&!g->ack);
        CHECK(!m.cancel_sends&&!m.kills&&!pw_wine_fixture_owner_release_ready(&owner));
        if(bad==10)CHECK(m.closes[82]==1);
    }
    /* With no queued proof, a failed one-shot cancellation remains HELD. */
    Generation *g=progress_waiter();pw_wine_fixture_owner_cancel(&owner);
    pw_wine_fixture_owner_pump(&owner);m.async_idle=1;m.cancel_send_error=1;
    pw_wine_fixture_owner_pump(&owner);
    CHECK(g->helper_possible&&atomic_load(&g->state)==G_UNCERTAIN&&m.cancel_sends==1);
    pw_wine_fixture_owner_pump(&owner);CHECK(m.cancel_sends==1&&!m.kills);
    /* A successful one-shot CANCEL can later receive same-transaction proof,
     * but never restores the cancelled guest startup. */
    g=progress_waiter();pw_wine_fixture_owner_cancel(&owner);
    pw_wine_fixture_owner_pump(&owner);m.async_idle=1;
    pw_wine_fixture_owner_pump(&owner);
    CHECK(g->helper_possible&&atomic_load(&g->state)==G_HELPER_DRAIN&&m.cancel_sends==1);
    uint64_t deadline=g->helper_recovery_end;m.async_idle=0;m.failure_frame=1;m.failure_flags=proof[1];
    pw_wine_fixture_owner_pump(&owner);
    CHECK(!g->helper_possible&&!g->ack&&atomic_load(&g->state)==G_CLEANUP&&m.cancel_sends==1);
    CHECK(!atomic_load(&owner.uncertain)&&!atomic_load(&g->startup_success)&&g->helper_recovery_end==deadline);
}
static void cleanup_owner_tests(void)
{
    const unsigned valid[]={PW_WCD_NO_DISPATCH,PW_WCD_POSSIBLE|PW_WCD_TERMINAL|PW_WCD_SETTLED_FAILURE,
        PW_WCD_TERMINAL|PW_WCD_SETTLED_FAILURE};
    for(unsigned cancelled=0;cancelled<2;cancelled++)for(unsigned kind=0;kind<3;kind++){
        Generation *g=progress_waiter();uint64_t end=g->helper_recovery_end;
        CHECK(end==g->startup_end+PW_WINE_CHILD_CLEANUP_MS&&end<=g->end);
        if(cancelled){pw_wine_fixture_owner_cancel(&owner);pw_wine_fixture_owner_pump(&owner);
            CHECK(atomic_load(&g->state)==G_HELPER_DRAIN&&!atomic_load(&owner.uncertain));}
        m.failure_frame=1;m.failure_flags=valid[kind];pw_wine_fixture_owner_pump(&owner);
        CHECK(!g->helper_possible&&!g->ack&&!atomic_load(&g->startup_success));
        CHECK(!atomic_load(&owner.uncertain)&&atomic_load(&owner.blocked));
        CHECK(g->helper_recovery_end==end&&m.cancel_sends==0);
        provider.startup_result(&owner,g->generation,0,WF_CANCELLED);
        CHECK(!report_root_exit(&owner,77));m.auto_present=0;m.now+=101;
        pw_wine_fixture_owner_pump(&owner);
        CHECK(atomic_load(&g->state)==G_RETIRED&&pw_wine_fixture_owner_release_ready(&owner));
        CHECK(atomic_load(&owner.root_result)==77&&atomic_load(&g->startup_success)==0);
    }
    const unsigned invalid[]={0,PW_WCD_POSSIBLE,PW_WCD_TERMINAL,
        PW_WCD_NO_DISPATCH|PW_WCD_POSSIBLE,PW_WCD_NO_DISPATCH|PW_WCD_TERMINAL,
        PW_WCD_NO_DISPATCH|PW_WCD_SETTLED_FAILURE,PW_WCD_SETTLED_FAILURE,
        PW_WCD_SETTLED_FAILURE|PW_WCD_POSSIBLE,
        PW_WCD_NO_DISPATCH|256};
    for(unsigned k=0;k<sizeof(invalid)/sizeof(invalid[0]);k++){
        Generation *g=progress_waiter();pw_wine_fixture_owner_cancel(&owner);pw_wine_fixture_owner_pump(&owner);
        m.failure_frame=1;m.failure_flags=invalid[k];pw_wine_fixture_owner_pump(&owner);
        CHECK(g->helper_possible&&atomic_load(&g->state)==G_UNCERTAIN&&atomic_load(&owner.uncertain));
        CHECK(!g->ack&&!m.kills&&!pw_wine_fixture_owner_release_ready(&owner));
    }
    for(unsigned k=1;k<=10;k++){
        Generation *g=progress_waiter();pw_wine_fixture_owner_cancel(&owner);pw_wine_fixture_owner_pump(&owner);
        m.failure_frame=1;m.failure_flags=valid[0];m.failure_mutation=k;pw_wine_fixture_owner_pump(&owner);
        CHECK(g->helper_possible&&atomic_load(&g->state)==G_UNCERTAIN&&!m.kills&&!g->ack);
    }
    for(unsigned scenario=0;scenario<4;scenario++){
        Generation *g=progress_waiter();pw_wine_fixture_owner_cancel(&owner);pw_wine_fixture_owner_pump(&owner);
        if(scenario==0)m.receive_eof=1;
        if(scenario==1){m.async_idle=1;m.cancel_send_error=1;}
        if(scenario==2)m.now=g->helper_recovery_end;
        if(scenario==3){m.inject_progress=2;m.progress_stage=2;}
        pw_wine_fixture_owner_pump(&owner);
        CHECK(g->helper_possible&&atomic_load(&g->state)==G_UNCERTAIN&&!m.kills&&!g->ack);
        unsigned sends=m.cancel_sends;pw_wine_fixture_owner_pump(&owner);CHECK(m.cancel_sends==sends);
    }
    /* A racing ACK is helper-settlement evidence only, never guest admission. */
    Generation *g=progress_waiter();pw_wine_fixture_owner_cancel(&owner);pw_wine_fixture_owner_pump(&owner);
    pw_wine_fixture_owner_pump(&owner);
    CHECK(!g->helper_possible&&!g->ack&&!atomic_load(&g->startup_success)&&m.cancel_sends==0);
    CHECK(atomic_load(&g->state)==G_CLEANUP&&!atomic_load(&owner.uncertain));
}

static void startup_observation_tests(void)
{
    Generation *g=progress_waiter();
    CHECK(m.bootstrap_sent==1&&!m.bootstrap_stopped);
    CHECK(!pw_wine_fixture_owner_pump(&owner));
    CHECK(g->ack&&!m.bootstrap_stopped&&!m.stop_control);
    for(unsigned kind=0;kind<4;kind++){
        g=progress_waiter();
        if(kind==0)m.receive_error=2; /* malformed payload at existing codec boundary */
        if(kind==1)m.receive_eof=1;
        if(kind==2)m.ack_bad=1;
        if(kind==3){m.inject_progress=1;m.progress_stage=PW_WCP_DATA_OBSERVED;
            CHECK(!pw_wine_fixture_owner_pump(&owner));m.now=g->startup_end;}
        pw_wine_fixture_owner_pump(&owner);
        CHECK(m.bootstrap_sent==1&&m.bootstrap_stopped==1&&m.stop_control==1);
        CHECK(m.stop_phase==3&&m.stop_helper==1&&!g->ack&&!m.kills);
        CHECK(m.stop_progress==(kind==3?PW_WCP_DATA_OBSERVED:0));
        if(kind==0)CHECK(m.stop_status==PW_WC_PROTOCOL&&m.stop_api==PW_WC_API_RECEIVE&&m.stop_raw==7);
        if(kind==1)CHECK(!m.stop_status&&g->wire.channel_zero_observed&&g->wire.hangup_observed);
        if(kind==2)CHECK(m.stop_status==PW_WC_PROTOCOL&&m.stop_api==PW_WC_API_RECEIVE);
        for(unsigned i=0;i<3;i++)pw_wine_fixture_owner_pump(&owner);
        CHECK(m.bootstrap_stopped==1&&m.stop_control==1);
    }
    g=bound(1);m.sleep_action=1;m.hello_bad=1;
    CHECK(provider.spawn(&owner,g->generation,70,46,47)!=WF_OK);
    CHECK(m.hello_refused==1&&m.hello_mismatch==32&&!m.bootstrap_sent);
    CHECK(m.bootstrap_stopped==1&&m.stop_phase==1&&!m.stop_progress&&!m.stop_helper);
}

int main(int argc,char **argv)
{
    startup_observation_tests();
    queued_terminal_before_cancel_tests();
    cleanup_owner_tests();
    if(argc==2&&!strcmp(argv[1],"cleanup-only"))return 0;
    progress_owner_tests();
    if(argc==2&&!strcmp(argv[1],"list-headroom")){list_headroom_tests();return 0;}
    if(argc==2&&!strcmp(argv[1],"creation-status")){creation_status_tests();return 0;}
    if(argc==2&&!strcmp(argv[1],"creation-queue")){creation_queue_tests();return 0;}
    if(argc==2&&!strcmp(argv[1],"async-helper-hold")){asynchronous_helper_hold();return 0;}
    if(argc==2&&!strcmp(argv[1],"helper-alias")){helper_alias_tests();return 0;}
    if(argc==2&&!strcmp(argv[1],"helper-identity")){helper_identity_tests();return 0;}
    if(argc==2&&!strcmp(argv[1],"launch-path-stop")){launch_path_callback_tests();return 0;}
    if(argc==2&&!strcmp(argv[1],"launch-failure")){launch_failure_tests(0);return 0;}
    if(argc==2&&!strcmp(argv[1],"launch-close-failure")){launch_failure_tests(1);return 0;}
    if(argc==2&&!strcmp(argv[1],"launch-wait-status")){launch_wait_status_tests();return 0;}
    if(argc==2&&!strcmp(argv[1],"launch-publication")){launch_cancel_publication_tests();return 0;}
    if(argc==2&&!strcmp(argv[1],"retained-handle")){release_deadlock();return 0;}
    if(argc==2&&!strcmp(argv[1],"retired-missing")){retired_missing_result();return 0;}
    if(argc==2&&!strcmp(argv[1],"wire-root-closure")){wire_root_closure();return 0;}
    if(argc==2&&!strcmp(argv[1],"seal-race")){seal_race_test();return 0;}
    list_headroom_tests();creation_status_tests();creation_queue_tests();asynchronous_helper_hold();init_preflight_tests();admission_tests();callbacks_tests();spawn_tests();list_launch_tests();release_tests();stop_budget_tests();signal_close_tests();missing_caller_tests();retired_missing_result();wire_root_closure();detach_gate_tests();seal_race_test();first_failure_tests();launch_failure_tests(0);launch_failure_tests(1);launch_wait_status_tests();launch_cancel_publication_tests();helper_alias_tests();helper_identity_tests();launch_path_callback_tests();
    printf("Actual Wine owner with mocked native/transport boundaries: %u checks passed\n",checks);return 0;
}
