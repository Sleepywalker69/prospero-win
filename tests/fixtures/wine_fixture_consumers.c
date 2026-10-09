/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Exact composed Wine bodies, ordinary dependency stubs; no Wine/native run. */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pw_wine_fixture_provider.h"
#include "socket-adapter.inc"
#define PW_WINE_SERVICE_FIXTURE 1
#define WINE_INPROCESS_SERVER 1
#define STATUS_WAIT_0 0u
#define STATUS_TIMEOUT 0x102u
#define STATUS_IO_TIMEOUT 0xc00000b5u
#define STATUS_INTERNAL_ERROR 0xc00000e5u
#define FALSE 0
#define TRACE(...) ((void)0)
#define ERR(...) ((void)0)
typedef uint32_t ULONG;
typedef int64_t LONGLONG;
typedef struct { int64_t QuadPart; } LARGE_INTEGER;
typedef unsigned long pthread_t;
static unsigned checks;
#define CHECK(x) do { ++checks; if(!(x)) { fprintf(stderr,"check line%d: %s\n",__LINE__,#x);exit(1); } } while(0)
static PwWineFixtureProvider provider;
static struct {
    uint32_t remaining[3], wait_status, query_status, reply_success, reply_exit;
    unsigned remaining_calls, wait_calls, query_calls, published, terminal_calls;
    unsigned terminal_success; uint32_t terminal_status;
    int64_t timeout;
    unsigned fixture_absent, signal_calls, state_calls, native_kill_calls, tkill_calls;
    int signal_result, native_result, native_errno;
    unsigned state_result, cleanup_request, died, timers, grabs;
    uint64_t generation; uint32_t wine_pid; int32_t native_pid; int64_t native_tid; int signo;
    void *timer_private; void (*timer_callback)(void *);
    unsigned registrations, registration_error, unregisters, connected, flag_setups, unsets;
    int installed_socket, fcntl_error, fatal;
} m;
static uint32_t remaining(void *context,uint64_t generation)
{ CHECK(context==&m && generation==UINT64_C(0x123456789abcdef0));CHECK(m.remaining_calls<3);return m.remaining[m.remaining_calls++]; }
static void terminal(void *context,uint64_t generation,uint32_t success,uint32_t status)
{ CHECK(context==&m && generation==UINT64_C(0x123456789abcdef0));++m.terminal_calls;m.terminal_success=success;m.terminal_status=status; }
static uint32_t NtWaitForSingleObject(void *handle,int alertable,LARGE_INTEGER *timeout)
{ CHECK(handle==(void *)(uintptr_t)42 && !alertable && timeout);++m.wait_calls;m.timeout=timeout->QuadPart;return m.wait_status; }
static struct { unsigned info,handle,exit_code; } request;
static unsigned request_kind;
enum { op_get_new_process_info,op_terminate_process,op_terminate_thread };
static unsigned root_server_call(void *);
static struct { unsigned success,exit_code; int self; } response;
#define SERVER_START_REQ(name) do { request_kind=op_##name; __typeof__(request) *req=&request; __typeof__(response) *reply=&response;
#define SERVER_END_REQ } while(0)
static unsigned wine_server_obj_handle(void *h) { CHECK(h==(void *)(uintptr_t)42 || h==(void *)(uintptr_t)UINT32_C(0xfffffffe));return (unsigned)(uintptr_t)h; }
static unsigned wine_server_call(void *req)
{ if(request_kind!=op_get_new_process_info)return root_server_call(req);CHECK(req==&request && request.info==42);++m.query_calls;response.success=m.reply_success;response.exit_code=m.reply_exit;return m.query_status; }
static unsigned startup(void)
{
    const PwWineFixtureProvider *fixture=&provider;uint64_t fixture_generation=UINT64_C(0x123456789abcdef0);
    void *process_info=(void *)(uintptr_t)42;unsigned status=0;int success=FALSE;
#include "startup.inc"
    /* Reaching the original output-attribute boundary permits publication. */
    ++m.published;status=0;
#include "startup-result.inc"
    return status;
}
const PwWineFixtureProvider *pw_wine_fixture_get(void) { return m.fixture_absent?NULL:&provider; }
static int signal_submit(void *c,uint64_t generation,uint32_t pid,int32_t native,int64_t tid,int32_t sig)
{ CHECK(c==&m);++m.signal_calls;m.generation=generation;m.wine_pid=pid;m.native_pid=native;m.native_tid=tid;m.signo=sig;errno=ESRCH;return m.signal_result; }
static uint32_t process_state(void *c,uint64_t generation,uint32_t pid,int32_t native,uint32_t cleanup)
{ CHECK(c==&m);++m.state_calls;m.generation=generation;m.wine_pid=pid;m.native_pid=native;m.cleanup_request=cleanup;return m.state_result; }
struct process { uint64_t fixture_generation;uint32_t id;int unix_pid;int64_t sigkill_delay;void *sigkill_timeout; };
struct thread { struct process *process;int unix_pid,unix_tid;unsigned id; };
static int debug_level;
#define SIGQUIT 3
#define SIGKILL 9
#define TICKS_PER_SEC INT64_C(10000000)
static int tkill(int pid,int tid,int sig) { (void)pid;(void)tid;(void)sig;++m.tkill_calls;errno=m.native_errno;return m.native_result; }
static int kill(int pid,int sig) { (void)pid;(void)sig;++m.native_kill_calls;errno=m.native_errno;return m.native_result; }
static const char *get_signal_name(int sig) { (void)sig;return "mock"; }
static int getpid(void) { return 599; }
static void process_died(struct process *p) { CHECK(p);++m.died; }
static void grab_object(struct process *p) { CHECK(p);++m.grabs; }
static void *add_timeout_user(int64_t relative,void(*callback)(void *),void *arg)
{ CHECK(relative<0);++m.timers;m.timer_private=arg;m.timer_callback=callback;return &m; }
#include "signal.inc"
#include "timers.inc"
static int fixture_local_threads;
static int (*register_server_thread)(long,pthread_t);
static void (*unregister_server_thread)(long);
static jmp_buf fatal_jump;
static void fatal_error(const char *format,...) { (void)format;++m.fatal;longjmp(fatal_jump,1); }
#define fatal_perror fatal_error
static pthread_t pthread_self(void) { return 123; }
#include "local-threads.inc"
static int add_local(long tid,pthread_t thread) { CHECK(tid==77 && thread==123);++m.registrations;return (int)m.registration_error; }
static void remove_local(long tid) { CHECK(tid==77);++m.unregisters; }
static int server_pid,fd_socket;
static int server_connect(void) { ++m.connected;return 90; }
#if PW_TEST_SOCKET_ADAPTER
#define PW_WF_SOCKET_CLOEXEC 1u
static int pw_wine_fixture_socket(int fd,unsigned flags)
{ CHECK(fd==m.installed_socket && flags==PW_WF_SOCKET_CLOEXEC);++m.flag_setups;return m.fcntl_error; }
#else
static int fcntl(int fd,int command,int flags)
{ CHECK(fd==m.installed_socket && command==2 && flags==1);++m.flag_setups;return m.fcntl_error; }
#endif
#define F_SETFD 2
#define FD_CLOEXEC 1
static int unsetenv(const char *name) { CHECK(!strcmp(name,"WINESERVERSOCKET"));++m.unsets;return 0; }
static const char *mock_getenv(const char *name) { CHECK(!strcmp(name,"WINEARCH"));return "win64"; }
#define getenv mock_getenv
static void inherited(const char *env_socket)
{
    int is_win64=1;
#include "inherited-server.inc"
}
#undef getenv
/* Actual logical-detach consumer bodies; all boundaries are mocked. */
typedef uint32_t NTSTATUS;
static struct {
    unsigned calls,sleeps,closes,exits,blocked,ready_at,requests,unregistered,detached;
    unsigned close_counts[128],status[2]; int self[2];
    uint32_t expected,observed,detached_success;
    int exit_status,sleep_error,close_fail_fd,close_fail_rc,extra_fail_fd,detached_raw,detached_error;
} x;
struct thread_data { int alert_fd,wait_fd[2],reply_fd,request_fd; };
static struct thread_data data;
static struct thread_data *get_thread_data(void) { return &data; }
static void *NtCurrentThread(void) { return (void *)(uintptr_t)UINT32_C(0xfffffffe); }
static jmp_buf exit_jump;
static int server_block_set;
#define SIG_BLOCK 0
static int mock_sigmask(int how,const int *set,void *old)
{ CHECK(how==SIG_BLOCK&&set==&server_block_set&&!old&&!x.blocked);++x.blocked;return 0; }
static unsigned root_server_call(void *req)
{
    CHECK(req==&request&&x.calls==1&&!x.closes&&!x.detached&&!x.exits&&request.exit_code==x.expected);
    CHECK(request_kind==(x.requests?op_terminate_thread:op_terminate_process));
    CHECK(request.handle==(x.requests?UINT32_C(0xfffffffe):0));
    CHECK(x.requests<2);unsigned n=x.requests++;response.self=x.self[n];return x.status[n];
}
void unregister_inprocess_thread(void) { CHECK(x.requests==2&&!x.closes&&!x.detached);++x.unregistered; }
static void root_detached(void *context,uint32_t success,int32_t raw,int32_t error)
{
    CHECK(context==&m&&x.calls==1&&!x.exits&&!x.detached);++x.detached;
    x.detached_success=success;x.detached_raw=raw;x.detached_error=error;
    if(success)CHECK(x.requests==2&&x.unregistered==1&&fd_socket==-1);
}
static uint32_t root_barrier(void *context,uint32_t status)
{
    CHECK(context==&m&&x.blocked==1&&!x.exits&&status==x.expected);
    ++x.calls;x.observed=status;
    if(x.calls==1){CHECK(!x.requests&&!x.closes&&!x.detached);return 0;}
    CHECK(x.detached==1);
    return x.detached_success && x.ready_at && x.calls>=x.ready_at;
}
static int mock_usleep(unsigned usec)
{
    CHECK(usec==10000&&!x.exits&&x.detached==1);
    ++x.sleeps;if(x.sleeps==4)longjmp(exit_jump,2);
    errno=EINTR;return x.sleep_error;
}
static int mock_close(int fd)
{
    CHECK(fd>=0&&fd<128&&!x.close_counts[fd]);
    if(!m.fixture_absent){CHECK(x.unregistered==1&&!x.detached);CHECK(data.alert_fd!=fd&&data.wait_fd[0]!=fd&&data.wait_fd[1]!=fd&&data.reply_fd!=fd&&data.request_fd!=fd&&fd_socket!=fd);}
    ++x.close_counts[fd];++x.closes;
    if(fd==x.close_fail_fd){errno=EINTR;return x.close_fail_rc;}
    if(fd==x.extra_fail_fd){errno=EBADF;return -1;}
    return 0;
}
static void mock_exit(int status)
{ CHECK(m.fixture_absent||(x.detached_success&&x.calls>=x.ready_at&&fd_socket==-1));++x.exits;x.exit_status=status;longjmp(exit_jump,1); }
#define pthread_sigmask mock_sigmask
#define usleep mock_usleep
#define close mock_close
#define exit mock_exit
#include "root-exit.inc"
#undef exit
#undef close
#undef usleep
#undef pthread_sigmask
static void reset(void)
{
    memset(&m,0,sizeof(m));memset(&x,0,sizeof(x));memset(&provider,0,sizeof(provider));
    provider.context=&m;provider.startup_remaining_ms=remaining;provider.startup_result=terminal;
    provider.signal=signal_submit;provider.process_state=process_state;provider.root_exit=root_barrier;provider.root_detached=root_detached;
    data=(struct thread_data){62,{63,64},65,66};fd_socket=61;x.self[0]=x.self[1]=1;x.close_fail_fd=x.extra_fail_fd=-1;
    m.remaining[0]=m.remaining[1]=m.remaining[2]=500;m.reply_success=1;m.signal_result=PW_WF_SIGNAL_QUEUED;
    fixture_local_threads=0;register_server_thread=NULL;unregister_server_thread=NULL;
}
static void startup_tests(void)
{
    reset();CHECK(startup()==0);CHECK(m.published==1 && m.query_calls==1 && m.wait_calls==1);
    CHECK(m.timeout==-5000000 && m.terminal_calls==1 && m.terminal_success==1 && !m.terminal_status);
    const uint32_t waits[]={STATUS_TIMEOUT,0x101,0xc0,0xc0000008};
    for(unsigned i=0;i<4;i++) {
        reset();m.wait_status=waits[i];CHECK(startup()==(i?waits[i]:STATUS_IO_TIMEOUT));
        CHECK(!m.query_calls && !m.published && m.terminal_calls==1 && !m.terminal_success);
    }
    const unsigned budgets[]={0,30001,UINT_MAX};
    for(unsigned i=0;i<3;i++) { reset();m.remaining[0]=budgets[i];CHECK(startup()==STATUS_IO_TIMEOUT);CHECK(!m.wait_calls&&!m.query_calls&&!m.published); }
    reset();m.remaining[0]=30000;CHECK(!startup());CHECK(m.timeout==-300000000);
    reset();m.remaining[1]=0;CHECK(startup()==STATUS_IO_TIMEOUT);CHECK(!m.query_calls&&!m.published);
    reset();m.remaining[2]=0;
    unsigned result=startup();printf("post-authority exhausted budget: status=%08x published=%u\n",result,m.published);
    CHECK(result==STATUS_IO_TIMEOUT && !m.published && !m.terminal_success);
    reset();m.query_status=0xc0000022;CHECK(startup()==0xc0000022);CHECK(!m.published && !m.terminal_success);
    reset();m.reply_success=0;m.reply_exit=0xc1234567;CHECK(startup()==0xc1234567);CHECK(!m.published);
    reset();m.reply_success=0;m.reply_exit=0;CHECK(startup()==STATUS_INTERNAL_ERROR);CHECK(!m.published);
}
static void signal_tests(void)
{
    const int states[]={PW_WF_SIGNAL_QUEUED,PW_WF_SIGNAL_NOT_OWNED,PW_WF_SIGNAL_FAILED,2,INT_MIN};
    for(unsigned i=0;i<5;i++) {
        reset();struct process p={UINT64_C(0xf123456789abcdef),0x1234,600,100,NULL};struct thread t={&p,600,601,0x4321};
        m.signal_result=states[i];CHECK(send_thread_signal(&t,SIGQUIT)==(i==0));
        CHECK(m.signal_calls==1&&!m.tkill_calls&&!m.native_kill_calls);
        CHECK(t.unix_pid==600&&t.unix_tid==601);CHECK(m.generation==p.fixture_generation&&m.wine_pid==p.id&&m.native_tid==601);
        if(i)CHECK(errno==EIO);
    }
    reset();m.fixture_absent=1;struct process p={9,0x1234,600,100,NULL};struct thread t={&p,600,601,0x4321};
    CHECK(!send_thread_signal(&t,SIGQUIT));CHECK(!m.signal_calls&&!m.tkill_calls&&!m.native_kill_calls&&t.unix_pid==600);
    reset();p.fixture_generation=0;m.native_result=-1;m.native_errno=ESRCH;
    CHECK(!send_thread_signal(&t,SIGQUIT));CHECK(m.tkill_calls==1&&t.unix_pid==-1&&t.unix_tid==-1);
}
static void timer_tests(void)
{
    const unsigned states[]={PW_WF_NOT_OWNED,PW_WF_OWNED_ACTIVE,PW_WF_OWNED_RETIRED,PW_WF_OWNED_UNCERTAIN,UINT_MAX};
    for(unsigned i=0;i<5;i++) {
        reset();struct process p={UINT64_C(0x123456789abcdef0),0x1234,-1,TICKS_PER_SEC/64,NULL};m.state_result=states[i];
        start_sigkill_timer(&p);CHECK(m.grabs==1&&m.timers==1&&!m.died);CHECK(m.timer_private==&p);
        m.timer_callback(m.timer_private);CHECK(m.state_calls==1&&!m.native_kill_calls);
        CHECK(m.generation==p.fixture_generation&&m.native_pid==-1&&m.wine_pid==p.id);
        CHECK(m.died==(i==2));CHECK(m.timers==(i==2?1u:2u));
        if(i!=2) { for(unsigned j=0;j<6;j++)m.timer_callback(m.timer_private);CHECK(m.cleanup_request==1&&!m.died&&!m.native_kill_calls); }
    }
    reset();m.fixture_absent=1;struct process p={7,0x1234,600,TICKS_PER_SEC/64,NULL};
    process_sigkill(&p);CHECK(!m.died&&!m.native_kill_calls&&m.timers==1);
    reset();p.fixture_generation=0;p.unix_pid=-1;start_sigkill_timer(&p);CHECK(m.grabs==1&&m.died==1&&!m.timers);
}
static void local_tests(void)
{
    reset();CHECK(pw_wine_fixture_local_threads(NULL,remove_local)==-1);CHECK(pw_wine_fixture_local_threads(add_local,NULL)==-1);
    CHECK(!pw_wine_fixture_local_threads(add_local,remove_local));CHECK(pw_wine_fixture_local_threads(add_local,remove_local)==-1);
    register_inprocess_thread(77);CHECK(m.registrations==1);unregister_server_thread(77);CHECK(m.unregisters==1);
    m.registration_error=1;if(!setjmp(fatal_jump)){register_inprocess_thread(77);CHECK(0);}CHECK(m.fatal==1);
    reset();m.installed_socket=17;if(!setjmp(fatal_jump)){inherited("17");CHECK(0);}CHECK(m.fatal==1&&!m.flag_setups&&!m.connected);
    reset();CHECK(!pw_wine_fixture_local_threads(add_local,remove_local));m.installed_socket=17;inherited("17");
    CHECK(fd_socket==17&&server_pid==-1&&m.flag_setups==1&&m.unsets==1&&!m.connected);
    reset();CHECK(!pw_wine_fixture_local_threads(add_local,remove_local));m.installed_socket=17;m.fcntl_error=-1;
    if(!setjmp(fatal_jump)){inherited("17");CHECK(0);}CHECK(m.fatal==1&&!m.unsets&&!m.connected);
    reset();inherited(NULL);CHECK(m.connected==1&&fd_socket==90&&!m.flag_setups);
}
static int run_root_exit(void)
{
    int result=setjmp(exit_jump);if(!result){exit_process((int)x.expected);CHECK(0);}return result;
}
static void root_exit_tests(void)
{
    const uint32_t values[]={0,1,77,0x100,0x0051002a,0x00510031,0x00510040,0x80000000,UINT32_MAX};
    for(unsigned role=0;role<2;role++)for(unsigned i=0;i<sizeof(values)/sizeof(values[0]);i++) {
        reset();m.fixture_absent=role;x.expected=values[i];x.ready_at=4;
        CHECK(run_root_exit()==1);CHECK(x.blocked==1&&x.exits==1);
        CHECK(x.closes==(role?1u:6u)&&x.calls==(role?0u:4u)&&x.sleeps==(role?0u:2u));
        CHECK(x.requests==(role?0u:2u)&&x.detached==(role?0u:1u));
        if(!role)CHECK(x.observed==values[i]&&x.detached_success&&!x.detached_raw&&!x.detached_error);
        CHECK(x.exit_status==get_unix_exit_code(values[i]));
    }
    for(unsigned phase=0;phase<2;phase++)for(unsigned failure=0;failure<2;failure++) {
        reset();x.expected=UINT32_MAX;x.ready_at=2;
        if(failure)x.status[phase]=0xc0000022;else x.self[phase]=0;
        CHECK(run_root_exit()==2);CHECK(x.requests==phase+1&&!x.unregistered&&!x.closes&&!x.exits);
        CHECK(x.detached==1&&!x.detached_success&&!x.detached_error);
        CHECK((uint32_t)x.detached_raw==(failure?0xc0000022u:0));
        CHECK(data.alert_fd==62&&fd_socket==61);
    }
    for(unsigned f=0;f<6;f++) {
        reset();x.expected=77;x.ready_at=2;x.close_fail_fd=61+(int)f;x.close_fail_rc=-1;
        CHECK(run_root_exit()==2);CHECK(x.closes==6&&!x.exits&&!x.detached_success&&x.detached_raw==-1&&x.detached_error==EINTR);
        CHECK(fd_socket==-1&&data.alert_fd==-1&&data.wait_fd[0]==-1&&data.wait_fd[1]==-1&&data.reply_fd==-1&&data.request_fd==-1);
    }
    reset();x.ready_at=2;x.close_fail_fd=62;x.close_fail_rc=1;
    CHECK(run_root_exit()==2&&x.detached_raw==1&&!x.detached_error&&!x.exits);
    reset();x.ready_at=2;x.close_fail_fd=62;x.close_fail_rc=-1;x.extra_fail_fd=63;
    CHECK(run_root_exit()==2&&x.detached_raw==-1&&x.detached_error==EINTR&&x.closes==6);
    reset();x.ready_at=2;data=(struct thread_data){61,{61,61},61,61};
    CHECK(run_root_exit()==1&&x.closes==1&&x.close_counts[61]==1&&x.detached_success);
    reset();x.ready_at=2;data.alert_fd=0;
    CHECK(run_root_exit()==1&&x.closes==6&&x.close_counts[0]==1);
    reset();x.ready_at=2;data=(struct thread_data){-1,{-1,-1},-1,-1};
    CHECK(run_root_exit()==1&&x.closes==1);
    reset();x.ready_at=4;x.sleep_error=-1;
    CHECK(run_root_exit()==1&&x.calls==4&&x.sleeps==2&&x.exits==1);
    reset();CHECK(run_root_exit()==2&&x.closes==6&&!x.exits&&x.detached_success);
}
/* The entire real done/cleanup/mask-restoration/return tail. These boundary
 * mocks test ordering and branch behavior; the actual SDK TU gate separately
 * establishes production declarations and compilation. */
static struct {
    unsigned events, terminals, handles, descriptors, frees, restores, errors, aborts, returns;
    unsigned expected_terminal, expected_handles, expected_descriptors;
    unsigned expected_success, expected_status, recorded_success, recorded_status;
    int masked, mask_error, reported_error, old_mask;
    char order[32];
} tail;
static jmp_buf tail_jump;
static unsigned char tail_storage[4];
static void tail_event(char event)
{ CHECK(tail.events<sizeof(tail.order)-1);tail.order[tail.events++]=event;tail.order[tail.events]=0; }
static void tail_terminal(void *context,uint64_t generation,uint32_t success,uint32_t status)
{
    CHECK(context==&tail&&generation==UINT64_C(0x123456789abcdef0));
    CHECK(!tail.events&&!tail.terminals&&!tail.handles&&!tail.descriptors&&!tail.frees&&!tail.restores);
    ++tail.terminals;tail.recorded_success=success;tail.recorded_status=status;tail_event('T');
    errno=ENOSPC;
}
static unsigned tail_handle(void *handle)
{
    CHECK(handle&&tail.terminals==tail.expected_terminal&&!tail.descriptors&&!tail.frees&&!tail.restores);
    ++tail.handles;tail_event('H');errno=EBADF;return STATUS_INTERNAL_ERROR;
}
static int tail_close(int fd)
{
    CHECK(fd>=0&&fd<=1&&tail.terminals==tail.expected_terminal&&tail.handles==tail.expected_handles&&!tail.frees&&!tail.restores);
    ++tail.descriptors;tail_event('D');errno=EINTR;return -1;
}
static void tail_free(void *p)
{
    CHECK(tail.terminals==tail.expected_terminal&&tail.handles==tail.expected_handles&&tail.descriptors==tail.expected_descriptors&&!tail.restores);
    CHECK(tail.frees<4&&p==&tail_storage[tail.frees]);++tail.frees;tail_event('F');errno=EBUSY;
}
static int tail_sigmask(int how,const int *set,void *old)
{
    CHECK(how==2&&set==&tail.old_mask&&!old&&tail.masked&&tail.frees==4&&!tail.restores);
    ++tail.restores;tail_event('M');errno=EAGAIN;return tail.mask_error;
}
static void tail_err(const char *format,int error)
{
    CHECK(strstr(format,"%d")&&tail.restores==1&&!tail.errors&&error==tail.mask_error);
    ++tail.errors;tail.reported_error=error;tail_event('E');errno=EDOM;
}
static void tail_abort(int status) __attribute__((noreturn));
static void tail_abort(int status)
{
    CHECK(status==1&&tail.errors==1&&tail.frees==4&&!tail.aborts&&!tail.returns);
    ++tail.aborts;tail_event('A');longjmp(tail_jump,1);
}
#undef ERR
#define ERR tail_err
#define NtClose tail_handle
#define close tail_close
#define free tail_free
#define pthread_sigmask tail_sigmask
#define SIG_SETMASK 2
#define abort_thread tail_abort
static unsigned actual_startup_tail(unsigned generation_present,unsigned resources)
{
    PwWineFixtureProvider f={.context=&tail,.startup_result=tail_terminal};
    const PwWineFixtureProvider *fixture=&f;
    uint64_t fixture_generation=generation_present?UINT64_C(0x123456789abcdef0):0;
    unsigned success=tail.expected_success,status=tail.expected_status;
    int fixture_masked=tail.masked;
    /* The production variable is a sigset_t; the boundary mock only checks its
     * address. No claim about the host or target signal-set representation. */
#define fixture_old_mask tail.old_mask
    void *file_handle=resources?&tail_storage[0]:NULL,*process_info=resources?&tail_storage[1]:NULL;
    void *process_handle=resources?&tail_storage[2]:NULL,*thread_handle=resources?&tail_storage[3]:NULL;
    int socketfd[2]={resources?0:-1,-1},unixdir=resources?1:-1;
    void *startup_info=&tail_storage[0],*winedebug=&tail_storage[1],*unix_name=&tail_storage[2];
    struct {void *Buffer;} nt_name={&tail_storage[3]};
    goto done;
#include "startup-tail.inc"
#undef fixture_old_mask
}
#undef abort_thread
#undef SIG_SETMASK
#undef pthread_sigmask
#undef free
#undef close
#undef NtClose
#undef ERR
#define ERR(...) ((void)0)
static void mask_tail_tests(void)
{
    const int errors[]={0,EINVAL,EACCES,-7};
    const unsigned statuses[]={0,0xc0000008u,UINT32_MAX};
    for(unsigned status=0;status<3;status++)for(unsigned success=0;success<2;success++)
    for(unsigned generation=0;generation<2;generation++)for(unsigned masked=0;masked<2;masked++)
    for(unsigned resources=0;resources<2;resources++)for(unsigned error=0;error<4;error++) {
        memset(&tail,0,sizeof(tail));tail.expected_success=success;tail.expected_status=statuses[status];
        tail.expected_terminal=generation;tail.expected_handles=resources?4:0;tail.expected_descriptors=resources?2:0;
        tail.masked=(int)masked;tail.mask_error=errors[error];errno=ERANGE;
        int escaped=setjmp(tail_jump);
        if(!escaped) { unsigned result=actual_startup_tail(generation,resources);++tail.returns;CHECK(result==statuses[status]); }
        CHECK(tail.terminals==generation&&tail.handles==tail.expected_handles&&tail.descriptors==tail.expected_descriptors&&tail.frees==4);
        if(generation)CHECK(tail.recorded_success==success&&tail.recorded_status==statuses[status]);
        CHECK(tail.restores==masked);
        if(masked&&errors[error]) {
            CHECK(escaped==1&&tail.aborts==1&&tail.errors==1&&!tail.returns);
            CHECK(tail.reported_error==errors[error]&&errno==EDOM);
        } else CHECK(!escaped&&!tail.aborts&&!tail.errors&&tail.returns==1);
        char expected[32]="";
        if(generation)strcat(expected,"T");
        if(resources)strcat(expected,"HHHHDD");
        strcat(expected,"FFFF");
        if(masked)strcat(expected,"M");
        if(masked&&errors[error])strcat(expected,"EA");
        CHECK(!strcmp(tail.order,expected));
    }
}

int main(void)
{
    startup_tests();signal_tests();timer_tests();local_tests();root_exit_tests();mask_tail_tests();
    printf("composed Wine fixture consumer bodies: %u checks passed; no native operations\n",checks);return 0;
}
