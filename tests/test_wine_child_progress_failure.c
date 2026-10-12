/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Real child main, data adapter and wire; only OS/native I/O is substituted.
 * The finite FIFO is a synthetic schedule, never a PS5 capacity measurement.
 * Every case stops before helper upload, log open or Wine entry. */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "../native/pw_wine_child_bootstrap.h"

static int mock_clock(clockid_t, struct timespec *);
static int mock_open(const char *, int, ...), mock_stat(const char *, struct stat *);
static int mock_lstat(const char *, struct stat *), mock_fstat(int, struct stat *);
static int mock_close(int), mock_poll(struct pollfd *, nfds_t, int);
static int mock_getsockopt(int, int, int, void *, socklen_t *);
static ssize_t mock_read(int, void *, size_t), mock_write(int, const void *, size_t);
static ssize_t mock_sendmsg(int, const struct msghdr *, int);
static ssize_t mock_recvmsg(int, struct msghdr *, int);
static int mock_setenv(const char *, const char *, int);
static pid_t mock_pid(void), mock_ppid(void);
static uid_t mock_uid(void);
static int mock_setuid(uid_t), mock_sleep(const struct timespec *, struct timespec *);
static void mock_exit(int) __attribute__((noreturn));
static int mock_thread(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
static int32_t mock_load(const char *, size_t, const void *, uint32_t, const void *, int *);
static int mock_info(int32_t, void *), mock_register(long, pthread_t), mock_kill(pid_t, long, int);
static void mock_unregister(long);

#define clock_gettime mock_clock
#define open mock_open
#define stat(...) mock_stat(__VA_ARGS__)
#define lstat(...) mock_lstat(__VA_ARGS__)
#define fstat mock_fstat
#define close mock_close
#define read mock_read
#define write mock_write
#define poll mock_poll
#define getsockopt mock_getsockopt
#define sendmsg mock_sendmsg
#define recvmsg mock_recvmsg
#define setenv mock_setenv
#define getpid mock_pid
#define getppid mock_ppid
#define geteuid mock_uid
#define seteuid mock_setuid
#define nanosleep mock_sleep
#define _exit mock_exit
#define pthread_create mock_thread
#define sceKernelLoadStartModule mock_load
#define sceKernelGetModuleInfo mock_info
#define pw_wine_thread_register mock_register
#define pw_wine_thread_unregister mock_unregister
#define pw_wine_thread_kill mock_kill
#define main native_child_main
#include "../native/pw_wine_child_main.c"
#undef main
#include "../native/pw_wine_child_data.c"
#include "../native/pw_wine_child_wire.c"
#undef clock_gettime
#undef open
#undef stat
#undef lstat
#undef fstat
#undef close
#undef read
#undef write
#undef poll
#undef getsockopt
#undef sendmsg
#undef recvmsg
#undef setenv
#undef getpid
#undef getppid
#undef geteuid
#undef seteuid
#undef nanosleep
#undef _exit
#undef pthread_create

enum { CHILD_FD = 3, HELPER_FD = 9, OWNER_FD = 10, NET_ID = 42, WINE_FD = 72, QUEUE_MAX = 16 };
enum { ORDINARY, EXPIRE_AFTER_FIVE, EXPIRE_IN_DATA_CHECK, CANCEL_AFTER_FIVE, REFUSE_AFTER_FIVE };
static const unsigned char helper[] = {0x7f, 'E', 'L', 'F', 'a', 'b', 'c', '!'};
static struct {
    uint64_t now;
    unsigned capacity, drain_before_six, scenario, fail_stage;
    int send_error, short_send, socket_raw, certificate_error, net_error;
    unsigned bootstrap_received, cancel_delivered, closed[128], reads;
    unsigned socket_calls, socket_closes, errno_calls, errno_pending, options;
    unsigned connects, uploads, net_receives, threads, modules, logs, envs, sleeps;
    unsigned attempts, accepted, failure_attempts, failure_accepted, hello, ack;
    unsigned queue_head, queue_count, observed_count, channel_closed, saw_eof;
    unsigned char queue[QUEUE_MAX][PW_WC_WIRE_BYTES];
    PwWineChildFrame observed[QUEUE_MAX], attempted_failure;
    PwWineChildWireResult owner_result;
    int exit_code;
} m;
static jmp_buf exited;
static PwWineChildFrame session(void)
{
    PwWineChildFrame f = {.kind = PW_WC_BOOTSTRAP, .sequence = 1, .parent_pid = 599,
        .child_pid = 600, .child_ppid = 53, .wine_pid = 20, .wine_tid = 24,
        .generation = 17, .profile = PW_WC_PROFILE_BATTLENET, .machine = PW_WC_MACHINE_I386};
    memcpy(f.build_id, PW_WINE_CHILD_BUILD_ID, sizeof(f.build_id));
    return f;
}
static void drain_owner(void)
{
    PwNativeChildIo io = {.clock_ms = clock_ms, .ready = 1, .last_clock = m.now,
        .stage_end = m.now + 1000, .total_end = m.now + 1000};
    /* This observation budget belongs only to the mock owner, never the child. */
    for (;;) {
        PwWineChildFrame f; int right = -1;
        int rc = pw_wine_child_wire_receive_nowait(&io, OWNER_FD,
            PW_WC_KIND(PW_WC_PROGRESS) | PW_WC_KIND(PW_WC_FAILURE),
            &f, &right, &m.owner_result);
        assert(right == -1);
        if (rc == PW_WC_IDLE) return;
        if (rc == PW_WC_CHANNEL_CLOSED) { m.saw_eof++; return; }
        assert(rc == PW_WC_RECORD && m.observed_count < QUEUE_MAX);
        m.observed[m.observed_count++] = f;
    }
}
static int mock_clock(clockid_t id, struct timespec *out)
{
    assert(id == CLOCK_MONOTONIC && !m.errno_pending);
    out->tv_sec = (time_t)(m.now / 1000);
    out->tv_nsec = (long)(m.now % 1000) * 1000000;
    if (m.errno_calls) m.net_error = ERANGE; /* Saved Net errno must survive observers. */
    errno = EINTR;
    return 0;
}
static pid_t mock_pid(void) { return 600; }
static pid_t mock_ppid(void) { return 53; }
static uid_t mock_uid(void) { assert(0); return 1000; }
static int mock_setuid(uid_t uid) { (void)uid; assert(0); return -1; }
static int mock_sleep(const struct timespec *pause, struct timespec *rest)
{ (void)pause; (void)rest; m.sleeps++; assert(0); return -1; }
static void mock_exit(int code) { m.exit_code = code; longjmp(exited, 1); }
static int mock_open(const char *path, int flags, ...)
{
    if (strcmp(path, "/app0/lapy.elf")) { m.logs++; assert(0); return -1; }
    assert(flags == (O_RDONLY | O_NOFOLLOW | O_NONBLOCK));
    return HELPER_FD;
}
static int mock_stat(const char *path, struct stat *out)
{ assert(!strcmp(path, "/data")); memset(out, 0, sizeof(*out)); errno = ENOENT; return -1; }
static int mock_lstat(const char *path, struct stat *out)
{ return mock_stat(path, out); }
static int mock_fstat(int fd, struct stat *out)
{
    assert(fd == HELPER_FD); memset(out, 0, sizeof(*out));
    out->st_mode = S_IFREG; out->st_size = sizeof(helper); out->st_dev = 1; out->st_ino = 2;
    return 0;
}
static ssize_t mock_read(int fd, void *out, size_t size)
{
    assert(fd == HELPER_FD && out);
    if (m.reads++) { assert(size == 1); return 0; }
    assert(size == sizeof(helper)); memcpy(out, helper, size); return (ssize_t)size;
}
static ssize_t mock_write(int fd, const void *bytes, size_t size)
{ (void)fd; (void)bytes; (void)size; m.logs++; assert(0); return -1; }
static int mock_close(int fd)
{
    assert(fd == CHILD_FD || fd == HELPER_FD || fd == WINE_FD);
    assert(!m.closed[fd]++);
    if (fd == CHILD_FD) m.channel_closed = 1;
    errno = EBADF; return 0;
}
static int mock_getsockopt(int fd, int level, int option, void *value, socklen_t *size)
{
    assert(level == SOL_SOCKET && option == SO_TYPE && *size == sizeof(int));
    assert(fd == CHILD_FD || fd == WINE_FD);
    *(int *)value = fd == CHILD_FD ? SOCK_SEQPACKET : SOCK_STREAM;
    return 0;
}
static int mock_poll(struct pollfd *p, nfds_t count, int timeout)
{
    assert(!m.errno_pending && count == 1 && p->events == POLLIN && timeout >= 0 && timeout <= 25);
    p->revents = 0;
    if (p->fd == CHILD_FD) {
        if (m.accepted == 5 && m.scenario == EXPIRE_IN_DATA_CHECK) m.now = child_io.stage_end;
        if (!m.bootstrap_received || (m.accepted == 5 && !m.cancel_delivered &&
            (m.scenario == CANCEL_AFTER_FIVE || m.scenario == REFUSE_AFTER_FIVE))) p->revents = POLLIN;
    } else {
        assert(p->fd == OWNER_FD && !timeout);
        if (m.queue_count) p->revents |= POLLIN;
        if (m.channel_closed) p->revents |= POLLHUP;
    }
    return p->revents ? 1 : 0;
}
static ssize_t mock_recvmsg(int fd, struct msghdr *msg, int flags)
{
    assert(!m.errno_pending && flags == MSG_DONTWAIT && msg->msg_iovlen == 1);
    assert(msg->msg_iov[0].iov_len == PW_WC_WIRE_BYTES);
    msg->msg_flags = 0;
    if (fd == OWNER_FD) {
        msg->msg_controllen = 0;
        if (!m.queue_count) { assert(m.channel_closed); return 0; }
        memcpy(msg->msg_iov[0].iov_base, m.queue[m.queue_head], PW_WC_WIRE_BYTES);
        m.queue_head = (m.queue_head + 1) % QUEUE_MAX; m.queue_count--;
    } else {
        assert(fd == CHILD_FD); PwWineChildFrame f = session();
        if (!m.bootstrap_received++) {
            assert(msg->msg_controllen >= CMSG_SPACE(sizeof(int)));
            struct cmsghdr *h = msg->msg_control;
            memset(h, 0, CMSG_SPACE(sizeof(int)));
            h->cmsg_level = SOL_SOCKET; h->cmsg_type = SCM_RIGHTS; h->cmsg_len = CMSG_LEN(sizeof(int));
            int right = WINE_FD; memcpy(CMSG_DATA(h), &right, sizeof(right));
            msg->msg_controllen = CMSG_SPACE(sizeof(int));
        } else {
            assert(!m.cancel_delivered++ && m.accepted == 5);
            f.kind = PW_WC_CANCEL;
            if (m.scenario == REFUSE_AFTER_FIVE) f.generation++;
            msg->msg_controllen = 0;
        }
        assert(!pw_wine_child_wire_encode(msg->msg_iov[0].iov_base, &f));
    }
    return PW_WC_WIRE_BYTES;
}
static ssize_t mock_sendmsg(int fd, const struct msghdr *msg, int flags)
{
    assert(!m.errno_pending && fd == CHILD_FD && flags == (MSG_DONTWAIT | MSG_NOSIGNAL));
    assert(msg->msg_iovlen == 1 && msg->msg_iov[0].iov_len == 136 && !msg->msg_controllen);
    PwWineChildFrame f;
    assert(!pw_wine_child_wire_decode(&f, msg->msg_iov[0].iov_base));
    if (f.kind == PW_WC_HELLO) { assert(!m.hello++); return PW_WC_WIRE_BYTES; }
    assert(f.kind != PW_WC_BOOTSTRAP_ACK); /* No failure may be acknowledged as ready. */
    if (f.kind == PW_WC_PROGRESS) {
        assert(f.failure_api == ++m.attempts && f.failure_api <= 6);
        assert(!f.target_tid && !f.signal && !f.status && !f.native_error &&
               !f.failure_raw && !f.returned_length && !f.returned_value && !f.errno_valid);
        if (f.failure_api == PW_WCP_NET_SOCKET_BEGIN) {
            assert(!m.socket_calls && !m.errno_calls);
            /* Host controls have no Prospero import slots; raw nonzero values
             * are covered by the codec/owner tests, not claimed as GOT proof. */
            assert(!f.net_socket_target && !f.net_errno_target && !f.data_prepare_anchor);
        } else assert(!f.net_socket_target && !f.net_errno_target && !f.data_prepare_anchor);
        if (f.failure_api == 6 && m.drain_before_six) drain_owner();
        if (f.failure_api == m.fail_stage) {
            if (m.short_send >= 0) return m.short_send;
            errno = m.send_error; return -1;
        }
    } else {
        assert(f.kind == PW_WC_FAILURE && !f.net_socket_target && !f.net_errno_target && !f.data_prepare_anchor);
        m.failure_attempts++; m.attempted_failure = f;
        if (m.certificate_error) { errno = m.certificate_error; return -1; }
    }
    if (m.queue_count == m.capacity) { errno = EAGAIN; return -1; }
    unsigned at = (m.queue_head + m.queue_count++) % QUEUE_MAX;
    memcpy(m.queue[at], msg->msg_iov[0].iov_base, PW_WC_WIRE_BYTES);
    if (f.kind == PW_WC_PROGRESS) {
        m.accepted++;
        if (f.failure_api == 5 && m.scenario == EXPIRE_AFTER_FIVE) m.now = child_io.stage_end;
    } else m.failure_accepted++;
    return PW_WC_WIRE_BYTES;
}
int sceNetSocket(const char *name, int family, int type, int protocol)
{
    assert(!strcmp(name, "pw-wine-child-data") && family == AF_INET && type == SOCK_STREAM && protocol == 6);
    assert(m.accepted == 5 && !m.socket_calls++);
    m.errno_pending = m.socket_raw < 0;
    return m.socket_raw;
}
int *sceNetErrnoLoc(void) { m.errno_calls++; m.errno_pending = 0; return &m.net_error; }
int sceNetSocketClose(int socket)
{ assert(socket == NET_ID && !m.socket_closes++); m.net_error = EBADF; return 0; }
int sceNetSetsockopt(int socket, int level, int option, const void *value, socklen_t size)
{
    assert(socket == NET_ID && level == 0xffff && option == 0x1105 && size == sizeof(uint32_t));
    assert(*(const uint32_t *)value == 5000000 && m.accepted == 6 && !m.options++);
    m.net_error = ENETDOWN; return -9; /* Deliberate safe stop after healthy progress. */
}
int sceNetConnect(int socket, const struct sockaddr *address, socklen_t size)
{ (void)socket; (void)address; (void)size; m.connects++; assert(0); return -1; }
int sceNetSend(int socket, const void *bytes, size_t size, int flags)
{ (void)socket; (void)bytes; (void)size; (void)flags; m.uploads++; assert(0); return -1; }
int sceNetRecv(int socket, void *bytes, size_t size, int flags)
{ (void)socket; (void)bytes; (void)size; (void)flags; m.net_receives++; assert(0); return -1; }
static int mock_setenv(const char *name, const char *value, int replace)
{ (void)name; (void)value; (void)replace; m.envs++; assert(0); return -1; }
static int mock_thread(pthread_t *t, const pthread_attr_t *a, void *(*entry)(void *), void *arg)
{ (void)t; (void)a; (void)entry; (void)arg; m.threads++; assert(0); return -1; }
static int32_t mock_load(const char *path, size_t n, const void *a, uint32_t f, const void *b, int *r)
{ (void)path; (void)n; (void)a; (void)f; (void)b; (void)r; m.modules++; assert(0); return -1; }
static int mock_info(int32_t handle, void *out) { (void)handle; (void)out; assert(0); return -1; }
static int mock_register(long id, pthread_t t) { (void)id; (void)t; assert(0); return -1; }
static void mock_unregister(long id) { (void)id; assert(0); }
static int mock_kill(pid_t pid, long tid, int sig) { (void)pid; (void)tid; (void)sig; assert(0); return -1; }

static void reset(void)
{
    memset(&m, 0, sizeof(m)); m.now = 1000; m.capacity = QUEUE_MAX;
    m.short_send = -1; m.socket_raw = NET_ID; m.net_error = EACCES;
    memset(&bootstrap, 0, sizeof(bootstrap)); memset(&bootstrap_failure, 0, sizeof(bootstrap_failure));
    memset(&data_readiness, 0, sizeof(data_readiness)); memset(&wire_result, 0, sizeof(wire_result));
    memset(&child_io, 0, sizeof(child_io)); memset(&active_session, 0, sizeof(active_session));
    child_cleanup_end = 0; owner_cancel_received = 0; log_fd = -1; log_bytes = 0; log_loss_marker = 0;
    atomic_store(&runtime_failure, 0); atomic_store(&socket_failure_attempted, 0);
    atomic_store(&log_dropped_records, 0); atomic_store(&log_dropped_bytes, 0);
    atomic_store(&log_counts_incomplete, 0); atomic_flag_clear(&send_claim);
}
static void run(void)
{
    if (!setjmp(exited)) native_child_main(0, NULL);
    assert(m.exit_code == 14 && m.hello == 1 && !m.ack && !bootstrap.started);
    assert(m.closed[CHILD_FD] == 1 && m.closed[WINE_FD] == 1 && m.closed[HELPER_FD] == 1);
    assert(!m.connects && !m.uploads && !m.net_receives && !m.threads && !m.modules && !m.logs && !m.envs && !m.sleeps);
    assert(child_io.stage_end == 31000 && child_io.total_end == 301000 && child_cleanup_end == 61000);
    assert(data_readiness.attempted && data_readiness.no_dispatch && data_readiness.no_request);
    assert(!data_readiness.ready && !data_readiness.possible_apply && !data_readiness.terminal && !data_readiness.settled_failure);
    assert(!data_readiness.cancel_attempted && data_readiness.transaction_id == 17 && !m.errno_pending);
    drain_owner();
    assert(m.saw_eof == 1 && !m.owner_result.status && m.owner_result.channel_zero_observed && m.owner_result.hangup_observed);
    assert(!m.owner_result.ownership_uncertain && !m.owner_result.cleanup_failed);
    assert(m.observed_count == m.accepted + m.failure_accepted);
    for (unsigned i = 0; i < m.accepted; i++)
        assert(m.observed[i].kind == PW_WC_PROGRESS && m.observed[i].failure_api == i + 1);
}
static void uncertain(unsigned attempts, unsigned accepted)
{
    assert(m.attempts == attempts && m.accepted == accepted);
    assert(wire_result.delivery_uncertain && !m.failure_attempts && !m.failure_accepted);
    assert(data_readiness.api == PW_WCD_PROGRESS && bootstrap_failure.api == PW_WCD_PROGRESS);
}
static void certificate(unsigned api, int raw, int error)
{
    assert(m.failure_attempts == 1 && m.failure_accepted == 1 && !wire_result.delivery_uncertain);
    const PwWineChildFrame *f = &m.observed[m.observed_count - 1];
    assert(f->kind == PW_WC_FAILURE && f->status == -PW_WCB_DATA && f->failure_api == api);
    assert(f->failure_raw == raw && f->errno_valid == (unsigned)(error > 0) && f->native_error == error);
    assert(f->returned_length == (PW_WCD_NO_DISPATCH << PW_WCD_STATE_SHIFT) && !f->returned_value);
    assert(bootstrap_failure.api == api && bootstrap_failure.raw == raw && bootstrap_failure.error == error);
}
int main(void)
{
    /* Finite synthetic queue: held records 1..5 refuse stage 6. */
    reset(); m.capacity = 5; run(); uncertain(6, 5);
    assert(m.socket_calls == 1 && m.socket_closes == 1 && !m.options && !m.errno_calls);
    assert(wire_result.status == PW_WC_OS && wire_result.api == PW_WC_API_SEND && wire_result.raw_result == -1 && wire_result.native_error == EAGAIN);
    /* Identical safe-stop input with an earlier owner drain or a wider FIFO.
     * Stage 6 is decoded, then a deliberate option failure proves no dispatch. */
    for (unsigned drain = 0; drain < 2; drain++) {
        reset(); m.capacity = drain ? 5 : QUEUE_MAX; m.drain_before_six = drain; run();
        assert(m.attempts == 6 && m.accepted == 6 && m.socket_calls == 1 && m.socket_closes == 1 && m.options == 1);
        certificate(PW_WCD_OPTION, -9, ENETDOWN);
    }
    const int errors[] = {EAGAIN, EPIPE, ENOBUFS};
    for (unsigned i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
        reset(); m.fail_stage = 6; m.send_error = errors[i]; run(); uncertain(6, 5);
        assert(wire_result.status == PW_WC_OS && wire_result.errno_valid && wire_result.native_error == errors[i]);
        assert(m.socket_calls == 1 && m.socket_closes == 1 && !m.options);
    }
    const int short_sends[] = {0, PW_WC_WIRE_BYTES - 1};
    for (unsigned i = 0; i < sizeof(short_sends) / sizeof(short_sends[0]); i++) {
        reset(); m.fail_stage = 6; m.short_send = short_sends[i]; run(); uncertain(6, 5);
        assert(wire_result.status == PW_WC_PROTOCOL && wire_result.raw_result == short_sends[i] && !wire_result.errno_valid);
        assert(m.socket_calls == 1 && m.socket_closes == 1 && !m.options);
    }
    reset(); m.scenario = EXPIRE_AFTER_FIVE; run(); uncertain(5, 5);
    assert(!wire_result.status && !m.socket_calls && !m.socket_closes && child_io.last_clock == 31000);
    reset(); m.scenario = EXPIRE_IN_DATA_CHECK; run();
    assert(m.attempts == 5 && m.accepted == 5 && !m.socket_calls && !m.socket_closes);
    assert(!wire_result.status && child_io.last_clock == 31000);
    certificate(PW_WCD_BUDGET, -1, 0); /* Original cleanup window, not renewed startup. */
    reset(); m.scenario = CANCEL_AFTER_FIVE; run();
    assert(m.attempts == 5 && m.accepted == 5 && owner_cancel_received && data_readiness.cancel_requested);
    assert(!data_readiness.control_refused && !m.socket_calls && !m.socket_closes);
    certificate(PW_WCD_CONTROL, 1, 0);
    reset(); m.scenario = REFUSE_AFTER_FIVE; run();
    assert(m.attempts == 5 && m.accepted == 5 && data_readiness.control_refused && !owner_cancel_received);
    assert(!m.socket_calls && !m.socket_closes && !m.failure_attempts && !wire_result.delivery_uncertain);
    reset(); m.socket_raw = -7; run(); certificate(PW_WCD_SOCKET, -7, EACCES);
    assert(m.attempts == 5 && m.accepted == 5 && m.socket_calls == 1 && !m.socket_closes && m.errno_calls == 1);
    reset(); m.socket_raw = -7; m.certificate_error = EPIPE; run();
    assert(m.attempts == 5 && m.accepted == 5 && m.failure_attempts == 1 && !m.failure_accepted);
    assert(m.socket_calls == 1 && !m.socket_closes && m.errno_calls == 1 && wire_result.delivery_uncertain);
    assert(m.attempted_failure.failure_api == PW_WCD_SOCKET && m.attempted_failure.failure_raw == -7);
    assert(m.attempted_failure.errno_valid && m.attempted_failure.native_error == EACCES);
    assert(bootstrap_failure.api == PW_WCD_SOCKET && bootstrap_failure.error == EACCES && wire_result.native_error == EPIPE);
    puts("child progress failure: real main/data/wire with synthetic OS I/O passed (no PS5 capacity or cause claim)");
    return 0;
}
