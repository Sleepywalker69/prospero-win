/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Original SELF adapter with every native boundary replaced. No sockets,
 * descriptors, processes, worker entry or platform startup are executed. */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "../native/pw_native_fd_report.h"

static int fake_clock(clockid_t, struct timespec *);
static int fake_poll(struct pollfd *, nfds_t, int);
static int fake_fcntl(int, int, ...);
static int fake_setsockopt(int, int, int, const void *, socklen_t);
static ssize_t fake_read(int, void *, size_t);
static ssize_t fake_write(int, const void *, size_t);
static pid_t fake_pid(void);
static void fake_exit(int) __attribute__((noreturn));
#define PW_NATIVE_CHILD_FD_MODE 1
#define PW_NATIVE_CHILD_BUILD_ID "worker-adapter-fixture"
/* This constant is consumed only by a mock, never by a host socket. */
#ifndef SO_NOSIGPIPE
#define SO_NOSIGPIPE 0x1022
#endif
#define clock_gettime fake_clock
#define poll fake_poll
#define fcntl fake_fcntl
#define setsockopt fake_setsockopt
#define read fake_read
#define write fake_write
#define getpid fake_pid
#define getppid fake_pid
#define _exit fake_exit
#define _start inert_worker_entry
#define memcpy worker_memcpy
#define memset worker_memset
#define memcmp worker_memcmp
#include "../native/pw_native_child_worker.c"
#undef memcpy
#undef memset
#undef memcmp
#undef clock_gettime
#undef poll
#undef fcntl
#undef setsockopt
#undef read
#undef write
#undef getpid
#undef getppid
#undef _exit
#undef _start

static struct {
    uint64_t now, fd_end;
    int poll_result, poll_events, fd_status, cleanup, phase_calls, expire_outer;
    uint8_t report[PW_NATIVE_FD_REPORT_BYTES];
    size_t written, chunk;
    PwNativeChildIo *io;
} mock;
static int fake_clock(clockid_t id, struct timespec *v)
{ assert(id == CLOCK_MONOTONIC); v->tv_sec = (time_t)(mock.now / 1000); v->tv_nsec = (long)(mock.now % 1000) * 1000000; return 0; }
static int fake_poll(struct pollfd *p, nfds_t n, int timeout)
{ assert(n == 1 && p->fd == STDIN_FILENO && p->events == POLLIN && timeout == 0); p->revents = (short)mock.poll_events; return mock.poll_result; }
static int fake_fcntl(int fd, int command, ...) { (void)fd; (void)command; abort(); }
static int fake_setsockopt(int f, int l, int o, const void *v, socklen_t s)
{ (void)f; (void)l; (void)o; (void)v; (void)s; abort(); }
static ssize_t fake_read(int fd, void *p, size_t n) { (void)fd; (void)p; (void)n; abort(); }
static ssize_t fake_write(int fd, const void *p, size_t n) { (void)fd; (void)p; (void)n; abort(); }
static pid_t fake_pid(void) { abort(); }
static void fake_exit(int status) { (void)status; abort(); }
static long receive_unused(void *c, void *p, size_t n, unsigned t)
{ (void)c; (void)p; (void)n; (void)t; abort(); }
static long send_report(void *c, const void *p, size_t n, unsigned remaining)
{
    (void)c; assert(remaining && remaining <= PW_NC_STAGE_MS);
    if (mock.chunk && n > mock.chunk) n = mock.chunk;
    assert(mock.written + n <= sizeof(mock.report));
    memcpy(mock.report + mock.written, p, n); mock.written += n; return (long)n;
}
int pw_native_fd_worker(const char *path, uint64_t token, const PwNativeFdContext *c, PwNativeFdResult *r)
{
    uint64_t now;
    assert(!strcmp(path, "/data/prospero-win/fd-00000011-8877665544332211/s"));
    assert(token == UINT64_C(0x8877665544332211));
    assert(c->deadline_ms == mock.io->stage_end - PW_NATIVE_FD_REPORT_RESERVE_MS);
    assert(!c->clock_ms(c->context, &now) && now == mock.io->last_clock);
    mock.fd_end = c->deadline_ms; ++mock.phase_calls;
    memset(r, 0, sizeof(*r)); r->status = (PwNativeFdStatus)mock.fd_status;
    if (c->cancelled(c->context)) r->status = PW_NATIVE_FD_CANCELLED;
    r->local_pid = 42; r->reported_peer_pid = 17;
    if (!r->status) {
        r->stage = PW_NATIVE_FD_COMPLETE;
        r->observations = PW_NATIVE_FD_CONNECTED | PW_NATIVE_FD_HELLO_OK | PW_NATIVE_FD_QUEUED_RIGHT_OK |
            PW_NATIVE_FD_FORWARD_OK | PW_NATIVE_FD_REVERSE_OK | PW_NATIVE_FD_REVERSE_EOF | PW_NATIVE_FD_COMPLETED;
    } else { r->stage = PW_NATIVE_FD_REVERSE; r->api = PW_NATIVE_FD_API_RECVMSG; r->raw_result = -1; }
    if (mock.cleanup) {
        r->status = PW_NATIVE_FD_OS; r->stage = PW_NATIVE_FD_CLEANUP; r->api = PW_NATIVE_FD_API_CLOSE;
        r->observations &= ~PW_NATIVE_FD_COMPLETED; r->cleanup_failed = 1; r->raw_result = -1;
    }
    if (r->status == PW_NATIVE_FD_TIMEOUT) mock.now = c->deadline_ms;
    if (mock.expire_outer) mock.now = mock.io->stage_end;
    return r->status;
}
static void setup(PwNativeChildIo *io)
{
    memset(&mock, 0, sizeof(mock)); memset(io, 0, sizeof(*io));
    mock.now = 100; mock.io = io; io->clock_ms = worker_clock;
    io->send = send_report; io->receive = receive_unused;
    assert(!pw_native_child_begin(io));
}
static PwNativeChildFrame frame(void)
{
    PwNativeChildFrame f = {0}; f.parent_pid = 17; f.child_pid = 42; f.child_ppid = 7;
    f.sequence = 3; f.correlation = UINT64_C(0x8877665544332211); return f;
}
int main(void)
{
    PwNativeChildIo io; PwNativeChildFrame f = frame(); PwNativeFdResult result;
    for (unsigned chunk = 1; chunk <= PW_NATIVE_FD_REPORT_BYTES; ++chunk) {
        setup(&io); mock.chunk = chunk;
        assert(!worker_capabilities(NULL, &io, &f) && mock.phase_calls == 1 && mock.written == sizeof(mock.report));
        assert(!pw_native_fd_report_decode(&result, mock.report, 17, 42, f.correlation));
        assert(pw_native_fd_result_matches(&result, 42, 17, 1));
    }
    for (int failure = PW_NATIVE_FD_EOF; failure < 0; ++failure) {
        setup(&io); mock.fd_status = failure;
        assert(worker_capabilities(NULL, &io, &f) == -1 && mock.written == sizeof(mock.report));
        assert(!pw_native_fd_report_decode(&result, mock.report, 17, 42, f.correlation));
        assert(result.status == failure && !pw_native_fd_result_matches(&result, 42, 17, 1));
        if (failure == PW_NATIVE_FD_TIMEOUT) assert(io.stage_end - mock.now == PW_NATIVE_FD_REPORT_RESERVE_MS);
    }
    setup(&io); mock.cleanup = 1;
    assert(worker_capabilities(NULL, &io, &f) == -1 && mock.written == sizeof(mock.report));
    assert(!pw_native_fd_report_decode(&result, mock.report, 17, 42, f.correlation) && result.cleanup_failed);
    for (int event = 0; event < 3; ++event) {
        setup(&io); mock.poll_result = event == 0 ? -1 : 1; mock.poll_events = event == 2 ? POLLHUP : POLLIN;
        assert(worker_capabilities(NULL, &io, &f) == -1 && mock.written == sizeof(mock.report));
        assert(!pw_native_fd_report_decode(&result, mock.report, 17, 42, f.correlation) && result.status == PW_NATIVE_FD_CANCELLED);
    }
    setup(&io); mock.now = io.stage_end - PW_NATIVE_FD_REPORT_RESERVE_MS;
    assert(worker_capabilities(NULL, &io, &f) == -1 && !mock.phase_calls && !mock.written);
    setup(&io); mock.expire_outer = 1;
    assert(worker_capabilities(NULL, &io, &f) == -1 && mock.phase_calls == 1 && !mock.written);
    puts("native FD worker adapter: correlated success/failure reports, cleanup, control-channel cancellation and reserved deadline passed with pure mocks");
    return 0;
}
