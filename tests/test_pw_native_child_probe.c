/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Controller integration with the real portable protocol. No host sockets,
 * native payload execution or real threads: every platform boundary is mocked. */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include "native_child_probe_fixture/native-child-build.h"
#ifndef PW_NATIVE_CHILD_PEER_MODE
#define PW_NATIVE_CHILD_PEER_MODE 0
#endif
#if PW_NATIVE_CHILD_FD_MODE
#include "../native/pw_native_fd_report.h"
#endif
#if PW_NATIVE_CHILD_PEER_MODE
#include "../native/pw_native_peer_probe.h"
#endif
#if PW_NATIVE_CHILD_FD_MODE || PW_NATIVE_CHILD_PEER_MODE
static int test_mkdir(const char *, mode_t);
static int test_rmdir(const char *);
#define mkdir test_mkdir
#define rmdir test_rmdir
#endif
#include "../native/pw_native_child_protocol.h"

static int test_clock_gettime(clockid_t, struct timespec *);
static int test_nanosleep(const struct timespec *, struct timespec *);
static pid_t test_getpid(void);
static int test_attr_init(pthread_attr_t *);
static int test_attr_setdetachstate(pthread_attr_t *, int);
static int test_attr_destroy(pthread_attr_t *);
static int test_pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
#define clock_gettime test_clock_gettime
#define nanosleep test_nanosleep
#define getpid test_getpid
#define pthread_attr_init test_attr_init
#define pthread_attr_setdetachstate test_attr_setdetachstate
#define pthread_attr_destroy test_attr_destroy
#define pthread_create test_pthread_create
#include "../native/pw_native_child_probe.c"
#undef clock_gettime
#undef nanosleep
#undef getpid
#undef pthread_attr_init
#undef pthread_attr_setdetachstate
#undef pthread_attr_destroy
#undef pthread_create
#if PW_NATIVE_CHILD_FD_MODE || PW_NATIVE_CHILD_PEER_MODE
#undef mkdir
#undef rmdir
#endif

const unsigned char pw_native_child_image[PW_NATIVE_CHILD_SELF_BYTES] = {0x50, 0x57};
const size_t pw_native_child_image_size = sizeof(pw_native_child_image);
static struct Mock {
    uint64_t now;
    int fd, open, socket_calls, option_calls, connect_calls, fcntl_calls, close_calls;
    int attr_calls, detach_calls, destroy_calls, thread_calls;
    int attr_error, detach_error, thread_error;
    int socket_error, option_error_at, connect_error, fcntl_error, close_error;
    int send_calls, receive_calls, poll_calls, send_interrupt, receive_interrupt, poll_interrupt;
    int clock_error, sce_error, recv_error, null_sce_errno, pace_error;
    int cancel_connect, cancel_poll, timeout_poll, boundary_on_read, poll_timeout, ticks_per_wait, eof_hup;
    int no_eof, poll_invalid, poll_error, write_hup;
    size_t chunk, input_size, position, output_size;
    unsigned char input[7 * PW_NC_FRAME_BYTES], output[PW_NATIVE_CHILD_SELF_BYTES + 5 * PW_NC_FRAME_BYTES];
    void *(*entry)(void *); void *context;
    char log[4096];
#if PW_NATIVE_CHILD_FD_MODE
    int directory, mkdir_calls, rmdir_calls, mkdir_error, rmdir_error;
    int fd_open_calls, fd_run_calls, fd_dispose_calls, fd_open_error, fd_failure, fd_clock_boundary;
    int fd_open_cancel, fd_open_expiry;
#endif
#if PW_NATIVE_CHILD_PEER_MODE
    int directory, mkdir_calls, rmdir_calls, mkdir_error, rmdir_error;
    int peer_open_calls, peer_exchange_calls, peer_pre_stop_calls, peer_observe_calls;
    int peer_open_error, peer_open_cancel, peer_open_expiry, peer_failure, peer_pending_failure;
    unsigned peer_open_api;
    int peer_exit_failure, peer_cleanup_failure, peer_close_late, peer_cooperative;
#endif
} mock;

#if PW_NATIVE_CHILD_FD_MODE
static PwNativeFdResult role_result(int worker)
{
    PwNativeFdResult r = {0};
    r.stage = PW_NATIVE_FD_COMPLETE;
    r.local_pid = worker ? 42 : 17; r.reported_peer_pid = worker ? 17 : 42;
    r.observations = PW_NATIVE_FD_CONNECTED | PW_NATIVE_FD_HELLO_OK | PW_NATIVE_FD_QUEUED_RIGHT_OK |
                     PW_NATIVE_FD_FORWARD_OK | PW_NATIVE_FD_REVERSE_OK | PW_NATIVE_FD_COMPLETED |
                     (worker ? PW_NATIVE_FD_REVERSE_EOF : PW_NATIVE_FD_FORWARD_EOF);
    r.peer_observations = worker ? 0 : PW_NATIVE_FD_REVERSE_EOF;
    return r;
}
static int test_mkdir(const char *path, mode_t mode)
{
    assert(!mock.directory && mode == 0700 && !strcmp(path, "/data/prospero-win/fd-00000011-0000001150574e27"));
    ++mock.mkdir_calls;
    if (mock.mkdir_error) { errno = mock.mkdir_error; return -1; }
    mock.directory = 1; return 0;
}
static int test_rmdir(const char *path)
{
    assert(mock.directory && !strcmp(path, probe.directory)); ++mock.rmdir_calls;
    if (mock.rmdir_error) { errno = mock.rmdir_error; return -1; }
    mock.directory = 0; return 0;
}
int pw_native_fd_parent_open(PwNativeFdListener *l, const char *path,
                            const PwNativeFdContext *c, PwNativeFdResult *r)
{
    uint64_t now;
    assert(mock.directory && !mock.socket_calls && !strcmp(path, "/data/prospero-win/fd-00000011-0000001150574e27/s"));
    assert(!c->clock_ms(c->context, &now) && now < c->deadline_ms);
    ++mock.fd_open_calls;
    if (mock.fd_open_error) { r->status = PW_NATIVE_FD_OS; return r->status; }
    l->fd = 79; l->bound = 1; l->last_clock_ms = now;
    if (mock.fd_open_cancel) pw_native_child_probe_cancel();
    if (mock.fd_open_expiry) mock.now = c->deadline_ms;
    return 0;
}
void pw_native_fd_dispose(PwNativeFdListener *l, PwNativeFdResult *r)
{
    (void)r;
    if (l->fd >= 0 || l->bound) { assert(l->fd == 79 && l->bound); ++mock.fd_dispose_calls; }
    l->fd = -1; l->bound = 0;
}
int pw_native_fd_parent(PwNativeFdListener *l, uint64_t correlation,
                       const PwNativeFdContext *c, PwNativeFdResult *r)
{
    uint64_t now;
    assert(mock.directory && l->fd == 79 && l->bound && correlation);
    assert(mock.position == 4 * PW_NC_FRAME_BYTES); /* report not yet consumed */
    assert(mock.output_size == PW_NATIVE_CHILD_SELF_BYTES + 3 * PW_NC_FRAME_BYTES); /* no STOP */
    assert(!c->clock_ms(c->context, &now));
    assert(c->deadline_ms == probe.io.stage_end - PW_NATIVE_FD_REPORT_RESERVE_MS);
    ++mock.fd_run_calls; *r = role_result(0);
    if (mock.fd_failure) { r->status = PW_NATIVE_FD_PROTOCOL; r->stage = PW_NATIVE_FD_FINISH; r->observations &= ~PW_NATIVE_FD_COMPLETED; }
    if (mock.fd_clock_boundary) mock.now = probe.io.stage_end;
    pw_native_fd_dispose(l, r);
    return r->status;
}
static void set_worker_report(PwNativeFdResult value)
{
    uint64_t correlation = 100 ^ ((uint64_t)17 << 32) ^ UINT64_C(0x50574e43);
    assert(!pw_native_fd_report_encode(mock.input + 4 * PW_NC_FRAME_BYTES, 17, 42, correlation, &value));
}
#endif

#if PW_NATIVE_CHILD_PEER_MODE
static int test_mkdir(const char *path, mode_t mode)
{
    assert(!mock.directory && mode == 0700 && !strcmp(path, "/data/prospero-win/peer-test"));
    ++mock.mkdir_calls;
    if (mock.mkdir_error) { errno = mock.mkdir_error; return -1; }
    mock.directory = 1; return 0;
}
static int test_rmdir(const char *path)
{
    assert(mock.directory && !strcmp(path, probe.peer_directory)); ++mock.rmdir_calls;
    if (mock.rmdir_error) { errno = mock.rmdir_error; return -1; }
    mock.directory = 0; return 0;
}
int pw_native_peer_paths(uint32_t pid, uint64_t correlation, char directory[PW_NP_PATH_CAP], char path[PW_NP_PATH_CAP])
{
    assert(pid == 17 && correlation); strcpy(directory, "/data/prospero-win/peer-test");
    strcpy(path, "/data/prospero-win/peer-test/s"); return 0;
}
int pw_native_peer_parent_open(PwNativePeerProbe *p, const char *path, PwNativeChildIo *io, PwNativePeerResult *r)
{
    assert(mock.directory && !mock.socket_calls && strstr(path, "/peer-test/s"));
    ++mock.peer_open_calls;
    if (mock.peer_open_error) {
        r->status = PW_NP_OS; r->phase = PW_NP_SETUP; r->api = mock.peer_open_api;
        r->raw_result = -1; r->native_error = EINVAL;
        return -1;
    }
    p->listener = 79; p->bound = 1;
    if (mock.peer_open_cancel) pw_native_child_probe_cancel();
    if (mock.peer_open_expiry) mock.now = io->stage_end;
    return 0;
}
int pw_native_peer_parent_exchange(PwNativePeerProbe *p, PwNativeChildIo *io,
                                    const PwNativeChildFrame *frame, PwNativePeerResult *r)
{
    assert(mock.directory && p->listener == 79 && frame->parent_pid == 17 && frame->child_pid == 42);
    assert(mock.position == 4 * PW_NC_FRAME_BYTES && mock.output_size == PW_NATIVE_CHILD_SELF_BYTES + 3 * PW_NC_FRAME_BYTES);
    assert(io == &probe.io); ++mock.peer_exchange_calls;
    p->listener = -1; p->bound = 0; p->queue = 80; p->armed = 1;
    r->worker_report_valid = r->nonce_match = r->reciprocal_ok = 1;
    if (mock.peer_failure) { r->status = PW_NP_PROTOCOL; return -1; }
    return 0;
}
int pw_native_peer_pre_stop(PwNativePeerProbe *p, PwNativeChildIo *io, PwNativePeerResult *r)
{
    assert(p->armed && io == &probe.io); ++mock.peer_pre_stop_calls;
    assert(mock.output_size == PW_NATIVE_CHILD_SELF_BYTES + 3 * PW_NC_FRAME_BYTES);
    if (r->status) return -1;
    assert(!mock.directory && mock.rmdir_calls == 1);
    if (mock.peer_pending_failure) { r->status = PW_NP_EXIT; return -1; }
    r->prestop_empty = 1; return 0;
}
int pw_native_peer_observe(PwNativePeerProbe *p, PwNativeChildIo *io, int cooperative, PwNativePeerResult *r)
{
    assert(p->armed && p->queue == 80 && mock.close_calls == 1 && io == &probe.io);
    ++mock.peer_observe_calls; mock.peer_cooperative = cooperative; p->queue = -1;
    if (mock.peer_exit_failure) { if (!r->status) r->status = PW_NP_EXIT; return -1; }
    r->exit_observed = r->exit_status_match = 1;
    if (!cooperative || r->status) return -1;
    r->phase = PW_NP_COMPLETE; return 0;
}
void pw_native_peer_parent_cleanup(PwNativePeerProbe *p, PwNativePeerResult *r)
{
    p->listener = p->stream = p->queue = -1; p->bound = 0;
    if (mock.peer_cleanup_failure) r->cleanup_failed = 1;
    if (mock.peer_close_late) mock.now = probe.io.stage_end;
}
#endif

static int test_clock_gettime(clockid_t id, struct timespec *out)
{
    assert(id == CLOCK_MONOTONIC);
    if (mock.clock_error) { errno = EIO; return -1; }
    out->tv_sec = (time_t)(mock.now / 1000); out->tv_nsec = (long)(mock.now % 1000) * 1000000;
    return 0;
}
static int test_nanosleep(const struct timespec *delay, struct timespec *unused)
{
    (void)unused;
    assert(delay->tv_sec == 0 && delay->tv_nsec == 75000000);
    mock.now += 75;
    for (int i = 0; i < mock.ticks_per_wait; ++i) pw_native_child_probe_tick();
    if (mock.pace_error) { errno = mock.pace_error; return -1; }
    return 0;
}
static pid_t test_getpid(void) { return 17; }
static int test_attr_init(pthread_attr_t *a) { (void)a; ++mock.attr_calls; return mock.attr_error; }
static int test_attr_setdetachstate(pthread_attr_t *a, int state)
{ (void)a; assert(state == PTHREAD_CREATE_DETACHED); ++mock.detach_calls; return mock.detach_error; }
static int test_attr_destroy(pthread_attr_t *a) { (void)a; ++mock.destroy_calls; return 0; }
static int test_pthread_create(pthread_t *t, const pthread_attr_t *a, void *(*entry)(void *), void *context)
{
    (void)t; (void)a; ++mock.thread_calls;
    if (mock.thread_error) return mock.thread_error;
    mock.entry = entry; mock.context = context;
    return 0;
}
void pw_diagnostics_log(const char *format, ...)
{
    size_t length = strlen(mock.log);
    va_list args; va_start(args, format);
    assert(vsnprintf(mock.log + length, sizeof(mock.log) - length, format, args) > 0);
    va_end(args);
    length = strlen(mock.log); assert(length + 2 < sizeof(mock.log));
    mock.log[length] = '\n'; mock.log[length + 1] = 0;
}
int ps5log_ps5_socket(int domain, int type, int protocol)
{
    assert(domain == AF_INET && type == SOCK_STREAM && protocol == IPPROTO_TCP);
    assert(!mock.open); ++mock.socket_calls;
    if (mock.socket_error) { errno = mock.socket_error; return -1; }
    mock.open = 1; return mock.fd;
}
static void owned(int fd) { assert(mock.open && fd == mock.fd); }
int ps5log_ps5_setsockopt(int fd, int level, int option, const void *value, socklen_t size)
{
    const int options[] = {0x1105, 0x1106, 0x1109};
    owned(fd); assert(level == 0xffff && mock.option_calls < 3);
    assert(option == options[mock.option_calls] && size == sizeof(uint32_t));
    assert(*(const uint32_t *)value == PW_NC_STAGE_MS * 1000u);
    ++mock.option_calls;
    if (mock.option_error_at == mock.option_calls) { errno = EINVAL; return -1; }
    return 0;
}
int ps5log_ps5_connect(int fd, const struct sockaddr *address, socklen_t size)
{
    const unsigned char *bytes = (const unsigned char *)address;
    owned(fd); ++mock.connect_calls;
    assert(size == 16 && bytes[0] == 16 && bytes[1] == AF_INET);
    assert(bytes[2] == (9021 >> 8) && bytes[3] == (9021 & 255));
    assert(bytes[4] == 127 && bytes[5] == 0 && bytes[6] == 0 && bytes[7] == 1);
    for (unsigned i = 8; i < size; ++i) assert(bytes[i] == 0);
    if (mock.cancel_connect) pw_native_child_probe_cancel();
    if (mock.connect_error) { errno = mock.connect_error; return -1; }
    return 0;
}
int ps5log_ps5_fcntl(int fd, int command, ...)
{
    owned(fd); assert(command == F_SETFL); ++mock.fcntl_calls;
    va_list args; va_start(args, command); assert(va_arg(args, int) == O_NONBLOCK); va_end(args);
    if (mock.fcntl_error) { errno = mock.fcntl_error; return -1; }
    return 0;
}
int ps5log_ps5_close(int fd)
{
    owned(fd); ++mock.close_calls;
    /* Failure does not claim that the OS has actually released the descriptor. */
    if (mock.close_error) { errno = mock.close_error; return -1; }
    mock.open = 0; return 0;
}
int ps5log_ps5_poll(struct pollfd *items, unsigned long count, int timeout)
{
    assert(count == 1 && timeout > 0 && timeout <= 100); owned(items[0].fd); ++mock.poll_calls;
    if (mock.poll_interrupt) { --mock.poll_interrupt; errno = EINTR; return -1; }
    if (!mock.boundary_on_read || items[0].events == POLLIN) {
        if (mock.cancel_poll) { mock.cancel_poll = 0; pw_native_child_probe_cancel(); }
        if (mock.timeout_poll) { mock.timeout_poll = 0; mock.now = probe.io.stage_end; }
    }
    if (mock.poll_timeout || (mock.no_eof && mock.position == mock.input_size && items[0].events == POLLIN)) {
        mock.now += (unsigned)timeout; return 0;
    }
    items[0].revents = items[0].events;
    if (mock.eof_hup && mock.position == mock.input_size && items[0].events == POLLIN) items[0].revents = POLLHUP;
    if (mock.write_hup && items[0].events == POLLOUT) items[0].revents = POLLHUP;
    if (mock.poll_invalid) items[0].revents = POLLNVAL;
    if (mock.poll_error) items[0].revents = POLLERR;
    return 1;
}
long ps5log_ps5_send(int fd, const void *bytes, size_t size, int flags)
{
    owned(fd); assert(!flags); ++mock.send_calls;
    if (mock.send_interrupt) { --mock.send_interrupt; errno = EINTR; return -1; }
    if (mock.chunk && size > mock.chunk) size = mock.chunk;
    assert(size <= sizeof(mock.output) - mock.output_size);
    memcpy(mock.output + mock.output_size, bytes, size); mock.output_size += size;
    return (long)size;
}
int *sceNetErrnoLoc(void) { return mock.null_sce_errno ? NULL : &mock.sce_error; }
int sceNetRecv(int fd, void *bytes, size_t size, int flags)
{
    owned(fd); assert(!flags); ++mock.receive_calls;
    if (mock.receive_interrupt) { --mock.receive_interrupt; mock.sce_error = EINTR; return -1; }
    if (mock.recv_error) { mock.sce_error = mock.recv_error; return -1; }
    if (size > mock.input_size - mock.position) size = mock.input_size - mock.position;
    if (mock.chunk && size > mock.chunk) size = mock.chunk;
    memcpy(bytes, mock.input + mock.position, size); mock.position += size;
    return (int)size;
}
static void append(PwNativeChildFrame value)
{
    assert(mock.input_size + PW_NC_FRAME_BYTES <= sizeof(mock.input));
    assert(!pw_native_child_encode(mock.input + mock.input_size, &value));
    mock.input_size += PW_NC_FRAME_BYTES;
}
static void reset(void)
{
    memset(&mock, 0, sizeof(mock)); memset(&probe, 0, sizeof(probe));
    atomic_init(&probe.state, PROBE_IDLE); atomic_init(&probe.stop, 0); atomic_init(&probe.ticks, 0);
    mock.fd = 41; mock.now = 100; mock.ticks_per_wait = 1; errno = 0;
    PwNativeChildFrame value = {0};
    value.kind = PW_NC_HELLO; value.child_pid = 42; value.child_ppid = 7;
    memcpy(value.build_id, PW_NATIVE_CHILD_BUILD_ID, sizeof(PW_NATIVE_CHILD_BUILD_ID)); append(value);
    value.parent_pid = 17; value.correlation = 100 ^ ((uint64_t)17 << 32) ^ UINT64_C(0x50574e43);
    for (unsigned i = 1; i <= PW_NC_ECHO_COUNT + 1; ++i) {
#if PW_NATIVE_CHILD_FD_MODE
        if (i == PW_NC_ECHO_COUNT + 1) {
            set_worker_report(role_result(1)); mock.input_size += PW_NATIVE_FD_REPORT_BYTES;
        }
#endif
        value.sequence = i; value.kind = i <= PW_NC_ECHO_COUNT ? PW_NC_ECHO_REPLY : PW_NC_STOP_ACK; append(value);
    }
}
static void run(void)
{
    assert(!pw_native_child_probe_start()); assert(mock.entry);
    assert(mock.entry(mock.context) == NULL);
    assert(atomic_load(&probe.state) == PROBE_DONE && probe.socket == -1);
    assert(pw_native_child_probe_start() == -1 && mock.thread_calls == 1);
    pw_native_child_probe_cancel(); assert(mock.close_calls <= 1);
}
static void expect_failed(int error)
{
    char text[100];
    assert(probe.status == -1 && probe.error == error);
    pw_native_child_probe_status(text, sizeof(text)); assert(strstr(text, "FAILED"));
    assert(strstr(mock.log, "native_reap=unverified windows_child=unsupported"));
}
static void test_success(void)
{
    for (unsigned chunk = 1; chunk <= PW_NC_FRAME_BYTES + 1; ++chunk) {
        reset(); mock.chunk = chunk; mock.fd = chunk == 1 ? 0 : 41; mock.eof_hup = 1; run();
        assert(!probe.status && !probe.error && probe.result.stop_ack && probe.result.stream_closed);
        assert(probe.result.echoes == 3 && mock.close_calls == 1 && !mock.open);
        assert(mock.output_size == PW_NATIVE_CHILD_SELF_BYTES + 4 * PW_NC_FRAME_BYTES);
        assert(!memcmp(mock.output, pw_native_child_image, PW_NATIVE_CHILD_SELF_BYTES));
        for (unsigned i = 0; i <= PW_NC_ECHO_COUNT; ++i) {
            PwNativeChildFrame frame;
            assert(!pw_native_child_decode(&frame, mock.output + PW_NATIVE_CHILD_SELF_BYTES + i * PW_NC_FRAME_BYTES));
            assert(frame.parent_pid == 17 && frame.child_pid == 42 && frame.child_ppid == 7 && frame.correlation);
            assert(frame.sequence == i + 1 && frame.kind == (i == 3 ? PW_NC_STOP : PW_NC_ECHO));
        }
        assert(strstr(mock.log, "ui_ticks=3 native_reap=unverified windows_child=unsupported"));
    }
}
static void test_start_cancel_and_ownership(void)
{
    char text[100];
    reset(); pw_native_child_probe_cancel();
    assert(!atomic_load(&probe.stop) && !mock.close_calls);
    pw_native_child_probe_status(text, sizeof(text)); assert(strstr(text, "RUN ONCE"));
    assert(!pw_native_child_probe_start());
    assert(pw_native_child_probe_start() == -1 && mock.thread_calls == 1 && !mock.socket_calls);
    pw_native_child_probe_status(text, sizeof(text)); assert(strstr(text, "RUNNING"));
    pw_native_child_probe_cancel(); assert(!mock.close_calls && atomic_load(&probe.stop));
    assert(!mock.entry(mock.context)); expect_failed(ECANCELED); assert(!mock.socket_calls);
    reset(); mock.cancel_connect = 1; run(); expect_failed(ECANCELED);
    assert(mock.close_calls == 1 && !mock.fcntl_calls && !mock.send_calls);
    reset(); mock.close_error = EIO; run(); expect_failed(EIO);
    assert(mock.close_calls == 1 && mock.open && probe.result.stream_closed);
}
static void test_setup_failures(void)
{
    for (int stage = 0; stage < 3; ++stage) {
        reset(); if (stage == 0) mock.attr_error = EAGAIN;
        if (stage == 1) mock.detach_error = EAGAIN;
        if (stage == 2) mock.thread_error = EAGAIN;
        assert(pw_native_child_probe_start() == -1 && atomic_load(&probe.state) == PROBE_DONE);
        assert(probe.error == EAGAIN && !mock.socket_calls && !mock.close_calls);
        assert(mock.destroy_calls == (stage != 0));
        assert(pw_native_child_probe_start() == -1 && mock.attr_calls == 1);
    }
    reset(); mock.clock_error = 1; run(); expect_failed(EIO); assert(!mock.socket_calls);
    reset(); mock.socket_error = EMFILE; run(); expect_failed(EMFILE); assert(!mock.close_calls);
    for (int i = 1; i <= 3; ++i) {
        reset(); mock.option_error_at = i; run(); expect_failed(EINVAL);
        assert(mock.option_calls == i && mock.close_calls == 1 && !mock.connect_calls);
    }
    reset(); mock.connect_error = ECONNREFUSED; run(); expect_failed(ECONNREFUSED); assert(mock.close_calls == 1);
    reset(); mock.fcntl_error = EIO; run(); expect_failed(EIO); assert(mock.close_calls == 1 && !mock.send_calls);
}
static void test_protocol_and_ui(void)
{
    reset(); mock.ticks_per_wait = 0; run(); expect_failed(EDEADLK);
    assert(probe.result.stop_ack && probe.result.stream_closed && mock.close_calls == 1);
    reset(); mock.no_eof = 1; run(); expect_failed(ETIMEDOUT);
    assert(probe.result.stop_ack && !probe.result.stream_closed && mock.close_calls == 1);
    reset(); mock.input[PW_NC_FRAME_BYTES + 40] ^= 1; run(); expect_failed(EPROTO);
    assert(!probe.result.echoes && !probe.result.stop_ack && !probe.result.stream_closed);
    reset(); mock.input_size = 13; run(); expect_failed(ECONNRESET);
    reset(); mock.input[mock.input_size++] = 1; run(); expect_failed(EPROTO); assert(probe.result.stop_ack);
    reset(); mock.poll_timeout = 1; run(); expect_failed(ETIMEDOUT); assert(!mock.send_calls);
    reset(); mock.poll_invalid = 1; run(); expect_failed(EBADF); assert(!mock.send_calls);
    reset(); mock.poll_error = 1; run(); expect_failed(EIO); assert(!mock.send_calls);
    reset(); mock.write_hup = 1; run(); expect_failed(EPIPE); assert(!mock.send_calls);
    reset(); mock.recv_error = ECONNRESET; run(); expect_failed(ECONNRESET);
    reset(); mock.recv_error = ECONNRESET; mock.null_sce_errno = 1; run(); expect_failed(EIO);
    reset(); mock.send_interrupt = 1; mock.receive_interrupt = 1; mock.poll_interrupt = 1; run();
    assert(!probe.status && mock.close_calls == 1);
    reset(); mock.pace_error = EINTR; run(); expect_failed(EINTR);
}
/* A readiness wait may return after a concurrent Stop or exact deadline. No
 * new send/receive should begin without rechecking that absolute bound. */
static void test_poll_completion_boundary(int stop, int reading)
{
    reset(); if (stop) mock.cancel_poll = 1; else mock.timeout_poll = 1;
    mock.boundary_on_read = reading;
    run(); expect_failed(stop ? ECANCELED : ETIMEDOUT);
    if (reading) assert(mock.send_calls == 1 && mock.output_size == PW_NATIVE_CHILD_SELF_BYTES && mock.receive_calls == 0);
    else assert(mock.send_calls == 0 && mock.output_size == 0);
    assert(mock.close_calls == 1);
}
#if PW_NATIVE_CHILD_FD_MODE
static void test_fd_results_and_order(void)
{
    reset();
    probe.io.context = &probe; probe.io.clock_ms = clock_ms; probe.io.send = send_bytes; probe.io.receive = receive;
    probe.io.cancelled = cancelled;
    assert(!pw_native_child_begin(&probe.io)); atomic_store(&probe.stop, 1);
    PwNativeChildFrame early = {0};
    assert(parent_capabilities(&probe, &probe.io, &early) == -1 && errno == ECANCELED && !mock.fd_run_calls);
    reset(); run(); assert(!probe.status && probe.worker_report && probe.result.capabilities_complete);
    assert(mock.fd_open_calls == 1 && mock.fd_run_calls == 1 && mock.fd_dispose_calls == 1);
    assert(mock.mkdir_calls == 1 && mock.rmdir_calls == 1 && !mock.directory);
    reset(); mock.mkdir_error = EEXIST; run(); expect_failed(EEXIST);
    assert(!mock.fd_open_calls && !mock.socket_calls && !mock.rmdir_calls);
    reset(); mock.fd_open_error = 1; run(); expect_failed(EIO);
    assert(!mock.socket_calls && !mock.fd_run_calls && mock.rmdir_calls == 1);
    reset(); mock.rmdir_error = EACCES; run(); expect_failed(EIO);
    assert(probe.worker_report && !probe.result.stop_ack && mock.rmdir_calls == 1);
    reset(); mock.fd_failure = 1; run(); expect_failed(EIO);
    assert(probe.worker_report && !probe.result.stop_ack && !probe.result.capabilities_complete);
    reset(); PwNativeFdResult failed = role_result(1); failed.status = PW_NATIVE_FD_OS;
    failed.stage = PW_NATIVE_FD_CLEANUP; failed.cleanup_failed = 1; failed.observations &= ~PW_NATIVE_FD_COMPLETED;
    set_worker_report(failed); run(); expect_failed(EIO); assert(probe.worker_report && !probe.result.stop_ack);
    reset(); mock.input[4 * PW_NC_FRAME_BYTES + 32] ^= 1; run(); expect_failed(EPROTO);
    assert(!probe.worker_report && !probe.result.stop_ack);
    reset(); mock.input_size = 4 * PW_NC_FRAME_BYTES; run(); expect_failed(ECONNRESET);
    assert(!probe.worker_report && !probe.result.stop_ack);
    reset(); mock.input_size = 4 * PW_NC_FRAME_BYTES + PW_NATIVE_FD_REPORT_BYTES - 1;
    run(); expect_failed(ECONNRESET); assert(!probe.worker_report && !probe.result.stop_ack);
    reset(); memmove(mock.input + 4 * PW_NC_FRAME_BYTES + 2 * PW_NATIVE_FD_REPORT_BYTES,
                     mock.input + 4 * PW_NC_FRAME_BYTES + PW_NATIVE_FD_REPORT_BYTES, PW_NC_FRAME_BYTES);
    memcpy(mock.input + 4 * PW_NC_FRAME_BYTES + PW_NATIVE_FD_REPORT_BYTES,
           mock.input + 4 * PW_NC_FRAME_BYTES, PW_NATIVE_FD_REPORT_BYTES);
    mock.input_size += PW_NATIVE_FD_REPORT_BYTES; run(); expect_failed(EPROTO);
    assert(probe.worker_report && !probe.result.stop_ack);
    reset(); mock.fd_open_cancel = 1; run(); expect_failed(ECANCELED);
    assert(!mock.send_calls && mock.fd_dispose_calls == 1 && mock.rmdir_calls == 1);
    reset(); mock.fd_open_expiry = 1; run(); expect_failed(ETIMEDOUT);
    assert(!mock.send_calls && mock.fd_dispose_calls == 1 && mock.rmdir_calls == 1);
    reset(); mock.fd_clock_boundary = 1; run(); expect_failed(ETIMEDOUT);
    assert(mock.position == 4 * PW_NC_FRAME_BYTES && !probe.worker_report && !probe.result.stop_ack);
}
#endif
#if PW_NATIVE_CHILD_PEER_MODE
static void test_peer_results_and_order(void)
{
    reset(); run(); assert(!probe.status && mock.peer_cooperative);
    assert(mock.peer_exchange_calls == 1 && mock.peer_pre_stop_calls == 1 && mock.peer_observe_calls == 1);
    assert(!mock.directory && mock.rmdir_calls == 1 && probe.peer_result.exit_observed);
    assert(strstr(mock.log, "image_identity=unverified exclusive_peer_ownership=unverified"));
    reset(); mock.mkdir_error = EEXIST; run(); expect_failed(EEXIST);
    assert(!mock.peer_open_calls && !mock.socket_calls && !mock.rmdir_calls);
    reset(); mock.peer_open_error = 1; run(); expect_failed(EIO);
    assert(!mock.socket_calls && mock.rmdir_calls == 1);
    for (unsigned api = 20; api <= 27; ++api) {
        reset(); mock.peer_open_error = 1; mock.peer_open_api = api;
        run(); expect_failed(EIO);
        assert(probe.peer_result.status == PW_NP_OS && probe.peer_result.phase == PW_NP_SETUP);
        assert(probe.peer_result.api == api && probe.peer_result.raw_result == -1 && probe.peer_result.native_error == EINVAL);
        assert(!mock.socket_calls && !mock.connect_calls && !mock.send_calls && !mock.receive_calls);
        assert(!mock.peer_exchange_calls && !mock.peer_pre_stop_calls && !mock.peer_observe_calls);
        assert(mock.mkdir_calls == 1 && mock.rmdir_calls == 1 && !mock.directory);
        assert(!probe.result.stop_ack && !probe.result.stream_closed && !probe.peer_result.exit_observed);
    }
    reset(); mock.peer_open_cancel = 1; run(); expect_failed(ECANCELED); assert(!mock.send_calls);
    reset(); mock.peer_open_expiry = 1; run(); expect_failed(ETIMEDOUT); assert(!mock.send_calls);
    reset(); mock.peer_failure = 1; run(); expect_failed(EIO);
    assert(!probe.result.stop_ack && !mock.peer_cooperative && probe.peer_result.exit_observed);
    reset(); mock.rmdir_error = EACCES; run(); expect_failed(EIO);
    assert(!probe.result.stop_ack && !mock.peer_cooperative && probe.peer_result.cleanup_failed);
    reset(); mock.peer_pending_failure = 1; run(); expect_failed(EIO);
    assert(!probe.result.stop_ack && probe.peer_result.status == PW_NP_EXIT);
    reset(); mock.peer_exit_failure = 1; run(); expect_failed(EIO);
    assert(probe.result.stop_ack && probe.result.stream_closed && !probe.peer_result.exit_observed);
    reset(); mock.peer_cleanup_failure = 1; run(); expect_failed(EIO);
    reset(); mock.peer_close_late = 1; run(); expect_failed(ETIMEDOUT);
    /* A valid independent event cannot substitute for an absent STOP_ACK. */
    reset(); mock.input_size -= PW_NC_FRAME_BYTES; run(); expect_failed(ECONNRESET);
    assert(!probe.result.stop_ack && !mock.peer_cooperative && probe.peer_result.exit_observed);
}
#endif
int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--deadline-control")) test_poll_completion_boundary(0, 0);
    else if (argc == 2 && !strcmp(argv[1], "--stop-control")) test_poll_completion_boundary(1, 0);
    else if (argc == 2 && !strcmp(argv[1], "--read-deadline-control")) test_poll_completion_boundary(0, 1);
    else if (argc == 2 && !strcmp(argv[1], "--read-stop-control")) test_poll_completion_boundary(1, 1);
    else {
        assert(argc == 1 || (argc == 2 && !strcmp(argv[1], "--baseline")));
        test_success(); test_start_cancel_and_ownership(); test_setup_failures(); test_protocol_and_ui();
        if (argc == 1) for (int reading = 0; reading < 2; ++reading)
            for (int stop = 0; stop < 2; ++stop) test_poll_completion_boundary(stop, reading);
    }
#if PW_NATIVE_CHILD_FD_MODE
    if (argc == 1) test_fd_results_and_order();
#endif
#if PW_NATIVE_CHILD_PEER_MODE
    if (argc == 1) test_peer_results_and_order();
#endif
    puts("native controller mock-only tests passed; native execution/reaping unverified");
    return 0;
}
