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
    unsigned char input[6 * PW_NC_FRAME_BYTES], output[PW_NATIVE_CHILD_SELF_BYTES + 5 * PW_NC_FRAME_BYTES];
    void *(*entry)(void *); void *context;
    char log[4096];
} mock;

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
    puts("native controller mock-only tests passed; native execution/reaping unverified");
    return 0;
}
