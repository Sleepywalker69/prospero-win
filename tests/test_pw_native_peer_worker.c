/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Original worker routing/exit controls. Every OS and protocol boundary is
 * replaced; no native entry, socket, thread or process is executed. */
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
#include "../native/pw_native_peer_probe.h"
static int fake_clock(clockid_t, struct timespec *);
static int fake_poll(struct pollfd *, nfds_t, int);
static int fake_fcntl(int, int, ...);
static int fake_setsockopt(int, int, int, const void *, socklen_t);
static ssize_t fake_read(int, void *, size_t);
static ssize_t fake_write(int, const void *, size_t);
static pid_t fake_pid(void);
static void fake_exit(int) __attribute__((noreturn));
#define PW_NATIVE_CHILD_PEER_MODE 1
#define PW_NATIVE_CHILD_BUILD_ID "peer-worker-adapter-fixture"
#ifndef SO_NOSIGPIPE
#define SO_NOSIGPIPE 0x0800 /* consumed only by a mock */
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
static struct { int begin_error, fcntl_error, socket_error, protocol_error, capability_error;
                unsigned fcntl_calls, socket_calls, protocol_calls, capability_calls; } mock;
static int fake_clock(clockid_t id, struct timespec *v)
{ assert(id == CLOCK_MONOTONIC); v->tv_sec = 1; v->tv_nsec = 0; return 0; }
static int fake_poll(struct pollfd *p, nfds_t n, int t) { (void)p; (void)n; (void)t; abort(); }
static int fake_fcntl(int fd, int command, ...)
{
    assert(fd == STDIN_FILENO); ++mock.fcntl_calls;
    assert(command == F_GETFL || command == F_SETFL);
    return mock.fcntl_error ? -1 : 0;
}
static int fake_setsockopt(int fd, int level, int option, const void *value, socklen_t size)
{
    assert(fd == STDOUT_FILENO && level == SOL_SOCKET && option == SO_NOSIGPIPE);
    assert(size == sizeof(int) && *(const int *)value == 1); ++mock.socket_calls;
    return mock.socket_error ? -1 : 0;
}
static ssize_t fake_read(int f, void *p, size_t n) { (void)f; (void)p; (void)n; abort(); }
static ssize_t fake_write(int f, const void *p, size_t n) { (void)f; (void)p; (void)n; abort(); }
static pid_t fake_pid(void) { return 42; }
static void fake_exit(int status) { (void)status; abort(); }
int pw_native_child_begin(PwNativeChildIo *io)
{
    assert(io->clock_ms == worker_clock && io->receive == worker_receive && io->send == worker_send);
    assert(io->capabilities == worker_peer_capabilities);
    return mock.begin_error ? -1 : 0;
}
int pw_native_peer_worker_exchange(PwNativeChildIo *io, const PwNativeChildFrame *frame, PwNativePeerResult *result)
{
    assert(io && frame && result); ++mock.capability_calls;
    return mock.capability_error ? -1 : 0;
}
int pw_native_child_worker(PwNativeChildIo *io, uint32_t pid, uint32_t ppid, const char *build)
{
    assert(pid == 42 && ppid == 42 && !strcmp(build, PW_NATIVE_CHILD_BUILD_ID));
    assert(mock.fcntl_calls == 2 && mock.socket_calls == 1); ++mock.protocol_calls;
    PwNativeChildFrame frame = {0};
    if (io->capabilities(io->context, io, &frame)) return -1;
    return mock.protocol_error ? -1 : 0;
}
int main(void)
{
    memset(&mock, 0, sizeof(mock)); assert(worker_main() == PW_NP_SUCCESS_EXIT);
    assert(mock.protocol_calls == 1 && mock.capability_calls == 1);
    memset(&mock, 0, sizeof(mock)); mock.begin_error = 1; assert(worker_main() == 2);
    assert(!mock.fcntl_calls && !mock.protocol_calls);
    memset(&mock, 0, sizeof(mock)); mock.fcntl_error = 1; assert(worker_main() == 3);
    assert(!mock.socket_calls && !mock.protocol_calls);
    memset(&mock, 0, sizeof(mock)); mock.socket_error = 1; assert(worker_main() == 3);
    assert(!mock.protocol_calls);
    memset(&mock, 0, sizeof(mock)); mock.capability_error = 1; assert(worker_main() == 4);
    memset(&mock, 0, sizeof(mock)); mock.protocol_error = 1; assert(worker_main() == 4);
    puts("peer worker routing and exact exit controls passed; all native boundaries mocked");
    return 0;
}
