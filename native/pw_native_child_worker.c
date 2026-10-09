/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Original finite native SELF worker. No payload CRT or runtime constructors. */
/* Use the SDK's native BSD interface, including its SO_NOSIGPIPE contract. */
#include "pw_native_child_protocol.h"
#ifndef PW_NATIVE_CHILD_FD_MODE
#define PW_NATIVE_CHILD_FD_MODE 0
#endif
#if PW_NATIVE_CHILD_FD_MODE
#include "pw_native_fd_report.h"
#endif
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifndef PW_NATIVE_CHILD_BUILD_ID
#error PW_NATIVE_CHILD_BUILD_ID must identify this worker source and build recipe
#endif

/* The converter requires a real RELRO section. This pointer also binds the
 * protocol identity to the original worker, without a circular file hash. */
static const char *const worker_build
    __attribute__((used, section(".data.rel.ro"))) = PW_NATIVE_CHILD_BUILD_ID;

/* Freestanding byte operations used by the shared protocol and C lowering.
 * The worker is single-threaded and owns every destination. */
void *memcpy(void *to, const void *from, size_t length)
{
    unsigned char *dst = to;
    const unsigned char *src = from;
    for (size_t i = 0; i < length; ++i) dst[i] = src[i];
    return to;
}
void *memset(void *to, int value, size_t length)
{
    unsigned char *dst = to;
    for (size_t i = 0; i < length; ++i) dst[i] = (unsigned char)value;
    return to;
}
int memcmp(const void *left, const void *right, size_t length)
{
    const unsigned char *a = left, *b = right;
    for (size_t i = 0; i < length; ++i)
        if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    return 0;
}

static int worker_clock(void *context, uint64_t *milliseconds)
{
    struct timespec value;
    (void)context;
    if (clock_gettime(CLOCK_MONOTONIC, &value) || value.tv_sec < 0 ||
        value.tv_nsec < 0 || value.tv_nsec >= 1000000000 ||
        (uint64_t)value.tv_sec > (UINT64_MAX - 999) / 1000) {
        return -1;
    }
    *milliseconds = (uint64_t)value.tv_sec * 1000 + (uint64_t)value.tv_nsec / 1000000;
    return 0;
}

static long worker_transfer(void *bytes, size_t size, unsigned timeout_ms, int writing)
{
    struct pollfd item = {writing ? STDOUT_FILENO : STDIN_FILENO,
                          writing ? POLLOUT : POLLIN, 0};
    int result = poll(&item, 1, (int)timeout_ms);
    /* This no-CRT adapter deliberately does not read native errno. A negative
     * result, including EINTR or an O_NONBLOCK readiness race, fails the run. */
    if (result != 1 || item.revents & (POLLNVAL | POLLERR)) return -1;
    if (writing && item.revents & (POLLERR | POLLHUP)) return -1;
    if (!(item.revents & (writing ? POLLOUT : POLLIN | POLLHUP))) return -1;
    return writing ? write(STDOUT_FILENO, bytes, size) : read(STDIN_FILENO, bytes, size);
}
static long worker_receive(void *context, void *bytes, size_t size, unsigned timeout_ms)
{
    (void)context;
    return worker_transfer(bytes, size, timeout_ms, 0);
}
static long worker_send(void *context, const void *bytes, size_t size, unsigned timeout_ms)
{
    (void)context;
    return worker_transfer((void *)bytes, size, timeout_ms, 1);
}

#if PW_NATIVE_CHILD_FD_MODE
static int fd_clock(void *context, uint64_t *value)
{
    PwNativeChildIo *io = context;
    unsigned remaining;
    /* Keep one clock history across control and descriptor phases. */
    if (pw_native_child_remaining(io, &remaining)) return -1;
    *value = io->last_clock;
    return 0;
}
static int fd_control_lost(void *unused)
{
    struct pollfd item = {STDIN_FILENO, POLLIN, 0};
    (void)unused;
    /* Parent reads our report before it sends STOP. No control bytes are
     * valid during this phase. EOF/Stop closes the control channel. */
    int result = poll(&item, 1, 0);
    return result != 0 || item.revents != 0;
}
static int worker_capabilities(void *unused, PwNativeChildIo *io, const PwNativeChildFrame *frame)
{
    char directory[PW_NATIVE_FD_PATH_CAP], path[PW_NATIVE_FD_PATH_CAP];
    uint8_t wire[PW_NATIVE_FD_REPORT_BYTES];
    PwNativeFdResult result = {0};
    PwNativeFdContext context = {io, fd_clock, fd_control_lost, 0};
    unsigned remaining;
    (void)unused;
    if (pw_native_child_remaining(io, &remaining) || remaining <= PW_NATIVE_FD_REPORT_RESERVE_MS ||
        pw_native_fd_paths(frame->parent_pid, frame->correlation, directory, path)) return -1;
    context.deadline_ms = io->last_clock + remaining - PW_NATIVE_FD_REPORT_RESERVE_MS;
    (void)pw_native_fd_worker(path, frame->correlation, &context, &result);
    /* All descriptor ownership is settled before reporting. A failure report
     * is still useful; its receipt cannot make the parent report success. */
    if (pw_native_fd_report_encode(wire, frame->parent_pid, frame->child_pid, frame->correlation, &result) ||
        pw_native_child_send(io, wire, sizeof(wire))) return -1;
    return pw_native_fd_result_matches(&result, frame->child_pid, frame->parent_pid, 1) ? 0 : -1;
}
#endif

static int worker_main(void)
{
    PwNativeChildIo io = {0};
    int flags, one = 1;
    io.clock_ms = worker_clock;
    io.receive = worker_receive;
    io.send = worker_send;
#if PW_NATIVE_CHILD_FD_MODE
    io.capabilities = worker_capabilities;
#endif
    if (pw_native_child_begin(&io)) return 2;
    flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    if (flags < 0 || fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK) ||
        setsockopt(STDOUT_FILENO, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one))) return 3;
    /* selfldr duplicates the accepted TCP endpoint to descriptors 0, 1 and 2;
     * the shared open-file description now has O_NONBLOCK for both I/O paths. */
    return pw_native_child_worker(&io, (uint32_t)getpid(), (uint32_t)getppid(), worker_build) ? 4 : 0;
}

/* Native executable entry ABI matches the pinned foundation's documented
 * app entry. This original worker needs no argv, constructors, libc state,
 * loader teardown or payload patch initialization. _exit closes its FDs. */
__attribute__((noreturn, visibility("default")))
void _start(void *process_parameters, void (*loader_teardown)(void))
{
    (void)process_parameters;
    (void)loader_teardown;
    _exit(worker_main());
}
