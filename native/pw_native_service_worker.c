/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Original finite fd3 service worker. No payload CRT, argv or constructors. */
#include "pw_native_service_packet.h"
#include <time.h>
#include <unistd.h>
#ifndef PW_NATIVE_CHILD_BUILD_ID
#error PW_NATIVE_CHILD_BUILD_ID must bind this source and build recipe
#endif
#ifndef PW_NATIVE_CHILD_FREESTANDING
#error Build the native service worker and protocol without libc errno
#endif
static const char *const worker_build
    __attribute__((used, section(".data.rel.ro"))) = PW_NATIVE_CHILD_BUILD_ID;

void *memcpy(void *to, const void *from, size_t size)
{
    unsigned char *out = to; const unsigned char *in = from;
    for (size_t i = 0; i < size; ++i) out[i] = in[i];
    return to;
}
void *memset(void *to, int value, size_t size)
{
    unsigned char *out = to;
    for (size_t i = 0; i < size; ++i) out[i] = (unsigned char)value;
    return to;
}
int memcmp(const void *left, const void *right, size_t size)
{
    const unsigned char *a = left, *b = right;
    for (size_t i = 0; i < size; ++i) if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    return 0;
}
typedef struct WorkerContext {
    PwNativeChildIo *io;
    PwNativeServicePacketResult packet;
} WorkerContext;
static int worker_clock(void *unused, uint64_t *milliseconds)
{
    struct timespec value;
    (void)unused;
    if (clock_gettime(CLOCK_MONOTONIC, &value) || value.tv_sec < 0 ||
        value.tv_nsec < 0 || value.tv_nsec >= 1000000000 ||
        (uint64_t)value.tv_sec > (UINT64_MAX - 999) / 1000) return -1;
    *milliseconds = (uint64_t)value.tv_sec * 1000 + (uint64_t)value.tv_nsec / 1000000;
    return 0;
}
static long worker_send(void *context, const void *bytes, size_t size, unsigned timeout)
{
    WorkerContext *worker = context;
    (void)timeout; /* adapter recomputes this same absolute engine budget */
    return pw_native_service_packet_send(worker->io, 3, bytes, size, &worker->packet);
}
static long worker_receive(void *context, void *bytes, size_t size, unsigned timeout)
{
    WorkerContext *worker = context;
    (void)timeout;
    return pw_native_service_packet_receive(worker->io, 3, bytes, size, &worker->packet);
}
static int worker_main(void)
{
    PwNativeChildIo io = {0};
    WorkerContext worker = {&io, {0}};
    io.context = &worker; io.clock_ms = worker_clock;
    io.send = worker_send; io.receive = worker_receive;
    if (pw_native_child_begin(&io)) return 2;
    if (pw_native_service_packet_validate(&io, 3, &worker.packet)) return 3;
    if (pw_native_child_worker(&io, (uint32_t)getpid(), (uint32_t)getppid(), worker_build)) return 4;
    return 0; /* Only STOP_ACK intent; parent observes service lifetime separately. */
}
__attribute__((noreturn, visibility("default")))
void _start(void *process_parameters, void (*loader_teardown)(void))
{
    (void)process_parameters; (void)loader_teardown;
    _exit(worker_main());
}
