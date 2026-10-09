/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _POSIX_C_SOURCE 200809L
#include "pw_native_child_probe.h"
#include "pw_native_child_protocol.h"
#include "native-child-build.h"
#include "pw_diagnostics.h"
#include "ps5log/ps5log_ps5_net.h"
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Generated from the verified final SELF by the isolated worker builder. The
 * title uploads only these immutable bytes; no path/URL/guest input is used. */
extern const unsigned char pw_native_child_image[];
extern const size_t pw_native_child_image_size;
extern int sceNetRecv(int, void *, size_t, int);
extern int *sceNetErrnoLoc(void);

struct native_probe {
    atomic_uint state, stop, ticks;
    int socket, status, error;
    unsigned hello_ticks, closed_ticks;
    PwNativeChildIo io;
    PwNativeChildResult result;
};
static struct native_probe probe;
enum { PROBE_IDLE, PROBE_RUNNING, PROBE_DONE };

static int clock_ms(void *unused, uint64_t *value)
{
    struct timespec now;
    (void)unused;
    if (clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec < 0 ||
        now.tv_nsec < 0 || now.tv_nsec >= 1000000000 ||
        (uint64_t)now.tv_sec > (UINT64_MAX - 999) / 1000) return -1;
    *value = (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
    return 0;
}
static int cancelled(void *context)
{
    struct native_probe *p = context;
    return atomic_load_explicit(&p->stop, memory_order_relaxed) != 0;
}
static void progress(void *context, unsigned stage)
{
    struct native_probe *p = context;
    unsigned ticks = atomic_load_explicit(&p->ticks, memory_order_relaxed);
    if (stage == PW_NC_EXCHANGING) p->hello_ticks = ticks;
    if (stage == PW_NC_CLOSED) p->closed_ticks = ticks;
}
static int pace(void *context, unsigned milliseconds)
{
    struct native_probe *p = context;
    struct timespec delay = {0, (long)milliseconds * 1000000};
    if (cancelled(p)) { errno = ECANCELED; return -1; }
    return nanosleep(&delay, NULL);
}
static int network_result(int value)
{
    if (value < 0) {
        int *error = sceNetErrnoLoc();
        errno = error && *error ? *error : EIO;
        return -1;
    }
    return value;
}
static long transfer(void *context, void *bytes, size_t size, unsigned timeout_ms, int writing)
{
    struct native_probe *p = context;
    (void)timeout_ms; /* Recompute against the unchanged absolute stage end. */
    for (;;) {
        unsigned remaining;
        struct pollfd item = {p->socket, writing ? POLLOUT : POLLIN, 0};
        if (pw_native_child_remaining(&p->io, &remaining)) return -1;
        int count = ps5log_ps5_poll(&item, 1, (int)(remaining < 100 ? remaining : 100));
        if (count < 0) return -1;
        if (!count) continue;
        if (pw_native_child_remaining(&p->io, &remaining)) return -1;
        if (item.revents & POLLNVAL) { errno = EBADF; return -1; }
        if (item.revents & POLLERR) { errno = EIO; return -1; }
        if (writing && item.revents & (POLLERR | POLLHUP)) { errno = EPIPE; return -1; }
        if (!(item.revents & (writing ? POLLOUT : POLLIN | POLLHUP))) { errno = EIO; return -1; }
        return writing ? ps5log_ps5_send(p->socket, bytes, size, 0) :
                         network_result(sceNetRecv(p->socket, bytes, size, 0));
    }
}
static long receive(void *context, void *bytes, size_t size, unsigned timeout_ms)
{
    return transfer(context, bytes, size, timeout_ms, 0);
}
static long send_bytes(void *context, const void *bytes, size_t size, unsigned timeout_ms)
{
    return transfer(context, (void *)bytes, size, timeout_ms, 1);
}

static void *controller(void *context)
{
    struct native_probe *p = context;
    struct {
        uint8_t length, family;
        uint16_t port;
        uint32_t address;
        uint16_t virtual_port;
        uint8_t zero[6];
    } address = {0};
    uint64_t started;
    unsigned remaining;
    int status = -1, error = EIO;
    p->socket = -1;
    p->io.context = p; p->io.clock_ms = clock_ms;
    p->io.receive = receive; p->io.send = send_bytes;
    p->io.cancelled = cancelled; p->io.wait_ms = pace; p->io.progress = progress;
    if (pw_native_child_begin(&p->io) || clock_ms(p, &started)) goto done;
    if (pw_native_child_image_size != PW_NATIVE_CHILD_SELF_BYTES ||
        pw_native_child_image_size < 32 || pw_native_child_image_size > 4u * 1024u * 1024u) {
        errno = EINVAL; goto done;
    }
    p->socket = ps5log_ps5_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (p->socket < 0 || pw_native_child_remaining(&p->io, &remaining)) goto done;
    uint32_t microseconds = remaining * 1000;
    const int options[] = {0x1105, 0x1106, 0x1109}; /* existing Lapy SceNet timeout contract */
    for (unsigned i = 0; i < sizeof(options) / sizeof(options[0]); ++i)
        if (ps5log_ps5_setsockopt(p->socket, 0xffff, options[i], &microseconds, sizeof(microseconds))) goto done;
    address.length = sizeof(address); address.family = AF_INET;
    address.port = htons(9021); address.address = UINT32_C(0x0100007f);
    pw_diagnostics_log("PW_NATIVE_CHILD stage=connect parent=%u build=%s self_sha256=%s bytes=%u context=loader_native_self",
                       (unsigned)getpid(), PW_NATIVE_CHILD_BUILD_ID, PW_NATIVE_CHILD_SELF_SHA256,
                       (unsigned)pw_native_child_image_size);
    if (ps5log_ps5_connect(p->socket, (const struct sockaddr *)&address, sizeof(address)) ||
        pw_native_child_remaining(&p->io, &remaining) ||
        ps5log_ps5_fcntl(p->socket, F_SETFL, O_NONBLOCK) ||
        pw_native_child_remaining(&p->io, &remaining) || pw_native_child_stage(&p->io)) goto done;
    /* One upload, no retry/half-close; SELF header extent delimits the image. */
    if (pw_native_child_send(&p->io, pw_native_child_image, pw_native_child_image_size)) goto done;
    uint64_t correlation = started ^ ((uint64_t)(uint32_t)getpid() << 32) ^ UINT64_C(0x50574e43);
    if (!correlation) correlation = 1; /* correlation only, never authentication */
    status = pw_native_child_parent(&p->io, (uint32_t)getpid(), correlation, PW_NATIVE_CHILD_BUILD_ID, &p->result);
    if (!status && p->closed_ticks - p->hello_ticks < 2) { status = -1; errno = EDEADLK; }
done:
    error = status ? (errno ? errno : EIO) : 0;
    if (p->socket >= 0 && ps5log_ps5_close(p->socket)) {
        status = -1; error = errno ? errno : EIO;
    }
    p->socket = -1; p->status = status; p->error = error;
    pw_diagnostics_log("PW_NATIVE_CHILD stage=complete status=%d error=%d protocol_stage=%u parent=%u child=%u child_ppid=%u echoes=%u stop_ack=%d eof=%d ui_ticks=%u native_reap=unverified windows_child=unsupported",
                       status, error, p->result.stage, (unsigned)getpid(), p->result.child_pid,
                       p->result.child_ppid, p->result.echoes, p->result.stop_ack, p->result.stream_closed,
                       p->result.stream_closed ? p->closed_ticks - p->hello_ticks : 0);
    atomic_store_explicit(&p->state, PROBE_DONE, memory_order_release);
    return NULL;
}

int pw_native_child_probe_start(void)
{
    pthread_attr_t attributes;
    pthread_t thread;
    unsigned expected = PROBE_IDLE;
    if (!atomic_compare_exchange_strong(&probe.state, &expected, PROBE_RUNNING)) return -1;
    int result = pthread_attr_init(&attributes);
    if (!result) {
        result = pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
        if (!result) result = pthread_create(&thread, &attributes, controller, &probe);
        (void)pthread_attr_destroy(&attributes);
    }
    if (result) {
        probe.status = -1; probe.error = result;
        atomic_store_explicit(&probe.state, PROBE_DONE, memory_order_release);
    }
    return result ? -1 : 0;
}
void pw_native_child_probe_cancel(void)
{
    if (atomic_load_explicit(&probe.state, memory_order_acquire) == PROBE_RUNNING)
        atomic_store_explicit(&probe.stop, 1, memory_order_relaxed);
}
void pw_native_child_probe_tick(void)
{
    atomic_fetch_add_explicit(&probe.ticks, 1, memory_order_relaxed);
}
void pw_native_child_probe_status(char *text, size_t capacity)
{
    switch (atomic_load_explicit(&probe.state, memory_order_acquire)) {
    case PROBE_IDLE: snprintf(text, capacity, "CROSS/ENTER: RUN ONCE. SQUARE/ESC: CANCEL."); break;
    case PROBE_RUNNING: snprintf(text, capacity, "NATIVE PROBE RUNNING. SQUARE/ESC: CANCEL."); break;
    default: snprintf(text, capacity, "%s. GET MATCHING SAVED LOG.",
                      probe.status ? "NATIVE PROBE FAILED" : "NATIVE ECHO AND EOF OBSERVED"); break;
    }
}
