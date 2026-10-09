/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _POSIX_C_SOURCE 200809L
#include "pw_native_child_probe.h"
#include "pw_native_child_protocol.h"
#include "native-child-build.h"
#ifndef PW_NATIVE_CHILD_PEER_MODE
#define PW_NATIVE_CHILD_PEER_MODE 0
#endif
#if PW_NATIVE_CHILD_FD_MODE && PW_NATIVE_CHILD_PEER_MODE
#error Native capability modes are mutually exclusive
#endif
#if PW_NATIVE_CHILD_FD_MODE
#include "pw_native_fd_report.h"
#elif PW_NATIVE_CHILD_PEER_MODE
#include "pw_native_peer_probe.h"
#endif
#if PW_NATIVE_CHILD_FD_MODE || PW_NATIVE_CHILD_PEER_MODE
#include <sys/stat.h>
#endif
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
#if PW_NATIVE_CHILD_FD_MODE
    PwNativeFdListener listener;
    PwNativeFdResult fd_local, fd_worker;
    char directory[PW_NATIVE_FD_PATH_CAP];
    int directory_owned, directory_cleanup, worker_report;
#endif
#if PW_NATIVE_CHILD_PEER_MODE
    PwNativePeerProbe peer;
    PwNativePeerResult peer_result;
    char peer_directory[PW_NP_PATH_CAP];
    int peer_directory_owned, peer_directory_cleanup;
#endif
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

#if PW_NATIVE_CHILD_FD_MODE
static int fd_clock(void *context, uint64_t *value)
{
    struct native_probe *p = context;
    unsigned remaining;
    if (pw_native_child_remaining(&p->io, &remaining)) return -1;
    *value = p->io.last_clock;
    return 0;
}
static void fd_directory_cleanup(struct native_probe *p)
{
    if (!p->directory_owned) return;
    p->directory_owned = 0; /* no retry after an uncertain cleanup result */
    p->directory_cleanup = rmdir(p->directory);
}
static int parent_capabilities(void *context, PwNativeChildIo *io, const PwNativeChildFrame *frame)
{
    struct native_probe *p = context;
    PwNativeFdContext fd_context = {p, fd_clock, cancelled, 0};
    uint8_t wire[PW_NATIVE_FD_REPORT_BYTES];
    unsigned remaining;
    if (pw_native_child_remaining(io, &remaining)) return -1;
    if (remaining <= PW_NATIVE_FD_REPORT_RESERVE_MS) { errno = ETIMEDOUT; return -1; }
    fd_context.deadline_ms = io->last_clock + remaining - PW_NATIVE_FD_REPORT_RESERVE_MS;
    (void)pw_native_fd_parent(&p->listener, frame->correlation, &fd_context, &p->fd_local);
    fd_directory_cleanup(p);
    /* The worker's control poll expects no inbound bytes until this report
     * has been consumed. STOP is sent only after both independent results. */
    if (pw_native_child_receive(io, wire, sizeof(wire))) return -1;
    if (pw_native_fd_report_decode(&p->fd_worker, wire, frame->parent_pid, frame->child_pid, frame->correlation)) {
        errno = EPROTO; return -1;
    }
    p->worker_report = 1;
    if (!pw_native_fd_result_matches(&p->fd_local, frame->parent_pid, frame->child_pid, 0) ||
        !pw_native_fd_result_matches(&p->fd_worker, frame->child_pid, frame->parent_pid, 1) ||
        p->directory_cleanup) { errno = EIO; return -1; }
    return 0;
}
static int fd_prepare(struct native_probe *p, uint32_t parent, uint64_t correlation)
{
    char path[PW_NATIVE_FD_PATH_CAP];
    PwNativeFdContext context = {p, fd_clock, cancelled, p->io.stage_end};
    if (pw_native_fd_paths(parent, correlation, p->directory, path)) { errno = EINVAL; return -1; }
    /* Ordinary creation only. Existing names and access failures stop the run;
     * no stale path removal, permission changes or alternate namespace. */
    if (mkdir(p->directory, 0700)) return -1;
    p->directory_owned = 1;
    if (pw_native_fd_parent_open(&p->listener, path, &context, &p->fd_local)) {
        errno = EIO; return -1;
    }
    return 0;
}
#endif

#if PW_NATIVE_CHILD_PEER_MODE
static void peer_directory_cleanup(struct native_probe *p)
{
    if (!p->peer_directory_owned) return;
    p->peer_directory_owned = 0;
    p->peer_directory_cleanup = rmdir(p->peer_directory);
    if (p->peer_directory_cleanup) {
        p->peer_result.cleanup_failed = 1;
        if (!p->peer_result.status) {
            p->peer_result.status = PW_NP_OS; p->peer_result.api = PW_NP_API_UNLINK;
            p->peer_result.raw_result = p->peer_directory_cleanup;
            p->peer_result.native_error = errno;
        }
    }
}
static int parent_peer_capabilities(void *context, PwNativeChildIo *io, const PwNativeChildFrame *frame)
{
    struct native_probe *p = context;
    int result = pw_native_peer_parent_exchange(&p->peer, io, frame, &p->peer_result);
    peer_directory_cleanup(p);
    if (!result) result = pw_native_peer_pre_stop(&p->peer, io, &p->peer_result);
    if (result || p->peer_directory_cleanup) { errno = EIO; return -1; }
    return 0;
}
static int peer_prepare(struct native_probe *p, uint32_t parent, uint64_t correlation)
{
    char path[PW_NP_PATH_CAP];
    unsigned remaining;
    if (pw_native_child_remaining(&p->io, &remaining) ||
        pw_native_peer_paths(parent, correlation, p->peer_directory, path)) return -1;
    if (mkdir(p->peer_directory, 0700)) return -1;
    p->peer_directory_owned = 1;
    if (pw_native_peer_parent_open(&p->peer, path, &p->io, &p->peer_result)) {
        errno = EIO; return -1;
    }
    return 0;
}
#endif

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
#if PW_NATIVE_CHILD_FD_MODE
    p->listener.fd = -1;
    p->io.capabilities = parent_capabilities;
#endif
#if PW_NATIVE_CHILD_PEER_MODE
    p->peer.listener = p->peer.stream = p->peer.queue = -1;
    p->io.capabilities = parent_peer_capabilities;
#endif
    p->io.context = p; p->io.clock_ms = clock_ms;
    p->io.receive = receive; p->io.send = send_bytes;
    p->io.cancelled = cancelled; p->io.wait_ms = pace; p->io.progress = progress;
    if (pw_native_child_begin(&p->io) || clock_ms(p, &started)) goto done;
    if (pw_native_child_image_size != PW_NATIVE_CHILD_SELF_BYTES ||
        pw_native_child_image_size < 32 || pw_native_child_image_size > 4u * 1024u * 1024u) {
        errno = EINVAL; goto done;
    }
    uint64_t correlation = started ^ ((uint64_t)(uint32_t)getpid() << 32) ^ UINT64_C(0x50574e43);
    if (!correlation) correlation = 1; /* correlation only, never authentication */
#if PW_NATIVE_CHILD_FD_MODE
    if (fd_prepare(p, (uint32_t)getpid(), correlation)) goto done;
#elif PW_NATIVE_CHILD_PEER_MODE
    if (peer_prepare(p, (uint32_t)getpid(), correlation)) goto done;
#endif
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
    status = pw_native_child_parent(&p->io, (uint32_t)getpid(), correlation, PW_NATIVE_CHILD_BUILD_ID, &p->result);
    if (!status && p->closed_ticks - p->hello_ticks < 2) { status = -1; errno = EDEADLK; }
done:
    error = status ? (errno ? errno : EIO) : 0;
    if (p->socket >= 0 && ps5log_ps5_close(p->socket)) {
        status = -1; if (!error) error = errno ? errno : EIO;
    }
#if PW_NATIVE_CHILD_PEER_MODE
    /* Close the control endpoint even after a failed sequence. Any later
     * kernel event remains a separate observation and cannot erase failure. */
    if (p->peer.armed && pw_native_peer_observe(&p->peer, &p->io,
            !status && p->result.stop_ack && p->result.stream_closed, &p->peer_result)) {
        status = -1; if (!error) error = EIO;
    }
    pw_native_peer_parent_cleanup(&p->peer, &p->peer_result);
    peer_directory_cleanup(p);
    if (p->peer_result.cleanup_failed || p->peer_directory_cleanup) {
        status = -1; if (!error) error = EIO;
    }
    if (!status && pw_native_child_remaining(&p->io, &remaining)) { status = -1; error = errno; }
    pw_diagnostics_log("PW_NATIVE_PEER status=%d phase=%u api=%u raw=%lld native_error=%d initial_kernel_pid=%u uid=%u euid=%u gid=%u groups=%u reciprocal=%u receipt=%u receipt_flags=%u receipt_fflags=%u receipt_data=%lld initial_empty=%u entropy_return=%lld entropy_bytes=%u entropy_ok=%u post_arm_kernel_pid=%u nonce_match=%u",
        p->peer_result.status, p->peer_result.phase, p->peer_result.api, (long long)p->peer_result.raw_result,
        p->peer_result.native_error, p->peer_result.initial_credential.pid, p->peer_result.initial_credential.uid,
        p->peer_result.initial_credential.euid, p->peer_result.initial_credential.gid, p->peer_result.initial_credential.groups,
        p->peer_result.reciprocal_ok, p->peer_result.receipt_ok, p->peer_result.receipt_flags,
        p->peer_result.receipt_fflags, (long long)p->peer_result.receipt_data, p->peer_result.initial_empty,
        (long long)p->peer_result.entropy_return, p->peer_result.entropy_bytes, p->peer_result.entropy_ok,
        p->peer_result.post_arm_credential.pid, p->peer_result.nonce_match);
    pw_diagnostics_log("PW_NATIVE_PEER worker_report=%u worker_status=%d worker_phase=%u worker_observed=%u worker_raw=%lld prestop_empty=%u exit_observed=%u exit_flags=%u exit_fflags=%u exit_data=%lld exit_status_match=%u event_pid=%llu event_filter=%d event_tag_match=%d cleanup=%u directory_cleanup=%d",
        p->peer_result.worker_report_valid, p->peer_result.worker_report.status,
        p->peer_result.worker_report.phase, p->peer_result.worker_report.observations,
        (long long)p->peer_result.worker_report.raw_result, p->peer_result.prestop_empty,
        p->peer_result.exit_observed, p->peer_result.exit_flags, p->peer_result.exit_fflags,
        (long long)p->peer_result.exit_data, p->peer_result.exit_status_match,
        (unsigned long long)p->peer_result.event_ident, p->peer_result.event_filter,
        p->peer_result.event_tag_matches, p->peer_result.cleanup_failed, p->peer_directory_cleanup);
    pw_diagnostics_log("PW_NATIVE_PEER image_identity=unverified exclusive_peer_ownership=unverified native_reap=unverified resource_reclamation=unverified wine_endpoint=untested windows_child=unsupported");
#endif
#if PW_NATIVE_CHILD_FD_MODE
    pw_native_fd_dispose(&p->listener, &p->fd_local);
    fd_directory_cleanup(p);
    if (p->fd_local.cleanup_failed || p->directory_cleanup) {
        status = -1; if (!error) error = EIO;
    }
    pw_diagnostics_log("PW_NATIVE_FD directory=%s local_status=%d local_stage=%u local_api=%u local_raw=%lld local_observed=%u local_peer_reported=%u local_cleanup=%u worker_report=%d worker_status=%d worker_stage=%u worker_api=%u worker_raw=%lld worker_observed=%u worker_cleanup=%u directory_cleanup=%d peer_identity_verified=0 wine_endpoint=untested",
        p->directory, p->fd_local.status, p->fd_local.stage, p->fd_local.api, (long long)p->fd_local.raw_result,
        p->fd_local.observations, p->fd_local.peer_observations, p->fd_local.cleanup_failed,
        p->worker_report, p->fd_worker.status, p->fd_worker.stage, p->fd_worker.api,
        (long long)p->fd_worker.raw_result, p->fd_worker.observations,
        p->fd_worker.cleanup_failed, p->directory_cleanup);
#endif
    p->socket = -1; p->status = status; p->error = error;
    pw_diagnostics_log("PW_NATIVE_CHILD stage=complete status=%d error=%d protocol_stage=%u capability_complete=%d parent=%u child=%u child_ppid=%u echoes=%u stop_ack=%d eof=%d ui_ticks=%u native_reap=unverified windows_child=unsupported",
                       status, error, p->result.stage, p->result.capabilities_complete, (unsigned)getpid(), p->result.child_pid,
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
const char *pw_native_child_probe_title(void)
{
    return PW_NATIVE_CHILD_PEER_MODE ? "NATIVE PEER AND EXIT PROBE" :
           PW_NATIVE_CHILD_FD_MODE ? "NATIVE FD CAPABILITY PROBE" : "NATIVE CHILD PROBE";
}
void pw_native_child_probe_status(char *text, size_t capacity)
{
    switch (atomic_load_explicit(&probe.state, memory_order_acquire)) {
    case PROBE_IDLE: snprintf(text, capacity, "CROSS/ENTER: RUN ONCE. SQUARE/ESC: CANCEL."); break;
    case PROBE_RUNNING: snprintf(text, capacity, "NATIVE PROBE RUNNING. SQUARE/ESC: CANCEL."); break;
    default: snprintf(text, capacity, "%s. GET MATCHING SAVED LOG.",
                      probe.status ? "NATIVE PROBE FAILED" :
                      PW_NATIVE_CHILD_FD_MODE ? "NATIVE FD AND EOF OBSERVED" : "NATIVE ECHO AND EOF OBSERVED"); break;
    }
}
