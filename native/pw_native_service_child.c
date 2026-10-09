/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _POSIX_C_SOURCE 200809L
#include "pw_native_service_child.h"
#include "native-service-build.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdatomic.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Original declarations matching the pinned public service caller. This ABI
 * has no SDK structure header; exact sizes are checked, not inferred. */
int sceSystemServiceGetAppStatus(void *);
int sceSystemServiceGetLocalProcessStatusList(void *, unsigned, unsigned *);
int sceSystemServiceAddLocalProcess(int, const char *, const char *const *, const void *);
int sceSystemServiceKillLocalProcess(int, int);

extern const unsigned char pw_native_service_image[];
extern const size_t pw_native_service_image_size;
static const char *const helper_paths[] = {
    "/app0/native-service.self", "/mnt/sandbox/PPSA99995_000/app0/native-service.self"
};
static atomic_uint service_claim;

typedef struct { int32_t id; char name[32]; } ServiceEntry;
typedef struct { uint32_t size; int32_t fd, crash_report; uint32_t other[15]; } ServiceOptions;
_Static_assert(sizeof(ServiceEntry) == 36 && offsetof(ServiceEntry, name) == 4, "service list ABI");
_Static_assert(sizeof(ServiceOptions) == 72 && offsetof(ServiceOptions, fd) == 4 &&
               offsetof(ServiceOptions, crash_report) == 8 && offsetof(ServiceOptions, other) == 12,
               "service launch ABI");
enum { CANARY = 0x719ac053 };

typedef struct {
    const PwNativeServiceChildContext *context;
    PwNativeServiceChildResult *result;
    PwNativeChildIo io;
    int parent_fd, passed_fd;
    unsigned hello_ticks, closed_ticks;
    ServiceOptions options;
    const char *arguments[3];
} ServiceRun;

static int fail(ServiceRun *run, unsigned status, unsigned api, int64_t raw, int error)
{
    if (!run->result->status) {
        run->result->status = status; run->result->api = api;
        run->result->raw_result = raw; run->result->native_error = error;
    }
    return -1;
}

static int now(ServiceRun *run, uint64_t end, int cleanup)
{
    uint64_t value;
    if (!cleanup && run->context->cancelled && run->context->cancelled(run->context->context))
        return fail(run, PW_SC_CANCELLED, PW_SC_API_NONE, 0, 0);
    if (run->context->clock_ms(run->context->context, &value) || value < run->result->last_clock)
        return fail(run, PW_SC_CLOCK, PW_SC_API_NONE, 0, 0);
    run->result->last_clock = value;
    if (value >= end) return fail(run, PW_SC_TIMEOUT, PW_SC_API_NONE, 0, 0);
    return 0;
}

static void report(ServiceRun *run, unsigned phase)
{
    run->result->phase = phase;
    run->context->record(run->context->context, run->result);
}

static void close_owned(ServiceRun *run, int *slot, unsigned *observed)
{
    if (*slot < 0) return;
    int fd = *slot; *slot = -1;
    errno = 0; int rc = close(fd), error = errno;
    if (observed) *observed = rc == 0;
    if (rc) {
        run->result->cleanup_uncertain = 1;
        fail(run, PW_SC_OWNERSHIP, PW_SC_API_CLOSE, rc, rc < 0 ? error : 0);
    }
}

static int helper_preflight(ServiceRun *run)
{
    PwNativeServiceChildResult *r = run->result;
    if (!pw_native_service_image_size || pw_native_service_image_size > 4u * 1024u * 1024u ||
        pw_native_service_image_size != PW_NATIVE_SERVICE_SELF_BYTES)
        return fail(run, PW_SC_FILE, PW_SC_API_NONE, 0, 0);
    r->selected_path = -1;
    for (unsigned i = 0; i < 2; ++i) {
        PwNativeServicePathResult *p = &r->path[i]; struct stat info;
        if (now(run, r->protocol_end, 0)) return -1;
        errno = 0; int fd = open(helper_paths[i], O_RDONLY | O_NOFOLLOW | O_NONBLOCK), error = errno;
        if (fd < 0) { p->open_error = error; continue; }
        p->opened = 1;
        if (now(run, r->protocol_end, 0)) { close_owned(run, &fd, NULL); return -1; }
        errno = 0; int rc = fstat(fd, &info); error = errno;
        if (rc) fail(run, PW_SC_FILE, PW_SC_API_STAT, rc, error);
        else {
            p->regular = S_ISREG(info.st_mode); p->size = info.st_size;
            p->size_matches = info.st_size >= 0 && (uint64_t)info.st_size == pw_native_service_image_size;
            if (!p->regular || !p->size_matches) fail(run, PW_SC_FILE, PW_SC_API_STAT, 0, 0);
        }
        size_t at = 0;
        while (!r->status && at < pw_native_service_image_size) {
            unsigned char bytes[1024]; size_t wanted = pw_native_service_image_size - at;
            if (wanted > sizeof(bytes)) wanted = sizeof(bytes);
            if (now(run, r->protocol_end, 0)) break;
            errno = 0; ssize_t got = read(fd, bytes, wanted); error = errno;
            if (got <= 0 || (size_t)got > wanted) { fail(run, PW_SC_FILE, PW_SC_API_READ, got, got < 0 ? error : 0); break; }
            if (memcmp(bytes, pw_native_service_image + at, (size_t)got)) { fail(run, PW_SC_FILE, PW_SC_API_READ, got, 0); break; }
            at += (size_t)got;
            if (now(run, r->protocol_end, 0)) break;
        }
        if (!r->status && at == pw_native_service_image_size && !now(run, r->protocol_end, 0)) {
            unsigned char extra;
            errno = 0; ssize_t got = read(fd, &extra, 1); error = errno;
            if (got) fail(run, PW_SC_FILE, PW_SC_API_READ, got, got < 0 ? error : 0);
            else p->bytes_match = 1;
        }
        unsigned closed = 0; close_owned(run, &fd, &closed); p->close_result = closed ? 0 : -1;
        if (now(run, r->protocol_end, 0) || r->status) return -1;
        if (p->bytes_match && r->selected_path < 0) r->selected_path = (int)i;
    }
    return r->selected_path < 0 ? fail(run, PW_SC_FILE, PW_SC_API_OPEN, -1, 0) : 0;
}

static int app_id(ServiceRun *run)
{
    struct { uint32_t before, words[4], after; } data = {CANARY, {0}, CANARY};
    if (now(run, run->result->protocol_end, 0)) return -1;
    int rc = sceSystemServiceGetAppStatus(data.words);
    run->result->app_status_return = rc;
    memcpy(run->result->app_status_words, data.words, sizeof(data.words));
    run->result->app_status_canary_valid = data.before == CANARY && data.after == CANARY;
    if (rc) return fail(run, PW_SC_OS, PW_SC_API_APP, rc, 0);
    if (!run->result->app_status_canary_valid || !data.words[0] || data.words[0] > INT_MAX)
        return fail(run, PW_SC_ABI, PW_SC_API_APP, data.words[0], 0);
    run->result->app_id = (int)data.words[0];
    return now(run, run->result->protocol_end, 0);
}

/* 0 absent, 1 present, -1 unknown. A failed/truncated list never proves absence. */
static int list(ServiceRun *run, int baseline)
{
    PwNativeServiceChildResult *r = run->result;
    struct { uint32_t before; ServiceEntry entries[PW_SC_LIST_CAP]; uint32_t after; } data;
    memset(&data, 0, sizeof(data)); data.before = data.after = CANARY;
    unsigned count = UINT_MAX;
    if (r->list_calls >= PW_SC_LIST_CALL_CAP || now(run, baseline ? r->protocol_end : r->cleanup_end, !baseline))
        return -1;
    int rc = sceSystemServiceGetLocalProcessStatusList(data.entries, PW_SC_LIST_CAP, &count);
    r->list_calls++; r->last_list_return = rc; r->last_list_count = count;
    if (rc) return fail(run, PW_SC_OS, PW_SC_API_LIST, rc, 0);
    if (data.before != CANARY || data.after != CANARY || count >= PW_SC_LIST_CAP)
        return fail(run, PW_SC_ABI, PW_SC_API_LIST, count, 0);
    int present = 0;
    for (unsigned i = 0; i < count; ++i) {
        if (data.entries[i].id <= 0) return fail(run, PW_SC_ABI, PW_SC_API_LIST, data.entries[i].id, 0);
        for (unsigned j = 0; j < i; ++j)
            if (data.entries[i].id == data.entries[j].id) return fail(run, PW_SC_ABI, PW_SC_API_LIST, data.entries[i].id, 0);
        if (baseline) r->baseline_ids[i] = data.entries[i].id;
        else if (data.entries[i].id == r->service_id) present = 1;
    }
    if (now(run, baseline ? r->protocol_end : r->cleanup_end, !baseline)) return -1;
    if (baseline) { r->baseline_count = count; r->baseline_valid = 1; }
    else if (present) r->listed = 1;
    else { r->absent = 1; r->retired = 1; }
    return present;
}

static int io_clock(void *context, uint64_t *value)
{
    ServiceRun *run = context;
    if (run->context->clock_ms(run->context->context, value) || *value < run->result->last_clock) return -1;
    run->result->last_clock = *value;
    return 0;
}
static int io_cancel(void *context)
{ ServiceRun *run = context; return run->context->cancelled && run->context->cancelled(run->context->context); }
static long io_send(void *context, const void *bytes, size_t size, unsigned timeout)
{
    ServiceRun *run = context; (void)timeout;
    return pw_native_service_packet_send(&run->io, run->parent_fd, bytes, size, &run->result->packet);
}
static long io_receive(void *context, void *bytes, size_t size, unsigned timeout)
{
    ServiceRun *run = context; (void)timeout;
    return pw_native_service_packet_receive(&run->io, run->parent_fd, bytes, size, &run->result->packet);
}
static void io_progress(void *context, unsigned stage)
{
    ServiceRun *run = context;
    if (stage == PW_NC_EXCHANGING) run->hello_ticks = run->context->ui_ticks(run->context->context);
    if (stage == PW_NC_CLOSED) run->closed_ticks = run->context->ui_ticks(run->context->context);
}
static int pace(void *context, unsigned milliseconds)
{
    ServiceRun *run = context; struct timespec delay = {0, (long)milliseconds * 1000000};
    if (now(run, run->result->protocol_end, 0)) return -1;
    if (nanosleep(&delay, NULL)) return -1;
    return now(run, run->result->protocol_end, 0);
}

static void service_cleanup(ServiceRun *run)
{
    PwNativeServiceChildResult *r = run->result;
    close_owned(run, &run->passed_fd, &r->passed_closed);
    close_owned(run, &run->parent_fd, &r->parent_closed);
    if (!r->launch_possible) return;
    if (r->service_id <= 0) { r->cleanup_uncertain = 1; return; }
    report(run, PW_SC_OBSERVING);
    uint64_t grace = r->last_clock > UINT64_MAX - PW_SC_GRACE_MS ? r->cleanup_end : r->last_clock + PW_SC_GRACE_MS;
    if (grace > r->cleanup_end) grace = r->cleanup_end;
    for (;;) {
        if (run->context->cancelled && run->context->cancelled(run->context->context))
            fail(run, PW_SC_CANCELLED, PW_SC_API_NONE, 0, 0);
        int present = list(run, 0);
        if (present < 0) { r->cleanup_uncertain = 1; break; }
        if (!present) {
            if (!r->child.child_pid) r->cleanup_uncertain = 1;
            break; /* Retired IDs are never used again, even if reused later. */
        }
        if (!r->kill_attempted && (r->status || r->last_clock >= grace)) {
            if (now(run, r->cleanup_end, 1)) { r->cleanup_uncertain = 1; break; }
            report(run, PW_SC_KILL_POSSIBLE);
            if (now(run, r->cleanup_end, 1)) { r->cleanup_uncertain = 1; break; }
            r->kill_attempted = r->forced_cleanup = 1;
            int rc = sceSystemServiceKillLocalProcess(r->app_id, r->service_id); r->kill_return = rc;
            if (rc) { r->cleanup_uncertain = 1; fail(run, PW_SC_OWNERSHIP, PW_SC_API_KILL, rc, 0); break; }
            if (!r->status) fail(run, PW_SC_FORCED_CLEANUP, PW_SC_API_KILL, 0, 0);
        }
        if (now(run, r->cleanup_end, 1)) { r->cleanup_uncertain = 1; break; }
        struct timespec pause = {0, 100000000};
        if (nanosleep(&pause, NULL)) { r->cleanup_uncertain = 1; fail(run, PW_SC_OS, PW_SC_API_NONE, -1, errno); break; }
    }
}

int pw_native_service_child_run(const PwNativeServiceChildContext *context, PwNativeServiceChildResult *result)
{
    if (!result) return -1;
    memset(result, 0, sizeof(*result)); result->selected_path = -1;
    unsigned expected = 0;
    if (!atomic_compare_exchange_strong(&service_claim, &expected, 1)) { result->status = PW_SC_ALREADY_ATTEMPTED; return -1; }
    result->attempted = 1;
    if (!context || !context->clock_ms || !context->ui_ticks || !context->record) { result->status = PW_SC_INVALID; return -1; }
    ServiceRun run = {.context=context, .result=result, .parent_fd=-1, .passed_fd=-1};
    uint64_t started;
    if (context->clock_ms(context->context, &started) || started > UINT64_MAX - PW_SC_ATTEMPT_MS)
        return fail(&run, PW_SC_CLOCK, PW_SC_API_NONE, 0, 0);
    result->started = result->last_clock = started;
    result->protocol_end = started + PW_SC_PROTOCOL_MS; result->cleanup_end = started + PW_SC_ATTEMPT_MS;
    report(&run, PW_SC_PREFLIGHT);
    if (helper_preflight(&run) || app_id(&run)) goto done;
    report(&run, PW_SC_BASELINE);
    if (list(&run, 1) < 0 || now(&run, result->protocol_end, 0)) goto done;
    int pair[2] = {-1, -1}; errno = 0;
    int rc = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair), error = errno;
    if (rc) {
        if (rc > 0 || pair[0] != -1 || pair[1] != -1) result->cleanup_uncertain = 1;
        fail(&run, PW_SC_OS, PW_SC_API_PAIR, rc, rc < 0 ? error : 0); goto done;
    }
    run.parent_fd = pair[0]; run.passed_fd = pair[1];
    if (pair[0] < 0 || pair[1] < 0 || pair[0] == pair[1]) {
        if (pair[0] == pair[1]) run.passed_fd = -1;
        result->cleanup_uncertain = 1; fail(&run, PW_SC_ABI, PW_SC_API_PAIR, 0, 0); goto done;
    }
    run.io.context = &run; run.io.clock_ms = io_clock; run.io.cancelled = io_cancel;
    run.io.send = io_send; run.io.receive = io_receive; run.io.progress = io_progress; run.io.wait_ms = pace;
    run.io.ready = 1; run.io.total_end = result->protocol_end; run.io.stage_end = result->protocol_end;
    run.io.last_clock = result->last_clock;
    if (pw_native_service_packet_validate(&run.io, run.parent_fd, &result->packet)) {
        fail(&run, PW_SC_PROTOCOL, PW_SC_API_TYPE, result->packet.raw_result, 0); goto done;
    }
    run.options.size = sizeof(run.options); run.options.fd = run.passed_fd; run.options.crash_report = 1;
    run.options.other[0] = UINT32_MAX; run.options.other[3] = 2; run.options.other[4] = UINT32_C(0x80000000);
    run.arguments[0] = helper_paths[result->selected_path]; run.arguments[1] = "native-service-probe-v1";
    if (now(&run, result->protocol_end, 0)) goto done;
    result->launch_possible = 1; report(&run, PW_SC_LAUNCH_POSSIBLE);
    if (now(&run, result->protocol_end, 0)) { result->launch_possible = 0; goto done; }
    rc = sceSystemServiceAddLocalProcess(result->app_id, run.arguments[0], run.arguments, &run.options);
    result->launch_return = rc;
    if (rc <= 0) { result->cleanup_uncertain = 1; fail(&run, PW_SC_OWNERSHIP, PW_SC_API_ADD, rc, 0); goto done; }
    for (unsigned i = 0; i < result->baseline_count; ++i)
        if (result->baseline_ids[i] == rc) { result->cleanup_uncertain = 1; fail(&run, PW_SC_OWNERSHIP, PW_SC_API_ADD, rc, 0); goto done; }
    result->service_id = rc;
    close_owned(&run, &run.passed_fd, &result->passed_closed);
    if (result->status || now(&run, result->protocol_end, 0)) goto done;
    report(&run, PW_SC_EXCHANGING);
    uint64_t correlation = started ^ ((uint64_t)(uint32_t)getpid() << 32) ^ UINT64_C(0x50575343);
    if (!correlation) correlation = 1;
    if (pw_native_child_parent(&run.io, (uint32_t)getpid(), correlation, PW_NATIVE_SERVICE_BUILD_ID, &result->child))
        fail(&run, PW_SC_PROTOCOL, PW_SC_API_PACKET, result->packet.raw_result, 0);
    else {
        result->ui_ticks = run.closed_ticks - run.hello_ticks;
        result->protocol_complete = 1;
        if (result->ui_ticks < 2) fail(&run, PW_SC_PROTOCOL, PW_SC_API_PACKET, 0, 0);
    }
done:
    if (result->packet.cleanup_failed || result->packet.ownership_uncertain) result->cleanup_uncertain = 1;
    service_cleanup(&run);
    if (now(&run, result->cleanup_end, 1) && result->launch_possible) result->cleanup_uncertain = 1;
    if (result->cleanup_uncertain) fail(&run, PW_SC_OWNERSHIP, PW_SC_API_NONE, 0, 0);
    report(&run, PW_SC_DONE);
    if (now(&run, result->cleanup_end, 0) && result->launch_possible && !result->retired)
        result->cleanup_uncertain = 1;
    return result->status ? -1 : 0;
}
