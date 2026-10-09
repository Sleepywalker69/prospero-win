/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Pure controller tests: all threads, clocks, backends, and logging are mocked. */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../native/pw_native_socket_diagnostic.h"
#include "../native/pw_native_service_child.h"
#include "../native/pw_native_suite.h"

static unsigned checks;
static unsigned largest_log;
#define CHECK(x) do { ++checks; if (!(x)) { \
    fprintf(stderr, "CHECK failed at %d: %s\n", __LINE__, #x); exit(1); \
} } while (0)

static struct {
    int attr_init_rc, attr_detach_rc, create_rc, attr_destroy_rc;
    unsigned init_calls, detach_calls, create_calls, destroy_calls;
    void *(*pending)(void *);
    void *pending_arg;
    unsigned inject_cancel_selected, injected, reentrant;
    unsigned socket_calls, service_calls, legacy_calls, legacy_cancel_calls;
    unsigned legacy_finished_calls, legacy_finish_after, tick_calls, sleep_calls;
    int backend_rc, legacy_start_rc;
    unsigned uncertain, backend_cancel_seen;
    int cancel_in_backend, cancel_in_sleep, service_progress;
    int clock_rc, expected_clock_rc;
    struct timespec clock_value;
    uint64_t expected_ms;
    unsigned check_clock, expected_ticks;
    PwNativeSocketDiagnosticResult socket_result;
    PwNativeServiceChildResult service_result;
    char logs[512][1024];
    unsigned lines, max_line;
} model;

static int mock_attr_init(pthread_attr_t *a) { (void)a; ++model.init_calls; return model.attr_init_rc; }
static int mock_attr_setdetachstate(pthread_attr_t *a, int state)
{ (void)a; CHECK(state == PTHREAD_CREATE_DETACHED); ++model.detach_calls; return model.attr_detach_rc; }
static int mock_attr_destroy(pthread_attr_t *a)
{ (void)a; ++model.destroy_calls; return model.attr_destroy_rc; }
static int mock_create(pthread_t *t, const pthread_attr_t *a, void *(*entry)(void *), void *arg)
{
    (void)t; (void)a; ++model.create_calls;
    if (model.reentrant) {
        for (unsigned i = 0; i < PW_SUITE_COUNT; ++i) {
            CHECK(!pw_native_suite_available(i)); CHECK(pw_native_suite_start(i) == -1);
        }
    }
    if (!model.create_rc) { CHECK(!model.pending); model.pending = entry; model.pending_arg = arg; }
    return model.create_rc;
}
static int mock_clock_gettime(clockid_t id, struct timespec *out)
{ CHECK(id == CLOCK_MONOTONIC); *out = model.clock_value; return model.clock_rc; }
static int mock_nanosleep(const struct timespec *req, struct timespec *rem)
{
    CHECK(req->tv_sec == 0 && req->tv_nsec == 100000000 && !rem);
    ++model.sleep_calls; CHECK(model.sleep_calls < 10);
    if (model.cancel_in_sleep) pw_native_suite_cancel();
    return 0;
}
static void store_hook(volatile atomic_uint *object);
static void mock_store(volatile atomic_uint *object, unsigned value, memory_order order)
{ atomic_store_explicit(object, value, order); store_hook(object); }

#define pthread_attr_init mock_attr_init
#define pthread_attr_setdetachstate mock_attr_setdetachstate
#define pthread_attr_destroy mock_attr_destroy
#define pthread_create mock_create
#define clock_gettime mock_clock_gettime
#define nanosleep mock_nanosleep
#undef atomic_store_explicit
#define atomic_store_explicit(object,value,order) mock_store(object,value,order)
#include "../native/pw_native_suite.c"
#undef pthread_attr_init
#undef pthread_attr_setdetachstate
#undef pthread_attr_destroy
#undef pthread_create
#undef clock_gettime
#undef nanosleep

static void store_hook(volatile atomic_uint *object)
{
    if (object == &suite.selected && model.inject_cancel_selected && !model.injected) {
        model.injected = 1;
        CHECK(!pw_native_suite_available(PW_SUITE_SOCKET));
        pw_native_suite_cancel();
    }
}
void pw_diagnostics_log_local(const char *format, ...)
{
    CHECK(model.lines < 512);
    va_list args; va_start(args, format);
    int length = vsnprintf(model.logs[model.lines], 1024, format, args);
    va_end(args);
    CHECK(length >= 0 && length < 1024);
    if ((unsigned)length > model.max_line) model.max_line = (unsigned)length;
    if ((unsigned)length > largest_log) largest_log = (unsigned)length;
    ++model.lines;
}
static void check_context(void *opaque, int (*clock_ms)(void *, uint64_t *), int (*cancelled)(void *))
{
    CHECK(!opaque && clock_ms && cancelled);
    if (model.cancel_in_backend) pw_native_suite_cancel();
    model.backend_cancel_seen = (unsigned)cancelled(opaque);
    if (model.check_clock) {
        uint64_t output = UINT64_C(0x123456789abcdef);
        int rc = clock_ms(opaque, &output);
        CHECK(rc == model.expected_clock_rc);
        CHECK(output == (rc ? UINT64_C(0x123456789abcdef) : model.expected_ms));
    }
}
int pw_native_socket_diagnostic_run(const PwNativeSocketDiagnosticContext *c, PwNativeSocketDiagnosticResult *r)
{
    ++model.socket_calls; check_context(c->context, c->clock_ms, c->cancelled);
    *r = model.socket_result; r->cleanup_uncertain = model.uncertain;
    return model.backend_rc;
}
int pw_native_service_child_run(const PwNativeServiceChildContext *c, PwNativeServiceChildResult *r)
{
    ++model.service_calls; check_context(c->context, c->clock_ms, c->cancelled);
    CHECK(c->ui_ticks && c->record); CHECK(c->ui_ticks(c->context) == model.expected_ticks);
    *r = model.service_result; r->cleanup_uncertain = model.uncertain;
    if (model.service_progress) {
        unsigned final_status = r->status; r->phase = PW_SC_DONE; r->status = PW_SC_OK;
        c->record(c->context, r); r->status = final_status;
    }
    return model.backend_rc;
}
int pw_native_child_probe_start(void) { ++model.legacy_calls; return model.legacy_start_rc; }
void pw_native_child_probe_cancel(void) { ++model.legacy_cancel_calls; }
void pw_native_child_probe_tick(void) { ++model.tick_calls; }
int pw_native_child_probe_finished(int *status, unsigned *uncertain)
{
    ++model.legacy_finished_calls;
    if (model.legacy_finished_calls < model.legacy_finish_after) return 0;
    *status = model.backend_rc; *uncertain = model.uncertain; return 1;
}
static void reset(void)
{
    /* Each case models a fresh title, with no real thread or owned descriptor. */
    memset(&suite, 0, sizeof(suite)); memset(&model, 0, sizeof(model));
    model.legacy_finish_after = 1;
}
static void finish(void)
{
    CHECK(model.pending != NULL);
    void *(*entry)(void *) = model.pending; void *arg = model.pending_arg;
    model.pending = NULL; CHECK(entry(arg) == NULL);
}
static const char *find_log(const char *prefix)
{
    for (unsigned i = 0; i < model.lines; ++i)
        if (!strncmp(model.logs[i], prefix, strlen(prefix))) return model.logs[i];
    return NULL;
}
static void cancellation_publication(void)
{
    reset(); model.inject_cancel_selected = 1;
    CHECK(pw_native_suite_start(PW_SUITE_SOCKET) == 0); CHECK(model.injected == 1);
    finish();
    printf("cancel_after_running observed=%u backend_calls=%u\n", model.backend_cancel_seen, model.socket_calls);
    CHECK(model.backend_cancel_seen == 1);
}
static void selections(void)
{
    reset(); model.reentrant = 1;
    CHECK(!strcmp(pw_native_suite_title(), "NATIVE DIAGNOSTIC SUITE"));
    CHECK(!strcmp(pw_native_suite_item(0), "SOCKET API MATRIX"));
    CHECK(!strcmp(pw_native_suite_item(1), "SERVICE CHILD (HEADLESS)"));
    CHECK(!strcmp(pw_native_suite_item(2), "LEGACY PEER / EXIT"));
    CHECK(!strcmp(pw_native_suite_item(UINT_MAX), "UNAVAILABLE"));
    CHECK(!pw_native_suite_available(PW_SUITE_COUNT));
    CHECK(!pw_native_suite_available(UINT_MAX));
    CHECK(pw_native_suite_start(UINT_MAX) == -1);
    CHECK(!model.init_calls);
    for (unsigned i = 0; i < PW_SUITE_COUNT; ++i) {
        CHECK(pw_native_suite_available(i));
        CHECK(pw_native_suite_start(i) == 0);
        for (unsigned j = 0; j < PW_SUITE_COUNT; ++j) {
            CHECK(!pw_native_suite_available(j)); CHECK(pw_native_suite_start(j) == -1);
        }
        finish();
        for (unsigned j = 0; j < PW_SUITE_COUNT; ++j)
            CHECK(pw_native_suite_available(j) == (j > i));
        CHECK(pw_native_suite_start(i) == -1);
    }
    CHECK(model.init_calls == 3 && model.detach_calls == 3 && model.create_calls == 3 && model.destroy_calls == 3);
    CHECK(model.socket_calls == 1 && model.service_calls == 1 && model.legacy_calls == 1);
}
static void thread_errors(void)
{
    const int errors[] = {1, 11, -1, INT_MAX};
    for (unsigned role = 0; role < PW_SUITE_COUNT; ++role)
        for (unsigned stage = 0; stage < 3; ++stage)
            for (unsigned n = 0; n < sizeof(errors)/sizeof(errors[0]); ++n) {
                reset();
                if (!stage) model.attr_init_rc = errors[n];
                else if (stage == 1) model.attr_detach_rc = errors[n];
                else model.create_rc = errors[n];
                CHECK(pw_native_suite_start(role) == -1); CHECK(!model.pending);
                CHECK(model.init_calls == 1);
                CHECK(model.detach_calls == (stage > 0));
                CHECK(model.create_calls == (stage > 1));
                CHECK(model.destroy_calls == (stage > 0));
                CHECK(!model.socket_calls && !model.service_calls && !model.legacy_calls);
                CHECK(!pw_native_suite_available(role)); CHECK(pw_native_suite_start(role) == -1);
                CHECK(pw_native_suite_available((role + 1) % PW_SUITE_COUNT));
                const char *line = find_log("PW_NATIVE_SUITE "); CHECK(line && strstr(line, "thread_error="));
                char status[128]; pw_native_suite_status(status, sizeof(status)); CHECK(strstr(status, "INCOMPLETE"));
            }
    /* attr_destroy failure cannot undo an already created detached owner. */
    reset(); model.attr_destroy_rc = 22;
    CHECK(pw_native_suite_start(PW_SUITE_SOCKET) == 0); CHECK(model.destroy_calls == 1);
    CHECK(!pw_native_suite_available(PW_SUITE_SERVICE)); finish(); CHECK(model.socket_calls == 1);
}
static void cancel_and_cleanup(void)
{
    for (unsigned role = 0; role < PW_SUITE_COUNT; ++role) {
        reset(); pw_native_suite_cancel();
        CHECK(pw_native_suite_start(role) == 0);
        pw_native_suite_cancel(); pw_native_suite_cancel();
        model.legacy_finish_after = 3; finish();
        if (role == PW_SUITE_LEGACY) {
            CHECK(!model.legacy_calls && !model.legacy_cancel_calls && !model.legacy_finished_calls && !model.sleep_calls);
        } else CHECK(model.backend_cancel_seen == 1);
        pw_native_suite_cancel();
        unsigned next = role == PW_SUITE_SOCKET ? PW_SUITE_SERVICE : PW_SUITE_SOCKET;
        CHECK(pw_native_suite_start(next) == 0); finish(); CHECK(model.backend_cancel_seen == 0);
    }
    reset(); model.cancel_in_sleep = 1; model.legacy_finish_after = 3;
    CHECK(pw_native_suite_start(PW_SUITE_LEGACY) == 0); finish();
    CHECK(model.legacy_cancel_calls == 2 && model.legacy_calls == 1);
    reset(); model.legacy_start_rc = -12;
    CHECK(pw_native_suite_start(PW_SUITE_LEGACY) == 0); finish();
    CHECK(model.legacy_calls == 1 && !model.legacy_finished_calls && !model.sleep_calls);
    for (unsigned role = 0; role < PW_SUITE_COUNT; ++role) {
        reset(); model.uncertain = 1; model.backend_rc = -9;
        CHECK(pw_native_suite_start(role) == 0); finish();
        for (unsigned j = 0; j < PW_SUITE_COUNT; ++j) {
            CHECK(!pw_native_suite_available(j)); CHECK(pw_native_suite_start(j) == -1);
        }
        char status[128]; pw_native_suite_status(status, sizeof(status)); CHECK(strstr(status, "STOP TESTING"));
        CHECK(strstr(find_log("PW_NATIVE_SUITE "), "locked=1"));
        reset(); model.backend_rc = -9;
        CHECK(pw_native_suite_start(role) == 0); finish();
        CHECK(pw_native_suite_available((role + 1) % PW_SUITE_COUNT));
    }
}
static void legacy_cancel_before_entry(void)
{
    reset(); CHECK(pw_native_suite_start(PW_SUITE_LEGACY) == 0);
    pw_native_suite_cancel(); finish();
    printf("legacy cancelled before queued entry: starts=%u polls=%u\n", model.legacy_calls, model.legacy_finished_calls);
    CHECK(!model.legacy_calls && !model.legacy_finished_calls && !model.sleep_calls);
    CHECK(strstr(find_log("PW_NATIVE_SUITE "), "returned=-1"));
}
static void clock_and_ticks(void)
{
    struct { int rc; time_t sec; long ns; int expected; uint64_t milliseconds; } cases[] = {
        {0, 0, 0, 0, 0}, {0, 12, 345678901, 0, 12345},
        {-1, 12, 0, -1, 0}, {1, 12, 0, -1, 0}, {0, -1, 0, -1, 0},
        {0, 0, -1, -1, 0}, {0, 0, 1000000000, -1, 0},
        {0, (time_t)((UINT64_MAX - 999)/1000 + 1), 0, -1, 0},
        {0, (time_t)((UINT64_MAX - 999)/1000), 999999999, 0, ((UINT64_MAX - 999)/1000)*1000 + 999}
    };
    for (unsigned role = 0; role < PW_SUITE_LEGACY; ++role)
        for (unsigned i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i) {
            reset(); model.check_clock = 1; model.clock_rc = cases[i].rc;
            model.clock_value.tv_sec = cases[i].sec; model.clock_value.tv_nsec = cases[i].ns;
            model.expected_clock_rc = cases[i].expected; model.expected_ms = cases[i].milliseconds;
            pw_native_suite_tick(); pw_native_suite_tick(); model.expected_ticks = 2;
            CHECK(pw_native_suite_start(role) == 0); finish(); CHECK(model.tick_calls == 2);
            pw_native_suite_tick(); CHECK(model.tick_calls == 3);
        }
}
static void status_bounds(void)
{
    for (unsigned mode = 0; mode < 5; ++mode) {
        reset();
        if (mode) {
            model.backend_rc = mode == 3 ? -1 : 0; model.uncertain = mode == 4;
            CHECK(pw_native_suite_start(PW_SUITE_SOCKET) == 0);
            if (mode != 1) finish();
        }
        const char *expected[] = {"SELECT TEST", "TEST ACTIVE", "OBSERVATIONS RECORDED", "TEST INCOMPLETE", "CLEANUP UNKNOWN"};
        for (size_t cap = 0; cap < 96; ++cap) {
            unsigned char bytes[98]; memset(bytes, 0xa5, sizeof(bytes));
            pw_native_suite_status((char *)bytes + 1, cap);
            CHECK(bytes[0] == 0xa5 && bytes[cap + 1] == 0xa5);
            if (cap) CHECK(memchr(bytes + 1, 0, cap));
            if (cap > strlen(expected[mode])) CHECK(!strncmp((char *)bytes + 1, expected[mode], strlen(expected[mode])));
        }
        if (mode == 1) finish();
    }
}
static void final_verdict(void)
{
    reset(); model.service_progress = 1; model.service_result.status = PW_SC_TIMEOUT; model.backend_rc = -1;
    CHECK(pw_native_suite_start(PW_SUITE_SERVICE) == 0); finish();
    const char *progress = find_log("PW_SERVICE_PROGRESS ");
    const char *final = find_log("PW_SERVICE_FINAL ");
    CHECK(progress && strstr(progress, "status=0"));
    CHECK(final && strstr(final, "returned=-1 status=3"));
    CHECK(strstr(find_log("PW_NATIVE_SUITE "), "returned=-1"));
    CHECK(strstr(find_log("PW_SERVICE_PROTOCOL "), "native_reap=unverified"));
    CHECK(strstr(find_log("PW_SERVICE_PROTOCOL "), "windows_child=unsupported"));
    char status[128]; pw_native_suite_status(status, sizeof(status)); CHECK(strstr(status, "INCOMPLETE"));
}
static void full_width_formatting(void)
{
    for (unsigned pass = 0; pass < 2; ++pass) {
        reset(); model.backend_rc = INT_MIN; model.uncertain = UINT_MAX;
        memset(&model.socket_result, 0xff, sizeof(model.socket_result));
        model.socket_result.rows = pass ? UINT_MAX : PW_SD_MAX_ROWS;
        for (unsigned i = 0; i < PW_SD_MAX_ROWS; ++i) {
            PwNativeSocketDiagnosticRow *r = &model.socket_result.row[i];
            r->descriptor = r->companion = r->input_value = r->native_error = INT_MIN;
            r->raw_return = INT64_MIN; r->output_value = INT32_MIN;
        }
        CHECK(pw_native_suite_start(PW_SUITE_SOCKET) == 0); finish();
        CHECK(model.lines == PW_SD_MAX_ROWS + 2);
        CHECK(strstr(model.logs[0], "collection_only=1 traffic_tested=0"));
        for (unsigned i = 0; i < PW_SD_MAX_ROWS; ++i) {
            CHECK(strstr(model.logs[i + 1], "rc=-9223372036854775808"));
            CHECK(strstr(model.logs[i + 1], "in=ffffffff out=ffffffff"));
            CHECK(strstr(model.logs[i + 1], "value=-2147483648 hex=ffffffff"));
        }
        printf("matrix format: rows=%u logged=%u longest=%u\n", model.socket_result.rows, model.lines, model.max_line);
    }
    reset(); model.backend_rc = INT_MIN; model.uncertain = UINT_MAX;
    PwNativeServiceChildResult *r = &model.service_result; memset(r, 0xff, sizeof(*r));
    r->raw_result = INT64_MIN; r->native_error = r->selected_path = r->app_id = r->service_id = INT_MIN;
    r->launch_return = r->app_status_return = r->last_list_return = r->kill_return = INT_MIN;
    for (unsigned i = 0; i < 2; ++i) {
        r->path[i].opened = r->path[i].open_error = r->path[i].regular = INT_MIN;
        r->path[i].size_matches = r->path[i].bytes_match = r->path[i].close_result = INT_MIN;
        r->path[i].size = INT64_MIN;
    }
    r->packet.status = r->packet.api = r->packet.native_error = r->packet.cleanup_native_error = INT_MIN;
    r->packet.raw_result = r->packet.received_bytes = INT64_MIN; r->packet.socket_type = INT_MIN;
    r->child.stop_ack = INT_MIN;
    CHECK(pw_native_suite_start(PW_SUITE_SERVICE) == 0); finish();
    CHECK(model.lines == 7);
    CHECK(strstr(find_log("PW_SERVICE_PACKET "), "control=18446744073709551615"));
    CHECK(strstr(find_log("PW_SERVICE_APP "), "words=ffffffff,ffffffff,ffffffff,ffffffff"));
    CHECK(strstr(find_log("PW_SERVICE_FINAL "), "returned=-2147483648"));
    printf("service format: logged=%u longest=%u\n", model.lines, model.max_line);
}
int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "legacy-cancel-red")) { legacy_cancel_before_entry(); return 0; }
    cancellation_publication();
    if (argc > 1 && !strcmp(argv[1], "cancel-red")) return 0;
    legacy_cancel_before_entry();
    selections(); thread_errors(); cancel_and_cleanup(); clock_and_ticks(); status_bounds();
    final_verdict(); full_width_formatting();
    CHECK(find_log("PW_NATIVE_SUITE ") != NULL);
    printf("native suite: %u checks passed; largest formatted payload=%u bytes\n", checks, largest_log);
    return 0;
}
