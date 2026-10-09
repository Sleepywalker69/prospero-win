/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _POSIX_C_SOURCE 200809L
#include "pw_wine_child_title.h"
#include "pw_wine_fixture_owner.h"
#include "pw_diagnostics.h"
#include "native-wine-child-build.h"
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

const char pw_wine_child_title_marker[] = "pw-wine-child-fixture/1";
extern const unsigned char pw_wine_child_image[];
extern const size_t pw_wine_child_image_size;
_Static_assert(PW_WINE_CHILD_PRIVATE_DISPATCH_ABI == 1, "private dispatcher ABI");
_Static_assert(PW_WINE_CHILD_WOW64_ABI == 1, "translated dispatcher ABI");

enum { TITLE_UNUSED, TITLE_PREPARING, TITLE_INACTIVE_FAILURE, TITLE_ACTIVE };
typedef struct Title {
    atomic_uint state, cancelled, install_claim, installed, socket_state;
    PwWineFixtureSocketResult socket_failure;
    PwWineFixtureOwner *owner;
    PwWineFixtureProvider provider;
    pthread_t supervisor;
    unsigned profile;
    uint64_t session;
    char child_hash[65];
} Title;
/* No resets, rebinds, frees or dlclose. Wine/server callbacks may outlive guest
 * termination and its open Windows process handles. */
static Title title;

static int equal_field(const char *field, size_t capacity, const char *expected)
{
    const char *end = memchr(field, 0, capacity);
    size_t n = strlen(expected);
    return end && (size_t)(end - field) == n && !memcmp(field, expected, n);
}
#define EQUAL(o, field, value) equal_field((o)->field, sizeof((o)->field), (value))
unsigned pw_wine_child_title_profile(const PwGameProfile *p)
{
    if (!p || !EQUAL(p, app.runtime, "wine-wow64") || !EQUAL(p, app.arguments, "") ||
        !EQUAL(p, app.dll_overrides, "") || p->app.startup_command_id ||
        p->app.graphics != PW_APP_GRAPHICS_AUTO || p->runtime.thread_scheduling ||
        p->runtime.shared_input || p->runtime.fast_clock || p->debug_env_count)
        return 0;
    if (EQUAL(p, app.id, "windows-child-fixture-v1") &&
        EQUAL(p, app.prefix, "windows-child-fixture-v1") &&
        EQUAL(p, app.executable, "C:\\windows-child-fixture\\parent.exe") &&
        EQUAL(p, app.working_directory, "C:\\windows-child-fixture") &&
        p->app.architecture == PW_APP_ARCH_PE64 && p->runtime.cpu == PW_GAME_CPU_DEFAULT)
        return 1;
    if (EQUAL(p, app.id, "battlenet-experimental-v1") &&
        EQUAL(p, app.prefix, "battlenet-experimental-v1") &&
        EQUAL(p, app.executable, "C:\\installer\\Battle.net-Setup.exe") &&
        EQUAL(p, app.working_directory, "C:\\installer") &&
        p->app.architecture == PW_APP_ARCH_PE32 && p->runtime.cpu == PW_GAME_CPU_TRANSLATOR)
        return 2;
    return 0;
}
#undef EQUAL

static int clock_ms(void *context, uint64_t *out)
{
    (void)context;
    struct timespec t;
    if (!out || clock_gettime(CLOCK_MONOTONIC, &t) || t.tv_sec < 0 ||
        t.tv_nsec < 0 || t.tv_nsec >= 1000000000L ||
        (uint64_t)t.tv_sec > (UINT64_MAX - 999u) / 1000u) return -1;
    *out = (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
    return 0;
}
static int cancelled(void *context)
{ return atomic_load_explicit(&((Title *)context)->cancelled, memory_order_acquire) != 0; }
static void record(void *context, const char *event, uint64_t generation,
                   int64_t first, int64_t second, int64_t third)
{
    const Title *t = context;
    pw_diagnostics_log_local("PW_WINE_CHILD_OWNER profile=%u session=%llu event=%s generation=%llu first=%lld second=%lld third=%lld",
        t->profile, (unsigned long long)t->session, event, (unsigned long long)generation,
        (long long)first, (long long)second, (long long)third);
}
static void socket_sink(void *context, const PwWineFixtureSocketResult *r)
{
    Title *t = context;
    if (!r) return;
    unsigned empty = 0;
    if (atomic_compare_exchange_strong_explicit(&t->socket_state, &empty, 1,
                                               memory_order_acquire, memory_order_relaxed)) {
        t->socket_failure = *r;
        atomic_store_explicit(&t->socket_state, 2, memory_order_release);
    }
    pw_wine_fixture_owner_socket_failure(t->owner, r);
}
static void report_socket(Title *t, unsigned *reported)
{
    if (*reported || atomic_load_explicit(&t->socket_state, memory_order_acquire) != 2) return;
    const PwWineFixtureSocketResult *r = &t->socket_failure;
    pw_diagnostics_log_local("PW_WINE_CHILD_SOCKET status=%d api=%d raw=%d native_error=%d errno_valid=%d returned_length=%u returned_value=%d",
        r->status, r->api, r->raw_result, r->native_error, r->errno_valid,
        r->returned_length, r->returned_value);
    *reported = 1;
}
static void *supervisor(void *context)
{
    Title *t = context;
    unsigned failure_reported = 0, sleep_reported = 0, socket_reported = 0;
    for (;;) {
        int rc = pw_wine_fixture_owner_pump(t->owner);
        if (rc && !failure_reported) {
            record(t, "supervisor_failure", 0, rc, 0, 0);
            failure_reported = 1;
        }
        report_socket(t, &socket_reported);
        if (pw_wine_fixture_owner_release_ready(t->owner)) return NULL;
        struct timespec delay = { 0, 10000000L };
        if (nanosleep(&delay, NULL)) {
            int error = errno;
            if (error != EINTR) {
                atomic_store_explicit(&t->cancelled, 1, memory_order_release);
                pw_wine_fixture_owner_cancel(t->owner);
                if (!sleep_reported) {
                    record(t, "supervisor_sleep_failure", 0, -1, error, 0);
                    sleep_reported = 1;
                }
            }
        }
    }
}
static int hexadecimal(const char *s, size_t n)
{
    if (!s || strnlen(s, n + 1) != n) return 0;
    for (size_t i = 0; i < n; ++i)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return 0;
    return 1;
}
/* d itself must already have passed pw_prx_find_descriptor's segment checks. */
static const void *unique_export(const PwPrxDescriptor *d, const char *name)
{
    const void *address = NULL;
    for (uint32_t i = 0; i < d->count; ++i) {
        if (!strcmp(d->exports[i].name, name)) {
            if (address || !d->exports[i].address) return NULL;
            address = d->exports[i].address;
        }
    }
    return address;
}
int pw_wine_child_title_prepare(unsigned profile, const char *fixture_hash)
{
    unsigned empty = TITLE_UNUSED;
    if (!atomic_compare_exchange_strong(&title.state, &empty, TITLE_PREPARING)) return -1;
    int status = -1;
    if ((profile != 1 && profile != 2) || (profile == 1 && !hexadecimal(fixture_hash, 64)) ||
        (profile == 2 && fixture_hash) || !hexadecimal(PW_WINE_CHILD_BUILD_ID, 40) ||
        !hexadecimal(PW_WINE_CHILD_SELF_SHA256, 64) ||
        pw_wine_child_image_size != PW_WINE_CHILD_SELF_BYTES ||
        !pw_wine_child_image_size || pw_wine_child_image_size > 16u * 1024u * 1024u) goto failure;
    uint64_t now;
    pid_t pid = getpid();
    if (pid <= 0 || (uint64_t)pid > INT_MAX || clock_ms(NULL, &now)) goto failure;
    title.profile = profile;
    /* Correlation only, not authentication or entropy. One title owner means
     * these generations are never recycled within this native process. */
    title.session = (uint64_t)(unsigned)pid << 32 | (uint32_t)now;
    if (profile == 1) memcpy(title.child_hash, fixture_hash, sizeof(title.child_hash));
    unsigned bytes = pw_wine_fixture_owner_bytes();
    if (!bytes || bytes > 1024u * 1024u) goto failure;
    title.owner = calloc(1, bytes);
    if (!title.owner) goto failure;
    PwWineFixtureOwnerConfig config = {
        .session = title.session, .profile = profile,
        .child_unix_path = profile == 1 ? "/data/prospero-win/prefixes/windows-child-fixture-v1/drive_c/windows-child-fixture/child.exe" : NULL,
        .child_sha256 = profile == 1 ? title.child_hash : NULL,
        .helper_image = pw_wine_child_image, .helper_bytes = (uint32_t)pw_wine_child_image_size,
        .build_id = PW_WINE_CHILD_BUILD_ID, .context = &title,
        .clock_ms = clock_ms, .cancelled = cancelled, .record = record
    };
    status = pw_wine_fixture_owner_init(title.owner, bytes, &config, &title.provider);
    if (status) goto failure;
    status = pthread_create(&title.supervisor, NULL, supervisor, &title);
    if (status) goto failure;
    atomic_store_explicit(&title.state, TITLE_ACTIVE, memory_order_release);
    pw_diagnostics_log_local("PW_WINE_CHILD_TITLE marker=%s profile=%u session=%llu build=%s supervisor=started",
        pw_wine_child_title_marker, profile, (unsigned long long)title.session, PW_WINE_CHILD_BUILD_ID);
    return 0;
failure:
    /* No successful pthread_create and no published provider: no owner I/O or
     * native child launch has occurred. Retain the unused storage until exit. */
    atomic_store_explicit(&title.state, TITLE_INACTIVE_FAILURE, memory_order_release);
    pw_diagnostics_log_local("PW_WINE_CHILD_TITLE prepare=failed profile=%u raw=%d active=0", profile, status);
    return -1;
}
int pw_wine_child_title_install(const PwPrxDescriptor *d)
{
    unsigned empty = 0;
    if (atomic_load_explicit(&title.state, memory_order_acquire) != TITLE_ACTIVE || !d ||
        cancelled(&title) || !atomic_compare_exchange_strong(&title.install_claim, &empty, 1)) return -1;
    int stage = 1, raw = -1;
    if (d->magic != PW_PRX_MAGIC || d->version != PW_PRX_VERSION ||
        !d->count || d->count > PW_PRX_MAX_EXPORTS) goto failure;
    unsigned (*abi)(void) = (unsigned (*)(void))(uintptr_t)unique_export(d, "__wine_ps5_private_dispatch_abi");
    unsigned (*wow64)(void) = (unsigned (*)(void))(uintptr_t)unique_export(d, "__wine_ps5_private_dispatch_wow64_abi");
    int (*install)(const PwWineFixtureProvider *) =
        (int (*)(const PwWineFixtureProvider *))(uintptr_t)unique_export(d, "pw_wine_fixture_install");
    int (*sink)(PwWineFixtureSocketSink, void *) =
        (int (*)(PwWineFixtureSocketSink, void *))(uintptr_t)unique_export(d, "pw_wine_fixture_socket_set_sink");
    if (!abi || !install || !sink || (title.profile == 2 && !wow64)) goto failure;
    stage = 2; raw = (int)abi();
    if (raw != PW_WINE_CHILD_PRIVATE_DISPATCH_ABI) goto failure;
    if (cancelled(&title)) { stage = 6; raw = -1; goto failure; }
    if (title.profile == 2) {
        stage = 3; raw = (int)wow64();
        if (raw != PW_WINE_CHILD_WOW64_ABI) goto failure;
    }
    if (cancelled(&title)) { stage = 6; raw = -1; goto failure; }
    stage = 4; raw = sink(socket_sink, &title);
    if (raw) goto failure;
    if (cancelled(&title)) { stage = 6; raw = -1; goto failure; }
    stage = 5; raw = install(&title.provider);
    if (raw) goto failure;
    if (cancelled(&title)) { stage = 6; raw = -1; goto failure; }
    atomic_store_explicit(&title.installed, 1, memory_order_release);
    pw_diagnostics_log_local("PW_WINE_CHILD_TITLE install=ready profile=%u private_abi=1 wow64_abi=%u guest_started=0",
        title.profile, title.profile == 2 ? 1u : 0u);
    return 0;
failure:
    pw_wine_child_title_cancel();
    pw_diagnostics_log_local("PW_WINE_CHILD_TITLE install=failed profile=%u stage=%d raw=%d ownership=held",
        title.profile, stage, raw);
    return -1;
}
void pw_wine_child_title_cancel(void)
{
    atomic_store_explicit(&title.cancelled, 1, memory_order_release);
    if (atomic_load_explicit(&title.state, memory_order_acquire) == TITLE_ACTIVE)
        pw_wine_fixture_owner_cancel(title.owner);
}
int pw_wine_child_title_restart_ready(void)
{
    unsigned state = atomic_load_explicit(&title.state, memory_order_acquire);
    if (state == TITLE_UNUSED || state == TITLE_INACTIVE_FAILURE) return 1;
    if (state != TITLE_ACTIVE) return 0;
    return pw_wine_fixture_owner_release_ready(title.owner) == 1;
}
