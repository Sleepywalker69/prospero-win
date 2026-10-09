/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
static int mock_clock_gettime(clockid_t, struct timespec *);
static int mock_nanosleep(const struct timespec *, struct timespec *);
static int mock_pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
static pid_t mock_getpid(void);
static void *mock_calloc(size_t, size_t);
#define clock_gettime mock_clock_gettime
#define nanosleep mock_nanosleep
#define pthread_create mock_pthread_create
#define getpid mock_getpid
#define calloc mock_calloc
#include "../native/pw_wine_child_title.c"
#undef clock_gettime
#undef nanosleep
#undef pthread_create
#undef getpid
#undef calloc

const unsigned char pw_wine_child_image[] = {1,2,3,4};
const size_t pw_wine_child_image_size = sizeof(pw_wine_child_image);
static _Alignas(max_align_t) unsigned char owner_storage[512];
static PwWineFixtureOwnerConfig captured;
static int init_result, create_result, clock_result, alloc_fail, pid_value;
static int pump_calls, pump_failure, ready, ready_after, cancel_calls, socket_calls;
static int sleep_calls, sleep_error, provider_calls, sink_calls, provider_result, sink_result;
static int abi_value, wow64_value, abi_calls, wow64_calls;
static int cancel_at;
static int early_start;
static uint64_t clock_seconds;
static long clock_nsec;
static void *(*created_entry)(void *);
static void *created_context;
static PwWineFixtureSocketSink installed_sink;
static void *installed_context;
static char logs[16384];
static const char hash[] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

static int mock_clock_gettime(clockid_t id, struct timespec *t)
{ assert(id == CLOCK_MONOTONIC); t->tv_sec = (time_t)clock_seconds; t->tv_nsec = clock_nsec; return clock_result; }
static pid_t mock_getpid(void) { return (pid_t)pid_value; }
static void *mock_calloc(size_t n, size_t bytes)
{ assert(n == 1 && bytes == sizeof(owner_storage)); return alloc_fail ? NULL : owner_storage; }
static int mock_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                               void *(*entry)(void *), void *context)
{
    assert(thread == &title.supervisor && !attr && entry == supervisor && context == &title);
    assert(!pw_wine_child_title_restart_ready());
    created_entry = entry; created_context = context;
    if (early_start && !create_result) {
        /* Model a complete supervisor iteration before pthread_create returns.
         * The owner release outcome is mocked solely to return this synchronous
         * test invocation; this is not a claim about real parallel scheduling. */
        assert(captured.context == &title && captured.profile == title.profile);
        ready_after = 1;
        assert(!entry(context));
        ready = ready_after = 0;
        assert(!pw_wine_child_title_restart_ready());
    }
    return create_result;
}
static int mock_nanosleep(const struct timespec *delay, struct timespec *remaining)
{
    assert(delay->tv_sec == 0 && delay->tv_nsec == 10000000L && !remaining);
    ++sleep_calls;
    if (sleep_error) { errno = sleep_error; sleep_error = 0; return -1; }
    return 0;
}
void pw_diagnostics_log_local(const char *format, ...)
{
    size_t n = strlen(logs); assert(n + 512 < sizeof(logs));
    va_list ap; va_start(ap, format);
    vsnprintf(logs + n, sizeof(logs) - n, format, ap);
    va_end(ap); strcat(logs, "\n");
}
unsigned pw_wine_fixture_owner_bytes(void) { return sizeof(owner_storage); }
int pw_wine_fixture_owner_init(void *storage, unsigned bytes,
                               const PwWineFixtureOwnerConfig *config, PwWineFixtureProvider *out)
{
    assert(storage == owner_storage && bytes == sizeof(owner_storage));
    captured = *config; memset(out, 0, sizeof(*out));
    out->abi = PW_WINE_FIXTURE_ABI; out->bytes = sizeof(*out); out->context = storage;
    return init_result;
}
int pw_wine_fixture_owner_pump(PwWineFixtureOwner *owner)
{
    assert(owner == (PwWineFixtureOwner *)owner_storage);
    ++pump_calls; assert(pump_calls < 10);
    if (ready_after && pump_calls >= ready_after) ready = 1;
    return pump_failure;
}
void pw_wine_fixture_owner_cancel(PwWineFixtureOwner *owner)
{ assert(owner == (PwWineFixtureOwner *)owner_storage); ++cancel_calls; }
int pw_wine_fixture_owner_release_ready(const PwWineFixtureOwner *owner)
{ assert(owner == (PwWineFixtureOwner *)owner_storage); return ready; }
void pw_wine_fixture_owner_socket_failure(void *owner, const PwWineFixtureSocketResult *r)
{ assert(owner == owner_storage && r); ++socket_calls; }
static unsigned abi(void) { ++abi_calls; if (cancel_at == 1) pw_wine_child_title_cancel(); return (unsigned)abi_value; }
static unsigned wow64(void) { ++wow64_calls; if (cancel_at == 2) pw_wine_child_title_cancel(); return (unsigned)wow64_value; }
static int provider_install(const PwWineFixtureProvider *p)
{ assert(p == &title.provider && sink_calls == 1); ++provider_calls; if (cancel_at == 4) pw_wine_child_title_cancel(); return provider_result; }
static int sink_install(PwWineFixtureSocketSink sink, void *context)
{ ++sink_calls; installed_sink = sink; installed_context = context; if (cancel_at == 3) pw_wine_child_title_cancel(); return sink_result; }
static struct Descriptor { uint64_t magic; uint32_t version, count; PwPrxExport exports[5]; } descriptor;
static const PwPrxDescriptor *desc(void) { return (const PwPrxDescriptor *)&descriptor; }
static void reset(void)
{
    memset(&title, 0, sizeof(title)); memset(owner_storage, 0, sizeof(owner_storage));
    memset(&captured, 0, sizeof(captured)); memset(logs, 0, sizeof(logs));
    init_result = create_result = clock_result = alloc_fail = 0; pid_value = 599;
    pump_calls = pump_failure = ready = ready_after = cancel_calls = socket_calls = 0;
    sleep_calls = sleep_error = provider_calls = sink_calls = provider_result = sink_result = 0;
    abi_value = wow64_value = 1; abi_calls = wow64_calls = 0;
    cancel_at = early_start = 0;
    clock_seconds = 123; clock_nsec = 456000000; created_entry = NULL; created_context = NULL;
    installed_sink = NULL; installed_context = NULL;
    descriptor = (struct Descriptor){ PW_PRX_MAGIC, PW_PRX_VERSION, 4,
        {{"__wine_ps5_private_dispatch_abi", (const void *)(uintptr_t)abi},
         {"__wine_ps5_private_dispatch_wow64_abi", (const void *)(uintptr_t)wow64},
         {"pw_wine_fixture_install", (const void *)(uintptr_t)provider_install},
         {"pw_wine_fixture_socket_set_sink", (const void *)(uintptr_t)sink_install}} };
}
static PwGameProfile profile(unsigned mode)
{
    PwGameProfile p = {0};
    strcpy(p.app.runtime, "wine-wow64"); p.app.graphics = PW_APP_GRAPHICS_AUTO;
    if (mode == 1) {
        strcpy(p.app.id, "windows-child-fixture-v1"); strcpy(p.app.prefix, p.app.id);
        strcpy(p.app.executable, "C:\\windows-child-fixture\\parent.exe");
        strcpy(p.app.working_directory, "C:\\windows-child-fixture"); p.app.architecture = PW_APP_ARCH_PE64;
    } else {
        strcpy(p.app.id, "battlenet-experimental-v1"); strcpy(p.app.prefix, p.app.id);
        strcpy(p.app.executable, "C:\\installer\\Battle.net-Setup.exe");
        strcpy(p.app.working_directory, "C:\\installer"); p.app.architecture = PW_APP_ARCH_PE32;
        p.runtime.cpu = PW_GAME_CPU_TRANSLATOR;
    }
    return p;
}
static void profiles(void)
{
    assert(!pw_wine_child_title_profile(NULL));
    for (unsigned mode = 1; mode <= 2; ++mode) {
        PwGameProfile good = profile(mode), p;
        assert(pw_wine_child_title_profile(&good) == mode);
#define BAD(change) do { p = good; change; assert(!pw_wine_child_title_profile(&p)); } while (0)
        BAD(p.app.id[0] = 'X'); BAD(p.app.prefix[0] = 'X'); BAD(p.app.executable[3] = 'X');
        BAD(p.app.working_directory[3] = 'X'); BAD(p.app.runtime[0] = 'X');
        BAD(strcpy(p.app.arguments, "--stop-observe")); BAD(strcpy(p.app.dll_overrides, "ntdll=n"));
        BAD(p.app.startup_command_id = 1); BAD(p.app.graphics = PW_APP_GRAPHICS_DXVK);
        BAD(p.app.architecture = mode == 1 ? PW_APP_ARCH_PE32 : PW_APP_ARCH_PE64);
        BAD(p.runtime.cpu = PW_GAME_CPU_NATIVE); BAD(p.runtime.thread_scheduling = 1);
        BAD(p.runtime.shared_input = 1); BAD(p.runtime.fast_clock = 1); BAD(p.debug_env_count = 1);
        BAD(memset(p.app.executable, 'x', sizeof(p.app.executable)));
#undef BAD
    }
}
static void preparation(void)
{
    reset(); assert(pw_wine_child_title_restart_ready());
    char copy[65]; memcpy(copy, hash, sizeof(copy));
    assert(!pw_wine_child_title_prepare(1, copy)); copy[0] = 'f';
    assert(captured.profile == 1 && !strcmp(captured.child_sha256, hash));
    assert(captured.child_sha256 == title.child_hash && captured.context == &title);
    assert(captured.session == ((uint64_t)599 << 32 | 123456u));
    assert(!strcmp(captured.child_unix_path, "/data/prospero-win/prefixes/windows-child-fixture-v1/drive_c/windows-child-fixture/child.exe"));
    assert(captured.helper_image == pw_wine_child_image && captured.helper_bytes == 4);
    assert(!pw_wine_child_title_restart_ready() && created_entry && !pump_calls);
    assert(pw_wine_child_title_prepare(1, hash) < 0);
    uint64_t now; assert(!captured.clock_ms(captured.context, &now) && now == 123456);
    clock_nsec = 1000000000L; assert(captured.clock_ms(captured.context, &now) < 0);
    reset(); assert(!pw_wine_child_title_prepare(2, NULL));
    assert(!captured.child_sha256 && !captured.child_unix_path);
    reset(); early_start = 1; assert(!pw_wine_child_title_prepare(2, NULL));
    assert(pump_calls == 1 && !pw_wine_child_title_restart_ready());
    reset(); create_result = EAGAIN; assert(pw_wine_child_title_prepare(1, hash) < 0);
    assert(pw_wine_child_title_restart_ready() && !pump_calls && !provider_calls);
    reset(); init_result = -8; assert(pw_wine_child_title_prepare(1, hash) < 0);
    assert(pw_wine_child_title_restart_ready() && !created_entry);
    reset(); alloc_fail = 1; assert(pw_wine_child_title_prepare(1, hash) < 0 && !created_entry);
    reset(); pid_value = -1; assert(pw_wine_child_title_prepare(1, hash) < 0 && !created_entry);
    reset(); clock_result = -1; assert(pw_wine_child_title_prepare(1, hash) < 0 && !created_entry);
    reset(); assert(pw_wine_child_title_prepare(1, "bad") < 0 && !created_entry);
    reset(); assert(pw_wine_child_title_prepare(2, hash) < 0 && !created_entry);
    reset(); assert(pw_wine_child_title_prepare(3, NULL) < 0 && !created_entry);
}
static void installation(void)
{
    reset(); assert(pw_wine_child_title_install(desc()) < 0);
    for (unsigned mode = 1; mode <= 2; ++mode) {
        reset(); assert(!pw_wine_child_title_prepare(mode, mode == 1 ? hash : NULL));
        if (mode == 1) descriptor.exports[1].name = "not-a-required-fixture-export";
        assert(!pw_wine_child_title_install(desc()));
        assert(abi_calls == 1 && wow64_calls == (mode == 2) && sink_calls == 1 && provider_calls == 1);
        assert(atomic_load(&title.installed) == 1 && !pw_wine_child_title_restart_ready());
        assert(pw_wine_child_title_install(desc()) < 0 && provider_calls == 1);
    }
    for (unsigned i = 0; i < 4; ++i) {
        reset(); assert(!pw_wine_child_title_prepare(2, NULL)); descriptor.exports[i].name = "missing";
        assert(pw_wine_child_title_install(desc()) < 0 && !sink_calls && !provider_calls);
        assert(!pw_wine_child_title_restart_ready() && cancel_calls == 1);
    }
    reset(); assert(!pw_wine_child_title_prepare(2, NULL)); descriptor.exports[4] = descriptor.exports[0]; descriptor.count = 5;
    assert(pw_wine_child_title_install(desc()) < 0 && !abi_calls && !sink_calls);
    reset(); assert(!pw_wine_child_title_prepare(2, NULL)); descriptor.magic = 0;
    assert(pw_wine_child_title_install(desc()) < 0 && !abi_calls);
    reset(); assert(!pw_wine_child_title_prepare(2, NULL)); abi_value = 0;
    assert(pw_wine_child_title_install(desc()) < 0 && !sink_calls);
    reset(); assert(!pw_wine_child_title_prepare(2, NULL)); wow64_value = 0;
    assert(pw_wine_child_title_install(desc()) < 0 && !sink_calls);
    reset(); assert(!pw_wine_child_title_prepare(2, NULL)); sink_result = -4;
    assert(pw_wine_child_title_install(desc()) < 0 && !provider_calls);
    reset(); assert(!pw_wine_child_title_prepare(2, NULL)); provider_result = -5;
    assert(pw_wine_child_title_install(desc()) < 0 && !pw_wine_child_title_restart_ready());
    for (int i = 1; i <= 4; ++i) {
        reset(); assert(!pw_wine_child_title_prepare(2, NULL)); cancel_at = i;
        assert(pw_wine_child_title_install(desc()) < 0 && !atomic_load(&title.installed));
        assert(!pw_wine_child_title_restart_ready() && provider_calls == (i == 4));
        if (i <= 2) assert(!sink_calls);
    }
}
static void supervision(void)
{
    reset(); assert(!pw_wine_child_title_prepare(2, NULL)); assert(!pw_wine_child_title_install(desc()));
    PwWineFixtureSocketResult failure = {-2,5,-1,13,1,4,256};
    size_t before = strlen(logs); installed_sink(installed_context, &failure);
    failure.native_error = 99; installed_sink(installed_context, &failure);
    assert(strlen(logs) == before && socket_calls == 2 && title.socket_failure.native_error == 13);
    pump_failure = -7; ready_after = 3; sleep_error = EIO;
    assert(!created_entry(created_context));
    assert(pump_calls == 3 && sleep_calls == 2 && cancel_calls == 1);
    assert(strstr(logs, "api=5 raw=-1 native_error=13 errno_valid=1 returned_length=4 returned_value=256"));
    assert(strstr(logs, "event=supervisor_failure") && strstr(logs, "event=supervisor_sleep_failure"));
    assert(pw_wine_child_title_restart_ready());
    reset(); assert(!pw_wine_child_title_prepare(1, hash));
    pw_wine_child_title_cancel(); assert(captured.cancelled(captured.context) && cancel_calls == 1);
    assert(!pw_wine_child_title_restart_ready());
    ready_after = 2; sleep_error = EINTR; assert(!created_entry(created_context));
    assert(pump_calls == 2 && cancel_calls == 1 && !strstr(logs, "sleep_failure"));
}
int main(void)
{
    profiles(); preparation(); installation(); supervision();
    puts("title adapter source-coupled mocks: PASS (no native boundaries executed)");
    return 0;
}
