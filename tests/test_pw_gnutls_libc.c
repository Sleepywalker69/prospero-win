/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* The production shim's symbols are renamed by the build flags; libc's
 * independent gmtime_r below is the oracle. No TLS connection is made. */
#ifdef __assert
#undef __assert /* glibc has a different private three-argument declaration. */
#endif
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Assembly names preserve the independent libc controls when -D renames
 * the production entry points for this executable. */
extern struct tm *control_gmtime_r(const time_t *, struct tm *) __asm__("gmtime_r");
extern struct tm *control_gmtime(const time_t *) __asm__("gmtime");
void pw_test_assert(const char *, const char *, int, const char *);
_Noreturn void thrd_exit(int);
static atomic_uint shared_gmtime_calls;

/* The production gmtime dependency is also renamed to this wrapper. A
 * correct reentrant implementation does not touch process-global storage. */
struct tm *gmtime(const time_t *clock)
{
    atomic_fetch_add(&shared_gmtime_calls, 1);
    return control_gmtime(clock);
}

static void same_tm(const struct tm *actual, const struct tm *expected)
{
    assert(actual->tm_sec == expected->tm_sec);
    assert(actual->tm_min == expected->tm_min);
    assert(actual->tm_hour == expected->tm_hour);
    assert(actual->tm_mday == expected->tm_mday);
    assert(actual->tm_mon == expected->tm_mon);
    assert(actual->tm_year == expected->tm_year);
    assert(actual->tm_wday == expected->tm_wday);
    assert(actual->tm_yday == expected->tm_yday);
    assert(actual->tm_isdst == 0 && expected->tm_isdst == 0);
}
static void compare(time_t seconds)
{
    struct tm expected, actual;
    int expected_errno, actual_errno;
    struct tm *a, *b;
    memset(&actual, 0xa5, sizeof(actual));
    memset(&expected, 0, sizeof(expected));
    errno = 0;
    a = control_gmtime_r(&seconds, &expected); expected_errno = errno;
    errno = 0;
    b = gmtime_r(&seconds, &actual); actual_errno = errno;
    assert(!!a == !!b);
    if (a) { assert(b == &actual); same_tm(&actual, &expected); }
    else assert(expected_errno == EOVERFLOW && actual_errno == EOVERFLOW);
}
static void test_calendar(void)
{
    static const int64_t boundaries[] = {
        -62167219200LL, /* year 0, Gregorian leap century */
        -2203977601LL, -2203977600LL, -2203891201LL, -2203891200LL, /* 1900 */
        -86401, -86400, -1, 0, 1, 86399, 86400,
        951782399, 951782400, 951868799, 951868800, /* 2000 leap day */
        2147483647, 2147483648LL, /* no 2038 truncation */
        4107542399LL, 4107542400LL, /* 2100 nonleap century */
        13574563199LL, 13574563200LL /* 2400 leap century */
    };
    struct tm result;
    time_t zero = 0, before = -1;
    assert(sizeof(time_t) == 8); /* target ABI under review */
    assert(gmtime_r(&zero, &result) == &result);
    assert(result.tm_year == 70 && result.tm_mon == 0 && result.tm_mday == 1 &&
           result.tm_hour == 0 && result.tm_min == 0 && result.tm_sec == 0 &&
           result.tm_wday == 4 && result.tm_yday == 0 && result.tm_isdst == 0);
    assert(gmtime_r(&before, &result) == &result);
    assert(result.tm_year == 69 && result.tm_mon == 11 && result.tm_mday == 31 &&
           result.tm_hour == 23 && result.tm_min == 59 && result.tm_sec == 59 &&
           result.tm_wday == 3 && result.tm_yday == 364 && result.tm_isdst == 0);
    for (unsigned i = 0; i < sizeof(boundaries) / sizeof(boundaries[0]); ++i)
        compare((time_t)boundaries[i]);
    /* Input fits time_t but its Gregorian year cannot fit struct tm. */
    compare((time_t)INT64_MIN); compare((time_t)INT64_MAX);
    /* Exercise large representable years and the int tm_year boundary. */
    compare((time_t)INT64_C(67768036191676799));
    compare((time_t)INT64_C(67768036191676800));
    compare((time_t)-INT64_C(67768040609740800));
}
static void *calendar_thread(void *arg)
{
    uint64_t seed = (uintptr_t)arg + 1;
    for (unsigned i = 0; i < 20000; ++i) {
        seed = seed * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);
        /* +/- about 2,000 years, covering negative dates and leap cycles. */
        time_t seconds = (time_t)(seed % UINT64_C(126227808000)) - INT64_C(63113904000);
        compare(seconds);
    }
    return NULL;
}
static void test_parallel(void)
{
    pthread_t workers[8];
    for (uintptr_t i = 0; i < 8; ++i) assert(!pthread_create(&workers[i], NULL, calendar_thread, (void *)i));
    for (unsigned i = 0; i < 8; ++i) assert(!pthread_join(workers[i], NULL));
}
static void test_no_password_database(void)
{
    struct passwd entry, before, *result = (void *)(uintptr_t)1;
    char buffer[32], saved[32];
    memset(&entry, 0xa5, sizeof(entry)); memcpy(&before, &entry, sizeof(entry));
    memset(buffer, 0x5a, sizeof(buffer)); memcpy(saved, buffer, sizeof(buffer));
    assert(!getpwuid_r((uid_t)0, &entry, buffer, sizeof(buffer), &result) && !result);
    assert(!memcmp(&entry, &before, sizeof(entry)) && !memcmp(buffer, saved, sizeof(buffer)));
    result = (void *)(uintptr_t)1;
    assert(!getpwuid_r((uid_t)12345, &entry, buffer, 0, &result) && !result);
}
static void *exit_thread(void *arg)
{
    thrd_exit((int)(intptr_t)arg);
}
static void test_thread_exit_and_assert(void)
{
    pthread_t thread;
    static const int results[] = {0, 23, -19, INT_MIN, INT_MAX};
    for (unsigned i = 0; i < sizeof(results) / sizeof(results[0]); ++i) {
        void *result = NULL;
        assert(!pthread_create(&thread, NULL, exit_thread, (void *)(intptr_t)results[i]));
        assert(!pthread_join(thread, &result));
        assert((intptr_t)result == results[i]);
    }
    {
        pid_t child = fork();
        int status;
        assert(child >= 0);
        if (!child) {
            const struct rlimit limit = {0, 0};
            (void)setrlimit(RLIMIT_CORE, &limit);
            pw_test_assert("fixture", "synthetic.c", 1, "intentional failure");
            _exit(99);
        }
        assert(waitpid(child, &status, 0) == child);
        assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT);
    }
}
int main(void)
{
    /* UTC conversion must ignore process-local timezone choices. */
    assert(!setenv("TZ", "UTC-13", 1));
    tzset();
    test_calendar();
    /* Fail deterministically on the old private-lock wrapper; timing a race
     * against other libc users would be nondeterministic evidence. */
    assert(!atomic_load(&shared_gmtime_calls));
    test_parallel();
    assert(!atomic_load(&shared_gmtime_calls));
    test_no_password_database();
    test_thread_exit_and_assert();
    puts("TLS libc shim passed: UTC boundaries and overflow, 160000 parallel oracle comparisons, "
         "no shared gmtime buffer, empty password database, thread exit and abort");
    return 0;
}
