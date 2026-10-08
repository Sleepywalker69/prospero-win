/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* libc functions GnuTLS and nettle (libgnutls.prx) name but the payload
 * SDK's system libraries lack: its assertions abort as assert() would; the
 * console's libc has gmtime but no gmtime_r, so UTC is converted without
 * shared libc storage (a private lock cannot protect other gmtime callers);
 * a title has no password database (GnuTLS asks for the home directory of
 * its configuration), so there is no entry; and GnuTLS's gnulib names C11's
 * thrd_exit, which the system libraries lack: it is pthread_exit. */
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <pwd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

void __assert(const char *function, const char *file, int line, const char *expression)
{
    (void)function; (void)file; (void)line; (void)expression;
    abort();
}

struct tm *gmtime_r(const time_t *clock, struct tm *result)
{
    _Static_assert(sizeof(time_t) <= sizeof(int64_t) && (time_t)-1 < 0,
                   "UTC conversion requires a signed time_t of at most 64 bits");
    static const unsigned month_days[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    int64_t seconds = *clock, days = seconds / 86400, remainder = seconds % 86400;
    int64_t cycles, year, weekday;
    unsigned length, month;
    struct tm value;

    /* Floor division keeps pre-epoch time within its preceding UTC day. */
    if (remainder < 0) { remainder += 86400; --days; }
    weekday = (days + 4) % 7;
    if (weekday < 0) weekday += 7;
    /* Every 400 consecutive Gregorian years contain 146097 days. This
     * bounds the remaining year loop to 400 even for extreme time_t. */
    cycles = days / 146097;
    if (days % 146097 < 0) --cycles;
    days -= cycles * 146097;
    year = 1970 + cycles * 400;
    for (;;) {
        length = 365 + (!(year % 4) && (year % 100 || !(year % 400)));
        if (days < length) break;
        days -= length;
        ++year;
    }
    if (year - 1900 < INT_MIN || year - 1900 > INT_MAX) {
        errno = EOVERFLOW;
        return NULL;
    }
    memset(&value, 0, sizeof(value));
    value.tm_year = (int)(year - 1900);
    value.tm_yday = (int)days;
    for (month = 0; month < 11; month++) {
        length = month_days[month] + (month == 1 && !(year % 4) &&
                                      (year % 100 || !(year % 400)));
        if (days < length) break;
        days -= length;
    }
    value.tm_mon = (int)month;
    value.tm_mday = (int)days + 1;
    value.tm_wday = (int)weekday;
    value.tm_hour = (int)(remainder / 3600);
    value.tm_min = (int)(remainder / 60 % 60);
    value.tm_sec = (int)(remainder % 60);
#if defined(__USE_MISC) || (defined(__BSD_VISIBLE) && __BSD_VISIBLE)
    value.tm_zone = "UTC";
#endif
    *result = value;
    return result;
}

int getpwuid_r(uid_t uid, struct passwd *entry, char *buffer, size_t size, struct passwd **result)
{
    (void)uid; (void)entry; (void)buffer; (void)size;
    *result = NULL;
    return 0;                   /* no entry, no error */
}

_Noreturn void thrd_exit(int result)
{
    pthread_exit((void *)(intptr_t)result);
}
