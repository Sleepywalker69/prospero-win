/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Actual logger with deterministic native write/close failure boundaries. */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static ssize_t test_write(int, const void *, size_t);
static int test_close(int);
#define write test_write
#define close test_close
#include "../native/pw_diagnostics.c"
#undef write
#undef close

static unsigned writes, closes, network_calls;
static int fail_write, short_write;
static char retained[4096];
static size_t retained_bytes;
static ssize_t test_write(int target, const void *data, size_t length)
{
    assert(target == 42 && data && length);
    ++writes;
    if (fail_write && (!short_write || writes > 1)) { errno = EIO; return -1; }
    if (short_write && length > 3) length = 3;
    assert(retained_bytes + length < sizeof(retained));
    memcpy(retained + retained_bytes, data, length); retained_bytes += length;
    return (ssize_t)length;
}
static int test_close(int target) { assert(target == 42); ++closes; return 0; }
int ps5log_line(const char *level, const char *text)
{ (void)level; (void)text; ++network_calls; return 0; }
int ps5log_raw(const void *data, size_t length)
{ (void)data; (void)length; ++network_calls; return 0; }
int ps5log_enabled(void) { ++network_calls; return 1; }
int ps5log_reconnect(void) { ++network_calls; return 0; }
void ps5log_close(const char *reason) { (void)reason; ++network_calls; }
static void reset(void)
{
    fd = 42; disk_error = 0; used = bytes = 0;
    writes = closes = network_calls = 0; fail_write = short_write = 0;
    retained_bytes = 0; memset(retained, 0, sizeof(retained));
}
int main(void)
{
    reset();
    pw_diagnostics_log_local("socket failure raw=%d errno=%d", -7, 13);
    assert(!writes && used); /* Normal local logging is still buffered. */
    errno = EACCES; pw_diagnostics_flush_local();
    assert(errno == EACCES && writes == 1 && !used && !closes && !network_calls);
    assert(strstr(retained, "socket failure raw=-7 errno=13\n"));
    pw_diagnostics_flush_local(); assert(writes == 1); /* Nothing to resend. */
    for (unsigned partial = 0; partial < 2; ++partial) {
        reset(); fail_write = 1; short_write = (int)partial;
        pw_diagnostics_log_local("helper_unsettled generation=17");
        errno = EACCES; pw_diagnostics_flush_local();
        assert(errno == EACCES && disk_error == EIO && fd == -1 && !used);
        assert(writes == 1 + partial && closes == 1 && !network_calls);
        assert(retained_bytes == (partial ? 3u : 0u));
        unsigned attempts = writes;
        pw_diagnostics_flush_local(); assert(writes == attempts && closes == 1);
    }
    reset(); fd = -1;
    pw_diagnostics_log_local("no open log");
    errno = EACCES; pw_diagnostics_flush_local();
    assert(errno == EACCES && !writes && !closes && !network_calls);
    puts("local immediate flush: source-coupled write/failure controls passed");
    return 0;
}
