#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Compile and exercise the exact added Wine fatal-diagnostic patch bodies.

No Wine executable, console, external files or downloaded software is used.
Optional --wine-source checks the same bodies in an already composed tree.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / 'wine/patches/0920-server-fatal-output-sink.patch'


def new_sides():
    files = {}
    current = None
    for line in PATCH.read_text().splitlines(keepends=True):
        if line.startswith('diff --git '):
            current = None
        elif line.startswith('+++ b/'):
            current = line[6:].strip()
            files.setdefault(current, [])
        elif current and line.startswith(('+', ' ')):
            files[current].append(line[1:])
    return {name: ''.join(lines) for name, lines in files.items()}


def block(source, start, end):
    assert source.count(start) == source.count(end) == 1, (start, end)
    return source[source.index(start):source.index(end) + len(end)]


HARNESS = r'''
#include <assert.h>
#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#define DECLSPEC_EXPORT
static jmp_buf exited;
static int exit_status, exit_errno, sink_calls, output_calls, format_fail;
static int stderr_calls, symbol_missing, install_failure;
static char captured[4096], stderr_text[4096];
static size_t captured_size, stderr_size;
static void append(char *to, size_t *used, const char *text, size_t length)
{
    assert(*used + length < 4096);
    memcpy(to + *used, text, length);
    *used += length;
    to[*used] = 0;
}
static void fake_exit(int status) __attribute__((noreturn));
static void fake_exit(int status)
{
    exit_status = status;
    exit_errno = errno;
    longjmp(exited, 1);
}
static int fake_vsnprintf(char *to, size_t size, const char *fmt, va_list args)
{
    int rc;
    if (format_fail) { errno = EILSEQ; return -1; }
    rc = vsnprintf(to, size, fmt, args);
    errno = ERANGE;
    return rc;
}
static int fake_vfprintf(FILE *file, const char *fmt, va_list args)
{
    char text[2048];
    int length;
    assert(file == stderr);
    ++stderr_calls;
    length = vsnprintf(text, sizeof(text), fmt, args);
    assert(length >= 0 && (size_t)length < sizeof(text));
    append(stderr_text, &stderr_size, text, (size_t)length);
    errno = EIO;
    return length;
}
static int fake_fprintf(FILE *file, const char *fmt, ...)
{
    va_list args;
    int rc;
    va_start(args, fmt);
    rc = fake_vfprintf(file, fmt, args);
    va_end(args);
    return rc;
}
static char *fake_strerror(int value)
{
    static char text[64];
    snprintf(text, sizeof(text), "native-error-%d", value);
    errno = E2BIG;
    return text;
}
static void record(const char *text, size_t length)
{
    ++sink_calls;
    assert(length > 0 && length < 1024);
    assert(text[length] == 0);
    assert(text[length - 1] == '\n');
    append(captured, &captured_size, text, length);
    errno = ENOSPC;
}
static void another_record(const char *text, size_t length)
{ record(text, length); }
#define vsnprintf fake_vsnprintf
#define fprintf fake_fprintf
#define vfprintf fake_vfprintf
#define strerror fake_strerror
#define exit fake_exit
/* PRODUCTION_SERVER */
#undef vsnprintf
#undef fprintf
#undef vfprintf
#undef strerror
#undef exit
static long wine_write_stderr(const void *text, size_t length)
{
    ++output_calls;
    append(captured, &captured_size, text, length);
    errno = EPIPE;
    return (long)length;
}
static int refusing_install(void (*sink)(const char *, size_t))
{ assert(sink); errno = EBADF; return -1; }
static void *fake_dlsym(void *module, const char *name)
{
    assert(module == (void *)1);
    assert(!strcmp(name, "pw_wineserver_set_fatal_sink"));
    errno = EBUSY;
    if (symbol_missing) return NULL;
    return install_failure ? (void *)refusing_install : (void *)pw_wineserver_set_fatal_sink;
}
#define dlsym fake_dlsym
/* PRODUCTION_BRIDGE */
#undef dlsym
static void reset(void)
{
    __atomic_store_n(&server_fatal_sink, NULL, __ATOMIC_RELEASE);
    exit_status = exit_errno = sink_calls = output_calls = format_fail = 0;
    stderr_calls = symbol_missing = install_failure = 0;
    captured_size = stderr_size = 0;
    captured[0] = stderr_text[0] = 0;
    errno = 0;
}
static void die_generic(const char *path)
{
    if (!setjmp(exited)) fatal_error("not a directory: %s\n", path);
}
static void die_errno(const char *path)
{
    if (!setjmp(exited)) fatal_perror("lstat %s", path);
}
static unsigned assertions;
#define CHECK(x) do { ++assertions; assert(x); } while (0)
static void diagnostic_tests(void)
{
    char expected[2048], huge[1200];
    const char *path = "/data/prospero-win/prefixes/test%p/.wineserver";
    reset();
    errno = EDOM;
    CHECK(pw_wineserver_set_fatal_sink(NULL) == -1);
    CHECK(errno == EDOM);
    CHECK(pw_wineserver_set_fatal_sink(record) == 0);
    CHECK(pw_wineserver_set_fatal_sink(record) == 0);
    CHECK(pw_wineserver_set_fatal_sink(another_record) == -1);
    CHECK(errno == EDOM);
    errno = EPERM;
    die_errno(path);
    snprintf(expected, sizeof(expected),
             "wineserver: fatal errno_valid=1 errno=%d truncated=0 message=lstat %s\n", EPERM, path);
    CHECK(!strcmp(captured, expected));
    CHECK(sink_calls == 1 && !stderr_calls);
    CHECK(exit_status == 1 && exit_errno == EPERM);
    CHECK(errno == EPERM);

    reset(); CHECK(!pw_wineserver_set_fatal_sink(record)); errno = ESTALE;
    die_generic(path);
    CHECK(strstr(captured, "errno_valid=0 errno=0 truncated=0") != NULL);
    CHECK(strstr(captured, path) != NULL);
    CHECK(exit_status == 1 && exit_errno == ESTALE && !stderr_calls);
    CHECK(sink_calls == 1);

    reset(); CHECK(!pw_wineserver_set_fatal_sink(record)); errno = EACCES;
    die_errno("/data/a\nb\rc%08x");
    CHECK(strstr(captured, "message=lstat /data/a b c%08x\n") != NULL);
    CHECK(strchr(captured, '\n') == captured + captured_size - 1);
    CHECK(exit_errno == EACCES);

    reset(); CHECK(!pw_wineserver_set_fatal_sink(record)); errno = ENAMETOOLONG;
    memset(huge, 'x', sizeof(huge)-1); huge[sizeof(huge)-1] = 0;
    die_errno(huge);
    CHECK(strstr(captured, "truncated=1 message=lstat ") != NULL);
    CHECK(captured_size < 1024 && captured[captured_size-1] == '\n');
    CHECK(sink_calls == 1 && !stderr_calls && exit_errno == ENAMETOOLONG);

    reset(); CHECK(!pw_wineserver_set_fatal_sink(record)); errno = ENOENT;
    format_fail = 1; die_errno(path);
    CHECK(strstr(captured, "truncated=1 message=<format-error>\n") != NULL);
    snprintf(expected, sizeof(expected), "errno_valid=1 errno=%d", ENOENT);
    CHECK(strstr(captured, expected) != NULL);
    CHECK(exit_status == 1 && exit_errno == ENOENT && sink_calls == 1 && !stderr_calls);

    reset(); errno = ENOTDIR; die_errno(path);
    snprintf(expected, sizeof(expected), "wineserver: lstat %s: native-error-%d\n", path, ENOTDIR);
    CHECK(!strcmp(stderr_text, expected));
    CHECK(!sink_calls && stderr_calls == 3 && exit_status == 1 && exit_errno == ENOTDIR);
    reset(); errno = EDOM; die_generic(path);
    snprintf(expected, sizeof(expected), "wineserver: not a directory: %s\n", path);
    CHECK(!strcmp(stderr_text, expected));
    CHECK(!sink_calls && stderr_calls == 2 && exit_status == 1 && exit_errno == EDOM);
}
static void bridge_tests(void)
{
    char expected[80];
    reset(); errno = EDOM; install_server_fatal_sink((void *)1);
    CHECK(!strcmp(captured, "wine startup: server fatal sink installed\n"));
    CHECK(errno == EDOM && output_calls == 1 && !stderr_calls);
    captured[0] = 0; captured_size = 0;
    errno = EPERM; die_errno("/data/test/.wineserver");
    snprintf(expected, sizeof(expected), "errno_valid=1 errno=%d", EPERM);
    CHECK(strstr(captured, expected) != NULL);
    CHECK(strstr(captured, "lstat /data/test/.wineserver") != NULL);
    CHECK(exit_status == 1 && exit_errno == EPERM && output_calls == 2 && !stderr_calls);
    reset(); symbol_missing = 1; errno = EDOM; install_server_fatal_sink((void *)1);
    CHECK(!strcmp(captured, "wine startup: server fatal sink unavailable\n"));
    CHECK(errno == EDOM && !server_fatal_sink && exit_status == 0);
    reset(); install_failure = 1; errno = EDOM; install_server_fatal_sink((void *)1);
    CHECK(!strcmp(captured, "wine startup: server fatal sink unavailable\n"));
    CHECK(errno == EDOM && !server_fatal_sink && exit_status == 0);
}
static int thread_results[2];
static void *install_thread(void *arg)
{
    size_t which = (size_t)arg;
    thread_results[which] = pw_wineserver_set_fatal_sink(which ? record : another_record);
    return NULL;
}
static void concurrent_install_test(void)
{
    pthread_t a, b;
    reset();
    CHECK(!pthread_create(&a, NULL, install_thread, (void *)0));
    CHECK(!pthread_create(&b, NULL, install_thread, (void *)1));
    CHECK(!pthread_join(a, NULL) && !pthread_join(b, NULL));
    CHECK((thread_results[0] == 0 && thread_results[1] == -1) ||
          (thread_results[1] == 0 && thread_results[0] == -1));
    errno = EPERM; die_errno("/data/.wineserver");
    CHECK(exit_errno == EPERM && sink_calls == 1 && !stderr_calls);
}
int main(void)
{
    diagnostic_tests();
    bridge_tests();
    concurrent_install_test();
    printf("server-fatal production-body checks passed: %u assertions\n", assertions);
    return 0;
}
'''


FALLBACK_HARNESS = r'''
#include <assert.h>
#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static jmp_buf exited;
static int status_seen, errno_seen;
static void fake_exit(int status) __attribute__((noreturn));
static void fake_exit(int status)
{ status_seen=status; errno_seen=errno; longjmp(exited,1); }
#define exit fake_exit
/* PRODUCTION_SERVER */
#undef exit
int main(void)
{
    errno=EPERM;
    if (!setjmp(exited)) fatal_perror("lstat %s", "/data/test%p");
    assert(status_seen==1 && errno_seen==EPERM);
    errno=EDOM;
    if (!setjmp(exited)) fatal_error("logical failure %s\n", "100%");
    assert(status_seen==1 && errno_seen==EDOM);
    puts("non-inprocess fallback passed");
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--wine-source', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    sides = new_sides()
    server = block(sides['server/request.c'], '/* PW_SERVER_FATAL_DIAGNOSTIC_BEGIN',
                   '/* PW_SERVER_FATAL_DIAGNOSTIC_END */')
    bridge = block(sides['dlls/ntdll/unix/server.c'], '/* PW_SERVER_FATAL_BRIDGE_BEGIN */',
                   '/* PW_SERVER_FATAL_BRIDGE_END */')
    for source, begin, end, expected in (
        ('server/request.c', '/* PW_SERVER_FATAL_DIAGNOSTIC_BEGIN', '/* PW_SERVER_FATAL_DIAGNOSTIC_END */', server),
        ('dlls/ntdll/unix/server.c', '/* PW_SERVER_FATAL_BRIDGE_BEGIN */', '/* PW_SERVER_FATAL_BRIDGE_END */', bridge)):
        if args.wine_source:
            assert block((args.wine_source / source).read_text(), begin, end) == expected, source
    # This installation must precede every in-process initialization operation.
    ntdll = sides['dlls/ntdll/unix/server.c']
    assert ntdll.index('if (!(module = dlopen(') < ntdll.index('    install_server_fatal_sink( module );')
    assert ntdll.index('    install_server_fatal_sink( module );') < ntdll.index('share_name_changes( module );')
    assert 'pw_wineserver_set_fatal_sink pw_wineserver_mutex_backend' in (ROOT/'tools/build_wine_ps5.sh').read_text()
    # Every errno-aware replacement passes the path directly, without strerror.
    patched = sides['server/request.c']
    assert patched.count('fatal_perror( "') == 11
    for line in patched.splitlines():
        if 'fatal_perror( "' in line:
            assert 'strerror' not in line, line
    harness = HARNESS.replace('/* PRODUCTION_SERVER */', server).replace('/* PRODUCTION_BRIDGE */', bridge)
    with tempfile.TemporaryDirectory() as temporary:
        out = args.output or Path(temporary)
        out.mkdir(parents=True, exist_ok=True)
        unit = out/'server-fatal.c'; unit.write_text(harness)
        compiler = shlex.split(os.environ.get('CC', 'cc'))
        flags = shlex.split(os.environ.get('CFLAGS', '-O2 -std=c11 -Wall -Wextra -Werror'))
        command = compiler + flags + ['-DWINE_INPROCESS_SERVER', '-pthread', str(unit), '-o', str(out/'server-fatal')]
        subprocess.run(command, check=True)
        done = subprocess.run([str(out/'server-fatal')], capture_output=True, text=True)
        print(done.stdout, end=''); print(done.stderr, end='')
        assert done.returncode == 0, done.returncode
        fallback = out/'server-fatal-fallback.c'
        fallback.write_text(FALLBACK_HARNESS.replace('/* PRODUCTION_SERVER */', server))
        fallback_command = compiler + flags + [str(fallback), '-o', str(out/'server-fatal-fallback')]
        subprocess.run(fallback_command, check=True)
        fallback_done = subprocess.run([str(out/'server-fatal-fallback')], capture_output=True, text=True)
        assert fallback_done.returncode == 0, fallback_done.stderr
        assert fallback_done.stderr.startswith('wineserver: lstat /data/test%p: ')
        assert fallback_done.stderr.endswith('wineserver: logical failure 100%\n')
        print(fallback_done.stdout, end='')
        result = {'patch_sha256': hashlib.sha256(PATCH.read_bytes()).hexdigest(),
                  'source_body_sha256': hashlib.sha256(harness.encode()).hexdigest(),
                  'command': command, 'run_exit': done.returncode, 'output': done.stdout,
                  'composed_source_checked': bool(args.wine_source),
                  'fallback_command': fallback_command, 'fallback_exit': fallback_done.returncode,
                  'target_compilation': False, 'console_run': False}
        if args.output:
            (out/'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
