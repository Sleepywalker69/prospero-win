/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Original real-file and hostile-call controls; no Wine or console execution. */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL line=%d: %s\n", __LINE__, #condition); exit(1); \
} } while (0)

int __wrap_mkstemp(char *pattern);
int __real_open(const char *path, int flags, ...);
static char directory[] = "/tmp/pw-radv-mkstemp-XXXXXX";
static atomic_uint open_calls, wrong_open;
static int fail_errno, random_mode;
static _Thread_local unsigned random_calls, thread_token;

uint32_t ps5_arc4random_uniform(uint32_t bound)
{
    CHECK(bound == 62);
    unsigned call = random_calls++;
    if (random_mode == 1) return call < 6 ? 0 : 1;
    if (random_mode == 2) return call < 6 ? 0 : thread_token;
    return 0;
}

int __wrap_open(const char *path, int flags, ...)
{
    va_list args;
    va_start(args, flags);
    int mode = va_arg(args, int);
    va_end(args);
    atomic_fetch_add(&open_calls, 1);
    if (flags != (O_RDWR | O_CREAT | O_EXCL) || mode != 0600) atomic_store(&wrong_open, 1);
    if (fail_errno) { errno = fail_errno; return -1; }
    return __real_open(path, flags, mode);
}

static void cleanup(void)
{
    DIR *dir = opendir(directory);
    if (!dir) return;
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char path[PATH_MAX];
        int n = snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
        if (n > 0 && (size_t)n < sizeof(path)) unlink(path);
    }
    closedir(dir);
    rmdir(directory);
}

static void reset(int mode, int error)
{
    random_mode = mode; fail_errno = error; random_calls = 0;
    atomic_store(&open_calls, 0); atomic_store(&wrong_open, 0);
}

static void path(char *buffer, size_t capacity, const char *name)
{
    int n = snprintf(buffer, capacity, "%s/%s", directory, name);
    CHECK(n > 0 && (size_t)n < capacity);
}

static void invalid_inputs(void)
{
    reset(0, 0);
    const char *bad[] = {"", "XXXXX", "plain", "XXXXXX.suffix", "XXXxXX"};
    CHECK(__wrap_mkstemp(NULL) == -1 && errno == EINVAL);
    for (unsigned i = 0; i < sizeof(bad)/sizeof(bad[0]); ++i) {
        char value[32]; strcpy(value, bad[i]);
        CHECK(__wrap_mkstemp(value) == -1 && errno == EINVAL);
        CHECK(!strcmp(value, bad[i]));
    }
    char overlong[PATH_MAX + 1]; memset(overlong, 'X', sizeof(overlong)); overlong[PATH_MAX] = 0;
    CHECK(__wrap_mkstemp(overlong) == -1 && errno == ENAMETOOLONG);
    CHECK(overlong[0] == 'X' && overlong[PATH_MAX-1] == 'X');
    CHECK(atomic_load(&open_calls) == 0 && random_calls == 0);
    puts("PASS invalid/truncated templates perform no entropy or file calls");
}

static void creation_and_fd_ownership(void)
{
    char value[PATH_MAX]; path(value, sizeof(value), "owner-XXXXXXX"); reset(0, 0);
    mode_t old = umask(0);
    int fd = __wrap_mkstemp(value);
    umask(old);
    CHECK(fd >= 0 && strstr(value, "owner-Xaaaaaa"));
    struct stat status; CHECK(fstat(fd, &status) == 0 && S_ISREG(status.st_mode));
    CHECK((status.st_mode & 0777) == 0600);
    CHECK(atomic_load(&open_calls) == 1 && !atomic_load(&wrong_open));
    CHECK((fcntl(fd, F_GETFL) & O_ACCMODE) == O_RDWR);
    CHECK(write(fd, "owned", 5) == 5 && lseek(fd, 0, SEEK_SET) == 0);
    char bytes[6] = {0}; CHECK(read(fd, bytes, 5) == 5 && !strcmp(bytes, "owned"));
    CHECK(close(fd) == 0 && fcntl(fd, F_GETFD) == -1 && errno == EBADF);
    CHECK(unlink(value) == 0);
    puts("PASS exclusive0600 real read/write file and caller fd ownership");
}

static void collision(int use_symlink)
{
    char occupied[PATH_MAX], target[PATH_MAX], value[PATH_MAX];
    path(occupied, sizeof(occupied), "collision-aaaaaa"); path(target, sizeof(target), "sentinel");
    path(value, sizeof(value), "collision-XXXXXX");
    int existing = __real_open(use_symlink ? target : occupied, O_WRONLY|O_CREAT|O_EXCL, 0600);
    CHECK(existing >= 0 && write(existing, "keep", 4) == 4 && close(existing) == 0);
    if (use_symlink) CHECK(symlink(target, occupied) == 0);
    reset(1, 0);
    int fd = __wrap_mkstemp(value); CHECK(fd >= 0);
    CHECK(strstr(value, "collision-bbbbbb") && atomic_load(&open_calls) == 2);
    CHECK(!atomic_load(&wrong_open));
    int check = __real_open(use_symlink ? target : occupied, O_RDONLY);
    char bytes[5] = {0}; CHECK(check >= 0 && read(check, bytes, 4) == 4 && !strcmp(bytes, "keep"));
    CHECK(close(check) == 0 && close(fd) == 0 && unlink(value) == 0 && unlink(occupied) == 0);
    if (use_symlink) CHECK(unlink(target) == 0);
    puts(use_symlink ? "PASS symlink collision preserves its target" : "PASS file collision retries without overwrite");
}

static void failure_semantics(void)
{
    for (unsigned i = 0; i < 3; ++i) {
        const int errors[] = {EACCES, ENOSPC, EINTR};
        char value[PATH_MAX]; path(value, sizeof(value), "error-XXXXXX"); reset(0, errors[i]);
        errno = 0; CHECK(__wrap_mkstemp(value) == -1 && errno == errors[i]);
        CHECK(atomic_load(&open_calls) == 1 && !atomic_load(&wrong_open));
        struct stat status; CHECK(lstat(value, &status) == -1 && errno == ENOENT);
    }
    char value[PATH_MAX], original[PATH_MAX]; path(value, sizeof(value), "full-XXXXXX"); strcpy(original, value);
    reset(0, EEXIST);
    CHECK(__wrap_mkstemp(value) == -1 && errno == EEXIST);
    CHECK(atomic_load(&open_calls) == 1000 && random_calls == 6000 && !strcmp(value, original));
    CHECK(!atomic_load(&wrong_open));
    puts("PASS noncollision errno propagation and bounded collision exhaustion");
}

struct contender { char value[PATH_MAX]; unsigned token; int fd; };
static void *create_concurrently(void *argument)
{
    struct contender *c = argument; thread_token = c->token; random_calls = 0;
    c->fd = __wrap_mkstemp(c->value); return NULL;
}

static void concurrency(void)
{
    struct contender a = {.token=1,.fd=-1}, b = {.token=2,.fd=-1}; pthread_t one, two;
    path(a.value, sizeof(a.value), "parallel-XXXXXX"); strcpy(b.value, a.value); reset(2, 0);
    CHECK(pthread_create(&one, NULL, create_concurrently, &a) == 0);
    CHECK(pthread_create(&two, NULL, create_concurrently, &b) == 0);
    CHECK(pthread_join(one, NULL) == 0 && pthread_join(two, NULL) == 0);
    struct stat sa, sb;
    CHECK(a.fd >= 0 && b.fd >= 0 && strcmp(a.value, b.value));
    CHECK(fstat(a.fd, &sa) == 0 && fstat(b.fd, &sb) == 0 && sa.st_ino != sb.st_ino);
    CHECK(atomic_load(&open_calls) == 3 && !atomic_load(&wrong_open));
    CHECK(close(a.fd) == 0 && close(b.fd) == 0 && unlink(a.value) == 0 && unlink(b.value) == 0);
    puts("PASS concurrent same-name contenders receive distinct exclusive files");
}

int main(int argc, char **argv)
{
    CHECK(mkdtemp(directory)); CHECK(atexit(cleanup) == 0);
    if (argc == 2 && !strcmp(argv[1], "creation-only")) { creation_and_fd_ownership(); return 0; }
    invalid_inputs(); creation_and_fd_ownership(); collision(0); collision(1);
    failure_semantics(); concurrency();
    puts("PASS RADV mkstemp host contract (six groups)");
    return 0;
}
