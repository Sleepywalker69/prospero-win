/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
/* Include implementation to exercise ancillary rejection/cleanup internals.
 * The production source has no fork, libc startup, stdio, or waitpid calls. */
#include "../../native/pw_native_fd_probe.c"
#ifndef __linux__
#error "This test harness is Linux-only; the implementation has a separate SDK ABI branch"
#endif

static int now_ms(void *unused, uint64_t *out)
{
    struct timespec t;
    (void)unused;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return -1;
    *out = (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
    return 0;
}

static PwNativeFdContext context(unsigned milliseconds)
{
    uint64_t now;
    PwNativeFdContext c = { NULL, now_ms, NULL, 0 };
    assert(!now_ms(NULL, &now)); c.deadline_ms = now + milliseconds;
    return c;
}

static int fd_count(void)
{
    int count = 0;
    for (int fd = 0; fd < 512; ++fd) if (fcntl(fd, F_GETFD) >= 0) ++count;
    return count;
}

static void child_result(int status, const PwNativeFdResult *r)
{
    if (status || r->cleanup_failed || r->peer_identity_verified ||
        r->reported_peer_pid != (uint32_t)getppid()) _exit(50);
    if ((r->observations & (PW_NATIVE_FD_QUEUED_RIGHT_OK | PW_NATIVE_FD_REVERSE_EOF |
                           PW_NATIVE_FD_COMPLETED)) !=
        (PW_NATIVE_FD_QUEUED_RIGHT_OK | PW_NATIVE_FD_REVERSE_EOF | PW_NATIVE_FD_COMPLETED)) _exit(51);
    _exit(0);
}

static void roundtrip(const char *path, int wrong_correlation)
{
    PwNativeFdContext c = context(3000);
    PwNativeFdListener l;
    PwNativeFdResult r;
    const uint64_t token = UINT64_C(0x54c31df8f406aac1);
    int before = fd_count(), exit_status;
    int opened = pw_native_fd_parent_open(&l, path, &c, &r);
    if (opened) { fprintf(stderr, "open failed rc=%d stage=%d api=%d raw=%lld path=%s\n", opened, (int)r.stage, (int)r.api, (long long)r.raw_result, path); perror("host diagnostic"); }
    assert(!opened);
    pid_t pid = fork();
    assert(pid >= 0);
    if (!pid) {
        /* Host fork inherited listener; close it without unlinking the path.
         * Real SELF worker starts independently and inherits none of this. */
        close(l.fd);
        int rc = pw_native_fd_worker(path, token + (unsigned)wrong_correlation, &c, &r);
        if (wrong_correlation) _exit(rc == PW_NATIVE_FD_PROTOCOL ? 0 : 52);
        child_result(rc, &r);
    }
    int rc = pw_native_fd_parent(&l, token, &c, &r);
    assert(waitpid(pid, &exit_status, 0) == pid);
    assert(WIFEXITED(exit_status) && WEXITSTATUS(exit_status) == 0);
    if (wrong_correlation) assert(rc == PW_NATIVE_FD_PROTOCOL && r.stage == PW_NATIVE_FD_HELLO);
    else {
        assert(!rc && r.stage == PW_NATIVE_FD_COMPLETE && !r.cleanup_failed);
        assert(r.reported_peer_pid == (uint32_t)pid && r.local_pid == (uint32_t)getpid());
        assert(!r.peer_identity_verified && r.observations == 191 && r.peer_observations == PW_NATIVE_FD_REVERSE_EOF);
    }
    assert(l.fd == -1 && !l.bound && access(path, F_OK) < 0);
    assert(fd_count() == before);
}

static void send_many(int fd, unsigned char tag, const int *rights, size_t count)
{
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(16 * sizeof(int))]; } buf;
    struct iovec iov = { &tag, 1 };
    struct msghdr msg = {0};
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    if (count) {
        msg.msg_control = buf.bytes; msg.msg_controllen = CMSG_SPACE(count * sizeof(int));
        memset(&buf, 0, sizeof(buf));
        struct cmsghdr *h = CMSG_FIRSTHDR(&msg);
        h->cmsg_len = CMSG_LEN(count * sizeof(int)); h->cmsg_level = SOL_SOCKET; h->cmsg_type = SCM_RIGHTS;
        memcpy(CMSG_DATA(h), rights, count * sizeof(int));
    }
    assert(sendmsg(fd, &msg, MSG_NOSIGNAL) == 1);
}

static void malformed_rights(size_t count, int wrong_tag, int byte_only)
{
    PwNativeFdContext c = context(1000);
    PwNativeFdResult r = {0};
    int s[2] = {-1,-1}, rights[16], received = -1;
    int before = fd_count();
    assert(!pair_new(s, 0, &r));
    for (size_t i = 0; i < count; ++i) { rights[i] = dup(s[0]); assert(rights[i] >= 0); }
    int held = fd_count();
    send_many(s[0], wrong_tag ? TAG_REPLY : TAG_ENDPOINT, rights, count);
    if (byte_only) {
        unsigned char byte;
        assert(receive_chunk(s[1], &byte, 1, 0, NULL, &c, &r) < 0);
    } else assert(receive_right(s[1], TAG_ENDPOINT, &received, &c, &r) < 0);
    assert(r.status == PW_NATIVE_FD_PROTOCOL && received == -1);
    assert(fd_count() == held); /* all delivered duplicates, including extras, closed */
    for (size_t i = 0; i < count; ++i) close(rights[i]);
    close(s[0]); close(s[1]);
    assert(fd_count() == before);
}

static int cancelled(void *unused) { (void)unused; return 1; }
static int broken_clock(void *unused, uint64_t *out) { (void)unused; (void)out; return -37; }

static void bounded_failures(const char *path)
{
    PwNativeFdContext c = context(70);
    PwNativeFdListener l;
    PwNativeFdResult r;
    uint64_t start, end;
    int before = fd_count();
    assert(!pw_native_fd_parent_open(&l, path, &c, &r));
    assert(!now_ms(NULL, &start));
    assert(pw_native_fd_parent(&l, 1, &c, &r) == PW_NATIVE_FD_TIMEOUT);
    assert(r.stage == PW_NATIVE_FD_ACCEPT && !r.cleanup_failed);
    assert(!now_ms(NULL, &end)); assert(end - start < 2000);
    assert(access(path, F_OK) < 0 && fd_count() == before);
    c = context(1000);
    assert(!pw_native_fd_parent_open(&l, path, &c, &r));
    c.cancelled = cancelled;
    assert(pw_native_fd_parent(&l, 1, &c, &r) == PW_NATIVE_FD_CANCELLED);
    assert(access(path, F_OK) < 0 && fd_count() == before);
    c = context(1000); c.clock_ms = broken_clock;
    assert(pw_native_fd_worker(path, 1, &c, &r) == PW_NATIVE_FD_CLOCK && r.raw_result == -37);
    assert(fd_count() == before);
    c = context(1000);
    assert(pw_native_fd_worker(path, 1, &c, &r) == PW_NATIVE_FD_OS);
    assert(r.stage == PW_NATIVE_FD_CONNECT && fd_count() == before);
    assert(pw_native_fd_worker(path, 0, &c, &r) == PW_NATIVE_FD_INVALID);
    assert(pw_native_fd_worker("/tmp/../bad", 1, &c, &r) == PW_NATIVE_FD_INVALID);
}

static int scripted_clock(void *context, uint64_t *out)
{
    uint64_t **cursor = context;
    *out = *(*cursor)++;
    return 0;
}

/* Pure callback contract inventory; not a socket-denial workaround. */
static void clock_contract(void)
{
    uint64_t values[] = {100, 99}, *cursor = values;
    PwNativeFdContext c = { &cursor, scripted_clock, NULL, 200 };
    PwNativeFdResult r = {0};
    assert(!check(&c, &r, NULL));
    assert(check(&c, &r, NULL) < 0 && r.status == PW_NATIVE_FD_CLOCK);
    assert(r.last_clock_ms == 100 && r.raw_result == 0);
}

static void preserve_existing_path(const char *path)
{
    PwNativeFdContext c = context(1000);
    PwNativeFdListener l;
    PwNativeFdResult r;
    char data[4];
    int before = fd_count(), fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    assert(fd >= 0 && write(fd, "keep", 4) == 4);
    assert(pw_native_fd_parent_open(&l, path, &c, &r) == PW_NATIVE_FD_OS);
    assert(!l.bound && l.fd == -1 && lseek(fd, 0, SEEK_SET) == 0);
    assert(read(fd, data, 4) == 4 && !memcmp(data, "keep", 4));
    assert(!close(fd) && !unlink(path) && fd_count() == before);
}

int main(void)
{
    char directory[] = "/tmp/pw-fd-original-XXXXXX", path[PW_NATIVE_FD_PATH_CAP];
    assert(mkdtemp(directory));
    assert(snprintf(path, sizeof(path), "%s/r", directory) < (int)sizeof(path));
    clock_contract();
    roundtrip(path, 0);
    roundtrip(path, 1);
    malformed_rights(2, 0, 0); /* extra rights */
    malformed_rights(1, 1, 0); /* wrong tag still closes FD */
    malformed_rights(1, 0, 1); /* unexpected rights on byte frame */
    malformed_rights(0, 0, 0); /* missing rights */
    malformed_rights(16, 0, 0); /* truncated control and duplicate cleanup */
    bounded_failures(path);
    preserve_existing_path(path);
    assert(!rmdir(directory));
    puts("PASS Linux only: distinct processes; queued endpoint/rights; reverse transfer; EOF; malformed/truncated rights cleanup; deadline; cancellation; clock failure; existing path preserved.");
    puts("PS5/FreeBSD ABI and cross-context behavior: NOT RUN. Windows children: NOT TESTED.");
    return 0;
}
