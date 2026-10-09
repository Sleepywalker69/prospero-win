/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_native_fd_probe.h"
#include <stddef.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <unistd.h>

#if !defined(__linux__) && !defined(__FreeBSD__) && !defined(__PROSPERO__)
#error "Review sockaddr_un and no-SIGPIPE ABI before adding a platform"
#endif

enum { TAG_QUEUED = 0x51, TAG_ENDPOINT = 0x52, TAG_REPLY = 0x53,
       HELLO_BYTES = 24, DATA_BYTES = 16, CONTROL_FDS = 8 };

static void zero_bytes(void *p, size_t n)
{
    unsigned char *out = p;
    while (n--) *out++ = 0;
}

static void put32(unsigned char *p, uint32_t n)
{
    for (unsigned i = 0; i < 4; ++i) p[i] = (unsigned char)(n >> (i * 8));
}

static void put64(unsigned char *p, uint64_t n)
{
    for (unsigned i = 0; i < 8; ++i) p[i] = (unsigned char)(n >> (i * 8));
}

static uint32_t get32(const unsigned char *p)
{
    uint32_t n = 0;
    for (unsigned i = 0; i < 4; ++i) n |= (uint32_t)p[i] << (i * 8);
    return n;
}

static uint64_t get64(const unsigned char *p)
{
    uint64_t n = 0;
    for (unsigned i = 0; i < 8; ++i) n |= (uint64_t)p[i] << (i * 8);
    return n;
}

static int fail(PwNativeFdResult *r, PwNativeFdStatus status, int64_t raw)
{
    if (r->status == PW_NATIVE_FD_OK) {
        r->status = status;
        r->raw_result = raw;
    }
    return -1;
}

static void api(PwNativeFdResult *r, PwNativeFdApi which)
{
    if (r->status == PW_NATIVE_FD_OK) r->api = which;
}

static void close_owned(int *fd, PwNativeFdResult *r)
{
    int rc;
    if (*fd < 0) return;
    api(r, PW_NATIVE_FD_API_CLOSE);
    rc = close(*fd);
    *fd = -1; /* never retry close: the number may already have been released */
    if (rc < 0) {
        r->cleanup_failed = 1;
        if (r->status == PW_NATIVE_FD_OK) r->stage = PW_NATIVE_FD_CLEANUP;
        fail(r, PW_NATIVE_FD_OS, rc);
    }
}

static int check(const PwNativeFdContext *c, PwNativeFdResult *r, int *slice)
{
    uint64_t now;
    int rc;
    if (!c || !c->clock_ms) return fail(r, PW_NATIVE_FD_INVALID, 0);
    if (c->cancelled && c->cancelled(c->context)) return fail(r, PW_NATIVE_FD_CANCELLED, 0);
    api(r, PW_NATIVE_FD_API_CLOCK);
    rc = c->clock_ms(c->context, &now);
    if (rc != 0) return fail(r, PW_NATIVE_FD_CLOCK, rc);
    if (r->clock_observed && now < r->last_clock_ms)
        return fail(r, PW_NATIVE_FD_CLOCK, 0);
    r->clock_observed = 1;
    r->last_clock_ms = now;
    if (now >= c->deadline_ms) return fail(r, PW_NATIVE_FD_TIMEOUT, 0);
    if (slice) {
        uint64_t left = c->deadline_ms - now;
        *slice = left > 25 ? 25 : (int)left;
    }
    return 0;
}

static int wait_ready(int fd, short events, const PwNativeFdContext *c, PwNativeFdResult *r)
{
    for (;;) {
        struct pollfd p = { fd, events, 0 };
        int slice, rc;
        if (check(c, r, &slice)) return -1;
        api(r, PW_NATIVE_FD_API_POLL);
        rc = poll(&p, 1, slice);
        if (rc < 0) return fail(r, PW_NATIVE_FD_OS, rc);
        if (!rc) continue;
        if (check(c, r, NULL)) return -1;
        api(r, PW_NATIVE_FD_API_POLL);
        if (p.revents & POLLNVAL) return fail(r, PW_NATIVE_FD_OS, p.revents);
        /* HUP/ERR are consumed by the next bounded nonblocking operation. */
        if (p.revents & (events | POLLHUP | POLLERR)) return 0;
        return fail(r, PW_NATIVE_FD_PROTOCOL, p.revents);
    }
}

static int prepare(int fd, PwNativeFdResult *r)
{
    int rc;
    api(r, PW_NATIVE_FD_API_FCNTL);
    rc = fcntl(fd, F_GETFD);
    if (rc < 0) return fail(r, PW_NATIVE_FD_OS, rc);
    rc = fcntl(fd, F_SETFD, rc | FD_CLOEXEC);
    if (rc < 0) return fail(r, PW_NATIVE_FD_OS, rc);
    rc = fcntl(fd, F_GETFL);
    if (rc < 0) return fail(r, PW_NATIVE_FD_OS, rc);
    rc = fcntl(fd, F_SETFL, rc | O_NONBLOCK);
    if (rc < 0) return fail(r, PW_NATIVE_FD_OS, rc);
#if defined(__FreeBSD__) || defined(__PROSPERO__)
    {
        int one = 1;
        api(r, PW_NATIVE_FD_API_SETSOCKOPT);
        rc = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
        if (rc < 0) return fail(r, PW_NATIVE_FD_OS, rc);
    }
#elif !defined(MSG_NOSIGNAL)
#error "Linux transport requires MSG_NOSIGNAL"
#endif
    return 0;
}

static int send_flags(void)
{
#ifdef __linux__
    return MSG_NOSIGNAL;
#else
    return 0; /* prepare() checked SO_NOSIGPIPE */
#endif
}

static int address(const char *path, struct sockaddr_un *a, socklen_t *size, PwNativeFdResult *r)
{
    size_t n = 0;
    if (!path || path[0] != '/') return fail(r, PW_NATIVE_FD_INVALID, 0);
    while (n < PW_NATIVE_FD_PATH_CAP && path[n]) ++n;
    if (!n || n >= PW_NATIVE_FD_PATH_CAP || n + 1 > sizeof(a->sun_path))
        return fail(r, PW_NATIVE_FD_INVALID, 0);
    /* The caller owns the directory. Reject lexical escapes/control bytes. */
    for (size_t i = 0; i < n; ++i) {
        if ((unsigned char)path[i] < 32 || path[i] == 127) return fail(r, PW_NATIVE_FD_INVALID, 0);
        if (path[i] == '/' && (path[i + 1] == '/' || !path[i + 1] ||
            (path[i + 1] == '.' && (!path[i + 2] || path[i + 2] == '/' ||
             (path[i + 2] == '.' && (!path[i + 3] || path[i + 3] == '/'))))))
            return fail(r, PW_NATIVE_FD_INVALID, 0);
    }
    zero_bytes(a, sizeof(*a));
    a->sun_family = AF_UNIX;
    for (size_t i = 0; i <= n; ++i) a->sun_path[i] = path[i];
    *size = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + n + 1);
#if defined(__FreeBSD__) || defined(__PROSPERO__)
    a->sun_len = (unsigned char)*size;
#endif
    return 0;
}

static int socket_new(PwNativeFdResult *r)
{
    int fd;
    api(r, PW_NATIVE_FD_API_SOCKET);
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { fail(r, PW_NATIVE_FD_OS, fd); return -1; }
    if (prepare(fd, r)) close_owned(&fd, r);
    return fd;
}

static int pair_new(int pair[2], int pipe_shape, PwNativeFdResult *r)
{
    int rc;
    api(r, PW_NATIVE_FD_API_SOCKETPAIR);
    rc = socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
    if (rc < 0) return fail(r, PW_NATIVE_FD_OS, rc);
    if (prepare(pair[0], r) || prepare(pair[1], r)) return -1;
    if (pipe_shape) {
        api(r, PW_NATIVE_FD_API_SHUTDOWN);
        rc = shutdown(pair[0], SHUT_WR);
        if (rc < 0) return fail(r, PW_NATIVE_FD_OS, rc);
        rc = shutdown(pair[1], SHUT_RD);
        if (rc < 0) return fail(r, PW_NATIVE_FD_OS, rc);
    }
    return 0;
}

static int send_data(int fd, const void *bytes, size_t length,
                     const PwNativeFdContext *c, PwNativeFdResult *r)
{
    const unsigned char *p = bytes;
    while (length) {
        struct iovec iov = { (void *)p, length };
        struct msghdr msg;
        ssize_t sent;
        if (wait_ready(fd, POLLOUT, c, r)) return -1;
        zero_bytes(&msg, sizeof(msg));
        msg.msg_iov = &iov; msg.msg_iovlen = 1;
        api(r, PW_NATIVE_FD_API_SENDMSG);
        sent = sendmsg(fd, &msg, send_flags());
        if (sent < 0) return fail(r, PW_NATIVE_FD_OS, sent);
        if (check(c, r, NULL)) return -1;
        if (!sent || (size_t)sent > length) return fail(r, PW_NATIVE_FD_PROTOCOL, sent);
        p += sent; length -= (size_t)sent;
    }
    return 0;
}

static int send_right(int fd, unsigned char tag, int right,
                      const PwNativeFdContext *c, PwNativeFdResult *r)
{
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } control;
    struct iovec iov = { &tag, 1 };
    struct msghdr msg;
    struct cmsghdr *h;
    ssize_t sent;
    if (wait_ready(fd, POLLOUT, c, r)) return -1;
    zero_bytes(&msg, sizeof(msg)); zero_bytes(&control, sizeof(control));
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    msg.msg_control = control.bytes; msg.msg_controllen = sizeof(control.bytes);
    h = CMSG_FIRSTHDR(&msg);
    h->cmsg_len = CMSG_LEN(sizeof(int)); h->cmsg_level = SOL_SOCKET; h->cmsg_type = SCM_RIGHTS;
    /* CMSG_DATA is SDK-aligned; native int is the documented FD payload. */
    *(int *)(void *)CMSG_DATA(h) = right;
    api(r, PW_NATIVE_FD_API_SENDMSG);
    sent = sendmsg(fd, &msg, send_flags());
    if (sent < 0) return fail(r, PW_NATIVE_FD_OS, sent);
    if (sent != 1) return fail(r, PW_NATIVE_FD_PROTOCOL, sent);
    return check(c, r, NULL);
}

/* Every receive reads ancillary data, even a byte-only frame, so unexpected
 * descriptors are explicitly closed. No errno, MSG_PEEK or CMSG_CLOEXEC ABI. */
static ssize_t receive_chunk(int fd, void *bytes, size_t length, int want_right, int *right,
                             const PwNativeFdContext *c, PwNativeFdResult *r)
{
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(CONTROL_FDS * sizeof(int))]; } control;
    struct iovec iov = { bytes, length };
    struct msghdr msg;
    struct cmsghdr *h;
    int rights[CONTROL_FDS], count = 0, bad = 0;
    ssize_t got;
    if (right) *right = -1;
    if (wait_ready(fd, POLLIN, c, r)) return -1;
    zero_bytes(&msg, sizeof(msg)); zero_bytes(&control, sizeof(control));
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    msg.msg_control = control.bytes; msg.msg_controllen = sizeof(control.bytes);
    api(r, PW_NATIVE_FD_API_RECVMSG);
    got = recvmsg(fd, &msg, 0);
    if (got < 0) { fail(r, PW_NATIVE_FD_OS, got); return -1; }
    if (msg.msg_controllen > sizeof(control.bytes) ||
        (msg.msg_controllen && msg.msg_controllen < CMSG_LEN(0))) bad = 1;
    else for (h = CMSG_FIRSTHDR(&msg); h; h = CMSG_NXTHDR(&msg, h)) {
        size_t at = (size_t)((unsigned char *)(void *)h - control.bytes);
        size_t payload;
        if (at > msg.msg_controllen || msg.msg_controllen - at < sizeof(*h) ||
            h->cmsg_len < CMSG_LEN(0) || h->cmsg_len > msg.msg_controllen - at) {
            bad = 1; break;
        }
        payload = h->cmsg_len - CMSG_LEN(0);
        if (h->cmsg_level != SOL_SOCKET || h->cmsg_type != SCM_RIGHTS) { bad = 1; continue; }
        if (payload % sizeof(int)) bad = 1;
        for (size_t i = 0; i < payload / sizeof(int); ++i) {
            int delivered = ((int *)(void *)CMSG_DATA(h))[i];
            if (count < CONTROL_FDS) rights[count++] = delivered;
            else { bad = 1; close_owned(&delivered, r); }
        }
    }
    if (msg.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) bad = 1;
    if ((size_t)got > length || count != want_right || (want_right && got != 1)) bad = 1;
    if (bad || r->status != PW_NATIVE_FD_OK) {
        fail(r, PW_NATIVE_FD_PROTOCOL, got);
        for (int i = 0; i < count; ++i) close_owned(&rights[i], r);
        return -1;
    }
    if (want_right) {
        *right = rights[0];
        if (prepare(*right, r)) { close_owned(right, r); return -1; }
    }
    /* recvmsg may have installed FDs even if readiness arrived after the
     * deadline. Always parse/close them before returning a clock/Stop error. */
    if (check(c, r, NULL)) {
        if (want_right) close_owned(right, r);
        return -1;
    }
    return got;
}

static int receive_data(int fd, void *bytes, size_t length,
                        const PwNativeFdContext *c, PwNativeFdResult *r)
{
    unsigned char *p = bytes;
    while (length) {
        ssize_t got = receive_chunk(fd, p, length, 0, NULL, c, r);
        if (got < 0) return -1;
        if (!got) return fail(r, PW_NATIVE_FD_EOF, 0);
        p += got; length -= (size_t)got;
    }
    return 0;
}

static int receive_right(int fd, unsigned char expected, int *right,
                         const PwNativeFdContext *c, PwNativeFdResult *r)
{
    unsigned char tag = 0;
    ssize_t got = receive_chunk(fd, &tag, 1, 1, right, c, r);
    if (got < 0) return -1;
    if (got != 1 || tag != expected) {
        fail(r, PW_NATIVE_FD_PROTOCOL, got);
        close_owned(right, r);
        return -1;
    }
    return 0;
}

static void data_frame(unsigned char p[DATA_BYTES], uint64_t correlation, uint32_t direction)
{
    put64(p, correlation); put32(p + 8, direction); put32(p + 12, 0x31444650u);
}

static int data_and_eof(int fd, uint64_t correlation, uint32_t direction,
                        const PwNativeFdContext *c, PwNativeFdResult *r)
{
    unsigned char data[DATA_BYTES], last;
    ssize_t got;
    if (receive_data(fd, data, sizeof(data), c, r)) return -1;
    if (get64(data) != correlation || get32(data + 8) != direction || get32(data + 12) != 0x31444650u)
        return fail(r, PW_NATIVE_FD_PROTOCOL, 0);
    got = receive_chunk(fd, &last, 1, 0, NULL, c, r);
    if (got < 0) return -1;
    return got == 0 ? 0 : fail(r, PW_NATIVE_FD_PROTOCOL, got);
}

static int hello(int fd, uint64_t correlation, const PwNativeFdContext *c, PwNativeFdResult *r)
{
    unsigned char own[HELLO_BYTES], peer[HELLO_BYTES];
    pid_t pid;
    api(r, PW_NATIVE_FD_API_GETPID);
    pid = getpid();
    if (pid <= 0) return fail(r, PW_NATIVE_FD_OS, pid);
    r->local_pid = (uint32_t)pid;
    zero_bytes(own, sizeof(own));
    put32(own, 0x31444650u); put32(own + 4, 1); put64(own + 8, correlation); put32(own + 16, r->local_pid);
    if (send_data(fd, own, sizeof(own), c, r) || receive_data(fd, peer, sizeof(peer), c, r)) return -1;
    if (get32(peer) != 0x31444650u || get32(peer + 4) != 1 || get64(peer + 8) != correlation ||
        !get32(peer + 16) || get32(peer + 16) == r->local_pid || get32(peer + 20))
        return fail(r, PW_NATIVE_FD_PROTOCOL, 0);
    r->reported_peer_pid = get32(peer + 16);
    r->observations |= PW_NATIVE_FD_HELLO_OK;
    return 0;
}

void pw_native_fd_dispose(PwNativeFdListener *l, PwNativeFdResult *r)
{
    int rc;
    if (!l || !r) return;
    close_owned(&l->fd, r);
    if (!l->bound) return;
    l->bound = 0;
    api(r, PW_NATIVE_FD_API_UNLINK);
    rc = unlink(l->path);
    if (rc < 0) {
        r->cleanup_failed = 1;
        if (r->status == PW_NATIVE_FD_OK) r->stage = PW_NATIVE_FD_CLEANUP;
        fail(r, PW_NATIVE_FD_OS, rc);
    }
}

int pw_native_fd_parent_open(PwNativeFdListener *l, const char *path,
                            const PwNativeFdContext *c, PwNativeFdResult *r)
{
    struct sockaddr_un a;
    socklen_t size;
    int rc;
    if (!r) return PW_NATIVE_FD_INVALID;
    zero_bytes(r, sizeof(*r));
    if (!l) { fail(r, PW_NATIVE_FD_INVALID, 0); return r->status; }
    zero_bytes(l, sizeof(*l)); l->fd = -1;
    if (check(c, r, NULL) || address(path, &a, &size, r)) return r->status;
    r->stage = PW_NATIVE_FD_LISTEN;
    if ((l->fd = socket_new(r)) < 0) return r->status;
    api(r, PW_NATIVE_FD_API_BIND);
    rc = bind(l->fd, (struct sockaddr *)(void *)&a, size);
    if (rc < 0) { fail(r, PW_NATIVE_FD_OS, rc); goto done; }
    l->bound = 1;
    for (size_t i = 0; i < PW_NATIVE_FD_PATH_CAP; ++i) {
        l->path[i] = path[i]; if (!path[i]) break;
    }
    api(r, PW_NATIVE_FD_API_LISTEN);
    rc = listen(l->fd, 1);
    if (rc < 0) { fail(r, PW_NATIVE_FD_OS, rc); goto done; }
    if (check(c, r, NULL)) goto done;
    l->last_clock_ms = r->last_clock_ms;
    return PW_NATIVE_FD_OK;
done:
    pw_native_fd_dispose(l, r);
    return r->status;
}

int pw_native_fd_parent(PwNativeFdListener *l, uint64_t correlation,
                       const PwNativeFdContext *c, PwNativeFdResult *r)
{
    int control = -1, s[2] = {-1, -1}, p[2] = {-1, -1}, reply = -1;
    unsigned char frame[DATA_BYTES];
    if (!r) return PW_NATIVE_FD_INVALID;
    zero_bytes(r, sizeof(*r));
    if (!l || l->fd < 0 || !l->bound || !correlation) {
        fail(r, PW_NATIVE_FD_INVALID, 0); goto done;
    }
    r->last_clock_ms = l->last_clock_ms;
    r->clock_observed = 1;
    r->stage = PW_NATIVE_FD_ACCEPT;
    if (wait_ready(l->fd, POLLIN, c, r)) goto done;
    api(r, PW_NATIVE_FD_API_ACCEPT);
    control = accept(l->fd, NULL, NULL);
    if (control < 0) { fail(r, PW_NATIVE_FD_OS, control); goto done; }
    if (prepare(control, r)) goto done;
    r->observations |= PW_NATIVE_FD_CONNECTED;
    r->stage = PW_NATIVE_FD_HELLO;
    if (hello(control, correlation, c, r)) goto done;
    r->stage = PW_NATIVE_FD_QUEUE;
    if (pair_new(s, 0, r) || pair_new(p, 1, r) || send_right(s[1], TAG_QUEUED, p[1], c, r)) goto done;
    close_owned(&p[1], r);
    if (r->status) goto done;
    r->stage = PW_NATIVE_FD_HANDOFF;
    if (send_right(control, TAG_ENDPOINT, s[0], c, r)) goto done;
    close_owned(&s[0], r);
    if (r->status) goto done;
    r->stage = PW_NATIVE_FD_FORWARD;
    if (data_and_eof(p[0], correlation, 1, c, r)) goto done;
    r->observations |= PW_NATIVE_FD_QUEUED_RIGHT_OK | PW_NATIVE_FD_FORWARD_OK | PW_NATIVE_FD_FORWARD_EOF;
    close_owned(&p[0], r);
    if (r->status) goto done;
    r->stage = PW_NATIVE_FD_REVERSE;
    if (receive_right(s[1], TAG_REPLY, &reply, c, r)) goto done;
    data_frame(frame, correlation, 2);
    if (send_data(reply, frame, sizeof(frame), c, r)) goto done;
    close_owned(&reply, r);
    if (r->status) goto done;
    r->stage = PW_NATIVE_FD_FINISH;
    if (receive_data(control, frame, sizeof(frame), c, r)) goto done;
    if (get64(frame) != correlation || get32(frame + 8) != 3 || get32(frame + 12) != 0x31444650u) {
        fail(r, PW_NATIVE_FD_PROTOCOL, 0); goto done;
    }
    r->observations |= PW_NATIVE_FD_REVERSE_OK;
    r->peer_observations |= PW_NATIVE_FD_REVERSE_EOF;
done:
    close_owned(&reply, r); close_owned(&p[0], r); close_owned(&p[1], r);
    close_owned(&s[0], r); close_owned(&s[1], r); close_owned(&control, r);
    if (l) pw_native_fd_dispose(l, r);
    if (!r->status) (void)check(c, r, NULL);
    if (!r->status) { r->stage = PW_NATIVE_FD_COMPLETE; r->api = PW_NATIVE_FD_API_NONE; r->observations |= PW_NATIVE_FD_COMPLETED; }
    return r->status;
}

int pw_native_fd_worker(const char *path, uint64_t correlation,
                       const PwNativeFdContext *c, PwNativeFdResult *r)
{
    struct sockaddr_un a;
    socklen_t size;
    int control = -1, endpoint = -1, writer = -1, q[2] = {-1, -1}, rc;
    unsigned char frame[DATA_BYTES];
    if (!r) return PW_NATIVE_FD_INVALID;
    zero_bytes(r, sizeof(*r));
    if (!correlation) { fail(r, PW_NATIVE_FD_INVALID, 0); goto done; }
    if (check(c, r, NULL) || address(path, &a, &size, r)) goto done;
    r->stage = PW_NATIVE_FD_CONNECT;
    if ((control = socket_new(r)) < 0) goto done;
    /* Nonblocking AF_UNIX: negative result, even EINPROGRESS, fails closed. */
    api(r, PW_NATIVE_FD_API_CONNECT);
    rc = connect(control, (struct sockaddr *)(void *)&a, size);
    if (rc < 0) { fail(r, PW_NATIVE_FD_OS, rc); goto done; }
    r->observations |= PW_NATIVE_FD_CONNECTED;
    r->stage = PW_NATIVE_FD_HELLO;
    if (hello(control, correlation, c, r)) goto done;
    r->stage = PW_NATIVE_FD_HANDOFF;
    if (receive_right(control, TAG_ENDPOINT, &endpoint, c, r)) goto done;
    r->stage = PW_NATIVE_FD_QUEUE;
    if (receive_right(endpoint, TAG_QUEUED, &writer, c, r)) goto done;
    r->observations |= PW_NATIVE_FD_QUEUED_RIGHT_OK;
    r->stage = PW_NATIVE_FD_FORWARD;
    data_frame(frame, correlation, 1);
    if (send_data(writer, frame, sizeof(frame), c, r)) goto done;
    close_owned(&writer, r);
    if (r->status) goto done;
    r->observations |= PW_NATIVE_FD_FORWARD_OK;
    r->stage = PW_NATIVE_FD_REVERSE;
    if (pair_new(q, 1, r) || send_right(endpoint, TAG_REPLY, q[1], c, r)) goto done;
    close_owned(&q[1], r);
    if (r->status || data_and_eof(q[0], correlation, 2, c, r)) goto done;
    r->observations |= PW_NATIVE_FD_REVERSE_OK | PW_NATIVE_FD_REVERSE_EOF;
    close_owned(&q[0], r);
    if (r->status) goto done;
    r->stage = PW_NATIVE_FD_FINISH;
    data_frame(frame, correlation, 3);
    if (send_data(control, frame, sizeof(frame), c, r)) goto done;
done:
    close_owned(&q[0], r); close_owned(&q[1], r); close_owned(&writer, r);
    close_owned(&endpoint, r); close_owned(&control, r);
    if (!r->status) (void)check(c, r, NULL);
    if (!r->status) { r->stage = PW_NATIVE_FD_COMPLETE; r->api = PW_NATIVE_FD_API_NONE; r->observations |= PW_NATIVE_FD_COMPLETED; }
    return r->status;
}
