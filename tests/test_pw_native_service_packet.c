/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Every socket/clock/close boundary is an original mock. No socket is opened. */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "../native/pw_native_service_packet.h"
static int mock_poll(struct pollfd *, nfds_t, int);
static int mock_type(int, int, int, void *, socklen_t *);
static ssize_t mock_send(int, const struct msghdr *, int);
static ssize_t mock_receive(int, struct msghdr *, int);
static int mock_close(int);
#define poll mock_poll
#define getsockopt mock_type
#define sendmsg mock_send
#define recvmsg mock_receive
#define close mock_close
#include "../native/pw_native_service_packet.c"
#undef poll
#undef getsockopt
#undef sendmsg
#undef recvmsg
#undef close

typedef struct Packet {
    unsigned char bytes[PW_NC_FRAME_BYTES];
    ssize_t length;
    int flags;
    short revents;
    _Alignas(struct cmsghdr) unsigned char control[CMSG_SPACE(16 * sizeof(int))];
    size_t control_length;
} Packet;
static struct {
    uint64_t now, poll_advance, io_advance;
    int clock_error, clock_reverse, cancelled, cancel_after_io;
    int type_rc, type; socklen_t type_length;
    int poll_rc, poll_calls, poll_unexpected, poll_zeros;
    int send_calls, receive_calls, type_calls, close_calls;
    ssize_t sent;
    int close_error, closed[32];
    Packet packets[8]; unsigned used, at;
    unsigned char sent_frames[8][PW_NC_FRAME_BYTES];
} m;
static PwNativeChildIo io;
static PwNativeServicePacketResult result;
static int clock_ms(void *unused, uint64_t *now)
{
    (void)unused;
    if (m.clock_error) return -1;
    *now = m.clock_reverse ? 0 : m.now;
    return 0;
}
static int cancelled(void *unused) { (void)unused; return m.cancelled; }
static long receive_callback(void *unused, void *bytes, size_t size, unsigned timeout)
{ (void)unused; (void)timeout; return pw_native_service_packet_receive(&io, 3, bytes, size, &result); }
static long send_callback(void *unused, const void *bytes, size_t size, unsigned timeout)
{ (void)unused; (void)timeout; return pw_native_service_packet_send(&io, 3, bytes, size, &result); }
static void reset(void)
{
    memset(&m, 0, sizeof(m)); memset(&io, 0, sizeof(io)); memset(&result, 0, sizeof(result));
    m.now = 100; m.type = SOCK_SEQPACKET; m.type_length = sizeof(int);
    m.poll_rc = 1; m.sent = PW_NC_FRAME_BYTES;
    io.clock_ms = clock_ms; io.cancelled = cancelled;
    io.receive = receive_callback; io.send = send_callback;
    assert(!pw_native_child_begin(&io));
}
static Packet *packet(ssize_t length, short revents)
{
    assert(m.used < 8); Packet *p = &m.packets[m.used++];
    p->length = length; p->revents = revents;
    for (size_t i = 0; i < sizeof(p->bytes); ++i) p->bytes[i] = (unsigned char)i;
    return p;
}
static int mock_poll(struct pollfd *p, nfds_t count, int timeout)
{
    assert(count == 1 && p->fd == 3 && timeout > 0 && timeout <= 25);
    ++m.poll_calls; m.now += m.poll_advance;
    if (m.poll_zeros) { --m.poll_zeros; return 0; }
    if (m.poll_rc != 1) { if (m.poll_rc < 0) errno = 13; return m.poll_rc; }
    p->revents = m.poll_unexpected ? POLLPRI :
        p->events == POLLOUT ? POLLOUT : m.packets[m.at].revents;
    return 1;
}
static int mock_type(int fd, int level, int option, void *value, socklen_t *size)
{
    assert(fd == 3 && level == SOL_SOCKET && option == SO_TYPE && *size == sizeof(int));
    ++m.type_calls; *(int *)value = m.type; *size = m.type_length;
    m.now += m.io_advance;
    if (m.type_rc < 0) errno = 22;
    return m.type_rc;
}
static ssize_t mock_send(int fd, const struct msghdr *msg, int flags)
{
    assert(fd == 3 && flags == (MSG_DONTWAIT | MSG_NOSIGNAL));
    assert(msg->msg_iovlen == 1 && msg->msg_iov[0].iov_len == PW_NC_FRAME_BYTES);
    assert(!msg->msg_name && !msg->msg_namelen && !msg->msg_control && !msg->msg_controllen);
    assert(m.send_calls < 8);
    memcpy(m.sent_frames[m.send_calls++], msg->msg_iov[0].iov_base, PW_NC_FRAME_BYTES);
    m.now += m.io_advance;
    if (m.cancel_after_io) m.cancelled = 1;
    if (m.sent < 0) errno = 13;
    return m.sent;
}
static ssize_t mock_receive(int fd, struct msghdr *msg, int flags)
{
    assert(fd == 3 && flags == MSG_DONTWAIT && m.at < m.used);
    assert(msg->msg_iovlen == 1 && msg->msg_iov[0].iov_len == PW_NC_FRAME_BYTES);
    assert(!msg->msg_name && !msg->msg_namelen);
    Packet *p = &m.packets[m.at++]; ++m.receive_calls;
    size_t capacity = msg->msg_controllen;
    memcpy(msg->msg_iov[0].iov_base, p->bytes, sizeof(p->bytes));
    memcpy(msg->msg_control, p->control, p->control_length < capacity ? p->control_length : capacity);
    msg->msg_controllen = (socklen_t)p->control_length; msg->msg_flags = p->flags;
    m.now += m.io_advance;
    if (m.cancel_after_io) m.cancelled = 1;
    if (p->length < 0) errno = 22;
    return p->length;
}
static int mock_close(int fd)
{
    assert(fd >= 0 && fd != 3 && m.close_calls < 32);
    m.closed[m.close_calls++] = fd;
    if (m.close_error) { errno = 9; return -1; }
    return 0;
}
static void rights(Packet *p, const int *fds, size_t count)
{
    struct cmsghdr h = {(socklen_t)CMSG_LEN(count * sizeof(int)), SOL_SOCKET, SCM_RIGHTS};
    memcpy(p->control, &h, sizeof(h));
    memcpy(p->control + CMSG_LEN(0), fds, count * sizeof(int));
    p->control_length = CMSG_SPACE(count * sizeof(int));
}
static long read_packet(size_t size)
{
    unsigned char bytes[PW_NC_FRAME_BYTES]; memset(bytes, 0xa5, sizeof(bytes));
    long rc = receive_callback(NULL, bytes, size, 999);
    if (rc < 0 || !rc) for (size_t i = 0; i < sizeof(bytes); ++i) assert(bytes[i] == 0xa5);
    return rc;
}
static void native_error_expected(int error)
{
#ifdef PW_NATIVE_CHILD_FREESTANDING
    (void)error; assert(!result.errno_valid && !result.native_error);
#else
    assert(result.errno_valid && result.native_error == error);
#endif
}
static void type_and_send(void)
{
    reset(); assert(!pw_native_service_packet_validate(&io, 3, &result));
    assert(result.socket_type == SOCK_SEQPACKET && result.socket_type_length == 4);
    reset(); m.type = 1; assert(pw_native_service_packet_validate(&io, 3, &result) < 0);
    assert(result.status == PW_NS_PACKET_PROTOCOL && !m.poll_calls);
    reset(); m.type_length = 3; assert(pw_native_service_packet_validate(&io, 3, &result) < 0);
    reset(); m.type_rc = -1; assert(pw_native_service_packet_validate(&io, 3, &result) < 0);
    native_error_expected(22);
    reset(); m.io_advance = PW_NC_STAGE_MS; assert(pw_native_service_packet_validate(&io, 3, &result) < 0);
    assert(result.status == PW_NS_PACKET_BUDGET);
    unsigned char bytes[PW_NC_FRAME_BYTES] = {0};
    reset(); assert(send_callback(NULL, bytes, sizeof(bytes), 1) == PW_NC_FRAME_BYTES);
    const ssize_t bad[] = {-1, 0, 1, 95, 97};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        reset(); m.sent = bad[i]; errno = EINTR;
        assert(pw_native_child_send(&io, bytes, sizeof(bytes)) < 0 && m.send_calls == 1);
#ifndef PW_NATIVE_CHILD_FREESTANDING
        assert(errno != EINTR);
#endif
        if (bad[i] < 0) native_error_expected(13);
        else assert(!result.errno_valid);
    }
    reset(); assert(send_callback(NULL, bytes, 1, 1) < 0 && !m.send_calls);
}
static void packet_boundaries(void)
{
    reset(); packet(96, POLLIN); assert(read_packet(96) == 96 && m.receive_calls == 1);
    reset(); packet(96, POLLIN)->flags = MSG_EOR; assert(read_packet(96) == 96);
    reset(); packet(96, POLLIN)->flags = MSG_EOR | MSG_DONTWAIT; assert(read_packet(96) == 96);
    for (int length = 0; length < 96; ++length) {
        reset(); packet(length, POLLIN); assert(read_packet(96) < 0 && m.receive_calls == 1);
    }
    reset(); packet(97, POLLIN); assert(read_packet(96) < 0);
    const int bad_flags[] = {MSG_TRUNC, MSG_CTRUNC, MSG_TRUNC | MSG_EOR, 0x40000000};
    for (size_t i = 0; i < sizeof(bad_flags) / sizeof(bad_flags[0]); ++i) {
        reset(); packet(96, POLLIN)->flags = bad_flags[i]; assert(read_packet(96) < 0);
    }
    for (int length = 1; length <= 97; ++length) {
        reset(); packet(length, POLLIN | POLLHUP); assert(read_packet(1) < 0 && m.receive_calls == 1);
    }
    reset(); packet(0, POLLIN); assert(read_packet(1) < 0 && result.channel_zero_observed);
    reset(); packet(0, POLLHUP)->flags = MSG_EOR; assert(read_packet(1) < 0);
    reset(); packet(0, POLLHUP); assert(read_packet(1) == 0);
    assert(result.channel_zero_observed && result.hangup_observed);
    reset(); packet(0, POLLHUP)->flags = MSG_DONTWAIT; assert(read_packet(1) == 0);
}
static void ancillary_ownership(void)
{
    int descriptors[] = {7, 8, 7};
    reset(); rights(packet(96, POLLIN), descriptors, 3);
    assert(read_packet(96) < 0 && m.close_calls == 2 && result.rights_closed == 2 && result.ownership_uncertain);
    reset(); rights(packet(96, POLLIN), descriptors, 2); m.close_error = 1;
    assert(read_packet(96) < 0 && m.close_calls == 2 && result.cleanup_failed && !result.rights_closed);
#ifdef PW_NATIVE_CHILD_FREESTANDING
    assert(!result.cleanup_errno_valid && !result.cleanup_native_error && !result.errno_valid);
#else
    assert(result.cleanup_errno_valid && result.cleanup_native_error == 9 && !result.errno_valid);
#endif
    reset(); Packet *p = packet(96, POLLIN); rights(p, descriptors, 2); p->flags = MSG_CTRUNC;
    assert(read_packet(96) < 0 && m.close_calls == 2 && result.ownership_uncertain);
    reset(); p = packet(96, POLLIN); rights(p, descriptors, 2); m.io_advance = PW_NC_STAGE_MS;
    assert(read_packet(96) < 0 && m.close_calls == 2 && result.status == PW_NS_PACKET_PROTOCOL);
    reset(); p = packet(96, POLLIN); rights(p, descriptors, 2); m.cancel_after_io = 1;
    assert(read_packet(96) < 0 && m.close_calls == 2 && result.status == PW_NS_PACKET_PROTOCOL);
    reset(); p = packet(96, POLLIN); rights(p, descriptors, 2);
    ((struct cmsghdr *)(void *)p->control)->cmsg_len = CMSG_LEN(sizeof(int)) + 1;
    assert(read_packet(96) < 0 && !m.close_calls && result.ownership_uncertain);
    reset(); p = packet(96, POLLIN); rights(p, descriptors, 2);
    ((struct cmsghdr *)(void *)p->control)->cmsg_len = 999;
    assert(read_packet(96) < 0 && !m.close_calls && result.ownership_uncertain);
    reset(); p = packet(96, POLLIN); rights(p, descriptors, 2); p->control_length = 999;
    assert(read_packet(96) < 0 && m.close_calls == 2 && result.ownership_uncertain);
    reset(); int invalid[] = {-1, 3}; rights(packet(96, POLLIN), invalid, 2);
    assert(read_packet(96) < 0 && !m.close_calls && result.ownership_uncertain);
    reset(); p = packet(0, POLLHUP); rights(p, descriptors, 2);
    assert(read_packet(1) < 0 && m.close_calls == 2 && !result.channel_zero_observed);
}
static void deadlines(void)
{
    reset(); packet(96, POLLIN); m.now = io.stage_end; assert(read_packet(96) < 0 && !m.poll_calls);
    reset(); packet(96, POLLIN); m.poll_advance = PW_NC_STAGE_MS;
    assert(read_packet(96) < 0 && !m.receive_calls);
    reset(); packet(96, POLLIN); m.io_advance = PW_NC_STAGE_MS;
    assert(read_packet(96) < 0 && result.status == PW_NS_PACKET_BUDGET);
    reset(); packet(0, POLLHUP); m.io_advance = PW_NC_STAGE_MS;
    assert(read_packet(1) < 0 && !result.channel_zero_observed);
    reset(); packet(96, POLLIN); m.poll_zeros = 1000; m.poll_advance = 25;
    assert(read_packet(96) < 0 && m.poll_calls == PW_NC_STAGE_MS / 25 && !m.receive_calls);
    reset(); packet(96, POLLIN); m.clock_reverse = 1; assert(read_packet(96) < 0 && !m.poll_calls);
    reset(); packet(96, POLLIN); m.clock_error = 1; assert(read_packet(96) < 0 && !m.poll_calls);
    reset(); packet(96, POLLIN); m.cancelled = 1; assert(read_packet(96) < 0 && !m.poll_calls);
    reset(); packet(96, POLLIN); m.cancel_after_io = 1; assert(read_packet(96) < 0);
    reset(); packet(96, POLLIN); m.poll_rc = -1; assert(read_packet(96) < 0 && !m.receive_calls);
    native_error_expected(13);
    reset(); packet(96, POLLIN); m.poll_rc = 2; assert(read_packet(96) < 0 && !m.receive_calls);
    reset(); packet(96, POLLIN); m.poll_unexpected = 1; assert(read_packet(96) < 0 && !m.receive_calls);
    reset(); packet(-1, POLLIN); errno = EINTR;
    unsigned char wire[96]; assert(pw_native_child_receive(&io, wire, sizeof(wire)) < 0 && m.receive_calls == 1);
    native_error_expected(22);
    reset(); packet(96, POLLNVAL); assert(read_packet(96) < 0 && !m.receive_calls);
    reset(); packet(96, POLLERR); assert(read_packet(96) < 0 && !m.receive_calls);
}
static PwNativeChildFrame frame(unsigned kind, unsigned sequence)
{
    PwNativeChildFrame f = {0}; f.kind = kind; f.sequence = sequence;
    f.parent_pid = 17; f.child_pid = 42; f.child_ppid = 7;
    f.correlation = 19; memcpy(f.build_id, "service-fixture", 16); return f;
}
static void engine_flow(void)
{
    reset(); PwNativeChildFrame f = frame(PW_NC_HELLO, 0); f.parent_pid = 0; f.correlation = 0;
    assert(!pw_native_child_encode(packet(96, POLLIN)->bytes, &f));
    for (unsigned i = 1; i <= 4; ++i) {
        f = frame(i == 4 ? PW_NC_STOP_ACK : PW_NC_ECHO_REPLY, i);
        assert(!pw_native_child_encode(packet(96, POLLIN)->bytes, &f));
    }
    packet(0, POLLHUP);
    PwNativeChildResult child;
    assert(!pw_native_child_parent(&io, 17, 19, "service-fixture", &child));
    assert(child.echoes == 3 && child.stop_ack && child.stream_closed && child.child_ppid == 7);
    assert(m.receive_calls == 6 && m.send_calls == 4 && result.channel_zero_observed);
    /* Child PPID7 differs from parent17. Existing contract deliberately accepts it. */
}
int main(void)
{
    type_and_send(); packet_boundaries(); ancillary_ownership(); deadlines(); engine_flow();
    puts("service packet mocks passed: strict records, ancillary ownership, deadlines, channel-zero scope; no native operations");
    return 0;
}
