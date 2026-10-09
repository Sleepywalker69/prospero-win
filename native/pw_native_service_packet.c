/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Original strict packet adapter; ordinary SDK/POSIX calls only. */
#include "pw_native_service_packet.h"
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#if !defined(MSG_DONTWAIT) || !defined(MSG_NOSIGNAL) || !defined(MSG_EOR)
#error Reviewed per-message nonblocking, no-SIGPIPE and record flags required
#endif
enum { CONTROL_FDS = 16, POLL_SLICE_MS = 25 };

static int reject(PwNativeServicePacketResult *r, int status, int api, int64_t raw)
{
    if (r && !r->status) {
        r->status = status; r->api = api; r->raw_result = raw;
    }
#ifndef PW_NATIVE_CHILD_FREESTANDING
    /* Prevent the shared engine from retrying a stale EINTR. The worker has
     * no errno import; its shared engine uses its own private error slot. */
    errno = status == PW_NS_PACKET_INVALID ? EINVAL :
            status == PW_NS_PACKET_PROTOCOL ? EPROTO : EIO;
#endif
    return -1;
}
static int os_failure(PwNativeServicePacketResult *r, int api, int64_t raw)
{
#ifndef PW_NATIVE_CHILD_FREESTANDING
    /* Read immediately after the failing call, before reject changes errno. */
    int native_error = errno;
    if (r && !r->status && raw < 0) { r->native_error = native_error; r->errno_valid = 1; }
#endif
    return reject(r, PW_NS_PACKET_OS, api, raw);
}
static int budget(PwNativeChildIo *io, PwNativeServicePacketResult *r, unsigned *left)
{
    unsigned remaining;
    if (pw_native_child_remaining(io, &remaining)) {
        if (r && !r->status) {
            r->status = PW_NS_PACKET_BUDGET;
            r->api = PW_NS_PACKET_API_BUDGET; r->raw_result = -1;
        }
        return -1;
    }
    if (left) *left = remaining;
    return 0;
}
static int arguments(PwNativeChildIo *io, int fd, PwNativeServicePacketResult *r)
{
    if (!r || !io || !io->ready || !io->clock_ms || fd < 0)
        return reject(r, PW_NS_PACKET_INVALID, PW_NS_PACKET_API_NONE, fd);
    if (r->status) return reject(r, r->status, r->api, r->raw_result);
    return budget(io, r, NULL);
}
static int wait_ready(PwNativeChildIo *io, int fd, int writing,
                      PwNativeServicePacketResult *r, short *observed)
{
    for (;;) {
        unsigned left;
        struct pollfd p = {fd, writing ? POLLOUT : POLLIN, 0};
        if (budget(io, r, &left)) return -1;
        int timeout = (int)(left < POLL_SLICE_MS ? left : POLL_SLICE_MS);
        int rc = poll(&p, 1, timeout);
        r->poll_revents = (uint32_t)(unsigned short)p.revents;
        if (rc < 0) return os_failure(r, PW_NS_PACKET_API_POLL, rc);
        if (rc > 1 || (!rc && p.revents))
            return reject(r, PW_NS_PACKET_PROTOCOL, PW_NS_PACKET_API_POLL, rc);
        if (budget(io, r, NULL)) return -1;
        if (!rc) continue;
        if (p.revents & (POLLNVAL | POLLERR))
            return reject(r, PW_NS_PACKET_OS, PW_NS_PACKET_API_POLL, p.revents);
        if ((writing && (p.revents & POLLHUP)) ||
            !(p.revents & (writing ? POLLOUT : POLLIN | POLLHUP)) ||
            (p.revents & ~(POLLIN | POLLOUT | POLLHUP)))
            return reject(r, PW_NS_PACKET_PROTOCOL, PW_NS_PACKET_API_POLL, p.revents);
        *observed = p.revents;
        return 0;
    }
}
int pw_native_service_packet_validate(PwNativeChildIo *io, int fd,
                                     PwNativeServicePacketResult *r)
{
    int type = 0;
    socklen_t length = sizeof(type);
    if (arguments(io, fd, r)) return -1;
    int rc = getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length);
    r->socket_type = type; r->socket_type_length = (uint32_t)length;
    if (rc) return os_failure(r, PW_NS_PACKET_API_TYPE, rc);
    if (length != sizeof(type) || type != SOCK_SEQPACKET)
        return reject(r, PW_NS_PACKET_PROTOCOL, PW_NS_PACKET_API_TYPE, type);
    return budget(io, r, NULL);
}
long pw_native_service_packet_send(PwNativeChildIo *io, int fd,
                                  const void *bytes, size_t size,
                                  PwNativeServicePacketResult *r)
{
    short observed;
    if (arguments(io, fd, r)) return -1;
    if (!bytes || size != PW_NC_FRAME_BYTES)
        return reject(r, PW_NS_PACKET_INVALID, PW_NS_PACKET_API_SEND, (int64_t)size);
    if (wait_ready(io, fd, 1, r, &observed)) return -1;
    struct iovec part = {(void *)bytes, size};
    struct msghdr message = {0};
    message.msg_iov = &part; message.msg_iovlen = 1;
    ssize_t sent = sendmsg(fd, &message, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (sent < 0) return os_failure(r, PW_NS_PACKET_API_SEND, sent);
    if ((size_t)sent != size)
        return reject(r, PW_NS_PACKET_PROTOCOL, PW_NS_PACKET_API_SEND, sent);
    if (budget(io, r, NULL)) return -1;
    return (long)sent;
}

/* Refuse all ancillary data. Close only unique nonnegative descriptors from
 * complete, bounded SCM_RIGHTS records. Malformed records are not ownership
 * evidence; never guess a descriptor from them or retry a failed close. */
static void refuse_control(int borrowed_fd, const unsigned char *control, size_t capacity,
                           size_t reported, PwNativeServicePacketResult *r)
{
    int closed[CONTROL_FDS];
    size_t count = 0, at = 0, used = reported;
    if (used > capacity) { r->ownership_uncertain = 1; used = capacity; }
    while (at < used) {
        struct cmsghdr header;
        if (used - at < sizeof(header)) { r->ownership_uncertain = 1; break; }
        memcpy(&header, control + at, sizeof(header));
        size_t header_size = CMSG_LEN(0), length = (size_t)header.cmsg_len;
        if (length < header_size || length > used - at) {
            r->ownership_uncertain = 1; break;
        }
        size_t payload = length - header_size;
        if (header.cmsg_level == SOL_SOCKET && header.cmsg_type == SCM_RIGHTS) {
            if (!payload || payload % sizeof(int)) r->ownership_uncertain = 1;
            else for (size_t position = 0; position < payload; position += sizeof(int)) {
                int fd, duplicate = 0;
                memcpy(&fd, control + at + header_size + position, sizeof(fd));
                if (fd < 0 || fd == borrowed_fd || count == CONTROL_FDS) {
                    r->ownership_uncertain = 1; continue;
                }
                for (size_t i = 0; i < count; ++i) if (closed[i] == fd) duplicate = 1;
                if (duplicate) { r->ownership_uncertain = 1; continue; }
                closed[count++] = fd;
                int rc = close(fd);
                if (rc) {
#ifndef PW_NATIVE_CHILD_FREESTANDING
                    int native_error = errno;
                    if (!r->cleanup_failed && rc < 0) {
                        r->cleanup_native_error = native_error; r->cleanup_errno_valid = 1;
                    }
#endif
                    r->cleanup_failed = 1;
                } else r->rights_closed++;
            }
        } else r->ownership_uncertain = 1;
        if (length == used - at) break;
        size_t next = CMSG_SPACE(payload);
        if (next > used - at) {
            /* Only trailing alignment padding may lie outside cmsg_len. */
            for (size_t i = length; i < used - at; ++i)
                if (control[at + i]) r->ownership_uncertain = 1;
            break;
        }
        at += next;
    }
}
long pw_native_service_packet_receive(PwNativeChildIo *io, int fd,
                                     void *bytes, size_t size,
                                     PwNativeServicePacketResult *r)
{
    union { struct cmsghdr alignment; unsigned char bytes[CMSG_SPACE(CONTROL_FDS * sizeof(int))]; } control;
    unsigned char packet[PW_NC_FRAME_BYTES];
    short observed;
    if (arguments(io, fd, r)) return -1;
    if (!bytes || (size != PW_NC_FRAME_BYTES && size != 1))
        return reject(r, PW_NS_PACKET_INVALID, PW_NS_PACKET_API_RECEIVE, (int64_t)size);
    if (wait_ready(io, fd, 0, r, &observed)) return -1;
    struct iovec part = {packet, sizeof(packet)};
    struct msghdr message = {0};
    memset(&control, 0, sizeof(control));
    message.msg_iov = &part; message.msg_iovlen = 1;
    message.msg_control = control.bytes; message.msg_controllen = sizeof(control.bytes);
    ssize_t got = recvmsg(fd, &message, MSG_DONTWAIT);
    r->received_bytes = got; r->message_flags = (uint32_t)message.msg_flags;
    r->control_bytes = (uint64_t)message.msg_controllen;
    if (got < 0) return os_failure(r, PW_NS_PACKET_API_RECEIVE, got);
    /* BSD recvmsg carries its input flags into msg_flags; DONTWAIT may be
     * echoed back. EOR is the only additional accepted output flag. */
    if (message.msg_controllen || (message.msg_flags & ~(MSG_EOR | MSG_DONTWAIT)))
        reject(r, PW_NS_PACKET_PROTOCOL, PW_NS_PACKET_API_RECEIVE, got);
    if (message.msg_flags & MSG_CTRUNC) r->ownership_uncertain = 1;
    if (message.msg_controllen)
        refuse_control(fd, control.bytes, sizeof(control.bytes), message.msg_controllen, r);
    /* Any delivered descriptors have been settled before a late deadline or
     * cancellation can return; a prior protocol failure remains primary. */
    int late = budget(io, r, NULL);
    if (r->status || late) {
        /* Keep the first recorded refusal primary even if a late clock
         * check also failed while settling unexpected ancillary ownership. */
        if (r->status != PW_NS_PACKET_BUDGET)
            reject(r, r->status, r->api, r->raw_result);
        return -1;
    }
    if (got == 0) {
        r->channel_zero_observed = 1;
        r->hangup_observed = (observed & POLLHUP) != 0;
        if (size == 1 && r->hangup_observed && !(message.msg_flags & MSG_EOR)) return 0;
        return reject(r, PW_NS_PACKET_PROTOCOL, PW_NS_PACKET_API_RECEIVE, got);
    }
    if (size == 1 || got != PW_NC_FRAME_BYTES)
        return reject(r, PW_NS_PACKET_PROTOCOL, PW_NS_PACKET_API_RECEIVE, got);
    memcpy(bytes, packet, PW_NC_FRAME_BYTES);
    return PW_NC_FRAME_BYTES;
}
