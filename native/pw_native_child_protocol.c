/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_native_child_protocol.h"
#include <errno.h>
#include <limits.h>
#include <string.h>

#ifdef PW_NATIVE_CHILD_FREESTANDING
/* The original no-CRT worker does not read a libc/TLS errno location.
 * Its OS adapters terminate on every negative return, including interrupts
 * and readiness races; only protocol-local errors use this private slot. */
#undef errno
static int protocol_error;
#define errno protocol_error
#endif

#define PW_NC_MAGIC UINT32_C(0x434e5750)
#define PW_NC_VERSION 1u
_Static_assert(CHAR_BIT == 8, "protocol requires octets");

static int fail(int error) { errno = error; return -1; }
static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static void put32(uint8_t *p, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) p[i] = (uint8_t)(value >> (i * 8));
}
static int build_copy(char to[PW_NC_BUILD_BYTES], const char *from)
{
    size_t size = 0;
    if (!from) return fail(EINVAL);
    while (size < PW_NC_BUILD_BYTES && from[size]) {
        if ((unsigned char)from[size] < 33 || (unsigned char)from[size] > 126) return fail(EINVAL);
        ++size;
    }
    if (!size || size == PW_NC_BUILD_BYTES) return fail(EINVAL);
    memset(to, 0, PW_NC_BUILD_BYTES);
    memcpy(to, from, size);
    return 0;
}
int pw_native_child_encode(uint8_t wire[PW_NC_FRAME_BYTES], const PwNativeChildFrame *frame)
{
    char build[PW_NC_BUILD_BYTES];
    if (!wire || !frame || frame->kind < PW_NC_HELLO || frame->kind > PW_NC_STOP_ACK ||
        build_copy(build, frame->build_id)) return fail(EINVAL);
    memset(wire, 0, PW_NC_FRAME_BYTES);
    put32(wire, PW_NC_MAGIC); put32(wire + 4, PW_NC_VERSION); put32(wire + 8, PW_NC_FRAME_BYTES);
    put32(wire + 12, frame->kind); put32(wire + 16, frame->sequence);
    put32(wire + 20, frame->parent_pid); put32(wire + 24, frame->child_pid); put32(wire + 28, frame->child_ppid);
    put32(wire + 40, (uint32_t)frame->correlation); put32(wire + 44, (uint32_t)(frame->correlation >> 32));
    memcpy(wire + 48, build, sizeof(build));
    return 0;
}
int pw_native_child_decode(PwNativeChildFrame *frame, const uint8_t wire[PW_NC_FRAME_BYTES])
{
    PwNativeChildFrame value = {0};
    char build[PW_NC_BUILD_BYTES];
    if (!frame || !wire) return fail(EINVAL);
    if (get32(wire) != PW_NC_MAGIC || get32(wire + 4) != PW_NC_VERSION || get32(wire + 8) != PW_NC_FRAME_BYTES ||
        get32(wire + 32) || get32(wire + 36)) return fail(EPROTO);
    value.kind = get32(wire + 12); value.sequence = get32(wire + 16);
    value.parent_pid = get32(wire + 20); value.child_pid = get32(wire + 24); value.child_ppid = get32(wire + 28);
    value.correlation = get32(wire + 40) | (uint64_t)get32(wire + 44) << 32;
    memcpy(value.build_id, wire + 48, PW_NC_BUILD_BYTES);
    if (value.kind < PW_NC_HELLO || value.kind > PW_NC_STOP_ACK || build_copy(build, value.build_id) ||
        memcmp(build, value.build_id, PW_NC_BUILD_BYTES)) return fail(EPROTO);
    *frame = value;
    return 0;
}
static int now(PwNativeChildIo *io, uint64_t *value)
{
    if (io->cancelled && io->cancelled(io->context)) return fail(ECANCELED);
    if (io->clock_ms(io->context, value) || *value < io->last_clock) return fail(EIO);
    io->last_clock = *value;
    return 0;
}
int pw_native_child_begin(PwNativeChildIo *io)
{
    uint64_t value;
#ifdef PW_NATIVE_CHILD_FREESTANDING
    protocol_error = 0;
#endif
    if (!io || !io->clock_ms || !io->receive || !io->send || io->ready) return fail(EINVAL);
    io->last_clock = 0;
    if (now(io, &value)) return -1;
    if (value > UINT64_MAX - PW_NC_TOTAL_MS) return fail(EOVERFLOW);
    io->total_end = value + PW_NC_TOTAL_MS;
    io->stage_end = value + PW_NC_STAGE_MS;
    io->ready = 1;
    return 0;
}
int pw_native_child_stage(PwNativeChildIo *io)
{
    uint64_t value;
    if (!io || !io->ready) return fail(EINVAL);
    if (now(io, &value)) return -1;
    if (value >= io->total_end || value >= io->stage_end) return fail(ETIMEDOUT);
    io->stage_end = io->total_end - value < PW_NC_STAGE_MS ? io->total_end : value + PW_NC_STAGE_MS;
    return 0;
}
int pw_native_child_remaining(PwNativeChildIo *io, unsigned *milliseconds)
{
    uint64_t value, end;
    if (!io || !io->ready || !milliseconds) return fail(EINVAL);
    if (now(io, &value)) return -1;
    end = io->stage_end < io->total_end ? io->stage_end : io->total_end;
    if (value >= end) return fail(ETIMEDOUT);
    *milliseconds = (unsigned)(end - value);
    return 0;
}
static int transfer(PwNativeChildIo *io, void *bytes, size_t size, int writing)
{
    uint8_t *p = bytes;
    while (size) {
        unsigned remaining;
        long count;
        if (pw_native_child_remaining(io, &remaining)) return -1;
        count = writing ? io->send(io->context, p, size, remaining) : io->receive(io->context, p, size, remaining);
        if (count < 0) {
            if (errno == EINTR) continue;
            return fail(errno ? errno : EIO);
        }
        if (!count) return fail(writing ? EPIPE : ECONNRESET);
        if ((unsigned long)count > size) return fail(EPROTO);
        p += count; size -= (size_t)count;
        if (pw_native_child_remaining(io, &remaining)) return -1;
    }
    return 0;
}
int pw_native_child_send(PwNativeChildIo *io, const void *bytes, size_t size)
{
    if (!bytes && size) return fail(EINVAL);
    return transfer(io, (void *)bytes, size, 1);
}
static int send_frame(PwNativeChildIo *io, const PwNativeChildFrame *frame)
{
    uint8_t wire[PW_NC_FRAME_BYTES];
    return pw_native_child_encode(wire, frame) || pw_native_child_send(io, wire, sizeof(wire)) ? -1 : 0;
}
static int receive_frame(PwNativeChildIo *io, PwNativeChildFrame *frame)
{
    uint8_t wire[PW_NC_FRAME_BYTES];
    return transfer(io, wire, sizeof(wire), 0) || pw_native_child_decode(frame, wire) ? -1 : 0;
}
static int same(const PwNativeChildFrame *a, const PwNativeChildFrame *b)
{
    return a->sequence == b->sequence && a->parent_pid == b->parent_pid && a->child_pid == b->child_pid &&
           a->child_ppid == b->child_ppid && a->correlation == b->correlation &&
           !memcmp(a->build_id, b->build_id, PW_NC_BUILD_BYTES);
}
int pw_native_child_parent(PwNativeChildIo *io, uint32_t parent_pid, uint64_t correlation,
                           const char *build_id, PwNativeChildResult *result)
{
    PwNativeChildFrame request = {0}, reply;
    if (!io || !result || parent_pid <= 1 || parent_pid > INT32_MAX || !correlation ||
        build_copy(request.build_id, build_id)) return fail(EINVAL);
    memset(result, 0, sizeof(*result));
    result->stage = PW_NC_WAIT_HELLO;
    if ((!io->ready && pw_native_child_begin(io)) || pw_native_child_stage(io) || receive_frame(io, &reply)) goto failed;
    if (reply.kind != PW_NC_HELLO || reply.sequence || reply.parent_pid || reply.correlation ||
        reply.child_pid <= 1 || reply.child_pid > INT32_MAX || reply.child_pid == parent_pid ||
        !reply.child_ppid || reply.child_ppid > INT32_MAX || memcmp(request.build_id, reply.build_id, PW_NC_BUILD_BYTES)) {
        errno = EPROTO; goto failed;
    }
    result->child_pid = request.child_pid = reply.child_pid;
    result->child_ppid = request.child_ppid = reply.child_ppid;
    request.parent_pid = parent_pid; request.correlation = correlation;
    result->stage = PW_NC_EXCHANGING;
    if (io->progress) io->progress(io->context, result->stage);
    for (uint32_t sequence = 1; sequence <= PW_NC_ECHO_COUNT; ++sequence) {
        unsigned remaining;
        if (pw_native_child_stage(io)) goto failed;
        if (io->wait_ms && io->wait_ms(io->context, 75)) goto failed;
        if (pw_native_child_remaining(io, &remaining)) goto failed;
        request.kind = PW_NC_ECHO; request.sequence = sequence;
        if (send_frame(io, &request) || receive_frame(io, &reply)) goto failed;
        if (reply.kind != PW_NC_ECHO_REPLY || !same(&request, &reply)) { errno = EPROTO; goto failed; }
        result->echoes++;
    }
    result->stage = PW_NC_STOPPING;
    request.kind = PW_NC_STOP; request.sequence = PW_NC_ECHO_COUNT + 1;
    if (pw_native_child_stage(io) || send_frame(io, &request) || receive_frame(io, &reply)) goto failed;
    if (reply.kind != PW_NC_STOP_ACK || !same(&request, &reply)) { errno = EPROTO; goto failed; }
    result->stop_ack = 1;
    for (;;) {
        unsigned remaining;
        uint8_t extra;
        long count;
        if (pw_native_child_remaining(io, &remaining)) goto failed;
        count = io->receive(io->context, &extra, 1, remaining);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) goto failed;
        if (count) { errno = EPROTO; goto failed; }
        if (pw_native_child_remaining(io, &remaining)) goto failed;
        result->stream_closed = 1; result->stage = PW_NC_CLOSED;
        if (io->progress) io->progress(io->context, result->stage);
        return 0;
    }
failed:
    result->error = errno ? errno : EIO;
    return fail(result->error);
}
int pw_native_child_worker(PwNativeChildIo *io, uint32_t child_pid, uint32_t child_ppid,
                           const char *build_id)
{
    PwNativeChildFrame hello = {0}, request, expected;
    if (!io || child_pid <= 1 || child_pid > INT32_MAX || !child_ppid || child_ppid > INT32_MAX ||
        build_copy(hello.build_id, build_id)) return fail(EINVAL);
    hello.kind = PW_NC_HELLO; hello.child_pid = child_pid; hello.child_ppid = child_ppid;
    if ((!io->ready && pw_native_child_begin(io)) || pw_native_child_stage(io) || send_frame(io, &hello)) return -1;
    expected = hello;
    for (uint32_t sequence = 1; sequence <= PW_NC_ECHO_COUNT + 1; ++sequence) {
        if (pw_native_child_stage(io) || receive_frame(io, &request)) return -1;
        if (sequence == 1) {
            if (request.parent_pid <= 1 || request.parent_pid > INT32_MAX || request.parent_pid == child_pid ||
                !request.correlation) return fail(EPROTO);
            expected.parent_pid = request.parent_pid; expected.correlation = request.correlation;
        }
        expected.sequence = sequence;
        if (!same(&expected, &request) || request.kind != (sequence <= PW_NC_ECHO_COUNT ? PW_NC_ECHO : PW_NC_STOP))
            return fail(EPROTO);
        request.kind = sequence <= PW_NC_ECHO_COUNT ? PW_NC_ECHO_REPLY : PW_NC_STOP_ACK;
        if (send_frame(io, &request)) return -1;
    }
    return 0; /* STOP_ACK is intent; stream closure is supplied by the caller returning/exiting. */
}
