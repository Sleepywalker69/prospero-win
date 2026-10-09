/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../native/pw_native_child_protocol.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

typedef struct Fixture {
    uint8_t input[8 * PW_NC_FRAME_BYTES], output[8 * PW_NC_FRAME_BYTES];
    size_t input_size, position, output_size, chunk;
    uint64_t now, clock_step, read_step;
    int clock_failed, cancelled, interrupt, zero_send, oversize, keep_open;
    uint64_t send_step, eof_step;
    int send_interrupt, send_oversize, receive_error, send_error, cancel_on_eof, cancel_in_wait;
    size_t cancel_after_input;
} Fixture;
static int clock_ms(void *arg, uint64_t *value)
{
    Fixture *f = arg;
    if (f->clock_failed) return -1;
    *value = f->now; f->now += f->clock_step;
    return 0;
}
static long receive(void *arg, void *bytes, size_t size, unsigned timeout)
{
    Fixture *f = arg;
    assert(timeout > 0 && timeout <= PW_NC_STAGE_MS);
    if (f->interrupt) { f->interrupt--; errno = EINTR; return -1; }
    if (f->oversize) return (long)size + 1;
    if (f->receive_error) { errno = f->receive_error; return -1; }
    if (f->position == f->input_size) {
        if (f->keep_open) { f->now += timeout; errno = ETIMEDOUT; return -1; }
        f->now += f->eof_step;
        if (f->cancel_on_eof) f->cancelled = 1;
        return 0;
    }
    if (size > f->input_size - f->position) size = f->input_size - f->position;
    if (f->chunk && size > f->chunk) size = f->chunk;
    memcpy(bytes, f->input + f->position, size); f->position += size; f->now += f->read_step;
    if (f->cancel_after_input && f->position >= f->cancel_after_input) f->cancelled = 1;
    return (long)size;
}
static long send_bytes(void *arg, const void *bytes, size_t size, unsigned timeout)
{
    Fixture *f = arg;
    assert(timeout > 0 && timeout <= PW_NC_STAGE_MS);
    if (f->send_interrupt) { --f->send_interrupt; errno = EINTR; return -1; }
    if (f->send_error) { errno = f->send_error; return -1; }
    if (f->send_oversize) return (long)size + 1;
    if (f->zero_send) return 0;
    if (f->chunk && size > f->chunk) size = f->chunk;
    assert(size <= sizeof(f->output) - f->output_size);
    memcpy(f->output + f->output_size, bytes, size); f->output_size += size; f->now += f->send_step;
    return (long)size;
}
static int wait_ms(void *arg, unsigned ms)
{
    Fixture *f = arg; f->now += ms;
    if (f->cancel_in_wait) f->cancelled = 1;
    return 0;
}
static int cancelled(void *arg) { return ((Fixture *)arg)->cancelled; }
static PwNativeChildIo io_for(Fixture *f)
{
    PwNativeChildIo io = {0};
    io.context = f; io.clock_ms = clock_ms; io.receive = receive; io.send = send_bytes;
    io.wait_ms = wait_ms; io.cancelled = cancelled;
    return io;
}
static PwNativeChildFrame frame(uint32_t kind, uint32_t sequence)
{
    PwNativeChildFrame f = {0};
    f.kind = kind; f.sequence = sequence; f.child_pid = 42; f.child_ppid = 7;
    if (kind != PW_NC_HELLO) { f.parent_pid = 17; f.correlation = UINT64_C(0x8877665544332211); }
    memcpy(f.build_id, "fixture", 8);
    return f;
}
static void append(Fixture *f, PwNativeChildFrame value)
{
    assert(f->input_size + PW_NC_FRAME_BYTES <= sizeof(f->input));
    assert(!pw_native_child_encode(f->input + f->input_size, &value));
    f->input_size += PW_NC_FRAME_BYTES;
}
static Fixture replies(void)
{
    Fixture f = {0};
    append(&f, frame(PW_NC_HELLO, 0));
    for (uint32_t i = 1; i <= PW_NC_ECHO_COUNT; i++) append(&f, frame(PW_NC_ECHO_REPLY, i));
    append(&f, frame(PW_NC_STOP_ACK, PW_NC_ECHO_COUNT + 1));
    return f;
}
static int parent(Fixture *f, PwNativeChildResult *r)
{
    PwNativeChildIo io = io_for(f);
    return pw_native_child_parent(&io, 17, UINT64_C(0x8877665544332211), "fixture", r);
}
/* Failures preserve diagnostic progress without asserting completion. */
static void expect_failure(Fixture *f, int error)
{
    PwNativeChildResult result;
    memset(&result, 0xa5, sizeof(result));
    assert(parent(f, &result) == -1);
    assert(result.error == error && errno == error);
    assert(!result.stream_closed && result.stage != PW_NC_CLOSED);
}
static void test_codec_rejections(void)
{
    uint8_t wire[PW_NC_FRAME_BYTES], broken[PW_NC_FRAME_BYTES];
    PwNativeChildFrame good = frame(PW_NC_ECHO, 1), output, before;
    const uint32_t bad_lengths[] = {0, 1, PW_NC_FRAME_BYTES - 1, PW_NC_FRAME_BYTES + 1, UINT32_MAX};
    assert(!pw_native_child_encode(wire, &good));
    assert(wire[40] == 0x11 && wire[47] == 0x88); /* canonical LE run identifier */
    memset(&before, 0xa5, sizeof(before));
    for (unsigned i = 0; i < sizeof(bad_lengths) / sizeof(bad_lengths[0]); ++i) {
        memcpy(broken, wire, sizeof(broken));
        for (unsigned b = 0; b < 4; ++b) broken[8 + b] = (uint8_t)(bad_lengths[i] >> (8 * b));
        memcpy(&output, &before, sizeof(output));
        assert(pw_native_child_decode(&output, broken) == -1 && errno == EPROTO);
        assert(!memcmp(&output, &before, sizeof(output)));
    }
    for (unsigned i = 32; i < 40; ++i) {
        memcpy(broken, wire, sizeof(broken)); broken[i] = 1; memcpy(&output, &before, sizeof(output));
        assert(pw_native_child_decode(&output, broken) == -1 && errno == EPROTO);
        assert(!memcmp(&output, &before, sizeof(output)));
    }
    for (unsigned which = 0; which < 6; ++which) {
        memcpy(broken, wire, sizeof(broken)); memcpy(&output, &before, sizeof(output));
        if (which == 0) memset(broken + 48, 0, PW_NC_BUILD_BYTES);
        if (which == 1) memset(broken + 48, 'x', PW_NC_BUILD_BYTES);
        if (which == 2) broken[48] = ' ';
        if (which == 3) broken[48] = 0x80;
        if (which == 4) broken[48] = 127;
        if (which == 5) broken[56] = '!'; /* nonzero bytes after the terminator */
        assert(pw_native_child_decode(&output, broken) == -1 && errno == EPROTO);
        assert(!memcmp(&output, &before, sizeof(output)));
    }
    memset(good.build_id, 'x', PW_NC_BUILD_BYTES - 1); good.build_id[PW_NC_BUILD_BYTES - 1] = 0;
    assert(!pw_native_child_encode(wire, &good) && !pw_native_child_decode(&output, wire));
    assert(!memcmp(output.build_id, good.build_id, PW_NC_BUILD_BYTES));
    memset(good.build_id, 'x', PW_NC_BUILD_BYTES);
    assert(pw_native_child_encode(wire, &good) == -1 && errno == EINVAL);
}
static void test_every_fragment_and_truncation(void)
{
    PwNativeChildResult result;
    Fixture full = replies();
    /* Exercise each possible frame-fragment boundary, not just 1-byte I/O. */
    for (size_t chunk = 1; chunk <= PW_NC_FRAME_BYTES + 1; ++chunk) {
        Fixture f = full; f.chunk = chunk;
        assert(!parent(&f, &result) && result.stream_closed && result.stop_ack && result.echoes == 3);
        assert(f.output_size == 4 * PW_NC_FRAME_BYTES);
    }
    /* EOF at every byte before a complete STOP_ACK is never completion. */
    for (size_t length = 0; length < full.input_size; ++length) {
        Fixture f = full; f.input_size = length; f.chunk = 7;
        expect_failure(&f, ECONNRESET);
    }
    {
        Fixture f = full;
        append(&f, frame(PW_NC_STOP_ACK, PW_NC_ECHO_COUNT + 1));
        expect_failure(&f, EPROTO); /* duplicate completion instead of EOF */
    }
}
static void test_reply_identity_and_order(void)
{
    const unsigned offsets[] = {20, 24, 28, 40, 44};
    for (unsigned reply = 1; reply <= PW_NC_ECHO_COUNT + 1; ++reply) {
        for (unsigned i = 0; i < sizeof(offsets) / sizeof(offsets[0]); ++i) {
            Fixture f = replies(); f.input[reply * PW_NC_FRAME_BYTES + offsets[i]] ^= 1;
            expect_failure(&f, EPROTO);
        }
        {
            Fixture f = replies();
            f.input[reply * PW_NC_FRAME_BYTES + 16] = (uint8_t)(reply - 1);
            expect_failure(&f, EPROTO); /* replay an earlier sequence */
        }
        {
            Fixture f = replies();
            f.input[reply * PW_NC_FRAME_BYTES + 12] = PW_NC_HELLO;
            expect_failure(&f, EPROTO);
        }
    }
    {
        const uint32_t ids[] = {0, 1, 17, UINT32_MAX};
        for (unsigned i = 0; i < sizeof(ids) / sizeof(ids[0]); ++i) {
            Fixture f = replies();
            for (unsigned b = 0; b < 4; ++b) f.input[24 + b] = (uint8_t)(ids[i] >> (8 * b));
            expect_failure(&f, EPROTO);
        }
    }
}
static void test_absolute_deadlines_and_cancel(void)
{
    Fixture f = replies();
    PwNativeChildResult result;
    /* Completing the last byte exactly at a deadline is still too late. */
    f.read_step = PW_NC_STAGE_MS; expect_failure(&f, ETIMEDOUT);
    f = replies(); f.send_step = PW_NC_STAGE_MS; expect_failure(&f, ETIMEDOUT);
    f = replies(); f.eof_step = PW_NC_STAGE_MS;
    assert(parent(&f, &result) == -1 && result.error == ETIMEDOUT && result.stop_ack && !result.stream_closed);
    f = replies(); f.cancel_on_eof = 1;
    assert(parent(&f, &result) == -1 && result.error == ECANCELED && result.stop_ack && !result.stream_closed);
    f = replies(); f.chunk = 1; f.cancel_after_input = 5;
    expect_failure(&f, ECANCELED); assert(f.position == 5 && !f.output_size);
    f = replies(); f.cancel_in_wait = 1;
    expect_failure(&f, ECANCELED); assert(f.position == PW_NC_FRAME_BYTES && !f.output_size);
    f = replies(); f.interrupt = 9999; f.clock_step = 100;
    expect_failure(&f, ETIMEDOUT); assert(!f.position);
    f = replies(); f.send_interrupt = 9999; f.clock_step = 100;
    expect_failure(&f, ETIMEDOUT); assert(!f.output_size);
    {
        PwNativeChildIo io;
        unsigned remaining;
        f = replies(); io = io_for(&f);
        assert(!pw_native_child_begin(&io));
        f.now = PW_NC_STAGE_MS;
        assert(pw_native_child_stage(&io) == -1 && errno == ETIMEDOUT);
        assert(io.stage_end == PW_NC_STAGE_MS && io.total_end == PW_NC_TOTAL_MS);
        f = replies(); io = io_for(&f);
        assert(!pw_native_child_begin(&io));
        f.now = PW_NC_TOTAL_MS - 100; /* elapsed upload time stays charged */
        assert(pw_native_child_parent(&io, 17, UINT64_C(0x8877665544332211), "fixture", &result) == -1);
        assert(result.error == ETIMEDOUT && io.total_end == PW_NC_TOTAL_MS && !result.stream_closed);
        if (f.now < PW_NC_TOTAL_MS) f.now = PW_NC_TOTAL_MS;
        assert(pw_native_child_stage(&io) == -1 && errno == ETIMEDOUT);
        assert(pw_native_child_remaining(&io, &remaining) == -1 && errno == ETIMEDOUT);
        assert(pw_native_child_begin(&io) == -1 && errno == EINVAL);
        f = (Fixture){0}; f.now = UINT64_MAX - PW_NC_TOTAL_MS + 1; io = io_for(&f);
        assert(pw_native_child_begin(&io) == -1 && errno == EOVERFLOW && !io.ready);
    }
}
static void test_callback_failures(void)
{
    Fixture f = replies();
    f.send_oversize = 1; expect_failure(&f, EPROTO);
    f = replies(); f.receive_error = EIO; expect_failure(&f, EIO);
    f = replies(); f.send_error = EIO; expect_failure(&f, EIO);
    f = replies(); f.send_interrupt = 3;
    {
        PwNativeChildResult result;
        assert(!parent(&f, &result) && result.stream_closed);
        assert(f.output_size == 4 * PW_NC_FRAME_BYTES);
    }
}
static Fixture requests(void)
{
    Fixture f = {0};
    for (uint32_t i = 1; i <= PW_NC_ECHO_COUNT; ++i) append(&f, frame(PW_NC_ECHO, i));
    append(&f, frame(PW_NC_STOP, PW_NC_ECHO_COUNT + 1));
    return f;
}
static void test_worker_strictness_and_completion_scope(void)
{
    for (unsigned request = 0; request <= PW_NC_ECHO_COUNT; ++request) {
        const unsigned offsets[] = {16, 20, 24, 28, 40};
        for (unsigned i = 0; i < sizeof(offsets) / sizeof(offsets[0]); ++i) {
            Fixture f = requests(); PwNativeChildIo io = io_for(&f);
            /* Parent/run identity is negotiated by the first request; later
             * changes are rejected. Child identity and order are fixed. */
            if (!request && (offsets[i] == 20 || offsets[i] == 40)) continue;
            f.input[request * PW_NC_FRAME_BYTES + offsets[i]] ^= 1;
            assert(pw_native_child_worker(&io, 42, 7, "fixture") == -1 && errno == EPROTO);
        }
    }
    {
        Fixture f = requests(); PwNativeChildIo io = io_for(&f);
        memset(f.input + 40, 0, 8);
        assert(pw_native_child_worker(&io, 42, 7, "fixture") == -1 && errno == EPROTO);
    }
    {
        Fixture f = requests(); PwNativeChildIo io = io_for(&f);
        f.input[12] = PW_NC_STOP;
        assert(pw_native_child_worker(&io, 42, 7, "fixture") == -1 && errno == EPROTO);
    }
    {
        Fixture f = requests(); PwNativeChildIo io = io_for(&f);
        f.keep_open = 1;
        assert(!pw_native_child_worker(&io, 42, 7, "fixture"));
        assert(f.output_size == 5 * PW_NC_FRAME_BYTES && f.position == 4 * PW_NC_FRAME_BYTES);
        /* Return means STOP_ACK was sent. This fake transport remains open,
         * and no native process was ever started or reaped by this test. */
    }
    puts("native child hostile controls: fragments, every EOF boundary, identity/order, absolute deadlines, cancellation and completion scope passed");
}

int main(void)
{
    test_codec_rejections();
    test_every_fragment_and_truncation();
    test_reply_identity_and_order();
    test_absolute_deadlines_and_cancel();
    test_callback_failures();
    test_worker_strictness_and_completion_scope();
    PwNativeChildResult result;
    Fixture f = replies();
    f.chunk = 1; f.interrupt = 2;
    assert(!parent(&f, &result));
    assert(result.stage == PW_NC_CLOSED && result.child_pid == 42 && result.child_ppid == 7);
    assert(result.echoes == 3 && result.stop_ack && result.stream_closed && !result.error);
    assert(f.output_size == 4 * PW_NC_FRAME_BYTES);
    for (uint32_t i = 0; i < 4; i++) {
        PwNativeChildFrame value;
        assert(!pw_native_child_decode(&value, f.output + i * PW_NC_FRAME_BYTES));
        assert(value.sequence == i + 1 && value.kind == (i == 3 ? PW_NC_STOP : PW_NC_ECHO));
    }
    for (unsigned offset = 0; offset < 48; offset += 4) {
        if (offset == 12 || offset == 28) continue; /* different legal kind/PPID tested below */
        f = replies(); f.input[offset] ^= 0x80;
        assert(parent(&f, &result) == -1 && !result.stream_closed);
    }
    f = replies(); f.input[24] = 17; assert(parent(&f, &result) == -1 && result.error == EPROTO);
    f = replies(); f.input[48] = 'x'; assert(parent(&f, &result) == -1 && result.error == EPROTO);
    f = replies(); f.input[PW_NC_FRAME_BYTES + 40] ^= 1;
    assert(parent(&f, &result) == -1 && result.error == EPROTO && !result.echoes);
    f = replies(); f.input[2 * PW_NC_FRAME_BYTES + 16] = 1;
    assert(parent(&f, &result) == -1 && result.error == EPROTO && result.echoes == 1);
    f = replies(); f.input[f.input_size++] = '!';
    assert(parent(&f, &result) == -1 && result.stop_ack && result.error == EPROTO);
    f = replies(); f.input_size = PW_NC_FRAME_BYTES - 1;
    assert(parent(&f, &result) == -1 && result.error == ECONNRESET);
    f = replies(); f.keep_open = 1;
    assert(parent(&f, &result) == -1 && result.stop_ack && !result.stream_closed);
    f = replies(); f.clock_failed = 1; assert(parent(&f, &result) == -1 && result.error == EIO);
    f = replies(); f.cancelled = 1; assert(parent(&f, &result) == -1 && result.error == ECANCELED);
    f = replies(); f.chunk = 1; f.clock_step = 100;
    assert(parent(&f, &result) == -1 && result.error == ETIMEDOUT); /* partial reads do not reset stage */
    f = replies(); f.read_step = 4000;
    assert(parent(&f, &result) == -1 && result.error == ETIMEDOUT && result.echoes == 2); /* total budget */
    f = replies(); f.zero_send = 1; assert(parent(&f, &result) == -1 && result.error == EPIPE);
    f = replies(); f.oversize = 1; assert(parent(&f, &result) == -1 && result.error == EPROTO);
    {
        PwNativeChildIo io = io_for(&f);
        f = (Fixture){0}; f.now = 100;
        assert(!pw_native_child_begin(&io));
        assert(pw_native_child_begin(&io) == -1 && errno == EINVAL);
        f.now = 99;
        assert(pw_native_child_stage(&io) == -1 && errno == EIO);
    }
    f = (Fixture){0}; f.chunk = 2;
    for (uint32_t i = 1; i <= PW_NC_ECHO_COUNT; i++) append(&f, frame(PW_NC_ECHO, i));
    append(&f, frame(PW_NC_STOP, PW_NC_ECHO_COUNT + 1));
    {
        PwNativeChildIo io = io_for(&f);
        assert(!pw_native_child_worker(&io, 42, 7, "fixture"));
        assert(f.output_size == 5 * PW_NC_FRAME_BYTES);
        PwNativeChildFrame last;
        assert(!pw_native_child_decode(&last, f.output + f.output_size - PW_NC_FRAME_BYTES));
        assert(last.kind == PW_NC_STOP_ACK);
    }
    f.position = f.output_size = 0; f.input[16] = 2;
    {
        PwNativeChildIo io = io_for(&f);
        assert(pw_native_child_worker(&io, 42, 7, "fixture") == -1 && errno == EPROTO);
    }
    puts("native child protocol: strict framing, ordered echo, distinct PID, bounded deadlines and shutdown intent passed");
    return 0;
}
