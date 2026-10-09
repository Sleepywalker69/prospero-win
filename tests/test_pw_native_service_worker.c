/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Actual shared finite engine + original mocked packet/clock/process calls. */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "../native/pw_native_service_packet.h"
static int fake_clock(clockid_t, struct timespec *);
static pid_t fake_pid(void), fake_ppid(void);
static void fake_exit(int) __attribute__((noreturn));
#define PW_NATIVE_CHILD_FREESTANDING 1
#define PW_NATIVE_CHILD_BUILD_ID "service-worker-fixture"
#define clock_gettime fake_clock
#define getpid fake_pid
#define getppid fake_ppid
#define _exit fake_exit
#define _start inert_service_entry
#define memcpy worker_memcpy
#define memset worker_memset
#define memcmp worker_memcmp
#include "../native/pw_native_service_worker.c"
#undef clock_gettime
#undef getpid
#undef getppid
#undef _exit
#undef _start
#undef memcpy
#undef memset
#undef memcmp
static struct {
    uint64_t now, clock_step, io_step;
    int clock_error, invalid_nsec, negative_sec, validation_error, packet_error, corrupt_sequence;
    int pid, ppid, pid_calls, ppid_calls, type_calls, sent, received, exits, exit_code;
    PwNativeChildIo *io;
} m;
static jmp_buf exit_target;
static void reset(void) { memset(&m, 0, sizeof(m)); m.now = 100; m.pid = 42; m.ppid = 7; }
static int fake_clock(clockid_t id, struct timespec *value)
{
    assert(id == CLOCK_MONOTONIC);
    value->tv_sec = m.negative_sec ? -1 : (time_t)(m.now / 1000);
    value->tv_nsec = m.invalid_nsec ? 1000000000 : (long)(m.now % 1000) * 1000000;
    m.now += m.clock_step;
    return m.clock_error ? -1 : 0;
}
static pid_t fake_pid(void) { ++m.pid_calls; return (pid_t)m.pid; }
static pid_t fake_ppid(void) { ++m.ppid_calls; return (pid_t)m.ppid; }
static void fake_exit(int code) { ++m.exits; m.exit_code = code; longjmp(exit_target, 1); }
int pw_native_service_packet_validate(PwNativeChildIo *io, int fd, PwNativeServicePacketResult *r)
{
    assert(fd == 3 && r && io->ready && io->context);
    assert(io->clock_ms == worker_clock && io->send == worker_send && io->receive == worker_receive);
    assert(!io->capabilities && !io->wait_ms && !io->progress);
    assert(io->total_end == 100 + PW_NC_TOTAL_MS && io->stage_end == 100 + PW_NC_STAGE_MS);
    m.io = io; ++m.type_calls; m.now += m.io_step;
    return m.validation_error ? -1 : 0;
}
long pw_native_service_packet_send(PwNativeChildIo *io, int fd, const void *bytes, size_t size,
                                  PwNativeServicePacketResult *r)
{
    PwNativeChildFrame frame;
    assert(io == m.io && fd == 3 && r && size == PW_NC_FRAME_BYTES);
    assert(!pw_native_child_decode(&frame, bytes));
    assert(frame.child_pid == 42 && frame.child_ppid == 7);
    assert(!strcmp(frame.build_id, PW_NATIVE_CHILD_BUILD_ID));
    if (!m.sent) assert(frame.kind == PW_NC_HELLO && !frame.parent_pid && !frame.correlation);
    else assert(frame.kind == (m.sent == 4 ? PW_NC_STOP_ACK : PW_NC_ECHO_REPLY) &&
                frame.sequence == (unsigned)m.sent && frame.parent_pid == 17 && frame.correlation == 19);
    ++m.sent; m.now += m.io_step;
    return m.packet_error ? -1 : PW_NC_FRAME_BYTES;
}
long pw_native_service_packet_receive(PwNativeChildIo *io, int fd, void *bytes, size_t size,
                                     PwNativeServicePacketResult *r)
{
    assert(io == m.io && fd == 3 && r && size == PW_NC_FRAME_BYTES);
    PwNativeChildFrame frame = {0}; ++m.received;
    frame.kind = m.received == 4 ? PW_NC_STOP : PW_NC_ECHO;
    frame.sequence = m.corrupt_sequence ? 99u : (unsigned)m.received;
    frame.parent_pid = 17; frame.child_pid = 42; frame.child_ppid = 7; frame.correlation = 19;
    memcpy(frame.build_id, PW_NATIVE_CHILD_BUILD_ID, sizeof(PW_NATIVE_CHILD_BUILD_ID));
    assert(!pw_native_child_encode(bytes, &frame)); m.now += m.io_step;
    return m.packet_error ? -1 : PW_NC_FRAME_BYTES;
}
int main(void)
{
    reset(); assert(worker_main() == 0 && m.type_calls == 1 && m.sent == 5 && m.received == 4);
    assert(m.pid_calls == 1 && m.ppid_calls == 1); /* PPID7 intentionally differs from parent17. */
    reset(); m.clock_error = 1; assert(worker_main() == 2 && !m.type_calls && !m.sent);
    reset(); m.invalid_nsec = 1; assert(worker_main() == 2 && !m.type_calls);
    reset(); m.negative_sec = 1; assert(worker_main() == 2 && !m.type_calls);
    reset(); m.validation_error = 1; assert(worker_main() == 3 && !m.pid_calls && !m.sent);
    reset(); m.io_step = PW_NC_STAGE_MS; assert(worker_main() == 4 && !m.sent);
    reset(); m.pid = 1; assert(worker_main() == 4 && !m.sent);
    reset(); m.ppid = 0; assert(worker_main() == 4 && !m.sent);
    reset(); m.packet_error = 1; assert(worker_main() == 4 && m.sent == 1 && !m.received);
    reset(); m.corrupt_sequence = 1; assert(worker_main() == 4 && m.sent == 1 && m.received == 1);
    reset(); m.clock_step = 800; assert(worker_main() == 4 && m.sent < 5 && m.now <= 20000);
    reset();
    if (!setjmp(exit_target)) inert_service_entry(NULL, NULL);
    assert(m.exits == 1 && m.exit_code == 0 && m.sent == 5);
    reset(); m.packet_error = 1;
    if (!setjmp(exit_target)) inert_service_entry(NULL, NULL);
    assert(m.exits == 1 && m.exit_code == 4 && m.sent == 1);
    puts("service fd3 worker mocks passed: independent finite engine, bootstrap refusal, STOP_ACK exit intent; no native entry executed");
    return 0;
}
