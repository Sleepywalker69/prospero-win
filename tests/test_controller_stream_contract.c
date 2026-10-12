/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Tests of a proposed HOST-ONLY REFERENCE MODEL. No production USER, native
 * controller, XInput ABI or runtime implementation is compiled by this test.
 * Existing test_pw_wine_display tests remain the actual-source evidence.
 */
#include "reference_controller_stream.h"
#include <assert.h>
#include <stdatomic.h>
#include <stdio.h>

static void test_order_and_consumers(void)
{
    PwRefStream s; PwRefRecord record;
    const uint32_t taps[] = {1, 0, 1, 0};
    assert(!pw_ref_init(&s));
    assert(pw_ref_publish(&s, taps, 4) == PW_REF_RECORD);
    assert(pw_ref_snapshot(&s) == 0);
    for (unsigned consumer = 0; consumer != 2; ++consumer) {
        for (unsigned i = 0; i != 4; ++i) {
            assert(pw_ref_take(&s, consumer, &record) == PW_REF_RECORD);
            assert(record.epoch == 1 && record.sequence == i + 1);
            assert(record.buttons == taps[i] && pw_ref_snapshot(&s) == 0);
        }
        assert(pw_ref_take(&s, consumer, &record) == PW_REF_EMPTY);
    }
    pw_ref_destroy(&s);
}
static void test_overflow_and_rearm(void)
{
    PwRefStream s; PwRefRecord record;
    const uint32_t full[PW_REF_CAPACITY] = {1, 0, 1, 0, 1, 0, 1, 0};
    const uint32_t next[] = {1, 0};
    assert(!pw_ref_init(&s));
    assert(pw_ref_publish(&s, full, PW_REF_CAPACITY) == PW_REF_RECORD);
    for (unsigned i = 0; i != PW_REF_CAPACITY; ++i)
        assert(pw_ref_take(&s, 0, &record) == PW_REF_RECORD);
    /* A slow independent consumer pins every slot. Atomic failure must not
     * publish the first event of the rejected two-record tap. */
    const uint64_t sequence = s.next_sequence;
    assert(pw_ref_publish(&s, next, 2) == PW_REF_OVERFLOW);
    assert(s.next_sequence == sequence && s.overflows == 1);
    assert(pw_ref_snapshot(&s) == 0 && s.blocked);
    for (unsigned c = 0; c != 2; ++c) {
        assert(pw_ref_take(&s, c, &record) == PW_REF_RESET);
        assert(record.epoch == 2 && !record.sequence && !record.buttons);
    }
    assert(pw_ref_ack_reset(&s, 0, 1) == PW_REF_INVALID);
    assert(pw_ref_ack_reset(&s, 0, 2) == PW_REF_RECORD);
    assert(pw_ref_take(&s, 1, &record) == PW_REF_RESET);
    assert(pw_ref_ack_reset(&s, 1, 2) == PW_REF_RECORD);
    /* No timer can rearm this model. Repeated empty polls and repeated fresh
     * held samples cannot substitute for an observed chronological neutral. */
    for (unsigned i = 0; i != 100; ++i) {
        assert(pw_ref_publish(&s, NULL, 0) == PW_REF_RECORD);
        assert(pw_ref_publish(&s, next, 1) == PW_REF_RECORD);
        assert(s.blocked && !pw_ref_snapshot(&s));
        assert(pw_ref_take(&s, 0, &record) == PW_REF_EMPTY);
    }
    const uint32_t rearm[] = {0, 1, 0};
    assert(pw_ref_publish(&s, rearm, 3) == PW_REF_RECORD && !s.blocked);
    for (unsigned c = 0; c != 2; ++c)
        for (unsigned i = 0; i != 3; ++i) {
            assert(pw_ref_take(&s, c, &record) == PW_REF_RECORD);
            assert(record.epoch == 2 && record.buttons == rearm[i]);
        }
    /* Oversized batch also fails before dereferencing the supplied pointer. */
    assert(pw_ref_publish(&s, next, PW_REF_CAPACITY + 1) == PW_REF_OVERFLOW);
    assert(s.overflows == 2 && s.blocked);
    assert(pw_ref_take(&s, 0, &record) == PW_REF_RESET && record.epoch == 3);
    assert(pw_ref_ack_reset(&s, 0, 2) == PW_REF_INVALID);
    pw_ref_destroy(&s);
}
static void test_endpoint_barrier(void)
{
    PwRefStream s; PwRefEndpoint e; PwRefRecord record;
    const uint32_t down = 1;
    assert(!pw_ref_init(&s)); pw_ref_endpoint_init(&e, 1);
    assert(pw_ref_publish(&s, &down, 1) == PW_REF_RECORD);
    assert(pw_ref_take(&s, 0, &record) == PW_REF_RECORD);
    assert(pw_ref_endpoint_enqueue(&e, record) == PW_REF_RECORD);
    assert(!e.applied); /* enqueue acknowledgement is not application */
    assert(pw_ref_reset(&s) == 2);
    assert(pw_ref_take(&s, 0, &record) == PW_REF_RESET);
    uint64_t ticket = pw_ref_endpoint_reset(&e, record.epoch);
    assert(ticket && !e.count && e.resetting);
    assert(pw_ref_mock_apply_next(&e) == PW_REF_EMPTY); /* old down cancelled */
    assert(pw_ref_mock_complete_reset(&e, 2, ticket, 0) == PW_REF_RECORD);
    assert(pw_ref_ack_reset(&s, 0, 2) == PW_REF_RECORD);
    /* Independent keystroke consumer has not acknowledged its own barrier. */
    assert(pw_ref_take(&s, 1, &record) == PW_REF_RESET);

    const uint32_t rearm[] = {0, 1};
    assert(pw_ref_publish(&s, rearm, 2) == PW_REF_RECORD);
    for (unsigned i = 0; i != 2; ++i) {
        assert(pw_ref_take(&s, 0, &record) == PW_REF_RECORD);
        assert(pw_ref_endpoint_enqueue(&e, record) == PW_REF_RECORD);
        assert(pw_ref_mock_apply_next(&e) == PW_REF_RECORD);
    }
    assert(e.applied == 1);
    assert(pw_ref_reset(&s) == 3);
    ticket = pw_ref_endpoint_reset(&e, 3);
    assert(e.applied == 1 && e.release_pending == 1 && e.resetting);
    /* Hook rejection/unknown completion and any number of retries cannot
     * erase a factual applied-down obligation. No elapsed-time completion. */
    for (unsigned i = 0; i != 100; ++i)
        assert(pw_ref_mock_complete_reset(&e, 3, ticket, 0) == PW_REF_INVALID);
    assert(e.applied == 1 && e.release_pending == 1);
    assert(pw_ref_endpoint_enqueue(&e, (PwRefRecord){3, 100, 1}) == PW_REF_INVALID);
    assert(pw_ref_reset(&s) == 4);
    uint64_t newer = pw_ref_endpoint_reset(&e, 4);
    assert(newer != ticket && e.release_pending == 1);
    assert(pw_ref_mock_complete_reset(&e, 3, ticket, 1) == PW_REF_INVALID);
    assert(pw_ref_mock_complete_reset(&e, 4, ticket, 1) == PW_REF_INVALID);
    assert(pw_ref_ack_reset(&s, 0, 3) == PW_REF_INVALID);
    assert(pw_ref_mock_complete_reset(&e, 4, newer, 1) == PW_REF_RECORD);
    assert(!e.applied && !e.release_pending && !e.resetting);
    assert(pw_ref_mock_complete_reset(&e, 4, newer, 1) == PW_REF_INVALID);
    assert(pw_ref_ack_reset(&s, 0, 4) == PW_REF_RECORD);
    assert(pw_ref_ack_reset(&s, 0, 4) == PW_REF_INVALID);
    pw_ref_destroy(&s);
}

static void test_composed_enqueue_rejection(void)
{
    PwRefStream s; PwRefEndpoint e; PwRefRecord record;
    const uint32_t down = 1, up = 0;
    const uint32_t held[PW_REF_CAPACITY] = {1,1,1,1,1,1,1,1};
    assert(!pw_ref_init(&s)); pw_ref_endpoint_init(&e, 1);
    assert(pw_ref_publish(&s, &down, 1) == PW_REF_RECORD);
    assert(pw_ref_transfer_one(&s, &e) == PW_REF_RECORD);
    assert(pw_ref_mock_apply_next(&e) == PW_REF_RECORD && e.applied == 1);
    assert(pw_ref_take(&s, 1, &record) == PW_REF_RECORD);
    assert(pw_ref_publish(&s, held, PW_REF_CAPACITY) == PW_REF_RECORD);
    for (unsigned i = 0; i != PW_REF_CAPACITY; ++i) {
        assert(pw_ref_transfer_one(&s, &e) == PW_REF_RECORD);
        assert(pw_ref_take(&s, 1, &record) == PW_REF_RECORD);
    }
    assert(e.count == PW_REF_CAPACITY);
    PwRefRecord delayed = record;
    assert(pw_ref_publish(&s, &up, 1) == PW_REF_RECORD);
    /* Endpoint full after a factual applied DOWN: rejected UP forces the
     * composed owner into reset, never silent cursor advancement alone. */
    assert(pw_ref_transfer_one(&s, &e) == PW_REF_RESET);
    assert(s.epoch == 2 && e.epoch == 2 && e.resetting);
    assert(e.applied == 1 && e.release_pending == 1 && !e.count);
    assert(pw_ref_endpoint_enqueue(&e, delayed) == PW_REF_INVALID);
    assert(pw_ref_take(&s, 0, &record) == PW_REF_RESET);
    assert(pw_ref_finish_barrier(&s, &e, 2, e.ticket, 0) == PW_REF_INVALID);
    assert(pw_ref_take(&s, 0, &record) == PW_REF_RESET);
    assert(e.applied == 1 && e.release_pending == 1);
    assert(pw_ref_finish_barrier(&s, &e, 2, e.ticket, 1) == PW_REF_RECORD);
    assert(pw_ref_take(&s, 0, &record) == PW_REF_EMPTY);
    assert(pw_ref_endpoint_enqueue(&e, delayed) == PW_REF_INVALID);
    assert(pw_ref_take(&s, 1, &record) == PW_REF_RESET);
    pw_ref_destroy(&s);
}

typedef struct {
    PwRefStream *stream;
    atomic_uint *seen;
} AliasArgs;
static void *alias_reader(void *opaque)
{
    AliasArgs *args = opaque; PwRefRecord record;
    int result;
    /* Two API aliases intentionally share one linearised consumer cursor.
     * pthread mutexes in take provide serialization; no scheduler is mocked. */
    while ((result = pw_ref_take(args->stream, 1, &record)) == PW_REF_RECORD) {
        assert(record.sequence >= 1 && record.sequence <= PW_REF_CAPACITY);
        atomic_fetch_add(&args->seen[record.sequence - 1], 1);
    }
    assert(result == PW_REF_EMPTY);
    return NULL;
}
static void test_concurrent_alias_cursor(void)
{
    PwRefStream s; PwRefRecord record;
    const uint32_t states[PW_REF_CAPACITY] = {1, 0, 2, 0, 1, 0, 2, 0};
    atomic_uint seen[PW_REF_CAPACITY];
    pthread_t a, b;
    assert(!pw_ref_init(&s));
    for (unsigned i = 0; i != PW_REF_CAPACITY; ++i) atomic_init(&seen[i], 0);
    assert(pw_ref_publish(&s, states, PW_REF_CAPACITY) == PW_REF_RECORD);
    AliasArgs args = {&s, seen};
    assert(!pthread_create(&a, NULL, alias_reader, &args));
    assert(!pthread_create(&b, NULL, alias_reader, &args));
    assert(!pthread_join(a, NULL) && !pthread_join(b, NULL));
    for (unsigned i = 0; i != PW_REF_CAPACITY; ++i) {
        assert(atomic_load(&seen[i]) == 1);
        assert(pw_ref_take(&s, 0, &record) == PW_REF_RECORD);
        assert(record.sequence == i + 1 && record.buttons == states[i]);
    }
    assert(pw_ref_snapshot(&s) == 0);
    pw_ref_destroy(&s);
}

static void test_exhaustion_terminal(void)
{
    PwRefStream s; PwRefRecord record;
    const uint32_t neutral = 0;
    assert(!pw_ref_init(&s));
    s.next_sequence = UINT64_MAX;
    assert(pw_ref_publish(&s, &neutral, 1) == PW_REF_INVALID);
    assert(s.epoch == UINT64_MAX && s.blocked);
    assert(pw_ref_reset(&s) == UINT64_MAX);
    assert(pw_ref_publish(&s, &neutral, 1) == PW_REF_INVALID);
    assert(pw_ref_take(&s, 0, &record) == PW_REF_RESET);
    assert(pw_ref_ack_reset(&s, 0, UINT64_MAX) == PW_REF_RECORD);
    assert(pw_ref_publish(&s, &neutral, 1) == PW_REF_INVALID);
    assert(!pw_ref_snapshot(&s));
    pw_ref_destroy(&s);
}

int main(void)
{
    test_exhaustion_terminal();
    test_order_and_consumers();
    test_overflow_and_rearm();
    test_endpoint_barrier();
    test_composed_enqueue_rejection();
    for (unsigned i = 0; i != 64; ++i) test_concurrent_alias_cursor();
    puts("controller stream REFERENCE MODEL passed; no production USER proof");
    return 0;
}
