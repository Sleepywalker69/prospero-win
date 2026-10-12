/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* HOST-ONLY REFERENCE SPECIFICATION. This is not a production input queue.
 * Input records are already canonical/chronological. Native ABI filtering,
 * HWND authority and real USER completion are outside this model.
 * Initial state assumes admission at neutral. Resets require new neutral.
 */
#ifndef PW_REFERENCE_CONTROLLER_STREAM_H
#define PW_REFERENCE_CONTROLLER_STREAM_H
#include <pthread.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
enum { PW_REF_CAPACITY = 8, PW_REF_CONSUMERS = 2 };
enum { PW_REF_EMPTY = 0, PW_REF_RECORD = 1, PW_REF_RESET = 2,
       PW_REF_INVALID = -1, PW_REF_OVERFLOW = -2 };
typedef struct {
    uint64_t epoch, sequence;
    uint32_t buttons;
} PwRefRecord;
typedef struct {
    pthread_mutex_t lock;
    PwRefRecord records[PW_REF_CAPACITY];
    uint64_t epoch, write, cursor[PW_REF_CONSUMERS], next_sequence;
    uint64_t reset_epoch[PW_REF_CONSUMERS], overflows;
    uint32_t snapshot;
    unsigned blocked;
} PwRefStream;
static inline int pw_ref_init(PwRefStream *s)
{
    memset(s, 0, sizeof(*s));
    s->epoch = 1;
    return pthread_mutex_init(&s->lock, NULL);
}
static inline void pw_ref_destroy(PwRefStream *s)
{
    pthread_mutex_destroy(&s->lock);
}
static inline void pw_ref_reset_locked(PwRefStream *s)
{
    /* Exhaustion is a terminal refusal rather than epoch reuse. */
    if (s->epoch != UINT64_MAX) ++s->epoch;
    s->write = s->cursor[0] = s->cursor[1] = 0;
    s->snapshot = 0;
    s->blocked = 1;
    for (unsigned i = 0; i < PW_REF_CONSUMERS; ++i)
        s->reset_epoch[i] = s->epoch;
}
static inline uint64_t pw_ref_reset(PwRefStream *s)
{
    pthread_mutex_lock(&s->lock);
    pw_ref_reset_locked(s);
    uint64_t epoch = s->epoch;
    pthread_mutex_unlock(&s->lock);
    return epoch;
}
static inline int pw_ref_publish(PwRefStream *s, const uint32_t *buttons, size_t count)
{
    if ((!buttons && count) || count > PW_REF_CAPACITY) {
        if (count > PW_REF_CAPACITY) {
            pthread_mutex_lock(&s->lock);
            ++s->overflows; pw_ref_reset_locked(s);
            pthread_mutex_unlock(&s->lock);
            return PW_REF_OVERFLOW;
        }
        return PW_REF_INVALID;
    }
    pthread_mutex_lock(&s->lock);
    if (s->epoch == UINT64_MAX || s->next_sequence > UINT64_MAX - count ||
        s->write > UINT64_MAX - count) {
        s->epoch = UINT64_MAX;
        pw_ref_reset_locked(s);
        pthread_mutex_unlock(&s->lock);
        return PW_REF_INVALID;
    }
    uint64_t oldest = s->cursor[0] < s->cursor[1] ? s->cursor[0] : s->cursor[1];
    /* Reserve for the entire supplied batch, including suppressed records.
     * A failed admission publishes no prefix and invalidates queued history. */
    if (count > PW_REF_CAPACITY - (s->write - oldest)) {
        ++s->overflows; pw_ref_reset_locked(s);
        pthread_mutex_unlock(&s->lock);
        return PW_REF_OVERFLOW;
    }
    for (size_t i = 0; i < count; ++i) {
        if (s->blocked) {
            if (buttons[i]) continue;
            s->blocked = 0; /* only an actual neutral record rearms */
        }
        s->snapshot = buttons[i];
        s->records[s->write % PW_REF_CAPACITY] =
            (PwRefRecord){s->epoch, ++s->next_sequence, buttons[i]};
        ++s->write;
    }
    pthread_mutex_unlock(&s->lock);
    return PW_REF_RECORD;
}
static inline uint32_t pw_ref_snapshot(PwRefStream *s)
{
    pthread_mutex_lock(&s->lock);
    uint32_t value = s->snapshot;
    pthread_mutex_unlock(&s->lock);
    return value;
}
static inline int pw_ref_take(PwRefStream *s, unsigned consumer, PwRefRecord *out)
{
    if (consumer >= PW_REF_CONSUMERS || !out) return PW_REF_INVALID;
    pthread_mutex_lock(&s->lock);
    int result = PW_REF_EMPTY;
    if (s->reset_epoch[consumer]) {
        *out = (PwRefRecord){s->reset_epoch[consumer], 0, 0};
        result = PW_REF_RESET; /* repeat until the exact barrier is acknowledged */
    } else if (s->cursor[consumer] != s->write) {
        *out = s->records[s->cursor[consumer] % PW_REF_CAPACITY];
        ++s->cursor[consumer];
        result = PW_REF_RECORD;
    }
    pthread_mutex_unlock(&s->lock);
    return result;
}
static inline int pw_ref_ack_reset(PwRefStream *s, unsigned consumer, uint64_t epoch)
{
    if (consumer >= PW_REF_CONSUMERS) return PW_REF_INVALID;
    pthread_mutex_lock(&s->lock);
    int ok = epoch && s->reset_epoch[consumer] == epoch && s->epoch == epoch;
    if (ok) s->reset_epoch[consumer] = 0;
    pthread_mutex_unlock(&s->lock);
    return ok ? PW_REF_RECORD : PW_REF_INVALID;
}
/* MOCK DOWNSTREAM ENDPOINT, not Wine/USER. One serialized owner supplies all
 * calls. enqueue only accepts data. mock_apply_next represents factual USER
 * application in tests; production cannot infer it from sink enqueue.
 * An out-of-band reset cancels unapplied old records and retains applied
 * downs until the matching mock release completion succeeds.
 */
typedef struct {
    PwRefRecord queue[PW_REF_CAPACITY];
    size_t count, next;
    uint64_t epoch, ticket, accepted_sequence;
    uint32_t applied, release_pending;
    unsigned resetting;
} PwRefEndpoint;
static inline void pw_ref_endpoint_init(PwRefEndpoint *e, uint64_t epoch)
{
    memset(e, 0, sizeof(*e)); e->epoch = epoch;
}
static inline int pw_ref_endpoint_enqueue(PwRefEndpoint *e, PwRefRecord record)
{
    if (e->resetting || record.epoch != e->epoch || !record.sequence ||
        record.sequence <= e->accepted_sequence || e->count == PW_REF_CAPACITY)
        return PW_REF_INVALID;
    e->queue[e->count++] = record;
    e->accepted_sequence = record.sequence;
    return PW_REF_RECORD;
}
static inline int pw_ref_mock_apply_next(PwRefEndpoint *e)
{
    if (e->resetting || e->next == e->count) return PW_REF_EMPTY;
    e->applied = e->queue[e->next++].buttons;
    if (e->next == e->count) e->next = e->count = 0;
    return PW_REF_RECORD;
}
static inline uint64_t pw_ref_endpoint_reset(PwRefEndpoint *e, uint64_t epoch)
{
    if (epoch <= e->epoch || e->ticket == UINT64_MAX) return 0;
    e->epoch = epoch; ++e->ticket;
    e->next = e->count = 0; /* cancellation occurs at this modeled consumer */
    e->release_pending |= e->applied;
    e->resetting = 1;
    return e->ticket;
}
static inline int pw_ref_mock_complete_reset(PwRefEndpoint *e, uint64_t epoch,
                                             uint64_t ticket, int release_applied)
{
    if (!e->resetting || e->epoch != epoch || e->ticket != ticket ||
        (e->release_pending && !release_applied)) return PW_REF_INVALID;
    e->applied = e->release_pending = 0;
    e->resetting = 0;
    return PW_REF_RECORD;
}
/* SERIALIZED REFERENCE OWNER for mapped consumer 0. A taken record belongs
 * to this owner until accepted by the endpoint or invalidated by an explicit
 * reset. Rejection cannot silently lose an UP. Other producer/consumer
 * concurrency is protected by the stream lock; endpoint calls stay serialized.
 */
static inline int pw_ref_transfer_one(PwRefStream *s, PwRefEndpoint *e)
{
    PwRefRecord record;
    int result = pw_ref_take(s, 0, &record);
    if (result == PW_REF_RECORD) {
        if (pw_ref_endpoint_enqueue(e, record) == PW_REF_RECORD) return result;
        uint64_t epoch = pw_ref_reset(s);
        (void)pw_ref_endpoint_reset(e, epoch);
        return PW_REF_RESET;
    }
    if (result == PW_REF_RESET && record.epoch > e->epoch)
        (void)pw_ref_endpoint_reset(e, record.epoch);
    return result;
}
static inline int pw_ref_finish_barrier(PwRefStream *s, PwRefEndpoint *e,
                                        uint64_t epoch, uint64_t ticket,
                                        int release_applied)
{
    if (pw_ref_mock_complete_reset(e, epoch, ticket, release_applied) != PW_REF_RECORD)
        return PW_REF_INVALID;
    return pw_ref_ack_reset(s, 0, epoch);
}
#endif
