/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_WINE_TAGGED_TRANSPORT_H
#define PW_WINE_TAGGED_TRANSPORT_H
#include "pw_wine_sink.h"
#include <pthread.h>

/* Dormant, process-local transport only. Not staged/exported to Wine or called
 * by any title/driver. No wire/PRX ABI, wake fd, ownership, USER receipt,
 * release, rearm, or neutrality claim. Legacy sink APIs are independent.
 *
 * Call init once on fresh storage, then destroy only after external quiescence.
 * Neither dequeue nor reset proves that a previously dequeued event finished;
 * a future owner must reconcile those immutable copies. Never copy a live
 * object, mutate its fields, or alias API arguments with its storage. Callers
 * must keep input arguments stable during each call. */
enum {
    PW_TAGGED_SOURCES=8, PW_TAGGED_CAPACITY=256, PW_TAGGED_ABI=1,
    PW_TAGGED_OK=0, PW_TAGGED_INVALID=-1, PW_TAGGED_FULL=-2,
    PW_TAGGED_STALE=-3, PW_TAGGED_CLOSED=-4,
    PW_TAGGED_EMPTY=0, PW_TAGGED_DATA=1, PW_TAGGED_CANCELLED=2
};
typedef struct {
    uint32_t abi,size,source,reserved;
    uint64_t session,epoch,sequence;
    PwWineInput event;
    uint32_t reserved_tail;
} PwTaggedInput;
_Static_assert(sizeof(PwTaggedInput)==64,"tagged input layout");
typedef struct {
    uint64_t session,epoch;
} PwTaggedSourceConfig;
typedef struct {
    uint32_t source,exhausted;
    uint64_t session,old_epoch,new_epoch,last_admitted_sequence;
} PwTaggedReset;
/* Public storage solely for caller-owned bounded allocation, not direct use. */
typedef struct {
    uint64_t session,epoch,last_sequence;
    unsigned closed,pending;
    PwTaggedReset reset;
} PwTaggedSource;
typedef struct {
    pthread_mutex_t lock;
    unsigned initialized,sources,head,count;
    PwTaggedSource source[PW_TAGGED_SOURCES];
    PwTaggedInput queue[PW_TAGGED_CAPACITY];
} PwTaggedTransport;

/* IDs are config indices 0..sources-1. All sessions/epochs must be nonzero.
 * A failed init leaves initialized=0 and no usable transport. Init/reinit of
 * a live object is forbidden. Destroy is not a reset or completion barrier. */
int pw_tagged_init(PwTaggedTransport *t,const PwTaggedSourceConfig *config,unsigned sources);
int pw_tagged_destroy(PwTaggedTransport *t);
/* OK means admission only. FULL/INVALID/STALE/CLOSED never consumes sequence.
 * One mutex publishes the entire envelope and its index atomically to pop. */
int pw_tagged_post(PwTaggedTransport *t,const PwTaggedInput *input);
/* DATA or CANCELLED plus the unchanged original envelope, EMPTY or INVALID.
 * Classification is linearized under the mutex: a pop before close is DATA
 * forever; a pop after close is CANCELLED, including at epoch exhaustion.
 * CANCELLED means this queue did not deliver that record as DATA. It does
 * not cancel any earlier DATA copy, nor prove downstream release. */
int pw_tagged_next(PwTaggedTransport *t,PwTaggedInput *output);
/* One-shot close/reset, independent of data capacity. Requires exact session
 * and original epoch. Atomically closes admission and snapshots last sequence.
 * MAX epoch stays MAX with exhausted=1; no wrap, and closure still succeeds.
 * Exact duplicate returns the same record, even after notification is consumed,
 * without advancing epoch or republishing. No API reopens this source.
 * OK and the record prove only transport closure, never completed USER work. */
int pw_tagged_close_source(PwTaggedTransport *t,uint32_t source,
                           uint64_t session,uint64_t original_epoch,PwTaggedReset *output);
/* 1 and a reset notification, EMPTY or INVALID. At most one per source;
 * source-index order, no cross-source chronological promise. Consuming this
 * notification changes neither closed state nor queued cancellation. */
int pw_tagged_next_reset(PwTaggedTransport *t,PwTaggedReset *output);
#endif
