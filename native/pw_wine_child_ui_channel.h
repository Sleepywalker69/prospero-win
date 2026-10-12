/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_WINE_CHILD_UI_CHANNEL_H
#define PW_WINE_CHILD_UI_CHANNEL_H
#include "pw_wine_child_ui.h"
#include <pthread.h>
#include <stdatomic.h>
/* A one-record, caller-budgeted transmit queue. The Wine sink callback never
 * performs socket IO, allocation, waiting or a blocking mutex acquisition.
 * One complete frame/input is committed before the supervisor can send it.
 * No replacement of partially-sent records. Busy frame submissions are dropped
 * before serialization without sequence gaps; input overflow is terminal.
 * Storage and this object are process-lifetime while callbacks can run. */
typedef struct PwWineChildUiChannel {
    pthread_mutex_t lock;
    atomic_uint cancelled;
    PwWineChildUiTx tx;
    unsigned char *storage;
    size_t capacity,used,sent;
    uint64_t lifetime_end,record_end,last_clock;
    unsigned write_ms,initialized,building,queued,retired,close_uncertain,detach_failed;
    int fd,error;
    void *context;
    int (*clock_ms)(void *,uint64_t *);
    int (*stop)(void *);
} PwWineChildUiChannel;
/* Initializes once into zero storage. Takes *owned_fd only on success; fd
 * must be the separate SOCK_STREAM associated with this admitted identity.
 * UI identity comes from an accepted handoff, never a received frame header.
 * The caller supplies preallocated storage (one full desired record), an
 * absolute lifetime and a finite per-record write deadline (1..1000 ms).
 * clock_ms/stop are nonblocking, nonreentrant callbacks. */
int pw_wine_child_ui_channel_init(PwWineChildUiChannel *,int *owned_fd,
                                 PwWineChildUiIdentity,unsigned kind,
                                 void *storage,size_t capacity,uint64_t lifetime_end,
                                 unsigned write_ms,int (*clock_ms)(void *,uint64_t *),
                                 int (*stop)(void *),void *context);
/* Matches PwWinePresentSink. Once installed, detach using the same ntdll
 * setter before close; that setter serializes with in-flight sink callbacks. */
int pw_wine_child_ui_channel_present(void *,const void *,uint32_t,uint32_t,uint32_t);
int pw_wine_child_ui_channel_input(PwWineChildUiChannel *,const PwWineInput *);
/* One nonblocking send of at most 65536 bytes. 1=progress, 0=idle/contention,
 * -1=terminal/cancelled/deadline. Call regularly until queued bytes drain.
 * Partial sends continue only from the exact reported byte count. */
int pw_wine_child_ui_channel_pump(PwWineChildUiChannel *);
void pw_wine_child_ui_channel_cancel(PwWineChildUiChannel *);
/* cancel -> detach outside the queue lock -> serialize -> poison -> close.
 * detach MUST quiesce every producer, and for input must certify the consumer
 * settled held keys/buttons before returning zero. It may refuse; then the
 * fd stays owned, storage stays live and no close is attempted. Retrying a
 * refused detach is allowed, retrying close is not. Never call from inside a
 * producer callback/Wine sink lock. No helper/process settlement is inferred. */
int pw_wine_child_ui_channel_retire(PwWineChildUiChannel *,int (*detach)(void *),void *);
#endif
