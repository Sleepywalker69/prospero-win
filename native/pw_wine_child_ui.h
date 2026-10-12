/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_WINE_CHILD_UI_H
#define PW_WINE_CHILD_UI_H
#include "../wine/ps5/pw_wine_sink.h"
#include <stddef.h>

/* Optional, dedicated UI stream. Never put these records on the startup,
 * helper, signal or wineserver channel. Identity must come from an already
 * authenticated owned-child admission, not from the received header. This
 * codec binds that identity; it does not authenticate a socket or grant it.
 * No descriptor, process, thread, listener or allocation is created here.
 * One serialized producer/consumer per direction; callbacks cannot reenter.
 * Disconnect retires this endpoint, never proves child/helper settlement. */
enum { PW_WCU_FRAME=1, PW_WCU_INPUT=2, PW_WCU_HEADER=64,
       PW_WCU_MAX_WIDTH=1920, PW_WCU_MAX_HEIGHT=1080,
       PW_WCU_MAX_BYTES=PW_WCU_MAX_WIDTH*PW_WCU_MAX_HEIGHT*4 };
typedef struct PwWineChildUiIdentity {
    uint64_t session, generation;
    uint32_t native_pid;
} PwWineChildUiIdentity;
/* Accept all bytes or return nonzero, including queue saturation/deadline.
 * The writer owns cancellation and a finite deadline. A partial/uncertain
 * write is terminal: never retry a frame on the same endpoint. Bytes are
 * borrowed for this call only and must be copied before returning. */
typedef int (*PwWineChildUiWrite)(void *, const void *, size_t);
typedef struct PwWineChildUiTx {
    PwWineChildUiIdentity identity;
    uint64_t next;
    unsigned kind, failed;
    PwWineChildUiWrite write;
    void *context;
} PwWineChildUiTx;
typedef int (*PwWineChildUiInput)(void *, const PwWineInput *);
typedef struct PwWineChildUiRx {
    PwWineChildUiIdentity identity;
    uint64_t next;
    unsigned kind, failed;
    unsigned char header[PW_WCU_HEADER];
    size_t header_used, payload_used, payload_bytes;
    unsigned char *storage;
    size_t capacity;
    PwWinePresentSink present;
    PwWineChildUiInput input;
    void *context;
} PwWineChildUiRx;
int pw_wine_child_ui_tx_init(PwWineChildUiTx *, PwWineChildUiIdentity,
                            unsigned kind, PwWineChildUiWrite, void *);
/* Retire after cancellation/detachment; serialized with writer callbacks. */
void pw_wine_child_ui_tx_end(PwWineChildUiTx *);
/* Signature matches PwWinePresentSink. Strided BGRA becomes tightly packed
 * on the wire; source padding is never disclosed. Return 0 only after all
 * bytes have been accepted by the writer, not proof of visible scanout. */
int pw_wine_child_ui_present(void *, const void *, uint32_t, uint32_t, uint32_t);
int pw_wine_child_ui_send_input(PwWineChildUiTx *, const PwWineInput *);
/* Caller-owned storage must outlive receiver; frame callback may inspect or
 * copy only during the call. No partial frame reaches it. Frame streams
 * require present only; input streams require input only and >=20 bytes. */
int pw_wine_child_ui_rx_init(PwWineChildUiRx *, PwWineChildUiIdentity, unsigned kind,
                            void *storage, size_t capacity,
                            PwWinePresentSink, PwWineChildUiInput, void *);
/* A nonzero result poisons the endpoint. Input may contain any fragmentation
 * or several records. Earlier complete records stay delivered on failure. */
int pw_wine_child_ui_feed(PwWineChildUiRx *, const void *, size_t);
/* Always retires receiver. 0 means record boundary, -1 means partial/error;
 * neither result is an acknowledgement or a native lifetime certificate. */
int pw_wine_child_ui_end(PwWineChildUiRx *);
#endif
