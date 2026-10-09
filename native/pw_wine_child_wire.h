/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_WINE_CHILD_WIRE_H
#define PW_WINE_CHILD_WIRE_H
#include "pw_native_child_protocol.h"

enum { PW_WC_WIRE_BYTES = 136, PW_WC_BUILD_CHARS = 40,
       PW_WC_STARTUP_MS = 30000, PW_WC_LIFETIME_MS = 60000, PW_WC_BATTLENET_LIFETIME_MS = 300000,
       PW_WC_SIGNAL_QUIT = 3, PW_WC_SIGNAL_USR1 = 30 };
enum { PW_WC_PROFILE_FIXTURE = 1, PW_WC_PROFILE_BATTLENET = 2,
       PW_WC_MACHINE_AMD64 = 0x8664, PW_WC_MACHINE_I386 = 0x014c };
enum { PW_WC_HELLO = 1, PW_WC_BOOTSTRAP, PW_WC_BOOTSTRAP_ACK,
       PW_WC_SIGNAL, PW_WC_SIGNAL_ACK, PW_WC_FAILURE };
#define PW_WC_KIND(kind) (1u << (kind))
enum { PW_WC_ERROR = -1, PW_WC_IDLE = 0, PW_WC_RECORD = 1, PW_WC_CHANNEL_CLOSED = 2 };
enum { PW_WC_OK, PW_WC_INVALID, PW_WC_BUDGET, PW_WC_OS, PW_WC_PROTOCOL };
enum { PW_WC_API_NONE, PW_WC_API_CLOCK, PW_WC_API_TYPE, PW_WC_API_POLL,
       PW_WC_API_SEND, PW_WC_API_RECEIVE, PW_WC_API_CLOSE };

/* Values, never a wire struct. The codec fixes every byte and reserved zero. */
typedef struct PwWineChildFrame {
    uint32_t kind, sequence, parent_pid, child_pid, child_ppid, wine_pid, wine_tid;
    uint32_t profile, machine; /* wire version 2: fixed native config, never paths */
    uint64_t generation;
    int64_t target_tid;
    int32_t signal, status, native_error;
    char build_id[PW_WC_BUILD_CHARS + 1];
    uint32_t failure_api, returned_length, errno_valid;
    int32_t failure_raw, returned_value; /* FAILURE only; otherwise all zero */
} PwWineChildFrame;

typedef struct PwWineChildWireResult {
    int status, api, native_error, cleanup_native_error;
    int64_t raw_result, received_bytes;
    uint32_t errno_valid, cleanup_errno_valid, message_flags, poll_revents;
    uint32_t rights_closed, cleanup_failed, ownership_uncertain;
    uint32_t delivery_uncertain, channel_zero_observed, hangup_observed;
    uint64_t control_bytes;
} PwWineChildWireResult;

int pw_wine_child_wire_encode(unsigned char out[PW_WC_WIRE_BYTES], const PwWineChildFrame *frame);
int pw_wine_child_wire_decode(PwWineChildFrame *frame, const unsigned char in[PW_WC_WIRE_BYTES]);
int pw_wine_child_wire_same_session(const PwWineChildFrame *a, const PwWineChildFrame *b);
int pw_wine_child_wire_validate(PwNativeChildIo *io, int fd, PwWineChildWireResult *result);
/* One sendmsg, MSG_DONTWAIT|MSG_NOSIGNAL. No polling, clocks, callbacks,
 * waiting, retries or logging. Caller serializes ownership/sends without
 * blocking the server lock. right_fd is borrowed and only BOOTSTRAP may carry
 * it. Any non-full send is a failed delivery; no transfer/launch retry. */
int pw_wine_child_wire_try_send(int fd, const PwWineChildFrame *frame, int right_fd,
                              PwWineChildWireResult *result);
int pw_wine_child_wire_send(PwNativeChildIo *io, int fd, const PwWineChildFrame *frame,
                          int right_fd, PwWineChildWireResult *result);
/* One bounded poll slice, then at most one recvmsg. IDLE never resets a
 * deadline. Only BOOTSTRAP returns one owned SOCK_STREAM descriptor; every
 * other kind refuses ancillary data. Caller must initialize *right_fd=-1.
 * On RECORD, caller owns *right_fd if>=0
 * and must close it on later session refusal. On all other outcomes it is-1.
 * CHANNEL_CLOSED is limited zero+HUP/noEOR evidence, never native death. */
int pw_wine_child_wire_receive_step(PwNativeChildIo *io, int fd, uint32_t allowed_kinds,
                                   PwWineChildFrame *frame, int *right_fd,
                                   PwWineChildWireResult *result);
int pw_wine_child_wire_receive(PwNativeChildIo *io, int fd, uint32_t allowed_kinds,
                              PwWineChildFrame *frame, int *right_fd,
                              PwWineChildWireResult *result);
/* Close one owned descriptor once, clear slot even on failure, preserve the
 * first failure and record cleanup uncertainty. Never retries close. */
void pw_wine_child_wire_close(int *fd, PwWineChildWireResult *result);
#endif
