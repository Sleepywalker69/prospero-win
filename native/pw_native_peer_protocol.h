/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_NATIVE_PEER_PROTOCOL_H
#define PW_NATIVE_PEER_PROTOCOL_H
#include "pw_native_child_protocol.h"
#include <stdint.h>

enum { PW_NP_RECORD_BYTES = 128, PW_NP_CHALLENGE_BYTES = 32,
       PW_NP_REPORT_RESERVE_MS = 750, PW_NP_SUCCESS_EXIT = 37 };
enum { PW_NP_WORKER_READY = 1, PW_NP_PARENT_READY, PW_NP_CHALLENGE,
       PW_NP_WORKER_ECHO, PW_NP_WORKER_RESULT };
enum { PW_NP_SETUP, PW_NP_READY, PW_NP_ARM, PW_NP_CHALLENGE_PHASE,
       PW_NP_ECHO_PHASE, PW_NP_REPORT, PW_NP_EXIT_PHASE, PW_NP_COMPLETE };
enum { PW_NP_OK = 0, PW_NP_INVALID = -1, PW_NP_OS = -2, PW_NP_TIMEOUT = -3,
       PW_NP_CANCELLED = -4, PW_NP_CLOCK = -5, PW_NP_PROTOCOL = -6,
       PW_NP_EOF = -7, PW_NP_REGISTRATION = -8, PW_NP_ENTROPY = -9, PW_NP_EXIT = -10 };
enum { PW_NP_WORKER_CREDENTIAL = 1, PW_NP_WORKER_ECHO_SENT = 2, PW_NP_WORKER_CLOSED = 4 };

typedef struct {
    uint32_t kind, parent_pid, child_pid, phase, observations;
    int32_t status;
    uint64_t correlation;
    char build_id[PW_NC_BUILD_BYTES];
    uint8_t challenge[PW_NP_CHALLENGE_BYTES];
    int64_t raw_result;
} PwNativePeerRecord;

/* Strict fixed records. Session fields are copied from the already validated
 * original control protocol; a nonce is never a log field or an FD grant. */
int pw_native_peer_encode(uint8_t[PW_NP_RECORD_BYTES], const PwNativePeerRecord *);
int pw_native_peer_decode(PwNativePeerRecord *, const uint8_t[PW_NP_RECORD_BYTES],
                          const PwNativeChildFrame *session);
void pw_native_peer_record(PwNativePeerRecord *, const PwNativeChildFrame *, uint32_t kind);
int pw_native_peer_worker_success(const PwNativePeerRecord *);
#endif
