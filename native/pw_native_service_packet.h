/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_NATIVE_SERVICE_PACKET_H
#define PW_NATIVE_SERVICE_PACKET_H
#include "pw_native_child_protocol.h"

enum { PW_NS_PACKET_OK, PW_NS_PACKET_INVALID, PW_NS_PACKET_BUDGET,
       PW_NS_PACKET_OS, PW_NS_PACKET_PROTOCOL };
enum { PW_NS_PACKET_API_NONE, PW_NS_PACKET_API_BUDGET, PW_NS_PACKET_API_TYPE,
       PW_NS_PACKET_API_POLL, PW_NS_PACKET_API_SEND, PW_NS_PACKET_API_RECEIVE };
typedef struct PwNativeServicePacketResult {
    int status, api;
    int64_t raw_result;
    int64_t received_bytes;
    uint64_t control_bytes;
    uint32_t message_flags, poll_revents;
    uint32_t rights_closed, cleanup_failed, ownership_uncertain;
    uint32_t channel_zero_observed, hangup_observed;
    int socket_type;
    uint32_t socket_type_length;
    int native_error, cleanup_native_error;
    uint32_t errno_valid, cleanup_errno_valid; /* unavailable in no-CRT worker */
} PwNativeServicePacketResult;

/* The caller owns fd and io. Results start zero and retain the first failure.
 * No descriptor flags, retry-on-error, native errno read or stream assembly.
 * Every packet uses the existing io's absolute budget and cancellation.
 * The type check is required before attaching this adapter to the engine. */
int pw_native_service_packet_validate(PwNativeChildIo *io, int fd,
                                     PwNativeServicePacketResult *result);
long pw_native_service_packet_send(PwNativeChildIo *io, int fd,
                                  const void *bytes, size_t size,
                                  PwNativeServicePacketResult *result);
long pw_native_service_packet_receive(PwNativeChildIo *io, int fd,
                                     void *bytes, size_t size,
                                     PwNativeServicePacketResult *result);
/* Send accepts exactly96 bytes. Receive accepts96, or1 only for the existing
 * engine's post-ACK check. The latter still receives a full96-byte record and
 * rejects every nonempty packet. A zero receive with HUP and without EOR is
 * recorded as a channel observation, not native death/reaping. The controller
 * must separately observe its owned service and latch uncertain cleanup. */
#endif
