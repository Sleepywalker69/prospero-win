/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_NATIVE_CHILD_PROTOCOL_H
#define PW_NATIVE_CHILD_PROTOCOL_H
#include <stddef.h>
#include <stdint.h>

enum { PW_NC_FRAME_BYTES = 96, PW_NC_BUILD_BYTES = 48,
       PW_NC_STAGE_MS = 5000, PW_NC_TOTAL_MS = 15000, PW_NC_ECHO_COUNT = 3 };
enum { PW_NC_HELLO = 1, PW_NC_ECHO = 2, PW_NC_ECHO_REPLY = 3,
       PW_NC_STOP = 4, PW_NC_STOP_ACK = 5 };
enum { PW_NC_INITIAL, PW_NC_WAIT_HELLO, PW_NC_EXCHANGING, PW_NC_STOPPING, PW_NC_CLOSED, PW_NC_CAPABILITIES };

typedef struct PwNativeChildFrame {
    uint32_t kind, sequence, parent_pid, child_pid, child_ppid;
    uint64_t correlation;
    char build_id[PW_NC_BUILD_BYTES];
} PwNativeChildFrame;

typedef struct PwNativeChildIo {
    void *context;
    int (*clock_ms)(void *, uint64_t *);
    long (*receive)(void *, void *, size_t, unsigned timeout_ms);
    long (*send)(void *, const void *, size_t, unsigned timeout_ms);
    int (*wait_ms)(void *, unsigned); /* optional finite pacing; never extends deadlines */
    int (*cancelled)(void *);
    void (*progress)(void *, unsigned stage); /* optional finite observer; no protocol I/O */
    /* Optional role-local capability phase after echo 3 and before STOP.
     * It must finish inside this stage and preserve the absolute total end. */
    int (*capabilities)(void *, struct PwNativeChildIo *, const PwNativeChildFrame *);
    uint64_t total_end, stage_end, last_clock;
    unsigned ready;
} PwNativeChildIo;

typedef struct PwNativeChildResult {
    uint32_t stage, child_pid, child_ppid, echoes;
    int stop_ack, stream_closed, error, capabilities_complete;
} PwNativeChildResult;

int pw_native_child_encode(uint8_t wire[PW_NC_FRAME_BYTES], const PwNativeChildFrame *frame);
int pw_native_child_decode(PwNativeChildFrame *frame, const uint8_t wire[PW_NC_FRAME_BYTES]);
int pw_native_child_begin(PwNativeChildIo *io);
int pw_native_child_stage(PwNativeChildIo *io);
int pw_native_child_remaining(PwNativeChildIo *io, unsigned *milliseconds);
/* An upload must use one stage across every chunk; no EOF/SHUT_WR delimiter. */
int pw_native_child_send(PwNativeChildIo *io, const void *bytes, size_t size);
int pw_native_child_receive(PwNativeChildIo *io, void *bytes, size_t size);
int pw_native_child_parent(PwNativeChildIo *io, uint32_t parent_pid, uint64_t correlation,
                           const char *build_id, PwNativeChildResult *result);
int pw_native_child_worker(PwNativeChildIo *io, uint32_t child_pid, uint32_t child_ppid,
                           const char *build_id);
#endif
