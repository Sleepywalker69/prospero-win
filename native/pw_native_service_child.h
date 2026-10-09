/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_NATIVE_SERVICE_CHILD_H
#define PW_NATIVE_SERVICE_CHILD_H
#include "pw_native_child_protocol.h"
#include "pw_native_service_packet.h"
#include <stdint.h>

enum { PW_SC_LIST_CAP = 16, PW_SC_ATTEMPT_MS = 20000, PW_SC_PROTOCOL_MS = 15000,
       PW_SC_GRACE_MS = 1000, PW_SC_LIST_CALL_CAP = 52 };
enum { PW_SC_OK, PW_SC_INVALID, PW_SC_CANCELLED, PW_SC_TIMEOUT, PW_SC_CLOCK,
       PW_SC_FILE, PW_SC_OS, PW_SC_ABI, PW_SC_PROTOCOL, PW_SC_OWNERSHIP,
       PW_SC_FORCED_CLEANUP, PW_SC_ALREADY_ATTEMPTED };
enum { PW_SC_INITIAL, PW_SC_PREFLIGHT, PW_SC_BASELINE, PW_SC_LAUNCH_POSSIBLE,
       PW_SC_EXCHANGING, PW_SC_KILL_POSSIBLE, PW_SC_OBSERVING, PW_SC_DONE };
enum { PW_SC_API_NONE, PW_SC_API_OPEN, PW_SC_API_STAT, PW_SC_API_READ,
       PW_SC_API_CLOSE, PW_SC_API_APP, PW_SC_API_LIST, PW_SC_API_PAIR,
       PW_SC_API_TYPE, PW_SC_API_ADD, PW_SC_API_KILL, PW_SC_API_PACKET };

typedef struct {
    int opened, open_error, regular, size_matches, bytes_match, close_result;
    int64_t size;
} PwNativeServicePathResult;

typedef struct {
    unsigned status, phase, api;
    int64_t raw_result;
    int native_error;
    unsigned attempted, launch_possible, cleanup_uncertain;
    uint64_t started, protocol_end, cleanup_end, last_clock;
    PwNativeServicePathResult path[2];
    int selected_path;
    int app_id, service_id, launch_return;
    int app_status_return;
    uint32_t app_status_words[4];
    unsigned app_status_canary_valid;
    unsigned baseline_count, list_calls, last_list_count;
    int baseline_ids[PW_SC_LIST_CAP];
    int last_list_return;
    unsigned baseline_valid, listed, absent, retired;
    unsigned kill_attempted;
    int kill_return;
    unsigned protocol_complete, forced_cleanup, ui_ticks;
    unsigned parent_closed, passed_closed;
    PwNativeChildResult child;
    PwNativeServicePacketResult packet;
} PwNativeServiceChildResult;

typedef struct {
    void *context;
    int (*clock_ms)(void *, uint64_t *);
    int (*cancelled)(void *);
    unsigned (*ui_ticks)(void *);
    void (*record)(void *, const PwNativeServiceChildResult *);
} PwNativeServiceChildContext;

/* One own-application service attempt per process. The fixed packaged image
 * and paths are build inputs, never supplied by the operator or peer.
 * Native exit status/reaping and service namespace interpretation are not
 * established by a service-list absence or a channel observation. */
int pw_native_service_child_run(const PwNativeServiceChildContext *, PwNativeServiceChildResult *);
#endif
