/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_LAPY_ELEVATION_H
#define PW_LAPY_ELEVATION_H

#include <stdint.h>

typedef struct PwLapyElevationResult {
    unsigned possible_apply; /* REQUEST may have reached the helper */
    unsigned terminal;       /* validated transaction response; not helper process-exit proof */
    unsigned no_dispatch, no_request, settled_failure, cancel_attempted;
    uint64_t transaction_id;
    uint32_t helper_status;  /* meaningful only when terminal is set */
} PwLapyElevationResult;

/* Detailed local evidence for callers that own the requested PID. Any possible
 * dispatch, including an ELF upload before REQUEST, requires retaining the
 * PID until a validated same-transaction terminal result. Only positive,
 * coherent no_dispatch evidence excludes helper work; no_request alone does
 * not permit exit, restart or retry. terminal is set only by the matched
 * adapter after its identity/phase/status checks, never from raw wire flags. */
int pw_lapy_elevation_request_result(int32_t pid, PwLapyElevationResult *result);

/* Initial-CANCEL fixture only. A zero result proves a verified transaction
 * CANCELLED receipt, never helper process exit. Available only in a build
 * with PW_LAPY_INITIAL_CANCEL_ONLY=1; normal preparation is not compiled. */
int pw_lapy_initial_cancel_result(int32_t pid, PwLapyElevationResult *result);

/* Send the bundled one-shot ELF to the local elfldr listener and wait for the
 * versioned result for this process. Returns 0 on success, -1 with errno. */
int pw_lapy_elevation_request(int32_t pid);

#endif
