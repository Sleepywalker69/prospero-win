/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_LAPY_ELEVATION_H
#define PW_LAPY_ELEVATION_H

#include <stdint.h>

typedef struct PwLapyElevationResult {
    unsigned possible_apply; /* REQUEST may have reached the helper */
    unsigned terminal;       /* validated final response; no helper work remains */
    uint32_t helper_status;  /* meaningful only when terminal is set */
} PwLapyElevationResult;

/* Detailed outcome for callers that own the requested PID. A possible request
 * with no terminal response must not be followed by exit, restart or retry. */
int pw_lapy_elevation_request_result(int32_t pid, PwLapyElevationResult *result);

/* Send the bundled one-shot ELF to the local elfldr listener and wait for the
 * versioned result for this process. Returns 0 on success, -1 with errno. */
int pw_lapy_elevation_request(int32_t pid);

#endif
