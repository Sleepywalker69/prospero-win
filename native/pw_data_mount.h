/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_DATA_MOUNT_H
#define PW_DATA_MOUNT_H
/* Observe ordinary /data access and, when required, request the bundled helper. */
#include <stdint.h>
#include <sys/stat.h>
#include "pw_lapy_elevation.h"

#ifndef PW_DATA_MOUNT_PATH
#define PW_DATA_MOUNT_PATH "/data"
#endif
#ifndef PW_DATA_MOUNT_WAIT_MS
#define PW_DATA_MOUNT_WAIT_MS 5000
#endif
#ifndef PW_DATA_MOUNT_POLL_MS
#define PW_DATA_MOUNT_POLL_MS 100
#endif
#ifndef PW_DATA_MOUNT_SETTLE_MS
#define PW_DATA_MOUNT_SETTLE_MS 1000
#endif

typedef struct PwDataMountObservation {
    unsigned observed; /* bit 0 stat, bit 1 lstat; zero means not attempted */
    int stat_raw, stat_errno, stat_directory;
    int lstat_raw, lstat_errno, lstat_directory;
} PwDataMountObservation;

typedef struct PwDataMountOps {
    int (*request)(int32_t pid, PwLapyElevationResult *result);
    int (*stat_path)(const char *path, struct stat *st);
    int (*lstat_path)(const char *path, struct stat *st);
    int (*sleep_ms)(int ms); /* zero only once the requested sleep completes */
} PwDataMountOps;

typedef struct PwDataMountResult {
    int data_before, helper_completed, helper_errno, data_after;
    int waited_ms, settled_ms, ready;
    int sleep_stage, sleep_raw, sleep_errno; /* failure: 1 polling, 2 settle */
    PwDataMountObservation before, after;
    PwLapyElevationResult helper;
} PwDataMountResult;

/* Exactly one helper request at most. Success requires a reusable directory
 * pair, or a successful terminal helper result followed by that same pair and
 * the settle delay. max_wait_ms bounds requested post-helper polling sleeps,
 * not helper duration, actual elapsed time, or the separate settle delay.
 * A failed possible_apply && !terminal request requires the caller to retain
 * its PID: neither timeout nor socket closure proves the helper has finished. */
int pw_data_mount_request_with(const PwDataMountOps *ops, int32_t pid, int max_wait_ms,
                               PwDataMountResult *detail);
int pw_data_mount_request(PwDataMountResult *detail);
#endif
