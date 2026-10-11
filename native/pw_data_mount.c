/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _POSIX_C_SOURCE 200809L
#include "pw_data_mount.h"
#include "lapy_elevation_protocol.h"

#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* 0 ready, 1 eligible for the existing helper (or post-helper polling), -1
 * refusal. These are ordinary path observations, not a privilege verdict. */
static int observe(const PwDataMountOps *ops, PwDataMountObservation *out)
{
    struct stat st;
    memset(out, 0, sizeof(*out));
    errno = 0;
    out->stat_raw = ops->stat_path(PW_DATA_MOUNT_PATH, &st);
    out->stat_errno = out->stat_raw < 0 ? errno : 0;
    out->observed |= 1;
    out->stat_directory = !out->stat_raw && S_ISDIR(st.st_mode);
    errno = 0;
    out->lstat_raw = ops->lstat_path(PW_DATA_MOUNT_PATH, &st);
    out->lstat_errno = out->lstat_raw < 0 ? errno : 0;
    out->observed |= 2;
    out->lstat_directory = !out->lstat_raw && S_ISDIR(st.st_mode);

    int absent = out->stat_raw == -1 && out->stat_errno == ENOENT;
    int needs_helper = (out->lstat_raw == -1 && out->lstat_errno == EPERM) ||
                       (absent && out->lstat_raw == -1 && out->lstat_errno == ENOENT);
    if ((!out->stat_directory && !absent) ||
        (!out->lstat_directory && !needs_helper) ||
        (absent && out->lstat_directory)) return -1;
    return needs_helper ? 1 : 0;
}

int pw_data_mount_request_with(const PwDataMountOps *ops, int32_t pid,
                               int max_wait_ms, PwDataMountResult *detail)
{
    PwDataMountResult local;
    int state;
    if (!detail) detail = &local;
    memset(detail, 0, sizeof(*detail));
    if (!ops || !ops->request || !ops->stat_path || !ops->lstat_path || !ops->sleep_ms ||
        pid <= 1 || max_wait_ms < 0 || PW_DATA_MOUNT_POLL_MS <= 0 || PW_DATA_MOUNT_SETTLE_MS < 0)
        return -1;

    state = observe(ops, &detail->before);
    detail->data_before = detail->before.stat_directory;
    if (state < 0) return -1;
    if (!state) {
        detail->data_after = detail->ready = 1;
        return 0;
    }

    errno = 0;
    int rc = ops->request(pid, &detail->helper);
    if (rc == 0 && detail->helper.possible_apply && detail->helper.terminal &&
        detail->helper.helper_status == LAPY_ELEVATION_OK)
        detail->helper_completed = 1;
    else
        detail->helper_errno = rc ? (errno ? errno : EIO) : EPROTO;
    if (!detail->helper_completed) return -1;

    for (;;) {
        state = observe(ops, &detail->after);
        detail->data_after = detail->after.stat_directory;
        if (state < 0) return -1;
        if (!state) {
            errno = 0;
            int slept = ops->sleep_ms(PW_DATA_MOUNT_SETTLE_MS);
            if (slept) {
                detail->sleep_stage = 2; detail->sleep_raw = slept;
                detail->sleep_errno = slept < 0 ? errno : 0;
                return -1;
            }
            detail->settled_ms = PW_DATA_MOUNT_SETTLE_MS;
            detail->ready = 1;
            return 0;
        }
        if (detail->waited_ms >= max_wait_ms) return -1;
        int remaining = max_wait_ms - detail->waited_ms;
        int delay = remaining < PW_DATA_MOUNT_POLL_MS ? remaining : PW_DATA_MOUNT_POLL_MS;
        errno = 0;
        int slept = ops->sleep_ms(delay);
        if (slept) {
            detail->sleep_stage = 1; detail->sleep_raw = slept;
            detail->sleep_errno = slept < 0 ? errno : 0;
            return -1;
        }
        detail->waited_ms += delay;
    }
}

static int native_helper_request(int32_t pid, PwLapyElevationResult *result)
{
#if defined(PW_DATA_MOUNT_HOST_TEST)
    (void)pid;
    memset(result, 0, sizeof(*result));
    errno = ENOENT;
    return -1;
#else
    return pw_lapy_elevation_request_result(pid, result);
#endif
}

static int native_sleep_ms(int ms)
{
    struct timespec ts = {ms / 1000, (long)(ms % 1000) * 1000000L};
    while (nanosleep(&ts, &ts) != 0)
        if (errno != EINTR) return -1;
    return 0;
}

int pw_data_mount_request(PwDataMountResult *detail)
{
    static const PwDataMountOps ops = {
        native_helper_request, stat, lstat, native_sleep_ms};
    return pw_data_mount_request_with(&ops, (int32_t)getpid(), PW_DATA_MOUNT_WAIT_MS, detail);
}
