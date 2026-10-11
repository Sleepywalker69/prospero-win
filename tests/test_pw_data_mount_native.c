/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Host build models the console helper as unavailable; real libc probes. */
#define _POSIX_C_SOURCE 200809L
#include "../native/pw_data_mount.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void)
{
    PwDataMountResult r;
    rmdir(PW_DATA_MOUNT_PATH);

    assert(pw_data_mount_request(&r) == -1);
    assert(r.data_before == 0 && r.helper_completed == 0);
    assert(r.helper_errno == ENOENT && r.data_after == 0);

    assert(mkdir(PW_DATA_MOUNT_PATH, 0755) == 0);
    assert(pw_data_mount_request(&r) == 0);
    assert(r.data_before == 1 && r.data_after == 1 && r.helper_completed == 0);
    assert(r.helper_errno == 0);
    assert(r.ready && r.before.stat_directory && r.before.lstat_directory);
    rmdir(PW_DATA_MOUNT_PATH);
    FILE *file = fopen(PW_DATA_MOUNT_PATH, "w");
    assert(file && fclose(file) == 0);
    assert(pw_data_mount_request(&r) == -1 && !r.ready && !r.helper.possible_apply);
    assert(r.before.stat_raw == 0 && !r.before.stat_directory);
    assert(unlink(PW_DATA_MOUNT_PATH) == 0);
    assert(mkdir(PW_DATA_MOUNT_PATH "-target", 0755) == 0);
    assert(symlink(PW_DATA_MOUNT_PATH "-target", PW_DATA_MOUNT_PATH) == 0);
    assert(pw_data_mount_request(&r) == -1 && !r.ready && !r.helper.possible_apply);
    assert(r.before.stat_directory && !r.before.lstat_directory && !r.before.lstat_raw);
    assert(unlink(PW_DATA_MOUNT_PATH) == 0);
    assert(rmdir(PW_DATA_MOUNT_PATH "-target") == 0);
    puts("data mount native: missing helper fails closed; directory pair reuses; file/symlink refused");
    return 0;
}
