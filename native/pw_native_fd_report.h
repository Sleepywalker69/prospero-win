/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_NATIVE_FD_REPORT_H
#define PW_NATIVE_FD_REPORT_H
#include "pw_native_fd_probe.h"
#include <stddef.h>
#include <stdint.h>

enum { PW_NATIVE_FD_REPORT_BYTES = 80, PW_NATIVE_FD_REPORT_RESERVE_MS = 750 };
/* Deterministic, bounded names beneath the existing granted library. A name
 * collision is a failure; the token is correlation, never authentication. */
int pw_native_fd_paths(uint32_t parent_pid, uint64_t correlation,
                       char directory[PW_NATIVE_FD_PATH_CAP], char socket_path[PW_NATIVE_FD_PATH_CAP]);
int pw_native_fd_result_matches(const PwNativeFdResult *, uint32_t local_pid,
                               uint32_t peer_pid, int worker);
/* A worker report never claims authenticated peer identity. Timer history is
 * process-local and is deliberately not serialized into this result record. */
int pw_native_fd_report_encode(uint8_t[PW_NATIVE_FD_REPORT_BYTES], uint32_t parent_pid,
                               uint32_t child_pid, uint64_t correlation, const PwNativeFdResult *);
int pw_native_fd_report_decode(PwNativeFdResult *, const uint8_t[PW_NATIVE_FD_REPORT_BYTES],
                               uint32_t parent_pid, uint32_t child_pid, uint64_t correlation);
#endif
