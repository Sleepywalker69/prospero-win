/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_native_fd_report.h"
#include <limits.h>

#define MAGIC UINT32_C(0x52444650)
static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static uint64_t get64(const uint8_t *p) { return get32(p) | (uint64_t)get32(p + 4) << 32; }
static void put32(uint8_t *p, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) p[i] = (uint8_t)(value >> (i * 8));
}
static void put64(uint8_t *p, uint64_t value)
{
    put32(p, (uint32_t)value); put32(p + 4, (uint32_t)(value >> 32));
}
static int64_t signed64(uint64_t value)
{
    return value <= INT64_MAX ? (int64_t)value : -(int64_t)(~value) - 1;
}
static int32_t signed32(uint32_t value)
{
    return value <= INT32_MAX ? (int32_t)value : -(int32_t)(~value) - 1;
}
static int valid_pid(uint32_t pid) { return pid > 1 && pid <= INT32_MAX; }
static void hex(char *out, uint64_t value, unsigned digits)
{
    static const char alphabet[] = "0123456789abcdef";
    for (unsigned i = 0; i < digits; ++i)
        out[i] = alphabet[(value >> ((digits - i - 1) * 4)) & 15];
}
int pw_native_fd_paths(uint32_t parent_pid, uint64_t correlation,
                       char directory[PW_NATIVE_FD_PATH_CAP], char socket_path[PW_NATIVE_FD_PATH_CAP])
{
    static const char prefix[] = "/data/prospero-win/fd-";
    enum { PREFIX = sizeof(prefix) - 1, LENGTH = PREFIX + 8 + 1 + 16 };
    _Static_assert(LENGTH + 3 <= PW_NATIVE_FD_PATH_CAP, "descriptor path exceeds native bound");
    if (!directory || !socket_path || !valid_pid(parent_pid) || !correlation) return -1;
    for (unsigned i = 0; i < PREFIX; ++i) directory[i] = prefix[i];
    hex(directory + PREFIX, parent_pid, 8);
    directory[PREFIX + 8] = '-';
    hex(directory + PREFIX + 9, correlation, 16);
    directory[LENGTH] = 0;
    for (unsigned i = 0; i < LENGTH; ++i) socket_path[i] = directory[i];
    socket_path[LENGTH] = '/'; socket_path[LENGTH + 1] = 's'; socket_path[LENGTH + 2] = 0;
    return 0;
}
int pw_native_fd_result_matches(const PwNativeFdResult *r, uint32_t local_pid, uint32_t peer_pid, int worker)
{
    const uint32_t common = PW_NATIVE_FD_CONNECTED | PW_NATIVE_FD_HELLO_OK | PW_NATIVE_FD_QUEUED_RIGHT_OK |
                            PW_NATIVE_FD_FORWARD_OK | PW_NATIVE_FD_REVERSE_OK | PW_NATIVE_FD_COMPLETED;
    const uint32_t expected = common | (worker ? PW_NATIVE_FD_REVERSE_EOF : PW_NATIVE_FD_FORWARD_EOF);
    return r && valid_pid(local_pid) && valid_pid(peer_pid) && local_pid != peer_pid &&
           r->status == PW_NATIVE_FD_OK && r->stage == PW_NATIVE_FD_COMPLETE && r->api == PW_NATIVE_FD_API_NONE &&
           !r->raw_result && !r->cleanup_failed && !r->peer_identity_verified &&
           r->local_pid == local_pid && r->reported_peer_pid == peer_pid && r->observations == expected &&
           r->peer_observations == (worker ? 0u : PW_NATIVE_FD_REVERSE_EOF);
}
static int valid_result(const PwNativeFdResult *r, uint32_t parent, uint32_t child)
{
    if (!r || !valid_pid(parent) || !valid_pid(child) || parent == child ||
        r->status > PW_NATIVE_FD_OK || r->status < PW_NATIVE_FD_EOF ||
        r->stage > PW_NATIVE_FD_COMPLETE || r->stage < PW_NATIVE_FD_VALIDATE ||
        r->api > PW_NATIVE_FD_API_UNLINK || r->api < PW_NATIVE_FD_API_NONE ||
        r->observations & ~UINT32_C(255) || r->peer_observations ||
        r->cleanup_failed > 1 || r->peer_identity_verified ||
        (r->local_pid && r->local_pid != child) ||
        (r->reported_peer_pid && r->reported_peer_pid != parent)) return 0;
    if (!r->status) return pw_native_fd_result_matches(r, child, parent, 1);
    /* Failed worker progress must be a prefix the actual role can produce.
     * HELLO installs both reported IDs before exposing its observation bit. */
    const uint32_t hello = PW_NATIVE_FD_CONNECTED | PW_NATIVE_FD_HELLO_OK;
    const uint32_t queued = hello | PW_NATIVE_FD_QUEUED_RIGHT_OK;
    const uint32_t forward = queued | PW_NATIVE_FD_FORWARD_OK;
    const uint32_t reverse = forward | PW_NATIVE_FD_REVERSE_OK | PW_NATIVE_FD_REVERSE_EOF;
    if (r->observations != 0 && r->observations != PW_NATIVE_FD_CONNECTED &&
        r->observations != hello && r->observations != queued &&
        r->observations != forward && r->observations != reverse) return 0;
    if ((r->observations & PW_NATIVE_FD_HELLO_OK) &&
        (r->local_pid != child || r->reported_peer_pid != parent)) return 0;
    return r->stage != PW_NATIVE_FD_COMPLETE;

}
int pw_native_fd_report_encode(uint8_t wire[PW_NATIVE_FD_REPORT_BYTES], uint32_t parent,
                               uint32_t child, uint64_t correlation, const PwNativeFdResult *r)
{
    if (!wire || !correlation || !valid_result(r, parent, child)) return -1;
    for (unsigned i = 0; i < PW_NATIVE_FD_REPORT_BYTES; ++i) wire[i] = 0;
    put32(wire, MAGIC); put32(wire + 4, 1); put32(wire + 8, PW_NATIVE_FD_REPORT_BYTES);
    put32(wire + 12, 2); /* worker role */
    put32(wire + 16, parent); put32(wire + 20, child); put32(wire + 24, 4);
    put64(wire + 32, correlation);
    put32(wire + 40, (uint32_t)r->status); put32(wire + 44, (uint32_t)r->stage);
    put32(wire + 48, (uint32_t)r->api); put32(wire + 52, r->observations);
    put32(wire + 56, r->peer_observations); put32(wire + 60, r->cleanup_failed);
    put64(wire + 64, (uint64_t)r->raw_result);
    put32(wire + 72, r->local_pid); put32(wire + 76, r->reported_peer_pid);
    return 0;
}
int pw_native_fd_report_decode(PwNativeFdResult *r, const uint8_t wire[PW_NATIVE_FD_REPORT_BYTES],
                               uint32_t parent, uint32_t child, uint64_t correlation)
{
    PwNativeFdResult value = {0};
    if (!r || !wire || !correlation || get32(wire) != MAGIC || get32(wire + 4) != 1 ||
        get32(wire + 8) != PW_NATIVE_FD_REPORT_BYTES || get32(wire + 12) != 2 ||
        get32(wire + 16) != parent || get32(wire + 20) != child || get32(wire + 24) != 4 ||
        get32(wire + 28) || get64(wire + 32) != correlation) return -1;
    value.status = (PwNativeFdStatus)signed32(get32(wire + 40));
    value.stage = (PwNativeFdStage)get32(wire + 44); value.api = (PwNativeFdApi)get32(wire + 48);
    value.observations = get32(wire + 52); value.peer_observations = get32(wire + 56);
    value.cleanup_failed = get32(wire + 60); value.raw_result = signed64(get64(wire + 64));
    value.local_pid = get32(wire + 72); value.reported_peer_pid = get32(wire + 76);
    if (!valid_result(&value, parent, child)) return -1;
    *r = value;
    return 0;
}
