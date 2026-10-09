/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_D3D12_QUERY_CONTRACT_H
#define PW_D3D12_QUERY_CONTRACT_H
#include <stdint.h>

enum { PW_D3D12_QUERY_BUDGET_MS = 25000 };
enum PwD3D12QueryResult {
    PW_D3D12_QUERY_COMPLETE = 0,
    PW_D3D12_QUERY_DEVICE_ERROR = 10,
    PW_D3D12_QUERY_LEVELS_ERROR = 11,
    PW_D3D12_QUERY_OPTIONS_ERROR = 12,
    PW_D3D12_QUERY_INVALID_DATA = 13,
    PW_D3D12_QUERY_HANDLE_ERROR = 14,
    PW_D3D12_QUERY_WORKER_ERROR = 15,
    PW_D3D12_QUERY_DEADLINE = 124,
    PW_D3D12_QUERY_CLOCK_ERROR = 125
};

/* Pure reporting policy. HRESULTs are raw unsigned bits; only S_OK supplies
 * usable queried fields. These functions do not query or alter a device. */
static inline int pw_d3d12_query_result(uint32_t device_hr, uint32_t levels_hr,
                                      uint32_t options_hr, uint32_t max_fl,
                                      uint32_t tiled_tier, uint32_t binding_tier)
{
    if (device_hr) return PW_D3D12_QUERY_DEVICE_ERROR;
    if (levels_hr) return PW_D3D12_QUERY_LEVELS_ERROR;
    if (options_hr) return PW_D3D12_QUERY_OPTIONS_ERROR;
    switch (max_fl) {
    case 0xb000: case 0xb100: case 0xc000: case 0xc100: case 0xc200: break;
    default: return PW_D3D12_QUERY_INVALID_DATA;
    }
    if (tiled_tier > 3 || binding_tier < 1 || binding_tier > 3)
        return PW_D3D12_QUERY_INVALID_DATA;
    return PW_D3D12_QUERY_COMPLETE;
}

/* One absolute budget covers thread creation, all API calls and cleanup.
 * A late completed worker cannot turn expiry into a successful query. */
static inline int pw_d3d12_query_remaining(uint64_t started, uint64_t *last, uint64_t now, uint32_t *remaining)
{
    if (now < started || now < *last) return PW_D3D12_QUERY_CLOCK_ERROR;
    *last = now;
    if (now - started >= PW_D3D12_QUERY_BUDGET_MS) return PW_D3D12_QUERY_DEADLINE;
    *remaining = PW_D3D12_QUERY_BUDGET_MS - (uint32_t)(now - started);
    return PW_D3D12_QUERY_COMPLETE;
}
/* Final reporting never promotes a prior error or an unclosed worker handle.
 * The caller separately logs close/budget errors even after a worker failure. */
static inline int pw_d3d12_query_finalize(int worker_status, int worker_finished, int exit_query_ok,
                                         uint32_t thread_exit, int close_ok, int budget_status)
{
    if (worker_status != PW_D3D12_QUERY_COMPLETE) return worker_status;
    if (!worker_finished || !exit_query_ok || thread_exit != 0) return PW_D3D12_QUERY_WORKER_ERROR;
    if (!close_ok) return PW_D3D12_QUERY_HANDLE_ERROR;
    return budget_status;
}
#endif
