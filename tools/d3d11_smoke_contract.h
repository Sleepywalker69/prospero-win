/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_D3D11_SMOKE_CONTRACT_H
#define PW_D3D11_SMOKE_CONTRACT_H
#include <stddef.h>
#include <stdint.h>

enum { PW_D3D11_BUDGET_MS = 25000, PW_D3D11_HANDLE_ERROR = 2, PW_D3D11_WORKER_ERROR = 3,
       PW_D3D11_DEADLINE = 124, PW_D3D11_CLOCK_ERROR = 125 };

static inline int pw_d3d11_surface_valid(uint32_t width, uint32_t height, uint32_t format,
                                        uint32_t expected_format, uint32_t samples,
                                        uint32_t quality, uint32_t mips, uint32_t array_size)
{
    return width == 1920 && height == 1080 && format == expected_format &&
           samples == 1 && quality == 0 && mips == 1 && array_size == 1;
}

/* Metadata only: the successful Map contract still owns the validity/lifetime
 * of the actual mapping. No caller pointer is read by this helper. */
static inline int pw_d3d11_center_offset(uintptr_t data, uint32_t pitch,
                                        uint32_t width, uint32_t height, size_t *offset)
{
    uint64_t at;
    if (!data || !offset || !width || !height || (uint64_t)width * 4 > pitch) return 0;
    at = (uint64_t)(height / 2) * pitch + (uint64_t)(width / 2) * 4;
    if (at > SIZE_MAX - 4 || data > UINTPTR_MAX - (uintptr_t)at - 4) return 0;
    *offset = (size_t)at;
    return 1;
}

/* One absolute budget, with every sampled clock value checked against the
 * previous sample. An intermediate backward jump never extends the budget. */
static inline int pw_d3d11_remaining(uint64_t started, uint64_t *last,
                                    uint64_t now, uint32_t *remaining)
{
    if (now < started || now < *last) return PW_D3D11_CLOCK_ERROR;
    *last = now;
    if (now - started >= PW_D3D11_BUDGET_MS) return PW_D3D11_DEADLINE;
    *remaining = PW_D3D11_BUDGET_MS - (uint32_t)(now - started);
    return 0;
}

static inline int pw_d3d11_completed(int query_ok, uint32_t worker_code, int finished)
{
    if (!query_ok) return PW_D3D11_HANDLE_ERROR;
    if (finished != 1) return PW_D3D11_WORKER_ERROR;
    return worker_code ? 1 : 0;
}

static inline int pw_d3d11_finalize(int worker_status, int closed, int budget_status)
{
    if (worker_status) return worker_status;
    if (!closed) return PW_D3D11_HANDLE_ERROR;
    return budget_status;
}
#endif
