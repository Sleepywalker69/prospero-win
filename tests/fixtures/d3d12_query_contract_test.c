/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Pure values only: no Windows headers, GPU, Wine, memory maps or threads. */
#include <assert.h>
#include <stdint.h>
#include "d3d12_query_contract.h"
static int budget_at(uint64_t started, uint64_t now, uint32_t *remaining)
{
    uint64_t last=started;
    return pw_d3d12_query_remaining(started,&last,now,remaining);
}
static int finalize(int status, int close_ok, int budget)
{
    return pw_d3d12_query_finalize(status,1,1,0,close_ok,budget);
}
int main(void)
{
    uint32_t remaining=777;
    /* A truthful low feature result is a completed query, never promoted. */
    assert(pw_d3d12_query_result(0,0,0,0xb000,0,1)==PW_D3D12_QUERY_COMPLETE);
    assert(pw_d3d12_query_result(0,0,0,0xb100,1,3)==PW_D3D12_QUERY_COMPLETE);
    assert(pw_d3d12_query_result(0,0,0,0xc200,3,3)==PW_D3D12_QUERY_COMPLETE);
    assert(pw_d3d12_query_result(0x80004005u,0,0,0xc200,3,3)==PW_D3D12_QUERY_DEVICE_ERROR);
    assert(pw_d3d12_query_result(0,0x80070057u,0,0xc200,3,3)==PW_D3D12_QUERY_LEVELS_ERROR);
    assert(pw_d3d12_query_result(0,0,0x80004001u,0xc200,3,3)==PW_D3D12_QUERY_OPTIONS_ERROR);
    assert(pw_d3d12_query_result(1,0,0,0xc200,3,3)==PW_D3D12_QUERY_DEVICE_ERROR);
    assert(pw_d3d12_query_result(0,0,0,0,0,0)==PW_D3D12_QUERY_INVALID_DATA);
    assert(pw_d3d12_query_result(0,0,0,0xa100,1,1)==PW_D3D12_QUERY_INVALID_DATA);
    assert(pw_d3d12_query_result(0,0,0,0xb000,4,1)==PW_D3D12_QUERY_INVALID_DATA);
    assert(pw_d3d12_query_result(0,0,0,0xb000,0,0)==PW_D3D12_QUERY_INVALID_DATA);
    assert(pw_d3d12_query_result(0,0,0,0xb000,0,4)==PW_D3D12_QUERY_INVALID_DATA);
    assert(budget_at(100,100,&remaining)==0 && remaining==25000);
    assert(budget_at(100,25099,&remaining)==0 && remaining==1);
    assert(budget_at(100,25100,&remaining)==PW_D3D12_QUERY_DEADLINE);
    assert(budget_at(100,26000,&remaining)==PW_D3D12_QUERY_DEADLINE);
    assert(budget_at(100,99,&remaining)==PW_D3D12_QUERY_CLOCK_ERROR);
    assert(budget_at(UINT64_MAX-3,UINT64_MAX,&remaining)==0 && remaining==24997);
    assert(finalize(0,1,0)==PW_D3D12_QUERY_COMPLETE);
    assert(finalize(0,0,0)==PW_D3D12_QUERY_HANDLE_ERROR);
    assert(finalize(0,1,PW_D3D12_QUERY_DEADLINE)==PW_D3D12_QUERY_DEADLINE);
    assert(finalize(0,1,PW_D3D12_QUERY_CLOCK_ERROR)==PW_D3D12_QUERY_CLOCK_ERROR);
    assert(finalize(PW_D3D12_QUERY_DEVICE_ERROR,0,PW_D3D12_QUERY_DEADLINE)==PW_D3D12_QUERY_DEVICE_ERROR);
    /* Original boundary mocks: valid worker completion followed by a close
     * ending exactly at or after the budget must not report COMPLETE. */
    assert(finalize(0,1,budget_at(100,25100,&remaining))==PW_D3D12_QUERY_DEADLINE);
    assert(finalize(0,1,budget_at(100,25101,&remaining))==PW_D3D12_QUERY_DEADLINE);
    {
        uint64_t last=1000;
        assert(pw_d3d12_query_remaining(1000,&last,2000,&remaining)==0 && last==2000 && remaining==24000);
        assert(pw_d3d12_query_remaining(1000,&last,1500,&remaining)==PW_D3D12_QUERY_CLOCK_ERROR);
        assert(last==2000 && remaining==24000); /* no renewed time grant */
    }
    assert(pw_d3d12_query_finalize(0,0,1,0,1,0)==PW_D3D12_QUERY_WORKER_ERROR);
    assert(pw_d3d12_query_finalize(0,1,0,0,1,0)==PW_D3D12_QUERY_WORKER_ERROR);
    assert(pw_d3d12_query_finalize(0,1,1,37,1,0)==PW_D3D12_QUERY_WORKER_ERROR);
    assert(pw_d3d12_query_finalize(0,1,1,259,1,0)==PW_D3D12_QUERY_WORKER_ERROR);
    return 0;
}
