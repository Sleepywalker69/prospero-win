/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Original headless capability query. No shaders, rendering, network or assets. */
#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <windows.h>
#include <dxgi1_2.h>
#include <d3d12.h>
#include <stdio.h>
#include <string.h>
#include "d3d12_query_contract.h"

enum { QUERY_ADAPTER_ERROR = 20, QUERY_NO_HARDWARE = 21, QUERY_THREAD_ERROR = 22, QUERY_CONFIGURATION_ERROR = 23 };
static const D3D_FEATURE_LEVEL requested_levels[] = {
    /* FL12_2 is 0xc200; older MinGW headers omit its enum spelling. */
    (D3D_FEATURE_LEVEL)0xc200, D3D_FEATURE_LEVEL_12_1, D3D_FEATURE_LEVEL_12_0,
    D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0
};

struct query_result {
    int status;
    volatile LONG finished; /* set only after all worker cleanup statements */
    HRESULT device_hr, levels_hr, options_hr;
    D3D12_FEATURE_DATA_FEATURE_LEVELS levels;
    D3D12_FEATURE_DATA_D3D12_OPTIONS options;
};

static void module_path(const char *name)
{
    char path[1024];
    HMODULE module = GetModuleHandleA(name);
    DWORD length;
    if (!module) {
        printf("D3D12_QUERY module=%s state=not_loaded\n", name);
        return;
    }
    length = GetModuleFileNameA(module, path, (DWORD)sizeof(path));
    if (!length || length >= (DWORD)sizeof(path)) {
        printf("D3D12_QUERY module=%s path_error=%lu\n", name, (unsigned long)GetLastError());
        return;
    }
    printf("D3D12_QUERY module=%s path=%s\n", name, path);
}

static int configuration_is_unforced(void)
{
    static const char *const names[] = { "VKD3D_FEATURE_LEVEL", "VKD3D_SHADER_MODEL" };
    unsigned i;
    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        DWORD size, error;
        SetLastError(ERROR_SUCCESS);
        size = GetEnvironmentVariableA(names[i], NULL, 0);
        error = GetLastError();
        if (size) {
            printf("D3D12_QUERY refused capability_override=%s\n", names[i]);
            return 0;
        }
        if (error != ERROR_SUCCESS && error != ERROR_ENVVAR_NOT_FOUND) {
            printf("D3D12_QUERY environment_error=%lu variable=%s\n", (unsigned long)error, names[i]);
            return 0;
        }
    }
    return 1;
}

static DWORD WINAPI query_worker(void *opaque)
{
    struct query_result *result = (struct query_result *)opaque;
    IDXGIFactory1 *factory = NULL;
    IDXGIAdapter1 *adapter = NULL;
    ID3D12Device *device = NULL;
    DXGI_ADAPTER_DESC1 desc;
    HRESULT hr;
    UINT index;
    int found = 0;

    hr = CreateDXGIFactory1(&IID_IDXGIFactory1, (void **)&factory);
    printf("D3D12_QUERY stage=factory hr=0x%08lx\n", (unsigned long)hr);
    if (hr != S_OK || !factory) { result->status = QUERY_ADAPTER_ERROR; goto done; }
    for (index = 0; index < 16; ++index) {
        hr = IDXGIFactory1_EnumAdapters1(factory, index, &adapter);
        if (hr == DXGI_ERROR_NOT_FOUND) break;
        if (hr != S_OK || !adapter) {
            printf("D3D12_QUERY stage=enumerate index=%u hr=0x%08lx\n", index, (unsigned long)hr);
            result->status = QUERY_ADAPTER_ERROR; goto done;
        }
        memset(&desc, 0, sizeof(desc));
        hr = IDXGIAdapter1_GetDesc1(adapter, &desc);
        if (hr != S_OK) {
            printf("D3D12_QUERY stage=adapter_desc hr=0x%08lx\n", (unsigned long)hr);
            result->status = QUERY_ADAPTER_ERROR; goto done;
        }
        printf("D3D12_QUERY adapter=%u vendor=0x%04x device=0x%04x flags=0x%x dedicated=%llu luid=%08lx:%08lx\n",
               index, desc.VendorId, desc.DeviceId, desc.Flags,
               (unsigned long long)desc.DedicatedVideoMemory,
               (unsigned long)desc.AdapterLuid.HighPart, (unsigned long)desc.AdapterLuid.LowPart);
        if (!(desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE)) { found = 1; break; }
        IDXGIAdapter1_Release(adapter); adapter = NULL;
    }
    if (!found) { result->status = QUERY_NO_HARDWARE; goto done; }

    result->device_hr = D3D12CreateDevice((IUnknown *)adapter, D3D_FEATURE_LEVEL_11_0,
                                        &IID_ID3D12Device, (void **)&device);
    printf("D3D12_QUERY stage=create_device min_fl=0xb000 hr=0x%08lx\n", (unsigned long)result->device_hr);
    fflush(stdout);
    if (result->device_hr != S_OK || !device) {
        result->status = PW_D3D12_QUERY_DEVICE_ERROR; goto done;
    }
    result->levels.NumFeatureLevels = (UINT)(sizeof(requested_levels) / sizeof(requested_levels[0]));
    result->levels.pFeatureLevelsRequested = requested_levels;
    result->levels_hr = ID3D12Device_CheckFeatureSupport(device, D3D12_FEATURE_FEATURE_LEVELS,
                                                       &result->levels, sizeof(result->levels));
    printf("D3D12_QUERY stage=feature_levels hr=0x%08lx", (unsigned long)result->levels_hr);
    if (result->levels_hr == S_OK) printf(" max_fl=0x%04x", (unsigned)result->levels.MaxSupportedFeatureLevel);
    putchar('\n');
    result->options_hr = ID3D12Device_CheckFeatureSupport(device, D3D12_FEATURE_D3D12_OPTIONS,
                                                        &result->options, sizeof(result->options));
    printf("D3D12_QUERY stage=options hr=0x%08lx", (unsigned long)result->options_hr);
    if (result->options_hr == S_OK)
        printf(" tiled_tier=%u binding_tier=%u rovs=%u", (unsigned)result->options.TiledResourcesTier,
               (unsigned)result->options.ResourceBindingTier, (unsigned)result->options.ROVsSupported);
    putchar('\n');
    result->status = pw_d3d12_query_result((uint32_t)result->device_hr, (uint32_t)result->levels_hr,
                                         (uint32_t)result->options_hr,
                                         (uint32_t)result->levels.MaxSupportedFeatureLevel,
                                         (uint32_t)result->options.TiledResourcesTier,
                                         (uint32_t)result->options.ResourceBindingTier);

done:
    module_path("dxgi.dll"); module_path("d3d12.dll"); module_path("d3d12core.dll");
    module_path("winevulkan.dll");
    if (device) ID3D12Device_Release(device);
    if (adapter) IDXGIAdapter1_Release(adapter);
    if (factory) IDXGIFactory1_Release(factory);
    InterlockedExchange(&result->finished, 1);
    return 0;
}

int main(int argc, char **argv)
{
    static struct query_result result; /* remains valid if self-termination returns */
    uint64_t started, last_observed, now;
    uint32_t remaining = 0;
    HANDLE worker;
    DWORD wait_result, wait_error, close_error, thread_exit = STILL_ACTIVE, exit_query_error;
    BOOL closed, exit_query_ok;
    LONG worker_finished;
    int budget;
    (void)argv;
    if (argc != 1) { fputs("Usage: d3d12-capability-query.exe\n", stderr); return 2; }
    memset(&result, 0, sizeof(result));
    result.status = QUERY_THREAD_ERROR;
    result.device_hr = result.levels_hr = result.options_hr = E_PENDING;
    started = GetTickCount64();
    last_observed = started;
    printf("D3D12_QUERY begin version=1 budget_ms=%u scope=capabilities_only\n", (unsigned)PW_D3D12_QUERY_BUDGET_MS);
    fflush(stdout);
    if (!configuration_is_unforced()) return QUERY_CONFIGURATION_ERROR;
    worker = CreateThread(NULL, 0, query_worker, &result, 0, NULL);
    if (!worker) {
        printf("D3D12_QUERY stage=runtime_thread_start error=%lu\n", (unsigned long)GetLastError());
        return QUERY_THREAD_ERROR;
    }
    now = GetTickCount64();
    budget = pw_d3d12_query_remaining(started, &last_observed, now, &remaining);
    wait_result = budget ? WAIT_TIMEOUT : WaitForSingleObject(worker, remaining);
    wait_error = wait_result == WAIT_FAILED ? GetLastError() : 0;
    now = GetTickCount64();
    if (!budget) budget = pw_d3d12_query_remaining(started, &last_observed, now, &remaining);
    if (wait_result != WAIT_OBJECT_0 || budget) {
        int status = budget ? budget : (wait_result == WAIT_TIMEOUT ? PW_D3D12_QUERY_DEADLINE : QUERY_THREAD_ERROR);
        printf("D3D12_QUERY incomplete status=%d wait=0x%08lx error=%lu elapsed_ms=%llu\n",
               status, (unsigned long)wait_result, (unsigned long)wait_error,
               (unsigned long long)(now >= started ? now - started : 0));
        fflush(stdout);
        /* Abandon concurrent cleanup; self-termination can end the Wine title.
         * Platform/GPU hangs may prevent delivery; this is not native cleanup proof. */
        {
            BOOL terminated = TerminateProcess(GetCurrentProcess(), (UINT)status);
            DWORD terminate_error = terminated ? ERROR_SUCCESS : GetLastError();
            printf("D3D12_QUERY self_termination_returned result=%u error=%lu cleanup=unverified\n",
                   terminated != FALSE, (unsigned long)terminate_error);
            fflush(stdout);
            ExitProcess((UINT)status);
        }
    }
    exit_query_ok = GetExitCodeThread(worker, &thread_exit);
    exit_query_error = exit_query_ok ? ERROR_SUCCESS : GetLastError();
    worker_finished = InterlockedCompareExchange(&result.finished, 0, 0);
    closed = CloseHandle(worker);
    close_error = closed ? ERROR_SUCCESS : GetLastError();
    now = GetTickCount64();
    budget = pw_d3d12_query_remaining(started, &last_observed, now, &remaining);
    if (!exit_query_ok || thread_exit != 0 || worker_finished != 1)
        printf("D3D12_QUERY stage=worker_completion finished=%ld exit_query=%u error=%lu thread_exit=0x%08lx\n",
               (long)worker_finished, exit_query_ok != FALSE, (unsigned long)exit_query_error,
               (unsigned long)thread_exit);
    if (!closed) printf("D3D12_QUERY close_thread_error=%lu\n", (unsigned long)close_error);
    if (budget) printf("D3D12_QUERY final_budget_status=%d\n", budget);
    result.status = pw_d3d12_query_finalize(result.status, worker_finished == 1, exit_query_ok != FALSE,
                                              (uint32_t)thread_exit, closed != FALSE, budget);
    printf("D3D12_QUERY %s status=%d elapsed_ms=%llu\n",
           result.status == PW_D3D12_QUERY_COMPLETE ? "COMPLETE" : "FAILED",
           result.status, (unsigned long long)(now >= started ? now - started : 0));
    fflush(stdout);
    return result.status;
}
