/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Original two-frame D3D11 diagnostic. No game assets, shaders or network. */
#define COBJMACROS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d11.h>
#include <dxgi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "d3d11_smoke_contract.h"

typedef struct { volatile LONG finished; } SmokeCompletion;

static LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    return DefWindowProcA(window, message, wparam, lparam);
}

static int result(const char *stage, HRESULT hr)
{
    printf("D3D11_SMOKE stage=%s hr=0x%08lx\n", stage, (unsigned long)hr);
    fflush(stdout);
    return hr == S_OK;
}

static DWORD WINAPI render_worker(void *argument)
{
    const D3D_FEATURE_LEVEL wanted[] = {D3D_FEATURE_LEVEL_11_0};
    const float colours[2][4] = {{0.25f, 0.5f, 0.75f, 1.0f}, {0.75f, 0.5f, 0.25f, 1.0f}};
    const unsigned expected[2][4] = {{64, 128, 191, 255}, {191, 128, 64, 255}};
    SmokeCompletion *completion = argument;
    WNDCLASSA wc = {0};
    ATOM class_atom = 0;
    DXGI_SWAP_CHAIN_DESC sd = {0};
    D3D11_TEXTURE2D_DESC td = {0};
    D3D_FEATURE_LEVEL level = 0;
    ID3D11Device *device = NULL;
    ID3D11DeviceContext *context = NULL;
    IDXGISwapChain *swapchain = NULL;
    ID3D11Texture2D *back = NULL, *staging = NULL;
    ID3D11RenderTargetView *view = NULL;
    IDXGIDevice *dxgi_device = NULL;
    IDXGIAdapter *adapter = NULL;
    HWND window = NULL;
    int exit_code = 1;
    unsigned frame;

    if (!completion) return PW_D3D11_WORKER_ERROR;
    wc.lpfnWndProc = window_proc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "ProsperoOriginalD3D11Smoke";
    class_atom = RegisterClassA(&wc);
    if (!class_atom) {
        printf("D3D11_SMOKE stage=register-window error=%lu\n", (unsigned long)GetLastError());
        goto cleanup;
    }
    window = CreateWindowExA(0, wc.lpszClassName, "Original D3D11 diagnostic", WS_POPUP | WS_VISIBLE,
                             0, 0, 1920, 1080, NULL, NULL, wc.hInstance, NULL);
    if (!window) {
        printf("D3D11_SMOKE stage=create-window error=%lu\n", (unsigned long)GetLastError());
        goto cleanup;
    }
    sd.BufferDesc.Width = 1920;
    sd.BufferDesc.Height = 1080;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.SampleDesc.Count = 1;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.BufferCount = 2;
    sd.OutputWindow = window;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    if (!result("create-hardware-device", D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE,
            NULL, 0, wanted, 1, D3D11_SDK_VERSION, &sd, &swapchain, &device, &level, &context))) goto cleanup;
    if (!device || !context || !swapchain) goto cleanup;
    printf("D3D11_SMOKE feature_level=0x%x requested_width=1920 requested_height=1080\n", (unsigned)level);
    if (level != D3D_FEATURE_LEVEL_11_0) goto cleanup;
    if (!result("query-dxgi-device", ID3D11Device_QueryInterface(device, &IID_IDXGIDevice,
                                                               (void **)&dxgi_device)) || !dxgi_device) goto cleanup;
    if (!result("get-adapter", IDXGIDevice_GetAdapter(dxgi_device, &adapter)) || !adapter) goto cleanup;
    {
        DXGI_ADAPTER_DESC description = {0};
        if (!result("adapter-desc", IDXGIAdapter_GetDesc(adapter, &description))) goto cleanup;
        printf("D3D11_SMOKE vendor=0x%04x device=0x%04x video_memory=%llu\n",
               description.VendorId, description.DeviceId, (unsigned long long)description.DedicatedVideoMemory);
    }
    if (!result("get-back-buffer", IDXGISwapChain_GetBuffer(swapchain, 0, &IID_ID3D11Texture2D,
                                                            (void **)&back)) || !back) goto cleanup;
    if (!result("create-render-target", ID3D11Device_CreateRenderTargetView(device,
                                 (ID3D11Resource *)back, NULL, &view)) || !view) goto cleanup;
    ID3D11Texture2D_GetDesc(back, &td);
    printf("D3D11_SMOKE actual_width=%u actual_height=%u format=%u samples=%u quality=%u mips=%u array=%u\n",
           td.Width, td.Height, (unsigned)td.Format, td.SampleDesc.Count, td.SampleDesc.Quality,
           td.MipLevels, td.ArraySize);
    if (!pw_d3d11_surface_valid(td.Width, td.Height, (uint32_t)td.Format,
                               DXGI_FORMAT_R8G8B8A8_UNORM, td.SampleDesc.Count,
                               td.SampleDesc.Quality, td.MipLevels, td.ArraySize)) goto cleanup;
    td.Usage = D3D11_USAGE_STAGING;
    td.BindFlags = 0;
    td.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    td.MiscFlags = 0;
    if (!result("create-staging", ID3D11Device_CreateTexture2D(device, &td, NULL, &staging)) || !staging) goto cleanup;
    for (frame = 0; frame < 2; ++frame) {
        D3D11_MAPPED_SUBRESOURCE mapped = {0};
        size_t centre;
        unsigned component, mismatches = 0;
        const uint8_t *pixel;
        MSG message;
        while (PeekMessageA(&message, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&message);
            DispatchMessageA(&message);
        }
        ID3D11DeviceContext_ClearRenderTargetView(context, view, colours[frame]);
        ID3D11DeviceContext_CopyResource(context, (ID3D11Resource *)staging, (ID3D11Resource *)back);
        if (!result("map-readback", ID3D11DeviceContext_Map(context, (ID3D11Resource *)staging,
                                                     0, D3D11_MAP_READ, 0, &mapped))) goto cleanup;
        if (!pw_d3d11_center_offset((uintptr_t)mapped.pData, mapped.RowPitch, td.Width, td.Height, &centre)) {
            printf("D3D11_SMOKE invalid_map pointer_null=%u row_pitch=%u\n", (unsigned)(mapped.pData == NULL), mapped.RowPitch);
            ID3D11DeviceContext_Unmap(context, (ID3D11Resource *)staging, 0);
            goto cleanup;
        }
        pixel = (const uint8_t *)mapped.pData + centre;
        for (component = 0; component < 4; ++component)
            mismatches += abs((int)pixel[component] - (int)expected[frame][component]) > 1;
        printf("D3D11_SMOKE frame=%u center=%02x%02x%02x%02x mismatches=%u\n",
               frame, pixel[0], pixel[1], pixel[2], pixel[3], mismatches);
        ID3D11DeviceContext_Unmap(context, (ID3D11Resource *)staging, 0);
        if (mismatches) goto cleanup;
        if (!result("present", IDXGISwapChain_Present(swapchain, 1, 0))) goto cleanup;
        Sleep(1000);
    }
    exit_code = 0;
cleanup:
    if (context) ID3D11DeviceContext_ClearState(context);
    if (view) ID3D11RenderTargetView_Release(view);
    if (staging) ID3D11Texture2D_Release(staging);
    if (back) ID3D11Texture2D_Release(back);
    if (adapter) IDXGIAdapter_Release(adapter);
    if (dxgi_device) IDXGIDevice_Release(dxgi_device);
    if (swapchain) IDXGISwapChain_Release(swapchain);
    if (context) ID3D11DeviceContext_Release(context);
    if (device) ID3D11Device_Release(device);
    if (window && !DestroyWindow(window)) exit_code = 1;
    if (class_atom && !UnregisterClassA(wc.lpszClassName, wc.hInstance)) exit_code = 1;
    InterlockedExchange(&completion->finished, 1);
    return (DWORD)exit_code;
}


int main(void)
{
    static SmokeCompletion completion;
    uint64_t started = GetTickCount64(), last = started, now;
    uint32_t remaining = 0;
    DWORD wait_result, wait_error, worker_code = STILL_ACTIVE, code_error, close_error;
    BOOL code_ok, closed;
    int budget, status;
    LONG finished;
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("D3D11_SMOKE begin budget_ms=%u scope=clear_readback_present\n", (unsigned)PW_D3D11_BUDGET_MS);
    HANDLE worker = CreateThread(NULL, 0, render_worker, &completion, 0, NULL);
    if (!worker) {
        printf("D3D11_SMOKE thread_error=%lu\n", (unsigned long)GetLastError());
        return PW_D3D11_HANDLE_ERROR;
    }
    budget = pw_d3d11_remaining(started, &last, GetTickCount64(), &remaining);
    wait_result = budget ? WAIT_TIMEOUT : WaitForSingleObject(worker, remaining);
    wait_error = wait_result == WAIT_FAILED ? GetLastError() : 0;
    now = GetTickCount64();
    if (!budget) budget = pw_d3d11_remaining(started, &last, now, &remaining);
    if (wait_result != WAIT_OBJECT_0 || budget) {
        status = budget ? budget : wait_result == WAIT_TIMEOUT ? PW_D3D11_DEADLINE : PW_D3D11_HANDLE_ERROR;
        printf("D3D11_SMOKE incomplete status=%d wait=0x%08lx error=%lu elapsed_ms=%llu\n",
               status, (unsigned long)wait_result, (unsigned long)wait_error,
               (unsigned long long)(now >= started ? now - started : 0));
        fflush(stdout);
        /* The worker owns COM objects. Never release them concurrently.
         * Self-termination may end the hosting Wine title; native/GPU hangs
         * may prevent delivery, so this is not a native-cleanup guarantee. */
        {
            BOOL terminated = TerminateProcess(GetCurrentProcess(), (UINT)status);
            DWORD terminate_error = terminated ? ERROR_SUCCESS : GetLastError();
            printf("D3D11_SMOKE termination_returned result=%u error=%lu\n",
                   (unsigned)terminated, (unsigned long)terminate_error);
            fflush(stdout);
            ExitProcess((UINT)status);
        }
        return status;
    }
    code_ok = GetExitCodeThread(worker, &worker_code);
    code_error = code_ok ? ERROR_SUCCESS : GetLastError();
    closed = CloseHandle(worker);
    close_error = closed ? ERROR_SUCCESS : GetLastError();
    now = GetTickCount64();
    budget = pw_d3d11_remaining(started, &last, now, &remaining);
    finished = InterlockedCompareExchange(&completion.finished, 0, 0);
    status = pw_d3d11_completed(code_ok != FALSE, worker_code, (int)finished);
    status = pw_d3d11_finalize(status, closed != FALSE, budget);
    printf("D3D11_SMOKE result=%s status=%d worker=0x%08lx finished=%lu code_error=%lu close_error=%lu budget=%d elapsed_ms=%llu\n",
           status ? "FAIL" : "PASS", status, (unsigned long)worker_code, (unsigned long)finished,
           (unsigned long)code_error, (unsigned long)close_error, budget,
           (unsigned long long)(now >= started ? now - started : 0));
    return status;
}
