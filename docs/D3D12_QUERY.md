# Original D3D12 capability query: build-only proposal

This is an original PE64 query fixture for a separately reviewed graphics overlay. It is not installed into the accepted diagnostic kit. It has no vendor assets, shader blobs, network code, DLL override changes or capability-forcing options. It refuses nonempty inherited VKD3D_FEATURE_LEVEL and VKD3D_SHADER_MODEL overrides before device creation, logging only their names. Missing/empty variables are distinct from query failure. This checks those two known overrides; other runtime configuration may still affect reported capabilities.

For older MinGW headers, the requested FL12_2 array member uses its standard
typed value 0xc200; this does not change the request or returned capabilities.

The program uses the first non-software DXGI adapter among a bounded16 entries, then calls D3D12CreateDevice with minimum feature level11_0. It reports actual CheckFeatureSupport results for maximum feature level, tiled-resources tier and resource-binding tier. Failed HRESULTs remain failures; values are not reported as supported when the corresponding query fails. Loaded module paths are diagnostic provenance, not file hashes or proof of vkd3d identity.

`D3D12_QUERY COMPLETE` means only that the API query and worker cleanup finished with usable results within the observed budget. It requires a marker written after the last Release plus a successfully queried normal Windows thread exit result; a merely signaled thread handle is insufficient. A truthful FL11_0/Tier0 or FL11_1/Tier1 result is COMPLETE. It does not mean FL12_0 support, successful rendering, Retail compatibility, working Agility SDK selection, sparse residency or independent native cleanup. There is no WARP/device fallback after hardware device-creation failure.

The current pinned PS5 RADV/vkd3d2.14 source chain yields at most FL11_1 because shader residency and strict nonresident semantics are unavailable. The original query records what the actual runtime returns instead of forcing that source prediction. Vulkan device creation can fail earlier for other reasons.

## Budget and failure behavior

A single25-second GetTickCount64 budget accounts for thread setup, DXGI/D3D12 calls and Release cleanup once those calls return. The worker wait uses only the remaining budget. This is deadline accounting and a watchdog for the worker wait, not a guaranteed end-to-end termination bound: DLL initialization can run before main, and configuration reads, CreateThread itself or platform calls may hang before or beyond the point where the main thread can supervise them. Remaining time is calculated after thread setup and rechecked after completion, so a late result cannot become COMPLETE. Every clock sample is checked against both the original start and the previous observed sample; a within-interval regression is an error and cannot increase remaining time. WAIT_FAILED captures GetLastError immediately. CloseHandle failure also captures its error immediately; final time is checked after the close. Prior worker failure is preserved while additional close/budget errors are logged, and none can produce COMPLETE.

On timeout/wait/clock failure, the main thread logs an incomplete result and requests self-termination. Shared result storage is static, so a returning/failed TerminateProcess does not leave a worker writing dead stack storage. If TerminateProcess unexpectedly returns, its immediate result/error is logged and ExitProcess is explicitly requested; the program does not return from that branch. Neither request guarantees delivery if the runtime/platform is stuck. Under the current Wine host this can terminate/restart the entire title. It does not release graphics resources concurrently from another thread, promise termination delivery during a kernel/driver hang, or claim native cleanup. Do not run this fixture as a child or with valuable unsaved application state.

No GPU commands, shader compilation, resource allocation, drawing or presentation are requested by the fixture. Device creation may itself allocate driver state and start its internal threads. A later smoke fixture must test those GPU execution contracts separately.

## Source validation and producer boundary

- `tests/fixtures/d3d12_query_contract_test.c` includes only the pure reporting/deadline header. It checks preserved low feature levels, each failed HRESULT, non-S_OK results, invalid capability values, the exact deadline, late completion, backward clocks, close failure, post-close deadline boundaries, missing cleanup marker and abnormal/unavailable Windows thread exit status. It executes no Windows, Wine, GPU, mapping or thread code.
- tests/test_d3d12_query.py checks source routing: the requested minimum remains FL11_0, known overrides are refused before thread/device creation, and final deadline evaluation follows handle close. Its additional original API mocks compile and exercise the exact environment-check function with missing, empty, forced and API-error responses. This is source/pure-control evidence, not runtime proof.
- The full Windows source compiles with Clang19, retained MinGW14 headers, AMD64 target and -std=c11 -Wall -Wextra -Werror. The retained review output was an inert AMD64 COFF object; it is not a repository artifact. This is not an executable validation.
- No D3D12 API, Wine or driver was executed; no MSVC or MinGW executable link was performed here.

Proposed Windows build, to be verified by the eventual producer:

    cl /nologo /std:c11 /W4 /WX /O2 /MT /D_CRT_SECURE_NO_WARNINGS tests\fixtures\d3d12_capability_query.c /Fe:d3d12-capability-query.exe /link d3d12.lib dxgi.lib dxguid.lib /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /FIXED:NO

A separate MinGW POSIX frontend producer can link -ld3d12 -ldxgi -ldxguid. Retain complete toolchain/source/licence identities. The final PE must be independently inspected for AMD64/PE32+, real relocations, ASLR/NX flags, all imports and actual source-built DLL/export bindings. Surface unexpected CRT/system DLL dependencies for review; do not infer executable imports from the COFF undefined-symbol list.

Before console use, assemble a separately reviewed matching Wine/RADV/DXVK/vkd3d diagnostic overlay. Static checks must distinguish d3d12.dll, the matching d3d12core.dll and DXGI, and verify the core's SDKVersion is a data export rather than Wine's existing stub. Do not call the stub Agility exports to test their existence. The query itself makes no Agility calls. Initial thread creation and worker-lifecycle errors have separate stages/statuses from factory/device/query errors; a failure identifies the observed API boundary, not a proven GPU fault. Absence of the D3D12_QUERY begin record means the fixture has not established entry into main; a loader/import/runtime failure before that point is not a measured GPU-capability failure.

The accepted software-GDI/HELLO/FD/HTTPS artifacts remain separate. No current Retail D3D11 or D3D12 compatibility is claimed by this proposal.
