# Single-process PE64 HTTPS diagnostic

Build-only proposal prepared 2026-10-09. The original C source was compiled to an AMD64 COFF object with warnings treated as errors. It has not been linked with MSVC, run on Windows/Wine/PS5, or used to contact any endpoint. The build script neither installs tools nor runs the resulting program.

This provides an earlier console milestone than Windows child support: one original PE64 process exercises the new DNS and TLS path. Its worker and DNS-threadpool threads remain in that same process. It does not start Battle.net, Agent, wineboot, an installer or another executable.

## Proposed build

On an already provisioned Windows machine with Visual Studio C++ tools:

```powershell
powershell -File tools/build_windows_https_probe.ps1
```

The script builds with MSVC `/std:c11 /W4 /WX /O2 /MT`, links WinHTTP/Crypt32 with explicit `/FIXED:NO`, and preserves ASLR/high-entropy VA/NX compatibility. It runs the fixture-specific Python inspector on the actual linked image before writing SHA256SUMS and BUILD-INFO.txt. Preinstalled Python3 is required for that static check. No private dispatcher ABI or process-child flags are involved. Integrated repository/CI changes remain the sole writer's responsibility.

`PE-VALIDATION.json` records the image/source hashes, AMD64 PE32+ identity, console subsystem, security flags, usable DIR64 base relocations and actual direct DLL/API imports. The expected direct DLL set is KERNEL32.dll, WINHTTP.dll and CRYPT32.dll. Unexpected DLLs, including a newly introduced dynamic CRT dependency, are rejected for review; no dependency is silently accepted or downloaded. Delay imports are also rejected for this fixture. This is static validation of a linked EXE, not proof that it executes or that the complete Wine dependency closure is available.

The explicit relocation check follows the real Windows reference finding: MSVC-produced parent/child fixtures previously had relocations stripped despite a comment saying they were retained. The HTTPS build keeps its separate ASLR policy, but must verify actual relocation bytes as well as the header flags. Microsoft's linker reference describes `/FIXED:NO` as the switch to generate relocations: https://learn.microsoft.com/en-us/cpp/build/reference/fixed-fixed-base-address?view=msvc-170

The new checks can be run on any Python3 host without loading an executable:

```text
python tests/test_windows_https_probe.py -v
python tools/inspect_windows_https_probe.py path/to/windows-https-probe.exe \
  --source tests/fixtures/windows_https_probe.c --output PE-VALIDATION.json
```

Four host tests cover an original inert PE-shaped sample, nineteen rejected image mutations, required builder flags and narrow source-policy regression guards. The source guards are not substitutes for runtime tests. The build-only CI should include both new files in path triggers and retain the inspector/test sources beside the artifact for review.

Local build-only check already completed:

```text
clang --target=x86_64-w64-windows-gnu -isystem <existing-mingw-include-dir> \
  -std=c11 -Wall -Wextra -Werror -c tests/fixtures/windows_https_probe.c
```

It produced an x86-64 COFF object, not a runnable test result. MSVC linking and the actual runtime import set still need verification.

## Required runtime

- A complete, matching Wine runtime containing the DNS/TLS candidate, not the native-title-only diagnostic kit. The source design was checked against combined candidate6dfdec30430a1af0a8d772eb34dffafd7013a2f0 and pinned Wine490f6d5dcbb2a5047345b8af88d114bbcaad69a8.
- Matching x64 PE runtime modules including ntdll, kernel32/kernelbase, winhttp, ws2_32, secur32 and crypt32, plus their normal bundled dependencies.
- Native ntdll, ws2_32, crypt32, secur32 and libgnutls PRXs from the same verified build. Schannel cannot work if the TLS-enabled native modules are absent even when winhttp.dll exists.
- The package's unchanged pinned root bundle at `win/wine/share/wine/ca-certificates.crt`, resolved by Crypt32 from its module path. Keep its recorded hash. Do not add an endpoint certificate to a trust store or change verification options to obtain a pass.
- An isolated offline-prepared x64-compatible Wine prefix and existing profile workflow pointing directly to this fixture. No online prefix bootstrap or installer is required for this diagnostic. Any existing packaging requirements unrelated to this PE still apply to the complete runtime.
- Correct console clock and permitted network access in the current homebrew environment. The fixture logs UTC so a date failure can be compared with an independent clock; it never changes the clock.

## Operator-selected endpoint and invocation

The program has no default destination. The user supplies a public or authorized test DNS hostname and optional port. It rejects full URLs, credentials, IP literals, single-label names, query strings and fragments. It always issues one logical `HEAD /` request. It does not follow redirects or provide authentication, cookies, client certificates, request bodies or a proxy.

```text
windows-https-probe.exe ok <valid-certificate-FQDN> [port]
windows-https-probe.exe cert-name <wrong-hostname-certificate-FQDN> [port]
windows-https-probe.exe cert-date <expired-or-not-yet-valid-certificate-FQDN> [port]
windows-https-probe.exe cert-ca <untrusted-issuer-certificate-FQDN> [port]
```

These are templates, not endpoint recommendations. Do not run them until the user has selected/authorized the endpoints. Run each case as a new process/session. Use endpoints which require no login/client certificate and support TLS1.2. The first test should be the positive case, followed by deliberately configured negative cases with known expected certificate defects. Multiple defects can produce ambiguous evidence.

A valid HTTP response of any100–599 status is sufficient for the `ok` DNS/TLS transport milestone. A301,401,403 or405 does not become proof of an application login or successful page request; its significance here is that a certificate-validated HTTPS response was received. Redirect following and authentication remain disabled.

## Source-supported call path

1. `WinHttpOpen(NO_PROXY)` creates a synchronous session.
2. `WinHttpSetTimeouts` sets DNS/connect/send/receive to5000ms. `WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT` is set separately to5000ms on both session and request because pinned Wine stores it separately and uses it for TLS/response socket reads.
3. `WINHTTP_OPTION_SECURE_PROTOCOLS=TLS1_2` selects a modern protocol explicitly. Pinned WinHTTP's `map_secure_protocols` maps through TLS1.2, not TLS1.3; this diagnostic makes no TLS1.3 claim.
4. `WinHttpConnect` and secure `WinHttpOpenRequest(HEAD, /)` prepare the request. Redirects, cookies, authentication and keepalive are disabled; automatic-logon policy is HIGH. No certificate-ignore option is ever set.
5. `WinHttpSendRequest` enters `open_connection`, resolves through `GetAddrInfoW` and ws2_32's Unix side, creates the TCP socket, acquires Schannel outbound credentials, and calls `InitializeSecurityContextW` through GnuTLS.
6. Pinned WinHTTP requests manual Schannel validation internally, then itself calls `CertGetCertificateChain` and `CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL)` with the requested hostname and zero ignore flags before sending HTTP bytes. The fixture does not replace this policy or accept a certificate after its rejection.
7. `WinHttpReceiveResponse` obtains headers. Positive acceptance additionally requires the secure flag, no ignore bits, a returned server-certificate context and nonzero reported key strength. It logs only status and certificate validity timestamps, never bodies, headers, certificate blobs or credentials.

This tests the existing WinHTTP trust/hostname/time/usage checks. It does not independently establish revocation freshness, every cipher/protocol, all DNS address families or fresh on-wire DNS traffic rather than an existing resolver cache.

## Deadline and cleanup

Each request phase has a5-second timeout, but those are not a whole-operation bound: multiple TLS fragments or ancillary certificate work can extend the total. A main-thread watchdog uses one25-second budget beginning just before worker creation. It includes thread creation, request processing and handle cleanup; the final elapsed time is checked before accepting PASS.

If the worker remains active at the deadline, the fixture logs the last stage and calls `TerminateProcess(GetCurrentProcess(),5)`. This stops only its current diagnostic process. On this project's in-process Wine title, it may return the console to Home rather than exercising the normal Wine-exit restart path. It never calls TerminateThread or retries the request. If the worker has already finished but the total budget has elapsed, the result is DEADLINE without another termination call.

The watchdog itself depends on the Wine scheduler, wait and same-process termination implementations. It cannot guarantee recovery if the entire runtime/kernel is unresponsive, nor does its25-second budget cover a loader hang before `wmain` starts. Missing begin/result records are distinct startup/runtime failures.

## Results and strict certificate-negative evidence

Exit codes:

-0 PASS: the requested positive transport result, or a specifically identified expected certificate rejection.
-1 FAIL: unexpected accepted certificate, wrong identified rejection, or inconsistent secure response.
-2 USAGE: invalid arguments; no network request begins.
-3 SETUP_ERROR: a required WinHTTP option, object or query failed.
-4 INCONCLUSIVE: network failure, timeout or ambiguous TLS/certificate evidence.
-5 DEADLINE: the whole diagnostic exceeded its budget or its controlling wait failed.

Observation bits are1 resolving,2 name resolved,4 connecting,8 connected after TLS validation,16 request sent and32 response received. `error_stage` records the API phase that failed. UTC and public certificate validity timestamps support clock diagnosis. They are not permission to adjust trust/clock settings.

### Important pinned-Wine limitation

`winhttp/net.c:netconn_secure_connect` obtains a specific certificate error from `netconn_verify_cert`, logs `cert verify failed: <error>`, but then returns generic `ERROR_WINHTTP_SECURE_CHANNEL_ERROR`12157. This pinned path also does not emit `WINHTTP_CALLBACK_STATUS_SECURE_FAILURE`. Therefore a negative test will commonly exit4 INCONCLUSIVE even when the internal validator correctly rejected the certificate. A DNS failure or incompatible TLS server can produce an indistinguishable outer failure, so treating12157 as an automatic certificate-test pass would be false evidence.

The fixture accepts a negative case automatically only with the specific expected WinHTTP certificate error, or matching secure-failure callback evidence on implementations that provide it. Contradictory callback flags remain INCONCLUSIVE. If a negative endpoint instead returns a validated HTTPS response, the result is FAIL.

For the PS5 run, a narrow diagnostic profile may use:

```text
WINEDEBUG=-all,warn+winhttp,err+crypt
```

Set that through the existing profile's documented debug option, not by changing TLS flags. The exact warning `winhttp:... cert verify failed:12038` supports hostname rejection;12037 supports date rejection;12045 supports untrusted/partial-chain rejection. The actual Wine log includes spaces/standard prefixes. Correlate the warning with that case's fixture begin/result and the known endpoint configuration, and retain the automated INCONCLUSIVE result unchanged. Report a separately reviewed certificate-negative observation only when the specific warning exists. No warning, wrong reason, generic TLS error, missing CA bundle or incorrect console time does not pass the intended case.

Avoid full `trace+winhttp` for routine sharing because it can include response headers, including server-issued cookies, even though this fixture does not reuse them. Review all captured logs before sharing.

## First-session acceptance card

1. Verify exact full-runtime and fixture hashes; confirm required PRXs, x64 PE modules and unchanged CA bundle are present.
2. Launch the original fixture directly with one authorized valid endpoint. Require the begin marker, plausible UTC, DNS/connection observations, positive secure response and bounded terminal result.
3. Run each authorized negative endpoint separately. Require rejection with its specific expected certificate evidence; generic failures remain inconclusive. Never add trust or ignore flags.
4. Confirm the title's actual close/return behavior and collect the matching saved session log.
5. Only then move on to Battle.net login or process-child diagnostics. This result establishes neither Agent spawning nor Retail launch, character selection or entering a world.

## Primary references

- Pinned WinHTTP TLS/certificate path: https://github.com/wine-mirror/wine/blob/490f6d5dcbb2a5047345b8af88d114bbcaad69a8/dlls/winhttp/net.c
- Pinned request/protocol mapping: https://github.com/wine-mirror/wine/blob/490f6d5dcbb2a5047345b8af88d114bbcaad69a8/dlls/winhttp/request.c
- Pinned timeout/options: https://github.com/wine-mirror/wine/blob/490f6d5dcbb2a5047345b8af88d114bbcaad69a8/dlls/winhttp/session.c
- WinHTTP timeout contract: https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpsettimeouts
- WinHTTP options/security contract: https://learn.microsoft.com/en-us/windows/win32/winhttp/option-flags
- Callback contract: https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpsetstatuscallback

