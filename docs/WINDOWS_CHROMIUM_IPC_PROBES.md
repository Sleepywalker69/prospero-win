# Original Chromium-shaped Windows API probes

These original, separate diagnostics measure Windows process and IPC requirements
without CEF, vendor assets or a compatibility workaround. They do not change the
existing `windows_child_process.c` fixture, its package, native admission, PS5
profiles, security settings or runtime implementation. A fixture source change
is not a Wine fix. No target execution is established by this document.

## Gates and commands

Run the existing [original Windows child reference](../tests/fixtures/windows_child_process.md)
first, including its inherited anonymous-pipe/event and full child exit-code
checks. A native helper HELLO is not this gate. Build both architectures on
Windows with preinstalled official Visual Studio C++ tools:

```powershell
powershell -File tools/build_windows_chromium_ipc.ps1 -Arch x64 -Out C:\scratch\ipc-x64-new
powershell -File tools/build_windows_chromium_ipc.ps1 -Arch x86 -Out C:\scratch\ipc-x86-new
```

The output directory must not exist. The one `chromium-ipc.exe` image launches
itself with `--worker`; no unrelated executable or process is opened. ASLR and NX
remain enabled. The script checks PE machine/optional-header architecture,
retains the original C/header, compiler-selection output, compiler hash and
source/PE SHA-256 values. Compiler bytes are not redistributed.

Run each case in its own **new** working directory, retaining stdout/stderr,
`ipc-NONCE-PID.log`, the actual parent exit code and original build evidence:

```powershell
New-Item -ItemType Directory C:\scratch\ipc-x64-new\self-memory
Set-Location C:\scratch\ipc-x64-new\self-memory
..\chromium-ipc.exe self-memory
# Capture $LASTEXITCODE immediately, then run the repository verifier:
python C:\repo\tools\check_windows_chromium_ipc.py --directory . --case self-memory --bits 64 --exit-code $LASTEXITCODE
```

The [Windows reference workflow](../.github/workflows/windows-chromium-ipc-reference.yml)
performs the original gate then these cases for x64 and x86 in order. It stops
dependent cases on any failure. Windows x86 success remains a reference until
there is separately admitted, actual PE32 target-child support.

1. `self-memory`: no child. Pseudo-self and real `OpenProcess` self handles each
   read and write a private DWORD through both kernelbase and direct ntdll APIs.
   A resets between cases; observed memory and exact byte counts are checked.
   Read-only and query-only process handles must deny writes/reads respectively,
   with exact access-denied error/status and zero transferred bytes.
2. `live-memory`: a separately launched child sends a versioned nonce/PID/width
   record with its real private-DWORD address. The parent reads A, writes B,
   reads B through ntdll, writes/restores A through ntdll, reads A and finally
   writes B. A reduced-rights handle must refuse a write. The parent's different
   DWORD stays unchanged. An inherited event releases the child, which checks B
   itself, returns a result record and exits with the full value `0x0052002a`.
   Failed child readiness leaves memory stages explicitly not run; the parent
   never substitutes its own pointer for an unobserved child address.
3. `suspended-memory`: a separate launch using `CREATE_SUSPENDED`. The pipe has no
   application record during a 100 ms observation, the child is not signaled,
   and `ResumeThread` must return prior count one. Then the same child-memory
   experiment runs. This is not a test of running-thread suspension/APCs,
   restricted tokens, mitigations, process jobs or effective CEF sandbox policy.
4. `section-readonly`: a fresh unnamed 64 KiB pagefile-backed section has an
   initialized, empty DACL (not a NULL DACL). Only a read/query duplicate reaches
   the child through the explicit inheritance list. Both processes inspect
   nonce-bound DWORDs at offsets 0, 4096, 8192, 12288 and 65532. `NtQuerySection`
   must report the expected size and a non-image section. Mapping for write and
   duplicating for write must fail with access denied; this empty-DACL control
   matters because DuplicateHandle can sometimes grant more source access.
5. `section-duplicate`: launch first; transfer a read/write/query handle using
   `DuplicateHandle` and send its **target-local** number over the inherited
   control pipe. The child maps, verifies, changes every boundary DWORD, then
   the parent sees all changed bytes through its existing shared view. The
   parent never closes a target-local handle as if it belonged to its table.
6. `section-close-source`: only after the ordinary transfer passes, perform the
   separate `DUPLICATE_CLOSE_SOURCE` case. The source handle must be invalid,
   while the target mapping and the parent's already mapped view remain usable.
   Windows closes the source even if that duplication fails: the fixture
   retires its bookkeeping without retrying or reclosing the numeric handle.
7. `mojo-pipe`: create a byte-mode duplex named pipe using OVERLAPPED and
   FIRST_PIPE_INSTANCE, open the inheritable endpoint, and require the
   preconnected `ERROR_PIPE_CONNECTED` result. `PIPE_REJECT_REMOTE_CLIENTS`
   prevents remote named-pipe use; no socket/listener is created. Each process
   independently registers its endpoint with its own completion port. The
   parent first establishes an actual pending read, then exchanges fixed-size
   nonce/PID/sequence records in both directions. Separate pending reads require
   cancellation completion (`ERROR_OPERATION_ABORTED`) and peer-close completion
   (`ERROR_BROKEN_PIPE`). Immediate I/O success still requires an IOCP packet.
8. `page-regression`: one original 16 KiB private allocation, four 4 KiB logical
   pages. Protect one page read-only, query all four protections, decommit and
   recommit a different page, inspect every byte for zeroing and unchanged
   neighbors, then release it. Section cases separately measure shared views;
   private allocation success says nothing about shared mappings. PE32 packet
   pointer validation rejects values above 4 GiB.

All child cases use `STARTUPINFOEX`/`PROC_THREAD_ATTRIBUTE_HANDLE_LIST` with only
the required endpoints, event and optional section/client handle. A deliberately
inheritable decoy event is excluded. The child reports its expected numeric
value in its nonce/PID-bound HELLO, then waits up to 5 seconds for a parent
acknowledgement before touching the test payload. Numeric values can be reused
by the loader, CRT or log file; a valid numeric handle is not itself leakage.

The parent duplicates that candidate from the still-live child into its own
table, pinning its object without closing or signaling the child's original.
An invalid candidate is absence only with successful child-liveness checks
before and after capture. A valid candidate must compare different from the
parent's excluded event using `CompareObjectHandles`, with
`ERROR_NOT_SAME_OBJECT`. Same-object leakage fails. Both a parent-local duplicate
of the decoy and an independently created event calibrate same/different-object
comparisons first. The known included release event is also duplicated back
from the child and must compare equal to the parent's event, ensuring that a
broken foreign-duplication path cannot pass by reporting every handle invalid.
No unknown child object is signaled, waited on or mutated.
Only successfully acquired parent-local copies are closed.

This is a narrow explicit-handle-list test, not a complete handle enumeration or
security-isolation claim. The identity test requires cross-process
`DuplicateHandle` and dynamically resolved `CompareObjectHandles` (Windows 10 /
Server 2016 or newer; also present in the pinned Wine source). Unsupported or
unexpected errors remain nonpass; they do not establish a leak or exclusion.
A 5-second acknowledgement timeout and external 90-second process deadline bound
the exchange; child termination during capture cannot satisfy the control.

## Evidence and bounded cleanup

Each machine-readable line includes schema, case, role, nonce, Windows PID,
claimed parent, pointer width, elapsed time, stage wait budget, result, Win32
error, NTSTATUS, transferred bytes and two stage-specific numeric observations.
API attempts precede measured calls. Child addresses
are only fixture-owned writable memory. No command lines, authentication data,
network contents or installer arguments are recorded.

A log contains at most 128 KiB. Any logged fail/timeout/unsupported/not-run stage
makes final success impossible; later cleanup cannot erase it. The checker
rejects truncated/mixed logs, missing peer records, unknown results, overflowing
fields, failed stages, nonzero actual parent exit, nonzero resource counts,
truncated child exit codes and contradictory native-settlement claims. Its
synthetic unit-test logs are not Windows reference evidence.

All polling and OS waits in these probes use finite budgets (5 s per ordinary
wait, 15 s child event, 20 s final cooperative child wait). These budgets do not
make synchronous API calls, stdout or filesystem writes asynchronously bounded.
The Windows workflow supplies a 90 s **outer** limit per original/new case and a
15 minute job limit. On timeout it preserves available evidence, reports
unresolved state, stops dependent cases and does not issue a fixture helper kill.
Runner shutdown is not a guest or native settlement receipt.

`OVERLAPPED` and associated data buffers have static process lifetime. They are
not freed or reused before a matching key-and-pointer completion is received.
CancelIoEx success/ERROR_NOT_FOUND, a closed handle or a timeout is not itself a
completion receipt. Unknown or missing completions retain pending state and
produce cleanup-uncertain. Cooperative release and, if needed, one resume of
this fixture's own suspended child allow it to follow its finite exit path. No
child or helper is terminated by this new fixture. There is no infinite wait.

Parent exit 0 requires passing stages, the designated full child code where
applicable, closed fixture handles, no outstanding operation and reliable logs.
Exit 1 is failure, 2 invalid invocation, 78 unresolved cleanup. Each process
records guest cleanup separately from its functional result. The parent always
records native settlement as **unverified**. Only the external runtime owner can
prove native helper retirement; neither this executable nor the checker can.
If the final diagnostic-log CloseHandle itself fails, the actual process exit
fails even if the just-written final line says pass; the checker also requires
the captured process exit.

## Required Windows-reference acceptance

1. Review the new source, build script, checker and workflow; preserve their
   SHA-256 values and commit/tree identity. Keep the older fixture untouched.
2. Establish the original child baseline separately for x64 and x86. Retain
   exact old/new PE hashes, original source/header hashes, compiler hash/version,
   OS version, workflow run/attempt and chronological logs. A host mock pass
   does not satisfy this step.
3. Run all eight modes once in fresh case directories. Verify every case with
   `check_windows_chromium_ipc.py` and the actual exit code. Investigate the
   earliest failed/unsupported stage; do not retry it into a successful result.
   A corrected rerun is a new experiment with new identity and preserved failure.
4. Repeat with fresh nonces/directories to demonstrate ordinary resource reuse.
   Preserve OS/helper observations separately. A missing child log or unresolved
   I/O means the reference is not accepted.

## Later PS5 acceptance, not performed or enabled here

1. First settle the original Windows-child gate on the exact approved runtime:
   nonce-bound Windows child entry, different PID, real inherited pipe/event,
   full exit code, native ownership/retirement receipts and fresh repeated run.
   Stop if only a native HELLO or title disappearance is established.
2. Review and implement a **new** source/PE/package/admission binding for this
   executable. This patch supplies no native title route/profile or package
   changes. Never replace a bound `parent.exe` in place, impersonate an existing
   fixture, or bypass admission. Target staging/deployment is a separate task.
3. Use the accepted x64 reference binary first, on a fresh nonce/run. Preserve
   runtime/artifact/fixture hashes, firmware/provider identity and the actual
   Windows-to-native process identity mapping. PE32 waits for separate support.
4. Run self-memory, live-memory, then suspended-memory as separate experiments;
   never treat pseudo-self read success as a real-self or foreign-write pass.
   Preserve first failure/address/size/error evidence. Do not enable privileges,
   disable a sandbox, copy private views to emulate shared pages, or substitute
   same-process execution to satisfy the test.
5. Only after that child gate, test read-only inheritance, ordinary section
   duplication, source-closing transfer, and the overlapped/IOCP case in that
   order. Stop dependent stages on unsupported/timeout/uncertain cleanup. Obtain
   native release/reap acknowledgements and zero-owned-resource baseline before
   closing a stuck title, replacing a runtime or beginning a new run.
6. Run the private-page regression and the existing image-protection and
   caller-section DIB fixtures as regressions against the same artifact. They
   are existing fixes, not replacements introduced here. Shared-view outcomes
   stay separate, including actual map address and 4/16 KiB boundaries.
7. Only after these gates, separately record supplied installer/libcef version
   and hashes, executable machine, actual parent/child role identity, an
   allowlist of process-role/sandbox booleans and Mojo-channel presence. Avoid
   secrets/arguments. Capture first failing API and module/offset plus effective
   CEF policy if available. Vendor-role capture is intentionally **not** part of
   this synthetic fixture. No Battle.net compatibility conclusion follows here.

## Local development checks and limits

```sh
make build/host/test_windows_chromium_ipc_contract build/host/test_windows_chromium_ipc_fixture
build/host/test_windows_chromium_ipc_contract
build/host/test_windows_chromium_ipc_fixture
python3 tests/test_windows_chromium_ipc_reference.py
make all
make sanitize
```

The portable predicate test checks wire width/identity, numeric overflow,
monotonic deadlines, exact bytes/completion identity and final verdicts. The
second test compiles the actual C fixture against explicit mock declarations
and injects pending/immediate/cancel/error/mismatched-completion paths. It tests
decisions and storage-retention accounting, not Windows ABI or API semantics.
Only the Windows x64/x86 MSVC jobs establish build and reference execution.

## API references

- [Explicit handle list](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [CompareObjectHandles identity and error contract](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-compareobjecthandles)
- [DuplicateHandle access and source-close semantics](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [CancelIoEx and completion lifetime](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelioex)
- [Chromium PlatformChannel](https://github.com/chromium/chromium/blob/da53563ceb66412e2637507c8724bd0cab05e453/mojo/public/cpp/platform/platform_channel.cc)
- [Chromium shared-memory implementation](https://github.com/chromium/chromium/blob/da53563ceb66412e2637507c8724bd0cab05e453/base/memory/platform_shared_memory_region_win.cc)

The pinned Chromium source is a comparison for required operations, not an
identification of the CEF version in a particular installer.
