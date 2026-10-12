# Owned Windows process-memory reference

This original fixture is a small future CEF capability check. It changes no
runtime code and is unrelated to diagnosing the current pre-Wine native crash.
It opens no existing process: the only process handle used for memory operations
comes from its own CreateProcessW call. It writes one DWORD to a PAGE_READWRITE
page allocated by that child. There are no vendor inputs, executable-memory
writes, remote thread creation, protection changes, or console APIs.

## Two independent cases

1. The data child allocates 4096 writable bytes, sets an initial DWORD, sends its
   actual address and Windows PID over an inherited anonymous pipe, then waits
   on an inherited event. A versioned magic/kind record and per-launch nonce bind
   the two messages to the expected child. The parent requires an exact four-byte
   ReadProcessMemory result matching the initial value and an exact four-byte
   WriteProcessMemory result for the replacement value. It signals the event;
   the child reports the value it actually observes before freeing its page.
   The parent requires matching address/PID/nonce, replacement data, child
   termination and exit zero.
2. A separate child starts with CREATE_SUSPENDED. Its entry point signals an
   initially unsignalled event. Before ResumeThread, the parent requires a
   250-ms event timeout and a still-running process. ResumeThread must return
   exactly one. The event must then signal and the child must exit zero.

Case 2 checks initial primary-thread suspension only. It does not read memory
before entry, test SuspendThread on running threads, or establish restricted
token, mitigation, AppContainer, COW, IPC sandbox, security isolation, full
Chromium, Agent.exe, or PS5 compatibility.

All waits are bounded. Failure cleanup terminates only a fixture-created child,
waits for its process handle, and checks closing its handles. Cleanup failure
fails the case. CreateProcessW and individual Win32 calls are synchronous and
can still hang in a defective runtime, so a separate supervisor is required.

## Build and evidence

The installed-MSVC builder compiles with C11, W4/WX, ASLR and NX enabled.
It verifies PE machine/optional-header architecture and ASLR/NX flags, retaining
compiler output and SHA-256 hashes of the source and executable.

    powershell -File tools/build_windows_memory_reference.ps1 -Arch x64
    build\windows-memory-reference-x64\memory-reference.exe

Use x86 instead of x64 for the second architecture. The workflow
windows-memory-reference.yml runs both on windows-2022 with a 45-second outer
deadline, ten-minute job limits and seven-day evidence artifacts. It requires
exit zero and all three final case/overall success markers; missing tools,
compilation errors, timeout, partial transfers and skipped execution fail.
Artifacts include raw stdout/stderr, exit status when available, architecture,
source/image hashes, compiler log, OS version, event SHA, PR head SHA, run ID
and attempt. On a pull request the event SHA identifies the tested merge ref;
do not substitute the PR head SHA for that executed identity.

This is deliberately a Windows baseline, with no Wine rebuild matrix. A later
Wine run must retain its exact Wine revision, patch set, architecture and fresh
prefix alongside the same fixture hashes. Linux-host results cannot establish
the PS5 target's process-memory backend.

## Public contracts

- [ReadProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory)
- [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
- [ResumeThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread)

## Review status

Prepared as a test-only candidate. No compile, execution or CI result is claimed.
