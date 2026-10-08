# Original Windows child-process diagnostic

This fixture tests real Windows process APIs before a launcher or game is tried. It contains no game files, networking, account data, custom mappings, or platform loader calls. A native helper launch does not satisfy any Windows-process gate below.

## Build and reference execution

On Windows with the official Visual Studio x64 C++ tools already installed:

    powershell -File tools/build_windows_child_fixture.ps1 -Arch x64
    build\windows-child-fixture-x64\parent.exe
    powershell -File tools/build_windows_child_fixture.ps1 -Arch x86
    build\windows-child-fixture-x86\parent.exe

For each selected architecture, the script verifies the PE machine and compiles one original image and copies it to `parent.exe` and `child.exe`; their SHA-256 values must match. `--child` selects the child role. Both files must remain beside one another. The test-image linker disables ASLR to make a same-virtual-address comparison deterministic; this does not change machine settings. Relocations remain available. If the loader chooses different addresses, address-space evidence is inconclusive rather than a pass.

The optional Windows Actions workflow separately builds and runs x64 and x86 copies of the same source with installed MSVC and a 45-second outer deadline per run. Artifact names include the architecture; use the x64 pair for the first AMD64-only experimental PS5 test. The x86 result remains a Windows reference until a real PE32 child path is supported. Its result is a Windows API reference, not PS5 evidence. Builds and logs have separate identity and must not be substituted for a console run.

For an experimental PS5 package, include the two built fixture executables together in a scratch Wine prefix and launch `parent.exe` through the ordinary Wine path. Do not call a loader helper from the fixture or synthesize successful process handles.

## Automated gates

1. `CreateProcessW` must create a real child and return usable process/thread handles. The independently reported child Windows PID must match both PROCESS_INFORMATION and GetProcessId, and differ from the parent's PID.
2. The child sends one versioned, nonce-bound record over a genuinely inherited Windows pipe. An inherited event keeps it alive until the parent acknowledges readiness. Pipe/event inheritance is a separate compatibility requirement; launch success alone is insufficient.
3. The child's ordinary initialized writable global must start at its image value, independently of the parent's changed value. The child changes its global while the parent remains alive and checks its own value. An isolation result additionally requires their recorded absolute global addresses to match. This is narrow same-address private-data evidence, not a hostile-code security-isolation claim. No allocator or fixed-map API is used.
4. A normal child exits with `0x0051002a`; the parent must observe a signaled process and that full 32-bit value, not an eight-bit native wait status.
5. A nonexistent executable must fail CreateProcess with FILE_NOT_FOUND or PATH_NOT_FOUND. A separate original child deliberately exits before readiness with `0x00510031`; its status must propagate without producing a successful readiness record. This is not a missing-DLL/loader-initialization test.
6. A waiting, fixture-owned child is stopped with TerminateProcess(`0x00510040`), then actually waited for and queried. The parent must survive, retain its private value, close its owned handles, and report zero fixture-owned handles. This checks guest termination semantics; it does not establish launcher Stop cleanup or native resource reclamation.

Exit 0 means all automated gates above passed. Exit 77 means an unsupported CreateProcess capability or an inconclusive isolation result; it is never a successful compatibility result. Other nonzero exits are failures or invocation/setup errors. No retries convert a failure into a pass. The underlying CreateProcess call itself has no fixture-side asynchronous timeout; the native provider must bound its bootstrap, and a reference supervisor supplies the outer deadline.

## Separate launcher Stop acceptance

Run `parent.exe --stop-observe`. Wait for `STOP_OBSERVE_READY`, record its nonce and both Windows PIDs, and press the actual launcher Stop while the parent heartbeat continues. This mode has a two-minute safety budget and never reports an automated Stop pass.

An independent runtime supervisor must save, for the same nonce/run:

- Native provider identity, firmware/loader context, runtime commit/artifact hashes, and both fixture hashes.
- The real Windows-PID to native-process identity association. The PE fixture cannot provide a native PID by normal Win32 APIs.
- The actual Stop request, termination and authoritative death/reap or release acknowledgements for every test-owned native child. A closed TCP stream, stopped logging, or a disappeared window is insufficient.
- Zero remaining test-owned children and return of tracked descriptors/handles/resources to the pre-run baseline, with the launcher still responsive.
- A subsequent fresh fixture launch with a new nonce, showing that stale state was not reused.

If the provider owns the native parent relationship (for example, a loader service), obtain its authoritative lifecycle acknowledgment; do not claim the title reaped a process it does not own. If no independent observer is available, Stop cleanup remains unverified.

## Explicit remaining gaps

This small fixture does not cover cross-process section semantics, filesystem installs, inherited environment/CWD beyond the ordinary launch defaults, CREATE_SUSPENDED/ResumeThread, running-thread suspension or APC delivery, multiple graphical processes, external native signal routing, memory budgets, Battle.net Agent installs/updates, or Retail launch. Each needs its own source-supported gate after this one. A Windows reference pass or a native ELF capability probe does not enable PS5 Windows child processes by itself.

## Public API references

- [CreateProcessW and asynchronous initialization](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)
- [Process handles and identifiers](https://learn.microsoft.com/en-us/windows/win32/procthread/process-handles-and-identifiers)
- [TerminateProcess and waiting for completion](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess)
