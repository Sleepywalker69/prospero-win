# Original native two-process probe

This opt-in build tests one fixed original worker SELF through an already
running public `elfldr` service. The title stays in its launcher while a
background controller uploads the embedded worker. No Wine process API is
enabled. Patch 0550 still refuses unsupported Windows child creation.

## Build and inspect

Prepare the public PRX foundation at commit
`30597512539e7edfde079cbcaf4a626bc0a948c5`, including its pinned SDK and host
zlib dependencies. The supported worker compiler is LLVM 18. Then run:

    PW_NATIVE_CHILD_PROBE=1 PW_OUTPUT_SUFFIX=-native-child \
      PW_NATIVE_CHILD_FOUNDATION=/path/to/prepared/prx-foundation \
      LLVM_CONFIG=/usr/bin/llvm-config-18 tools/build_native.sh

The `hello` mode is the default probe. For the separate synthetic descriptor
mode, add `PW_NATIVE_CHILD_MODE=fd` and use `PW_OUTPUT_SUFFIX=-native-fd`.
Its title says **NATIVE FD CAPABILITY PROBE**. The mode and every linked source
are part of the worker build ID and manifest; a HELLO worker cannot satisfy an
FD-mode run. The hosted workflow accepts a manual `hello`/`fd` choice, or the
same-repository opt-in label `build-native-child-probe`/`build-native-fd-probe`.
The two modes produce separately named artifacts. The successful earlier
HELLO-only checkpoint remains a distinct first test.

The normal native title remains the default. A probe build requires an
isolated output suffix and rejects unattended launcher scripting. It shows
only the probe tile and never selects a library game. The native title still
uses its existing data-mount helper; a helper refusal remains a stop condition.

The worker builder compiles an original `_start`, the finite protocol and
original byte operations. It links directly to the ordinary `libkernel` stub
and rebuilds its native converter from checked, pinned source. It includes no
payload CRT, credential changes, kernel helpers, general syscall trampoline,
libc startup or arbitrary executable loader. Every required import is checked
as an actual visible kernel function; unexpected imports, data/TLS imports,
raw syscalls, wrong entry, recursive byte-helper lowering and analyzer errors
fail the build. Actual SDK headers and selected LLVM tools are recorded.

The build creates `build/native-native-child/child/native-child-build.json`
with source, toolchain, SDK, converter, layout and worker hashes. The final
worker SELF is also embedded as immutable bytes in the title. The controller
uploads only that image; no pathname, URL, vendor program or guest input can
select a different executable. The protocol carries a source/recipe build ID;
the separately recorded complete SELF SHA-256 avoids a circular embedded hash.

## Existing loader and SELF framing

The transport is the existing loopback `elfldr` port 9021, whose inspected
public revision is `02cfe91eb3f9697787460ad77d73ff951f801f50`. Its native SELF
route duplicates the accepted stream to descriptors 0, 1 and 2 before native
execution. The parent uses existing SceNet wrappers; the worker uses ordinary
native descriptor I/O. These are distinct socket namespaces and API families.

The pinned converter can append ELF version records beyond SELF
`header.file_size`, while the loader reads exactly that declared extent.
For this original worker only, the builder changes that field to the complete
existing image length. All other bytes must remain identical. Before and
after, the actual converter must inspect valid format integrity, extract
byte-identical ELF data and report the same digest, also recomputed by Python.
Version records are preserved. Normal title artifacts and the shared signer
are unchanged. This proves a container-format invariant; it is not official
platform cryptographic authentication or a native loading result.

The pinned signer omits one separate, terminal 24-byte SIE build-ID note from
its reconstructed ELF. The builder accepts zeroing only that exact unmapped
note, with its fixed header/shape and no overlap with other segments. All other
bytes, program headers, LOAD payloads, version records and the mapped GNU note
remain identical, apart from the signer's documented OSABI normalization.
The manifest records this specific omission. Failure evidence retains the
actual linked/converted ELF, original/final SELF and extracted ELF files that
were produced, their hashes and corresponding project source for diagnosis.

## Operator acceptance

Use only an already working homebrew/loader environment on the user's own
console. Record firmware, loader version, source commit and artifact hashes.
No new exploit, loader installation or privilege change is part of this probe.
Keep a rollback copy of the installed app and existing library data. Do not
overlay this native-only artifact onto a complete runtime and then diagnose
the omitted Wine files as a runtime failure.

The build suffix separates files on the build machine only. Both the normal
kit and probe retain console title ID `PPSA99995`; they are not two separately
installable apps. With the title closed, back up its complete installed app
folder, stage the complete probe folder using the existing app-loader workflow,
and restore the complete normal folder before game/runtime testing. Preserve
all existing prefixes, profiles, games and saves under `/data/prospero-win`.
The probe-only launcher cannot start those games.

1. Verify the artifact's SHA256SUMS and read BUILD-INFO.txt. Start the native
   launcher manually and confirm its normal picture and controls.
2. Select the single native probe once with Cross or keyboard Enter. Square or
   keyboard Escape requests cancellation while it is running.
   The controller alone owns and closes its socket; the UI never races a close.
3. Require a positive child PID different from the title PID, the exact build
   ID, three ordered correlation echoes, STOP_ACK and then stream EOF. At least
   two successful launcher frame presentations must occur after HELLO and
   before completion. The UI counter runs after input polling and successful
   presentation, not on the controller thread.
4. Collect the matching saved `PW_NATIVE_CHILD` log and manifest. On malformed
   output, timeout, same PID, failed presentation or incomplete closure, keep
   the failing stage. The title will not retry or launch a second worker.

Both peers enforce absolute five-second stage and fifteen-second whole-session
budgets. Partial reads, interrupts and new stages cannot renew the total budget.
The parent checks Stop during polling; the initial connect is bounded by the
existing SceNet timeout. The worker exits on deadline, EOF or malformed input.
Stop prevents further sends after cancellation is observed. Bytes already
submitted to the loader cannot be withdrawn; cancellation does not prove that
an already submitted worker will not enter or that it has died.
It deliberately treats every negative native I/O return as failure, including
interrupts and readiness races, without reading a libc errno location. This
can produce a conservative false negative. The public stubs do not establish
the internal initialization needs of every native wrapper; actual startup and
I/O on the console are still capability gates.

STOP_ACK expresses cooperative exit intent. EOF is channel closure. Neither
is an authoritative waitpid/reaping result, a full native exit code, authenticated
peer identity or proof of native resource reclamation. The correlation value
is not a secret or authentication credential. A successful probe demonstrates
the narrowly observed original native exchange and concurrent launcher progress.

The worker deadline begins only after native entry. It cannot bound the loader's
work before entry. If the title closes, channel loss is a stop request to an
already running worker; no independent supervisor currently proves its death.
The inspected loader also leaves its own `/user/temp/payload_<pid>.self` file.
This probe does not claim or implement complete loader-resource cleanup.

## Optional synthetic descriptor capability mode

After the three control echoes and before STOP, FD mode tests ordinary native
AF_UNIX/SCM_RIGHTS in the title and original worker contexts. The title creates
one fresh directory below `/data/prospero-win`, derived from its PID and the
non-secret session correlation, with mode 0700. It opens the listener before
uploading the fixed worker. A collision or permission failure stops the run.
There is no stale-path deletion, alternate namespace, chmod or credential
change to force access. The worker derives the same bounded path and never
owns its removal. Namespace visibility and ordinary access are console gates.

The exchange sends a synthetic socket endpoint with an already queued writer
FD, verifies known bytes and forward EOF, then transfers a worker-created
writer in reverse. It uses checked one-way socketpairs, not native `pipe()`.
All descriptors are disposable test objects; no Wine server endpoint, file,
section or application handle is transferred. The original Linux reference
can establish its own host behavior only.

Both roles close their owned descriptors before recording completion. The
parent removes only its owned socket path and directory. Close, unlink or
rmdir failure prevents a successful final result and is retained in the log;
there is no retry after an uncertain close or directory cleanup. A process
crash can still leave a directory, and loader-owned files are outside this
cleanup contract. Do not delete an existing path merely to repeat the test.

The descriptor phase reserves 750 ms of its existing five-second stage for a
fixed 80-byte worker result. It does not extend the stage or fifteen-second
whole-session deadline. The parent reads this correlated report before sending
STOP. During the descriptor exchange the worker treats unexpected control
readability, EOF or poll failure as cancellation. This is channel observation,
not proof that the parent died. All clock checks share each process's existing
monotonic history. A missing, partial, duplicated or malformed report fails.

Require `PW_NATIVE_CHILD capability_complete=1`, then STOP_ACK, EOF and launcher
progress, together with both role results in `PW_NATIVE_FD`. Parent-local
observations and peer-reported reverse EOF are separate fields. Both independent
roles must report their exact completed operations, matching PIDs and successful
cleanup. A peer bit alone is insufficient. `peer_identity_verified=0` remains
explicit even on success: these PIDs and correlations do not authenticate a
peer. The title and worker use different startup/security contexts, so this
finite capability test is necessary before designing an authenticated channel.
No Windows-child or cross-process-section support is enabled by this mode.

## Remaining Windows-child gates

Real Windows children still need tested native startup context, authenticated
descriptor transfer, one authoritative Wine server and startup handshake,
process-local dispatcher storage, real cross-process sections, child-local
thread control and owned-child shutdown before title restart. Native parentage
alone is not the deciding factor: Wine already double-forks and uses its server
startup object. No handle or successful CreateProcess result may be invented
to bridge an absent capability. Battle.net Agent installation/update and Retail
launch remain unverified.

Public source contracts: [loader SELF route](https://github.com/ps5-payload-dev/elfldr/blob/02cfe91eb3f9697787460ad77d73ff951f801f50/selfldr.c),
[native entry ABI](https://github.com/mpereiraesaa/ps5-native-app-boilerplate/blob/30597512539e7edfde079cbcaf4a626bc0a948c5/tooling/native/app_crt.cpp),
[container conversion](https://github.com/mpereiraesaa/ps5-native-app-boilerplate/blob/30597512539e7edfde079cbcaf4a626bc0a948c5/tooling/native/self_container.cpp).
