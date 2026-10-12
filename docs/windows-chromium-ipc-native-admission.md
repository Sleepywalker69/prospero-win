# Fixed Chromium IPC diagnostic admission

This opt-in admits the repository's original, hash-bound Windows diagnostic.
It does not admit Chromium, arbitrary renamed executables, or arbitrary profile
arguments. The older `windows-child-fixture-v1`, USER, network and Battle.net
controls keep their existing identities and budgets.

## Fixed identities and scope

`native/pw_wine_ipc_profile.h` is the native identity table. The prefix slug is
`windows-chromium-ipc-v1`, with native root
`/data/prospero-win/prefixes/windows-chromium-ipc-v1`.
For each row, the profile ID is `windows-chromium-ipc-CASE-v1`, the Windows image
is `C:\windows-chromium-ipc\pw-ipc-CASE.exe`, and its CWD is
`C:\windows-chromium-ipc\CASE`. Arguments must be empty.

| Mode | CASE | Maximum direct helper admissions |
| --- | --- | --- |
| 16 | self-memory | 0 |
| 17 | live-memory | 1 |
| 18 | suspended-memory | 1 |
| 19 | section-readonly | 1 |
| 20 | section-duplicate | 1 |
| 21 | section-close-source | 1 |
| 22 | mojo-pipe | 1 |
| 23 | page-regression | 0 |

Each row requires a fresh title/owner launch. There is no cumulative suite
wrapper and no increase to the existing sixteen-generation storage limit.
The numeric modes do not repurpose the earlier unsupported mode 5 sentinel.
The table is understood by helper wire/bootstrap code and the Wine child-identity
installer, but title/owner admission
is disabled unless the build explicitly sets `PW_WINE_IPC_PROFILE_ENABLED=1`.
The generated title inputs must also bind `PW_WINE_IPC_CHILD_SHA256` to the
verified compiled AMD64 fixture; absent optional evidence leaves admission off.

The selected profile requires PE64, default CPU, the exact prefix/image/CWD,
empty arguments, empty DLL overrides and debug environment, no runtime tweaks,
800 by 600 desktop view, and no FPS overlay. A byte-identical executable under
another case's fixed alias is not an interchangeable selected path.

## Root and worker checkpoints

Before publishing the owner callback table or entering guest code, the owner
checks the selected root image's SHA-256 through a bounded regular-file read.
The only child paths admitted are that row's exact `drive_c/.../pw-ipc-CASE.exe`
path or its exact `dosdevices/c:/.../pw-ipc-CASE.exe` alias. The path actually
submitted for child admission is hashed again, including the alias path.
A missing, wrong, malformed, replaced, or unreadable image is a failure. These
are digest checkpoints, not a claim that the Windows loader consumes the same
open descriptor or that later filesystem mutation is impossible.

The native fixture-provider ABI 1 does not expose child argv or CWD. Native
admission therefore does **not** parse or authenticate worker arguments. The
trusted, hash-bound fixture generates and checks its exact worker route:
`--worker`, selected case, bounded numeric parent PID, nonce and handles. Its
actual module basename is checked, never just `argv[0]`. Alias workers must
match their selected case; self-memory and page-regression reject worker mode.
The native bootstrap uses the selected fixed prefix, image and CWD; ordinary
Wine startup still owns serialized Windows process parameters and outcomes.
This narrow arrangement is appropriate for this exact original fixture, not a
generic untrusted-executable sandbox or a reusable arbitrary-argv allowance.

Capacity-zero cases refuse child admission before image reads or generation
reservation. Capacity-one cases cannot admit a second child even after their
first generation retires. Descendant creation remains unsupported. The whole
owner attempt is bounded by the existing 180-second endpoint and a child by
60 seconds; startup and cleanup consume their existing portions of those
absolute deadlines. Deadlines are never evidence that a possible native child
has disappeared.

## Evidence statuses

Keep these observations separate:

- Windows reference: actual x64 **and** x86 execution, including all eight
  explicit cases, all eight empty-argument aliases, and twelve rejection
  controls per architecture, with strict source/build/run/artifact bindings.
- Package/title admission: the selected fixed identity and compiled digest are
  bound to the same source cohort, title, helper, runtime and prefix artifacts.
- Windows guest probe result: selected case's structured parent/worker logs,
  complete Windows process status and guest resource cleanup.
- Native helper settlement: the existing owner/controller receipts for that
  exact generation, owned service identity, endpoint ownership and retirement.

A Windows reference pass, guest exit, `native_settlement=unverified`, helper
bootstrap ACK, timeout, or package schema pass cannot establish native helper
settlement. Possible-launch, mismatched identity, failed handoff or uncertain
ownership retains the existing hold behavior. No new timeout-based release,
raw foreign kill, helper enumeration shortcut, or cleanup-success inference is
introduced here. Host source/mocked tests establish contracts only; they do not
establish PS5 or Wine behavior. The composed admission regression carries an
actual owner-produced BOOTSTRAP frame through the real codec, bootstrap export
lookup and Wine child-identity installer. Its OS, service, transport, image-read
and PRX boundaries remain simulated. Structural decode/install support does not
replace the separately default-off title and owner admission gates.

## Acceptance order

1. Review the immutable patch and source identities, rerun the focused native
   and package negative controls, and preserve the older fixture regressions.
2. Build a fresh complete source cohort. Run the real Windows reference on
   both architectures. Validate ZIP digests, strict reference records, source
   and compiler inputs, all case logs, all negative exits, and exact aliases.
   Historical PR102 reference evidence is useful diagnosis, not a substitute
   for the new cohort's reference receipts.
3. Verify the opt-in package against its exact source archive, native title
   compile record, helper/runtime capabilities, fixed profiles, prefix files,
   inventories and selected compiled PE hash. A missing or contradictory
   component prevents packaging/admission. This step does not launch anything.
4. Only after the separately approved deployment prerequisites are satisfied,
   preserve a new dated backup and verify every staged file against the matched
   package. The original matched headless fixture remains the first console
   control; this document grants no deployment or launch authority.
5. With that control settled, launch self-memory and page-regression as separate
   owners. Confirm no helper admission and retain structured guest and native
   owner logs. Then run each of the six one-child cases in a fresh owner, one
   at a time, only after the previous owner's safe-release evidence is complete.
6. For a failing case, retain its guest logs, native diagnostics and exact
   artifact/profile identity. Classify guest failure independently from helper
   cleanup. Any unresolved helper ownership stops the sequence; do not close
   or relaunch the title merely to advance the remaining cases.

The packaging workflow is opt-in and produces reviewable artifacts. It does not
automatically deploy, install, launch, or replace a console build.

## Combined source, separate admitted modes

The composed source retains both default-off IPC selection and the existing
read-only child preview. IPC-only builds keep preview disabled; preview-only
builds keep IPC selection disabled. Selecting both is unsupported and rejected
before heavy build work, by the native builder and worker/title validators,
and by compile-flag checks. UI-enabled worker wire/bootstrap/profile paths also
refuse all eight fixed IPC modes before transferring a UI channel; received
rights are closed through the existing ownership cleanup. No silent fallback
or cross-process input capability is introduced. Each later supported combined
mode would need a separately reviewed actual callgraph and strict cohort checks.
