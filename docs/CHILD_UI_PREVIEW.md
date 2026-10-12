# Default-off matched child preview

This is a runnable **host-tested, target-unvalidated** wiring candidate. The
normal build remains `PW_WINE_CHILD_UI_ENABLED=0`, using the existing v2
bootstrap and no child UI allocation, callback or presentation path. This
increment has not built or run on PS5 and does not establish Battle.net or
Chromium compatibility.

## Opt-in and provenance

`PW_WINE_CHILD_UI_ENABLED=1` is accepted by `tools/build_native.sh` only together
with the existing isolated `PW_WINE_CHILD_FIXTURE_MODE=1` title. All other
matched-foundation, full-CRT runtime, helper, original Windows fixture and
isolated-output requirements still apply. The shell forwards `--child-ui` to
both `tools/build_wine_service_child.py build` and its `check-title` inspection.
The [hosted static-validation option](CHILD_UI_TARGET_VALIDATION.md) is an explicit
default-false workflow dispatch input; it does not enable an installed title.
Do not substitute this flag into an installed or unmatched title.

The worker input manifest binds the exact flag, v3/two-right contract, disabled
input, source/header bytes and runtime-unvalidated status into its build ID.
The generated worker/title header contains `PW_WINE_CHILD_UI_COHORT`; both
entry points statically reject a compiler flag that disagrees with it. Title
compile receipts bind the added sources and exact effective compiler flag;
conflicting definitions, undefines and hand-written cohort overrides fail.
Reusing a worker or title inspection from the opposite mode is refused. The
existing exact-build HELLO and child-image hash admission remain mandatory.

## Actual call graph

1. `pw_wine_child_title_prepare` creates one process-lifetime tagged thumbnail
   mailbox and configures the original fixture owner. It does not alter profile
   selection or broaden service/Windows child admission.
2. `pw_wine_fixture_owner.c:start_generation_attempt` first verifies its
   existing positive service-launch receipt and exact matched HELLO. Only then
   does `pw_wine_child_ui_owner_init` create a fresh private stream socketpair
   and bind its receiving end to this session, generation and native PID.
   The sending half is internal owner state, never an incoming/caller-selected
   descriptor. The original server fd is the first bootstrap right, and this
   internally created UI half is the second. Inode distinctness detects aliases;
   it is not the authority assigning either role.
3. `pw_wine_child_main.c:run_child` selects only v3 in the enabled cohort and
   compares the received bootstrap with its own HELLO identity before accepting
   either right. It allocates the bounded frame queue and then follows the
   existing profile/data/helper/PRX bootstrap path. Subsequent control records
   retain the existing v2 format. No frame or input bytes use control.
4. `pw_wine_child_bootstrap_prepare` requires the existing present-sink and
   display-release exports, installs the frame-only queue sink before Wine
   entry, and refuses display release permanently in that worker. The child
   cannot acquire the root's native/Vulkan display. It installs no input sink.
5. The worker main loop performs at most 32 nonblocking 64 KiB queue pumps per
   control iteration, then polls the original control channel without waiting.
   Idle iterations sleep 1 ms. A pending frame has a non-renewing 1000 ms write
   deadline and the original absolute child lifetime. Cancellation, a partial
   write failure or deadline expiry retires only UI. The sender has no receive
   path, so it does not acquire unexpected ancillary rights; owner loss is
   detected on a later write or the existing lifetime limit.
6. The owner supervisor reads at most eight 64 KiB chunks per generation per
   iteration. Complete verified frames produce a fixed 320 by 180 BGRA
   thumbnail tagged with the admitted identity. The latest complete thumbnail
   replaces the previous one, including when a different admitted child
   presents. Busy puts drop a whole frame. Main's try-lock snapshot never
   waits for a frame. Retirement invalidates only an exact matching identity.
7. In the root's existing **software/native VideoOut** presentation loop,
   `wine64_main.c` copies the root image, including its ordinary controller-mode badge, to separate bounded storage
   and draws a small bordered `CHILD VIEW ONLY` picture-in-picture. A preview
   update can reuse the cached original root image. Retirement restores that
   original root/badge image. Mode changes recompose the preview after repainting
   the badge, even without a new game frame. The Vulkan-owned presentation branch does not render this
   preview. A root software frame is required before the first preview.

The control/helper call graph is unchanged by a UI fault. In particular,
retiring UI does not set a helper's settlement certificate, force a helper
exit, kill a child or authorize generation reuse. Existing helper uncertainty
still holds the owner/worker alive under the original rules.

## Lifetime and resource budget

There are at most 16 generation records and none are recycled. Each admitted
UI receiver retains at most 8,294,400 bytes of frame storage for the native
process lifetime, at most 132,710,400 bytes for 16 generations. Each enabled
worker retains one 8,294,464-byte transmit record. The root has a 230,400-byte
thumbnail mailbox plus an equally sized main-thread snapshot, small metadata,
and at most 8,294,400 bytes of separate composite storage. OS allocation
rounding and stack/other existing runtime storage are additional. Allocation
failure refuses that UI startup; no dynamic expansion or unbounded queue is
possible. Native composite allocation failure leaves the ordinary root image.

Only the original supervisor touches owner channel records. Only Wine's
existing sink synchronization touches the installed producer. Worker teardown
is cancel, remove the real present sink through its synchronized setter, then
close once. Storage and callback objects remain live until process exit.
Retirement refuses uncertain descriptor accounting and records uncertainty;
no failed close is retried on a potentially reused numeric fd. The mailbox
mutex also lives until process exit. Its retiring writer waits only for main's
bounded snapshot copy, with no IO under that lock.

The frame channel accepts no ancillary data. The owner closes all complete,
bounds-checked delivered rights before refusing a record, including a complete
SCM_RIGHTS integer prefix in an in-bounds odd-length payload. An over-reported
record length cannot separate payload from alignment padding, so that record
is not harvested and ownership uncertainty is retained. Unknown/truncated
metadata records uncertainty and prevents silently claiming cleanup. Missing,
extra, aliased, wrongly typed or malformed bootstrap rights remain covered by
[the handoff contract](CHILD_UI_HANDOFF.md).

## Explicit gates still open

- PS5 socket identity (`fstat` nonzero, distinct socket inodes), exact two-right
  `SCM_RIGHTS` transfer, ancillary truncation/cleanup semantics, nonblocking
  stream IO, and target callback/CRT behavior need a matched target build and
  original capability controls. Host Linux success is not that evidence.
- The title and full-CRT worker must pass the existing source, artifact and
  compiler provenance checks for the **same enabled cohort**, then be reviewed
  before any PS5 enablement. No target build is supplied by this increment.
- This is read-only software preview, not cross-process window focus or a
  desktop compositor. Root keyboard/mouse/controller routing stays root-local.
  There is no `pw_wine_post_input` route to children. Event type 4 stays with the
  local switcher and must never enter the current UI codec. Focus requires
  acknowledged release settlement at the old consumer before enabling input.
- Chromium/CEF renderer, GPU and browser processes need role-aware validation.
  A renderer may use IPC to its browser without presenting directly. This
  channel neither replaces that IPC nor supplies missing Chromium APIs,
  graphics support, services.exe/winedevice admission or security semantics.

## Host verification

The ordinary test list and sanitizer aggregate include the six enabled
controls `test_pw_wine_child_ui_{runtime,runtime_faults,owner,main,bootstrap,title}` alongside
legacy default-off controls and the first increment's real fork/handoff tests.
The runtime suite transfers real descriptors and actual Wine software frames
into the mailbox; it checks ancillary refusal/fd accounting, wrong identity,
retirement, root isolation and bounded overlays. Owner/main suites include the
actual production call graphs with inert native/service boundaries. Bootstrap
controls require both exports and assert install-before-entry and detach order.

`tests/test_child_ui_build.py` compiles both flag/cohort modes, refuses crossed
and invalid modes, syntax-checks both main presentation branches and checks
early shell refusal before external build work. The service/user title build
suites check manifest identity and actual compile-receipt mismatch refusal.
The full host aggregate was also attempted: all its C suites and startup/build
Python controls passed before the existing native i386 differential could not
execute on this VM (`Exec format error`). Later aggregate stages remain unrun.
There is no target build, visible PS5 launcher-child run or Chromium test.

The PR97 combined integration preserves settings and startup diagnostics; see
[the composition contract](CHILD_UI_COMPOSITION.md).
