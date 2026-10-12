# Dedicated child UI handoff and bounded transmit queue

This is a runnable **host** increment on the [child UI codec](CHILD_UI_TRANSPORT.md).
It remains default-off. A separate follow-on increment adds opt-in owner,
worker and title wiring; see [the preview contract](CHILD_UI_PREVIEW.md). It proves a
real two-process descriptor handoff, software frame and input roundtrip through
Wine's actual sink/queue code on Linux. It does not prove PS5 inheritance,
Windows execution, visible scanout, Battle.net or Chromium compatibility.

## Source-established route

`native/pw_wine_fixture_owner.c:start_generation_attempt` creates an ordinary
`AF_UNIX/SOCK_SEQPACKET` pair, supplies exactly one endpoint in
`ServiceOptions.fd`, and launches the exact matched worker using
`sceSystemServiceAddLocalProcess`. `native/pw_wine_child_main.c:run_child`
validates and uses that service-mapped control endpoint at fd 3. There is no
source evidence for a second direct service-inherited descriptor. Do not guess
fd 4, broaden service options, or add a listener.

The existing v2 BOOTSTRAP sends the Wine server's stream descriptor as a single
`SCM_RIGHTS` entry over control. The new, opt-in v3 bootstrap extends that same
ancillary-transfer mechanism to two separately owned stream descriptors. Only
the descriptor grant and bootstrap identity use control. All frame and input
bytes travel on the dedicated UI socket. The existing v2 codec remains unchanged; the separate preview increment
selects v3 only in a matched enabled cohort.

The host test creates both stream pairs **after fork**, so the worker cannot
use an implicitly inherited copy. It receives them only through the bootstrap
rights. Distinct known bytes use the server channel; padded BGRA and key
press/release use UI. The worker installs the actual Wine presentation sink
and consumes both input edges through the actual Wine input queue.

## Version, identity and ownership

`pw_wine_child_ui_handoff.{c,h}` defines a 152-byte v3 BOOTSTRAP. The first 136
bytes use the v2 layout, except the version word is 3. An explicit nonzero
64-bit little-endian UI session follows at offset 136, then eight reserved zero
bytes. Exactly one ancillary record must contain exactly two rights, ordered
Wine server then UI. Both must be distinct `SOCK_STREAM` objects. The service
control endpoint remains `SOCK_SEQPACKET`.

A v2 receiver refuses the v3 record (including its extra bytes/rights), closes
all collected rights and never runs Wine. The v3 receiver refuses v2. There is
no automatic downgrade, replay, second transfer or retry after an attempted
send. Idle polling may continue within the original absolute startup budget.
An unexpected/partial send is terminal and its delivery is marked uncertain.
Use a fresh zero-initialized handoff state for each newly owned control channel.
Never reset it on an existing stream.

The sending owner must already have its verified positive service-launch
receipt and matching HELLO. The receiver compares its locally constructed
HELLO's native PID, PPID and exact build ID before returning either descriptor.
The accepted bootstrap must pass the caller's existing admission checks.
`pw_wine_child_ui_handoff_identity` then derives the codec identity from that
same bootstrap and the root-provided session. The owner associates a socket
with its existing generation; received UI headers cannot select another owner.
These values are correlation, not authentication secrets. This API does not
make an unrelated socket, user-supplied PID or self-declared build trusted.

Refusal collects all complete, bounds-checked rights before cleanup; every
known unique delivered descriptor is closed once. Missing, extra, repeated,
wrongly typed, aliased, truncated or malformed rights are refused. Unknown
ancillary layouts/lengths are not interpreted as guessed fd numbers. Truncation
or uncertain cleanup is recorded; it must not become permission to recycle
owner state. Both accepted rights receive FD_CLOEXEC before Wine starts.

**Additional target gate:** checking aliases uses standard `fstat` socket
identity: nonzero `st_ino`, plus `st_dev`. A platform that returns zero or the
same object fingerprint cannot enable this mode. The host tests cover both
unavailable identity and aliases installed under different fd numbers. No PS5
socket-inode behavior is claimed here; it requires SDK/source review and an
original target capability control. Do not remove the fail-closed check merely
to make target startup pass.

## Bounded callbacks and lifetime

`pw_wine_child_ui_channel.{c,h}` owns one transmit descriptor and one
caller-allocated record buffer, bounded by 8,294,464 bytes (header plus maximum
frame). It takes the descriptor slot only on successful initialization. The
caller chooses a smaller buffer if it admits smaller frames. No allocation or
socket operation occurs in the presentation callback.

A presentation callback uses try-lock only and copies one whole record before
publishing it to the pump. A busy presentation is dropped *before* serialization
without advancing sequence or corrupting the pending frame. An oversized or
partially queued record fails the endpoint. Input overflow/lock contention is
terminal because dropping a release is unsafe. These are different from a
stream write failure: once bytes of a record may have been emitted, no new
record replaces it and no uncertain bytes are retransmitted.

Each supervisor pump performs at most one nonblocking send of 65,536 bytes.
Known short sends resume at the exact byte offset; EAGAIN waits for a later
pump without extending the original deadline. EINTR, other IO errors, clock
reversal, cancellation and deadline expiry are terminal. The absolute lifetime
and a finite per-record deadline (1 through 1000 ms) are checked before and
after sends, including the final send. Clock and stop callbacks must themselves
be nonblocking. A caller may perform a bounded batch of pumps per supervisor
iteration; a 25 ms control wait after every tiny write would starve large frames.

Retirement is `cancel -> detach producers -> serialize -> poison -> close`.
The detach callback runs outside the queue lock. For a Wine presentation sink,
its existing setter with `(NULL, NULL)` takes the same Wine sink lock and waits
until an in-flight producer has returned. The threaded host test proves the fd
stays open while this detachment is waiting. Close is attempted once; the slot
is cleared even if close fails, and uncertainty remains recorded. Storage is
process-lifetime and is never freed beneath a callback.

An input detach callback must also certify that held keys/buttons are settled
at the consumer. Merely dropping queued events, observing EOF or closing a
socket cannot supply that certificate. If detach refuses, the descriptor stays
owned and memory stays live. This increment provides no automatic cross-process
focus/held-input settlement protocol. Local window-cycle event type 4 is not a
wire event: route it through the local switcher, never into this channel.

UI errors and EOF are independent of native/helper settlement. They never
justify killing a child, closing another channel, reusing a generation, or
claiming that asynchronous helper work has finished.

## Concrete next production integration

Production wiring needs a separately reviewed matched-cohort build. A suitable
opt-in path is:

1. Add a default-off cohort flag to both the title and full-CRT worker build.
   Bind the flag, new source/header hashes and compiler inputs into
   `tools/build_wine_service_child.py`, its worker manifest and the title compile
   receipt. A title and worker must agree exactly. Existing builds stay v2.
2. In `pw_wine_fixture_owner.c`, add generation-owned UI endpoints, handoff
   state and bounded receive storage. Create the UI pair after matched HELLO,
   send v3 BOOTSTRAP instead of v2, close the parent's passed duplicates exactly
   once, and bind receiver identity to that same generation. Every launch,
   startup and uncertain-retirement path must account for the new descriptors.
3. In `pw_wine_child_main.c`, select v3 only for that compile-time cohort, accept
   both rights before the existing data/helper/bootstrap path, and leave all
   helper lifetime rules unchanged. Failure cleans the UI fd independently.
4. In `pw_wine_child_bootstrap.c`, resolve and validate the already-exported
   `pw_wine_set_present_sink` and `pw_wine_post_input` APIs. Install the queue sink
   before `pw_wine_child_bootstrap_start`. Keep its storage process-lifetime.
   The worker's main loop pumps UI without blocking control and detaches the
   sink before UI close on every return path.
5. Receive complete frames into a generation-tagged title mailbox. Keep one
   explicit selected live generation and preserve the root's separate sink.
   Do not mix different children into one untagged `wine_present` callback.
   Admission and memory budgets must be explicit for all 16 possible children.
6. Add focus/release acknowledgement before enabling title-to-child input.
   Stop routing to the old generation, settle held input at its consumer, then
   route to the new generation. Do not treat queue acceptance as delivery.
7. Compile and inspect a matched target cohort, prove socket identity and
   two-right transfer in an original control, then prove two-process visible
   windows/input through the actual launcher and relaunch without reboot.
   Only then test actual Battle.net process roles. CEF renderers may present
   through IPC to the browser; not every renderer needs a direct UI channel.

The original transport increment did not perform steps 1–7. The separate
[default-off preview wiring](CHILD_UI_PREVIEW.md) now implements steps 1–5 for
frame-only passive preview. It deliberately does not install post_input or
perform steps 6–7. No Chromium API or target-runtime compatibility is claimed.

## Verification

The ordinary and sanitizer test aggregates include:

- `test_pw_wine_child_ui_handoff`: real fork and post-fork two-right transfer,
  server/UI byte isolation, exact identity, actual Wine sink/input, close/FD
  accounting, v2 refusal, kernel ancillary truncation, alias refusal and
  concurrent producer detachment before close.
- `test_pw_wine_child_ui_handoff_faults`: malformed ancillary metadata, numeric
  duplicates, unavailable socket identity, fcntl failure, cancellation and
  deadlines around receive/send, partial/uncertain send, close uncertainty and
  terminal-state refusal.
- `test_pw_wine_child_ui_channel`: exact-offset partial writes, EAGAIN, EINTR,
  absolute/per-record deadlines, cancellation, clock failure/reversal, overflow,
  pre-record frame drops, input refusal, detach refusal and close-once behavior.

The existing codec and legacy wire suites also remain unchanged and pass.
Host assertions, sanitizers and source audits are separate evidence from a
PS5 build, console execution or a Windows/CEF GUI run.
