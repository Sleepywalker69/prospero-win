# Owned child UI transport foundation

This portable codec is a foundation for software-composited child windows. It
is not enabled in the PS5 title or worker, creates no sockets, and does not
establish Chromium, Battle.net, native child startup or visible presentation.
CEF renderers commonly send their results back to a browser process through
CEF IPC; not every renderer needs this separate native presentation path.
See the [CEF process architecture](https://chromiumembedded.github.io/cef/general_usage#processes).

## Implemented contract

`native/pw_wine_child_ui.h` defines two independently sequenced directions:
child-to-title BGRA frames and title-to-child `PwWineInput` events. The caller
supplies an already-admitted session, generation and native child PID. Incoming
records must match all three, direction, version and the next sequence exactly.
These values bind a stream to its owner; they are not authentication secrets.
The caller must bind the peer to the verified owner launch receipt and the
same admitted session, generation and native PID. A header match alone cannot
prove this association.
No received identity may select a different owner, and a retired endpoint must
not be reset on the same stream.

Headers are 64 bytes, explicitly little-endian; no compiler structure layout
is serialized. Layout: magic `PWUI` at 0, version 1 (16 bits) at 4, kind (16 bits)
at 6, session at 8, generation at 16, sequence at 24 (all 64 bits), native PID
at 32, payload length at 36, width at 40, height at 44, stride at 48 (all 32
bits), and twelve zero reserved bytes. Sequences start at 1 and never wrap;
UINT64_MAX is refused. Frame/input directions use kinds 1/2 respectively.

Frames are top-down BGRA, at most 1920 by 1080 and 8,294,400 bytes. The sender
copies only each row's pixels, never source padding. Wire stride is exactly
width times four. The receiver requires exact payload size and sufficient
caller-owned storage before accepting payload bytes. It accepts arbitrary
stream fragmentation and invokes its frame callback only for a complete frame.
The callback must consume or copy the borrowed storage before returning.

Input payloads are exactly twenty bytes: type, code, signed x, signed y and
down, each 32 bits. They retain existing `PwWineInput` semantics and validation;
this layer does not reinterpret mouse coordinates or synthesize focus. Input
callbacks run only after a complete validated record. A queue-full callback
fails the stream rather than pretending the event was delivered.

The sender's presentation adapter has the existing `PwWinePresentSink`
signature. Its write callback must accept/copy every supplied byte or fail,
with bounded queue capacity, cancellation and a finite deadline controlled by
the caller. A partial/uncertain write poisons the sender; it cannot retry that
frame on the same stream. Receiver protocol errors or callback failures likewise
poison the receiver. EOF retires it, distinguishing a record boundary from a
truncated record. No partial frame is presented. Previously delivered complete
records are not rolled back. EOF is not a child-exit/helper-settlement proof.

## Integration gates still required

1. Admit a separate UI stream descriptor through the matched owned-child
   transport. Never multiplex this codec onto startup, helper, signal or Wine
   server descriptors. No new listener or guessed inherited descriptor is used.
   A host socketpair test does not prove descriptor inheritance through
   `sceSystemServiceAddLocalProcess`. The actual transfer/inheritance mechanism
   must be designed, source-verified and tested before target wiring.
2. Integrate a bounded writer/pump with explicit cancellation and deadlines.
   The synchronous presentation adapter must not introduce unbounded waits while
   the Wine sink lock is held. Memory budgets and queue-full behavior need tests.
3. Bind the worker sink before Wine entry and route complete frames into the
   title's frame mailbox/compositor. Software frames do not transfer Vulkan
   display ownership or implement per-window geometry, alpha or global z-order.
4. Route input only to the selected live generation. Focus handoff must stop
   old routing, settle queued events and release held keys/buttons before a new
   target receives input. Stream identity alone does not solve focus ordering.
5. Keep endpoint storage alive while callbacks can run; retire UI independently
   of native/helper transaction settlement. A UI error must not authorize unsafe
   process closure or resource reuse. Detach the presentation/input producers,
   serialize retirement with callbacks, reject new writes, then let the owner
   close its verified descriptor. This codec neither closes descriptors nor
   certifies an uncertain close. Input retirement must preserve an explicit
   release/settlement path for held keys/buttons; merely dropping the socket
   does not release them.
6. Prove an original two-process visible-window/input control through the actual
   launcher, then re-launch without reboot. Only then evaluate the installed
   Battle.net process roles and first actual unsupported API.

## Verification

`make build/host/test_pw_wine_child_ui` builds the focused test; run the resulting
binary. It is also registered in the ordinary and sanitizer test aggregates.
The test uses real host `socketpair` and `fork`: the child installs the actual
Wine presentation sink adapter; the parent receives its frame and sends a key
press/release; the child posts and consumes those through the real Wine input
queue. Reads and writes are deliberately fragmented. The test has a ten-second
alarm; this host test does not execute Windows or PS5 binaries.

Deterministic controls cover every split point, every header-byte mutation,
identity/version/direction/sequence refusal, padding omission, insufficient
capacity, truncation at every record prefix, failed writes, failed sinks,
invalid input and signed-coordinate extremes. Full repository checks and
actual PS5 transport/presentation remain separate gates.
