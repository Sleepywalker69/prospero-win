# Experimental Wine service consumers

`PW_WINE_SERVICE_FIXTURE=1` builds the Wine side of an experimental native
child provider. It requires the matched private dispatcher runtime. Both
selectors default to zero; a compiler definition supplied outside the selector
is rejected, including `PW_WINE_SERVICE_FIXTURE=0`, because the consumer guards
use `#ifdef`. The selector is recorded in the runtime report and build stamp.
The native service owner and title admission policy are separate consumers of
this interface; this source checkpoint alone cannot launch a native child.

The provider table is installed once in each native module, with size and ABI
checks. Its pointers are valid only inside the title's address space. They are
never serialized to a child. Each admitted attempt receives an immutable
generation, bound to the exact Wine caller and newly reserved server process.
Signal, timer and destruction callbacks carry that generation instead of
reconstructing ownership from a possibly reused native PID.

Wine retains process creation authority: normal image lookup, `new_process`,
`new_thread`, the original reserved stream, the `startup_info` wait and
`get_new_process_info` all remain required. The provider borrows the original
stream through its callback and must own a duplicate before asynchronous
handoff. Native bootstrap acknowledgement does not publish Windows handles.
The wait requires exactly `STATUS_WAIT_0`; a nonnegative timeout is not success.
The original startup budget is checked again after the server's final response
and before output publication. Normal admitted exits report their full status
once. An aborted caller may never report it, so the native owner must retain
that missing outcome without waiting forever for a dead thread.

The ordinary root exit path preserves the full Windows DWORD before Unix exit
conversion. It freezes admission, uses Wine's existing process and current
thread termination requests, checks their results, unregisters the local
thread, then clears and closes each unique owned client endpoint once. The
server's normal channel teardown removes its last thread and signals the
Windows process. Native host retention runs afterward, keeping the embedded
server and supervisor alive while owned services settle. This permits a child
to observe its Windows parent's exit without requiring the native title to
exit first. It does not manufacture a process signal or native reap result.
The existing in-process own-PID timer exemption remains in force.

This guarantee covers the ordinary serialized root exit path. Fatal exits,
direct `_exit`, process crashes and simultaneous uncontrolled teardown remain
unverified. A native owner must distinguish safe host release after a settled
failed run from a successful Windows compatibility result. It must never use
elapsed time to clear uncertain ownership.

Patch 0913 prepares only newly owned ordinary stream endpoints used by Wine
IPC. It checks exact `SO_TYPE`, successful `FIOCLEX` when requested, and
successful `SO_NBIO` setter/getter with an exact integer length and nonzero
readback. Every caller retains its own cleanup. Generic file and section
descriptor handling keeps its existing semantics. The shared socket helper
publishes an immutable structured failure through a nonblocking sink; it does
not rely on a service child's stderr. Socket option readback alone does not
prove all Wine I/O behavior on the target.

Validation includes the pure provider installer, both real build-selector
branches, the actual pipe wrapper with mocked boundaries, and executable
controls extracted from the fully composed pinned Wine source. Source CI and
the native Wine builder require `tools/check_wine_fixture_consumers.py` to
succeed before compilation. Missing source or extraction failures cannot skip
that gate. These checks establish source contracts, not console execution.

The source reference is the pinned
[Wine process implementation](https://github.com/wine-mirror/wine/blob/490f6d5dcbb2a5047345b8af88d114bbcaad69a8/dlls/ntdll/unix/process.c)
and its existing server process and thread lifecycle. The original two-program
fixture and a separately admitted installer attempt must still be built and
validated with one matching runtime cohort.
