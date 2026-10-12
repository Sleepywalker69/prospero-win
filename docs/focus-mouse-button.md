# Default-off tracked mouse-button source

This is an additive successor to the compile-only protocol963 focus cohort. The
ordinary protocol962 build remains unchanged. PW_WINE_FOCUS_NEUTRAL still defaults
to zero. Neutral native entry, legacy input sink, controller exposure, provider
installation and package refusal remain unchanged. No console input is enabled.

## Wire and ownership scope

PW_FOCUS_MOUSE_BUTTON (type2) accepts exactly code0=left, code1=right or code2=middle,
x=y=0 and down0/1. The handler constructs a zero-initialized INPUT_MOUSE containing
exactly one canonical up/down flag. Receipt keys256..258 are distinct from
keyboard keys1..255; the existing fixed wire sizes and protocol number remain
unchanged. Complete source-marker matching rejects mixed old/new source cohorts.

The queue adapter validates the reserved ticket, current permit, sampled clock,
exact live window, desktop, phase, operation kind and matching button edge before
injection. One ticket transfers to exactly one Wine hardware message. The same
low-level hook, free/error and desktop-state completion observers as keyboard
input finish that ticket once. No mouse auto-repeat timer is attached.

A successful submit return means admission only. POLL retains a factual receipt;
only the matching server/client sequence ACK retires it. QUIESCE closes ordinary
input admission. Button-up operations can discharge held slots while releasing,
but SETTLE still rejects held state, outstanding operations, unacknowledged
results, poison or timers. Suppression, failed allocation, invalid clocks and
other failures do not certify release or permit the next focus epoch.

Mouse motion, wheel, X buttons, raw samples, multiple button flags and mixed
movement/button requests are excluded. The existing Wine raw-input dispatch
semantics are preserved. A receipt certifies desktop key-state processing, not
application delivery, raw-input delivery, rendered pixels or a usable controller.
A raw-input observer can therefore see an event whose later low-level hook
suppresses the ordinary desktop event; that is not a clean settlement receipt.

## Source composition and evidence

The three existing optional patches are unchanged. The explicit inventory gains
0004-tracked-mouse-button.patch after them. Its bytes enter the existing complete
source digest and eleven-marker identity check. Accepted first/second patch
hashes remain pinned; no default Wine patch changes.

The mandatory hosted source regression reconstructs pinned Wine plus the exact
repository patch chain and exercises extracted actual core, request and queue
bodies with explicit Wine boundary mocks. Strict compilation and ASan/UBSan
are separate executions. Regressions must reject malformed requests and stale or
duplicate acknowledgments and exercise real hook/free completion, cancellation,
button release and settlement sequencing. Retained source hashes, compiler
commands and output logs bind the evidence. Source mocks are not target execution.

No hosted run, target build or PS5 result is claimed by this document. Before any
runtime activation, the independent native permit provider, USER consumer,
input/ACK transport, physical-source reconciliation, frame/window binding,
failure quarantine, full linked source-matched cohort and package/prefix design
must be reviewed and validated. PR109 diagnostics and PR110 reuse remain separate.
