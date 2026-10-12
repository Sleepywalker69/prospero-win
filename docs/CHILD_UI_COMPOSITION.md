# Combined child preview and startup diagnostics

This integration starts from the PR97 settings/controller tree
`9d8c00f3b01f7d41758eefa2e9fde5efe72ba039` and composes the separately reviewed
child handoff, default-off preview wiring, bounded startup diagnostics and
service-list headroom guard.
The child preview remains default-off and view-only. It does not add child
input, cross-process focus, privileged setup, listeners or helper termination.

## Explicitly resolved boundaries

- The root's existing frame cache and controller-mode badge remain the source
  image. A child preview is rendered only into separate composite storage.
  New child pixels never overwrite the cached root/badge image. A controller
  mode change repaints the badge and recomposes the current preview even when
  the game has not sent another frame. Exact child retirement re-presents the
  root with its current badge. A rejected new root frame invalidates the old
  cache, preventing stale re-presentation. Preview allocation failure retains
  the existing root/badge presentation. The Vulkan path stays unchanged.
- Settings modal dispatch, atomic profile persistence, root-local controller
  routing, queued release delivery, close-chord freshness gating, and the
  local window switcher are retained. Local event type 4 is not child traffic.
- Worker startup checkpoints bracket either bootstrap version. The v3 handoff
  error result feeds the same final numeric diagnostic snapshot as v2. The
  best-effort final snapshot occurs after `run_child`; frame-producer detach
  and UI close occur before the existing unresolved-helper hold. None of these
  observations settle asynchronous helper work.
- Owner HELLO refusal, bootstrap-sent and once-only interrupted-start messages
  remain on their existing control-flow edges. UI endpoint creation happens
  only after the original service/HELLO admission; bootstrap rights remain
  ordered server then internally created UI endpoint.
- Baseline service-list count 15 or higher is refused before launching a new
  child, reserving one observable entry in the unchanged 16-entry list. Count
  14 remains admissible; concurrent growth to 16 remains uncertain. Existing
  helper transactions are not settled or terminated by this refusal.
- The native build retains all settings/controller sources and appends the UI
  sources. The title compile receipt explicitly binds controller settings,
  profile, library, rendering, routing and pad sources/headers along with the
  UI sources. Missing units and post-compile edits fail inspection. The
  default-off/opt-in worker and title flags must still agree exactly.

`tests/test_child_ui_composition.py` extracts and executes the actual main-loop
presentation branch in both feature modes, with controlled platform edges and
real preview composition. It covers initial preview without root pixels,
controller badge repaint, preview retirement, allocation fallback, root-cache
invalidation and resumed root presentation. The existing launcher settings
control executes the actual modal dispatch separately. The enabled worker and
owner suites also execute the composed startup-diagnostic call graph.

A first integration run exposed a test-only mock mismatch: the old UI wrapper
returned its error through the legacy result object, whereas real v3 admission
returns it through the handoff result. The combined fixture now preserves that
result and grants the fake UI descriptor only on successful admission. The
initial failing output is retained in integration evidence. Final validation
records each command and its exit status independently; one passing final
binary cannot mask an earlier failing binary.

See [preview lifetime/platform gates](CHILD_UI_PREVIEW.md) and
[startup diagnostic limits](WINDOWS_CHILD_FIXTURE_BUILD.md). Host composition
acceptance does not establish target socket identity/ancillary behavior, a
matched PS5 build, visible console child windows, CEF process compatibility or
cross-process input release settlement.
