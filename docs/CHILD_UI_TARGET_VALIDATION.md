# Opt-in hosted child preview static validation

`windows-child-fixture.yml` has one optional boolean dispatch input,
`child_ui_preview`, defaulting to `false`. Normal dispatches and pushes still
produce only the existing default-off fixture package and evidence. An
explicit alternative is the PR label `build-child-ui-preview-static` on a
same-repository, non-seed-head pull request. The normal title recipe, deployment
packager, source pins, reference joins and runtime admission are unchanged.

The preview label's own `labeled` event must name that label and include it in
the PR's current label list. Later `opened`, `synchronize` and `reopened` events
also retain the opt-in while that current label remains. Applying ordinary or
unrelated labels does not enable preview. Missing, removed or different labels,
external forks and the already push-built seed branch are refused. Label
removal is not a subscribed build event and does not cancel an already-running
build. Admitted builds keep the existing non-cancelling per-ref concurrency
group. Ignored events get a unique run-ID group so an unrelated label cannot
replace a pending admitted build; GitHub otherwise permits a newer pending run
to replace the existing pending run in the same group even with cancellation of
running builds disabled ([concurrency reference](https://docs.github.com/en/actions/concepts/workflows-and-actions/concurrency)).

All four heavy/reference job gates now also verify the exact triggering label
and current label list for `labeled` events. Adding an unrelated label cannot
start another expensive runtime build just because a build label is already
present. The existing `build-windows-child-fixture` label keeps its default-off
behavior. Adding the preview label explicitly requests the ordinary control
plus the extra static preview in the same workflow run. Labels are an opt-in
build route only; they do not authorize console execution or deployment.

When explicitly enabled, the workflow first completes and uploads the ordinary
**default-off** control package. Only then it makes a fresh detached worktree
at the exact same commit and tree, and runs `build_native.sh` with
`PW_WINE_CHILD_UI_ENABLED=1`. The existing admitted
`PW_OUTPUT_SUFFIX=-windows-child-fixture` is used inside the separate checkout;
there is no new suffix exception or overwrite of the control build. The child
worker build and the internal title check receive `--child-ui` through the
reviewed shell recipe. The separate workflow title inspection also passes
`--check-title --child-ui` explicitly.

The expensive host Wine, target Wine, TLS builds and original MSVC references
are not repeated. Their same-run inputs are reused. Compiler caches remain
restricted to their existing host/target runtime stages, with their current
source/recipe/ABI keys and revalidation. Neither title nor worker build output
is cached or copied between modes. The additional cost is the enabled native
title/helper/worker build and static inspections, only on an explicit dispatch or label opt-in.

## Evidence gate and artifact

Before collecting any successful preview bundle,
`tools/collect_child_ui_preview_validation.py`:

1. Requires separate clean source checkouts at the same exact commit and tree.
2. Replays the existing default-off title admission without changing it, then
   replays full title/worker/source/compiler/helper inspection with explicit
   `child_ui=True` for the preview. Each replay must match its earlier receipt.
3. Requires the exact child UI contracts in both worker manifests, both title
   input records and both title compile-input records. The preview must bind
   `enabled: true`, `bootstrap_version: 3`, `bootstrap_rights: 2`,
   `preview_only: true`, `input_enabled: false`,
   `socket_identity: nonzero-distinct-fstat`, and `runtime_validated: false`.
   The control must retain its exact default-off v2/one-right contract.
4. Requires identical checked project/source/runtime records across modes, and
   distinct title images, worker images and worker build IDs. This verifies the
   same-runtime reuse rather than inferring compatibility from a cache hit.
5. Rechecks complete retained project, Wine, foundation, SDK and dependency
   sources, licence notices and the preview's own source-bound helper cohort
   through the existing source-retention validator. It hashes and rechecks
   copied images and receipts and refuses existing/linked output paths.

The success artifact is named
`child-ui-preview-static-validation-<commit>-<attempt>`. It contains inert
`target-images/`, static `inspection/`, exact `sources/`, provenance records,
`STATIC-VALIDATION.json` and `SHA256SUMS`. It is intentionally **not a deployment
package or release-ready artifact**. There are no console prefixes/profiles or
fixture deployment manifest, and all target execution/runtime flags remain
false. The ordinary default-off package keeps its existing distinct name.
Only bounded preview logs are uploaded by the separate always-run evidence
step after a failure; failed checks cannot upload the successful bundle.

The host workflow suite executes the actual opt-in shell with inert build
stand-ins, preserves the control, refuses reuse, and rejects missing recipes,
wrong flags, default-on/gate changes, output/artifact collisions, source/runtime
mismatch, crossed receipt modes and changed images/receipts. Those controls do
not emulate target execution. A hosted build still needs to be dispatched and
its exact terminal checks reviewed; adding this workflow is not build success.

## Later runnable preview packaging remains separate

The existing `package_windows_child_fixture.py` deploy assembler still invokes
its service/title rechecks without `child_ui`; therefore it continues to demand
its default-off cohort. This change deliberately does not weaken or broaden
that admission. A future explicitly requested runnable preview candidate
requires separate review of at least these bounded changes:

- Introduce an explicit default-false preview mode in the producer input schema
  and a separately named artifact. Pass that exact boolean to both
  `validate_service` and `validate_title`; never infer the mode from a supplied
  manifest, an environment variable, or a previous inspection's claim.
- Bind the selected mode, exact child UI contract and source/compile receipts
  into the package manifest and retained title/worker source identities. Replay
  both child and title validators, including exact original fixture hashes,
  run/attempt, embedded child identity and helper admission.
- Extend directory and archive verification to reject missing, conflicting,
  stale, duplicated or opposite-mode declarations. Verify every worker/title
  contract, compile flag/cohort, image and source hash agrees with the explicit
  package mode. Keep missing/false mode as the existing default-off contract.
- Add successful default-off and enabled synthetic packaging controls plus
  negatives for omitted mode/flag, v2/v3 and one/two-right mismatch, input true,
  stale source/helper/runtime/receipt, changed compiled image, mode-swapped
  archive, output collision and preview bytes hidden in a default-off archive.
- Preserve the runtime capability, original fixture, USER/network and helper
  gates. Keep execution/presentation/input/resource-settlement claims false
  until independently established by the exact approved target run.

No deployment, console launch, child input, cross-process focus, CEF/Battle.net
execution, socket/ancillary compatibility or native cleanup is established by
this static-validation artifact. See [the preview contract](CHILD_UI_PREVIEW.md)
for the target gates and unchanged admission boundaries.
