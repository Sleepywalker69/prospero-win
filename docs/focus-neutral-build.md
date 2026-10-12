# Compile-only focus protocol963 cohort

This increment integrates the previously reviewed server core, timer/window adapter and request/watchdog source into an explicit build selection. The default remains protocol962. It does not enable guest input, install a native permit provider, implement a USER receipt consumer, or make the neutral cohort deployable.

## Selection and source binding

`PW_WINE_FOCUS_NEUTRAL=1` selects the optional source in `tools/build_wine_ps5.sh`. It requires both `PW_WINE_PRIVATE_DISPATCH=1` and `PW_WINE_SERVICE_FIXTURE=1`, and the exact project default patch series. Manual focus compiler definitions are refused. The three optional patches live outside `wine/patches`; the first two retain their reviewed hashes, and the third adds only the neutral identity boundary.

The staging tool verifies the original pinned Wine Git HEAD, rejects dirty or untracked source, and independently replays the default patch series in a temporary Git index. The selected source index must exactly match before optional application. This does not modify the caller's index while calculating the expected default tree. Each actual optional application uses `git apply --index` and fails closed; a failed build must reset its private source before retrying.

A deterministic SHA256 covers the pinned Wine commit, all default and optional patches, native and standalone runtime source, and selection/identity tools. The generated header fixes mode1, protocol963 and eight complete 32-bit source words. The build stamp and report retain this contract. The host-proof provider mode2 is not a target selection.

Both ntdll and wineserver expose constant-return ABI, protocol, mode and eight source-word markers. The static checker reads actual shared ELF, converted ELF and SELF descriptors and function bytes. Immediately after loading the server module, ntdll compares those same eleven markers before installing callbacks, forwarding existing providers, sharing paths or connecting the server. A mismatch returns a failed connection. Its existing caller then passes descriptor -1 to `pw_wine_fixture_socket`: the existing argument-failure path records the failure and can invoke an already installed native socket-failure sink. The caller then closes -1 and its existing startup `fatal_error` exits(1). This is not the server request parser SIGQUIT/fixture-signal path, but it is also not a purely local refusal. Any helper/resource uncertainty remains governed by the existing native failure policy. Both neutral main entries refuse before reaching this path; future routing cannot treat it as settlement. Existing generic Wine framing/fatal behavior remains unchanged.

The owner and full-CRT worker use the same explicit selector. Worker inputs, generated creation header, compiled title recipe and retained runtime identity bind the selected contract. Native 962/963 and focus/default header mixtures fail compilation. The checked build rejects reports from a different selection, rather than inferring opt-in from a report.

## Neutral entry and sink

Both real native main functions return78 as their first operation in this cohort. This precedes their local clock initialization, logging, helper work, bootstrap transport, profile/prefix access and Wine startup. All profile names are refused, including existing962 prefixes and any proposed new prefix. No prefix is created, rewritten or upgraded. This is an entrypoint guarantee after the unchanged platform loader/CRT has entered main; it is not a claim about pre-main platform activity.

The refusal is an immutable, function-local volatile constant with no setter. The read intentionally preserves the complete compiler/linker call graph, so a neutral target build still compiles and links the normal owner/worker source. It does not open a runtime transition back to untracked input. No native controller, USB, script, close-chord, queue-drain or XInput producer is reachable from these refused entries.

The standalone Wine sink independently protects its input APIs from startup: under the existing mutex it discards any old queued events, clears cached pad and rumble state, refuses every legacy post (including local event4), delivers no queue item, returns no connected controller and creates no input wake pipe. Display/audio behavior is unchanged. This defense does not certify desktop held-key release; no tracked grant is issued.

Existing fixture packaging explicitly refuses a focus-neutral runtime or worker before output/prefix staging. The ordinary package validator remains protocol962. General release admission also rejects a focus declaration. Native entry and packaging must remain disabled until separately reviewed USER/native routing and prefix contracts exist.

## Reproduction and evidence limits

`make test` builds and runs the neutral sink test and invokes all three focus
Python suites. The source suite always runs its inert Git index controls. Its
archive/full-TU section is optional: supply both `FOCUS_WINE_SOURCE` (raw pinned
archive export) and `FOCUS_HOST_CONFIG` (host syntax config) to enable it. Neither
configured input may be missing or invalid; a partial pair is an error before
output creation. An absent pair emits an explicit archive-only skip. The focused
`make focus-neutral-host-check` target runs the same focus controls, including the
sink, and accepts the same optional pair. These host fixtures do not constitute
target compiler validation.

- `python3 tests/test_wine_focus_identity.py` exercises real static ELF/SELF identity readers using inert fixtures, including every missing/mutated word, 962/963 in both directions, and header/source contradictions.
- `python3 tests/test_wine_focus_neutral.py --out /tmp/unique-neutral-test [--preview] [--sanitize undefined]` builds the actual complete owner and worker translation units. Undefined external symbols are renamed only in those objects to inert traps. Selected entries return78 before any trap, while default entries reach the first mocked external call. It also executes the real sink with seeded backlog/pad/rumble and reruns the legacy sink.
- `python3 tests/test_wine_focus_source.py --wine-source <pinned archive export> --host-config <host syntax config> --out /tmp/unique-source-test` records every archive source hash, applies all default and optional patches for the server/include/ntdll subset, compiles complete server and ntdll translation units, and executes the actual composed marker comparator. Its archive-subset staging bypasses the original Git-pin verifier only inside the test fixture. A separate inert Git repository exercises the real pin/index/dirty/untracked verifier. Neither substitutes for real pinned target build proof.

The build recipe adds actual generated target object gates for core, requests, queue, window, winstation, USER handles and main, in addition to the existing service translation-unit checks. This recipe has not yet been executed with the PS5 compiler for this increment. Host header checks, source selection, and actual target compilation are distinct evidence.

ASan runs use `detect_leaks=0` where recorded; that is not a LeakSanitizer pass. Native entry trap tests use strict/UBSan objects when the surrounding run selects ASan, because sanitizer constructors themselves require real runtime entry; the sink remains ASan-instrumented.

## Opt-in uncached target translation-unit gate

The dedicated `focus-neutral-target-compile.yml` workflow is selected by the exact
`build-focus-neutral-target-compile-only` PR label or the default-false
`focus_neutral_target_compile_only` dispatch input. Eligible PR events use the
same-repository reviewed head, not the generated merge ref. Forks, the existing
push-backed seed head, unrelated label events, removed labels and push events do
not admit this target job. A requested neutral cohort with any fixture, preview
or strict-IPC label fails a small refusal job before expensive work, including
either order of adding those labels. The existing
fixture workflow also excludes the neutral label from its heavy jobs and its
accepted concurrency group. Accepted runs serialize per ref without cancellation;
ignored and refused runs use unique run groups.

One job prepares pinned public Wine/foundation/SDK sources, matching host tools
with `--tools-only`, one selected LLVM18 SDK and checked TLS input. Compiler-cache
restore/save actions and compiler-cache launchers are absent. Clean command
environments discard inherited cache, preview, IPC, graphics and provider
selections. A fresh default962 `check_focus_target_compile.py run --neutral 0`
receipt must validate before the fresh neutral963 `run --neutral 1` begins. Both
use private/service selectors, `CFLAGS='-O2 -g'`, the same SDK/TLS/host-tool bytes,
and distinct work and receipt directories outside the source checkout.

The success artifact name begins `focus-neutral-target-translation-units-` and
binds the actual checked-out commit and run attempt. Its paired receipts and
source archives are collected only after both compile-only checks succeed. The
scope is 22 default object targets, 29 neutral object targets and four separately
recorded syntax-only source checks per mode. This does not compile the complete
native owner/worker main translation units or `pw_wine_sink.c`; their existing
host entry/sink controls remain separate. It does not build or validate a full
runtime, converter, title, prefix or deployable package, and no target executes.
Full module-marker admission and owner/worker linkage are not established.

Failed or cancelled work cannot upload the accepted artifact. A separate
`focus-neutral-target-compile-unaccepted-` artifact retains at most 32 log tails
of 256 KiB each, with explicit unaccepted metadata. A timeout is a failed gate and
does not establish descendant-process settlement. Workflow tests execute the
actual YAML shell bodies with inert owned helper/SDK fixtures and evaluate both
workflows' event and concurrency expressions; they do not provide real target
compiler evidence. No hosted pass is claimed by adding this workflow.

### Translation-unit receipt contents

`TARGET-COMPILE.json` records integer `focus_mode=0` for the default962 control
and `focus_mode=1` for neutral963, cross-bound to `neutral` and `protocol`. It
admits that selection only after the checked driver exits zero,
all expected actual command receipts exit zero, and freshly created output
objects match their recorded hashes and target object format. Each make command
records its complete selected target list; four SDK compiler invocations are
listed separately as syntax-only checks. Pre-existing, missing, changed, wrong
format, wrong-mode or unexpected runtime outputs are refused. The source index,
actual staged source bytes, generated Makefile/configuration, selected flags,
compiler wrappers, LLVM18 resources, explicit MinGW compiler providers, shared
host-tool bytes and checked TLS inputs are bound before/after compilation.

The pair collector rechecks both modes against the same project commit/tree,
source/SDK/compiler/TLS bytes and run/attempt, refuses overlapping work or receipt
directories, and retains selected objects, generated configurations, command
receipts, bounded logs and corresponding project/Wine/SDK/foundation/TLS/FreeType
sources. `TRANSLATION-UNIT-VALIDATION.json`, `SCOPE.txt` and `SHA256SUMS` describe
this partial evidence. Compiler/TLS verification and collection use the exact
same clean PATH as the build; historical receipts are not a source-cohort control.
These trusted post-build checks detect stale or changed files; they are not
cryptographic attestations or a hostile-filesystem isolation guarantee. Timeouts
remain failures and do not establish descendant-process settlement.

The separate selected-mode compiler-cache repair is still required for ordinary
cached builds against this neutral-capable source. This gate does not invoke or
validate that cache. Full module marker readers, native worker/title compilation
and runtime linkage remain outside these receipts.

## Remaining gates

A real trusted native permit provider, USER-side receipt/held-input ledger, root tracking from the first input, per-source reconciliation, focused-generation selection, bounded input/ACK transport, failure quarantine and reviewed prefix packaging remain absent. No target compile or console execution is claimed. The accepted default-off two-right frame preview is independent of this compile-only cohort.
