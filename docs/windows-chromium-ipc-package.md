# Opt-in original Chromium IPC diagnostic package

This adds eight fixed diagnostic profiles to the existing matched original
Windows-child package. It is disabled by default. It does not enable a Chromium
application, arbitrary executables, arbitrary root arguments, x86 console
admission, descendant helpers, or a general compatibility claim.

## Fresh complete-cohort reference gate

The `Matched original Windows child fixture` workflow has one optional boolean
`enable_chromium_ipc`, default `false`. Only an explicit workflow-dispatch choice
of `true` runs the reusable original IPC Windows reference workflow and adds the
IPC prefix/package inputs. Ordinary dispatches, labeled pull requests and the
existing build branch retain the original fixture, USER and network behavior.
This document describes the workflow; implementing these changes does not run it.

Both x64 and x86 references must belong to the same complete Git commit **and**
tree, repository, Actions run and attempt as the native title/runtime cohort.
An earlier successful run, a pull-request head instead of its tested merge commit,
or an earlier reference built from identical diagnostic files is not acceptable.
Changing unrelated native code still requires references for the new complete
commit. The original independent headless child fixture remains mandatory.

`tools/join_windows_chromium_ipc.py` waits for the two reference jobs to complete
successfully in the exact attempt. It obtains artifact IDs, names, compressed
sizes and SHA-256 digests from the authenticated read-only GitHub Actions API.
Those are external expected anchors. Values inside an artifact's `BUILD-INFO`
or summary cannot provide authority for accepting that artifact. The join writes
only a fresh local directory containing `anchors.json`, `x64.zip` and `x86.zip`.
It verifies compressed bytes against the API digest before creating the bundle,
does not extract or execute members, and never starts or retries a build.

`tools/windows_chromium_ipc_contract.py` performs bounded, in-memory ZIP reading:
no links, reparse entries, absolute paths, traversal, case collisions, duplicate
members, encrypted members or unexpected payloads. It independently binds:

- exact producer source, contract header, build recipe, checker and reference
  workflow bytes to the current project
- both architecture-specific PEs and all eight byte-identical aliases
- both explicit-case and empty-argument launches, using every actual case log,
  captured stdout, exit receipt and the original strict checker
- exact nonce/PID log filenames, separate launches, actual successful parent
  exits and explicitly unverified native settlement
- twelve negative entry controls per architecture: actual exit 2 with no
  diagnostic case log, including unknown executable names and alias arguments

A saved `REFERENCE.json` or `ENTRY-REFERENCE.json` is compared with the result of
those checks; it does not replace them. x86 ZIPs and logs remain provenance only.
The two actual archives are retained in the final package and revalidated during
both directory and tar verification, without extraction. Corresponding source
copies must also equal their members of the retained complete project archive.

## Dedicated prefix and profiles

`initialize-ipc` and `export-ipc` use the existing fresh, audited prefix pathway,
matched private-dispatch PE overlay, registry conversion and CPU module. The
reference diagnostics are copied as bytes; they are not run during export.
Only the eight x64 aliases are staged into the application directory:

- prefix: `windows-chromium-ipc-v1`
- profile: `windows-chromium-ipc-CASE-v1`
- executable: `C:\windows-chromium-ipc\pw-ipc-CASE.exe`
- working directory: `C:\windows-chromium-ipc\CASE`
- arguments: explicitly empty
- runtime: `wine-wow64`; architecture: `pe64`; CPU: default
- display: 800x600 desktop, FPS hidden; graphics: auto

`CASE` is exactly one of `self-memory`, `live-memory`, `suspended-memory`,
`section-readonly`, `section-duplicate`, `section-close-source`, `mojo-pipe`, or
`page-regression`. Each case working directory starts empty. There is no generic
`chromium-ipc.exe` launch profile. The eight final profiles are separate files;
none replaces the original headless, USER, network or experimental installer
profile. Prefix inventory merging rejects overwrites and out-of-scope paths.

The package assembler's optional fields are `ipc_enabled: true` and paths
`ipc_fixture`, `ipc_prefix`, `ipc_prefix_report`. The environment variable
`PW_WINDOWS_CHROMIUM_IPC_DIR` explicitly selects the validated reference bundle
for the native title producer; `--ipc-fixture` supplies it to title inspection.
Missing either architecture, anchors, a current run/attempt, source evidence or
an exact profile causes refusal. Disabled packages reject stray IPC payloads.

## Native admission and evidence limits

The title builder generates `PW_WINE_IPC_PROFILE_ENABLED=1` and the x64
`PW_WINE_IPC_CHILD_SHA256` only after full reference admission. Direct hash macro
overrides, contradictory enable flags, altered source/object/compiler receipts
and mismatched title/reference/package hashes are rejected. The shared IPC
profile header and runtime provider/header bytes are source-bound; no ABI or
protocol bump is inferred from adding these fixed modes.

Root arguments and root CWD are bound by exact title profile selection. ABI1
child admission does not receive child argv or CWD and does not parse them. The
exact accepted diagnostic PE hash binds its own internal child argument,
nonce/PID and handle parser; native bootstrap uses the selected fixed CWD.
Native admission allows only the selected alias's exact direct/dosdevices path.
The root hashes it before entry and each direct child admission hashes the
actual admitted path again. See [native boundary details](windows-chromium-ipc-native-admission.md).

Modes 16 through 23 map in the case order above. Self-memory and page-regression
allow zero helpers. Each other case allows one direct lifetime helper and depth
one. No descendants are admitted and the global 16-child limit is not enlarged.
The existing budgets remain 180 seconds per attempt and 60 seconds per child.

Reference results never assert PS5 execution, runtime validation, console
validation, child presentation/input or native settlement. The Windows producer
continues to declare `native_admission: not_implemented`: it only produces
reference evidence. The separate opt-in package capability describes the native
admission implemented here. Actual console execution and settlement remain
future independent evidence requirements.

## Host-only regression commands

```
PYTHONDONTWRITEBYTECODE=1 python3 tests/test_windows_chromium_ipc_package.py
PYTHONDONTWRITEBYTECODE=1 python3 tests/test_wine_ipc_title_build.py
PYTHONDONTWRITEBYTECODE=1 python3 tests/test_windows_chromium_ipc_reference.py
```

The new package controls use inert PE headers and synthetic logs with real
validators, real ZIP parsing and real directory/tar verification. They are test
inputs, not Windows execution evidence. Negatives cover archive safety, missing
or changed per-case evidence, wrong exits, mixed commits/trees/runs/attempts,
missing architecture, x86 substitution, wrong alias bytes, unexpected profiles,
nonempty root arguments, source mismatch, macro override and inflated limits.
No target binaries are executed by these Python controls.
