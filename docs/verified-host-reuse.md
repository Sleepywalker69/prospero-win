# Verified host-only runtime reuse

The next matched diagnostic build can reuse the installed host Wine from successful same-repository run 38223633711. This is deliberately narrower than native-only package reuse: target Wine, fresh prefix construction, original Windows references, host tests/sanitizers, the native pair, and all ABI/source/package checks still run.

## Measured baseline

Run 38223633711: complete host Wine 49m22s; target cohort 6m48s; host aggregate 2m35s; sanitizer aggregate 4m51s; SDK/TLS 2m18s; early target compilation 1m17s; full native child/title 42s; final source/package assembly 5m46s. These are baseline step durations, not claimed savings.

## Admission

Only a fully successful owned matched-runtime workflow with all three unique, unexpired, same-attempt package/checkpoint/evidence artifacts is eligible. Downloaded ZIP sizes and SHA-256 digests are checked against GitHub. The complete accepted package verifier is rerun. Its source commit/tree must match the workflow commit or recorded PR merge parent. The original successful host receipt, exact compiler/environment partition, host recipes, actual staged Wine host/target source snapshots, configure output and precious environment, selected host workflow contract, and hosted runner image must agree.

Project commit/tree changes alone do not invalidate identical host inputs. Donor receipts are preserved unchanged under host-reuse-inputs; host-reuse.json explicitly separates the donor producer from the new consumer. These receipts are also carried by the host checkpoint. A reuse hit is never recorded as a new full host compilation.

The support rebuild explicitly builds loader/wine, server/wineserver, ntdll.so and four required import/runtime archives. Their existence and executable bits are checked before CPU conversion, preventing build_wowprospero.sh from silently launching a full make.

## Fallback and retained checks

An absent, expired, incomplete, corrupted or incompatible donor causes the unchanged full host build to run. Unexpected ambient compiler/configure overrides are refused. The standard setup-python pkgconfig path is admitted only with matching configure and runner/workflow identity. Exact absolute hosted paths are required; path drift falls back rather than weakening the comparison.

No target runtime, prefix or Windows reference output is reused by this version. Their current same-project/same-run matching contracts remain intact. Both native images and their source/ABI/protocol bindings are rebuilt and inspected. The existing always-on target ELF/object diagnostic retention remains enabled. The workflow omits only two redundant external package scans because assemble already performs those same directory/archive validations and round-trip checks without an intervening mutation.

The pinned donor is retained for seven days by the existing artifact policy. A future donor update must identify another fully accepted full-build run; reused checkpoints lacking a genuine full-host receipt are not silently promoted. Expiry intentionally triggers the full-build fallback.

## Validation

Focused negative controls are registered in make all. Hosted end-to-end timing and a demonstrated reuse receipt are required before claiming a speedup. No console result is implied by build success.
