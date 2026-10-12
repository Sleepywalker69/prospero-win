# Incremental host Wine: staged policy, not activated
This draft adds source reconciliation policy and a small real compiler/Make DAG
test. It does not restore Wine objects, skip production compilation, or change
the host build recipe. The only active matched-workflow change publishes a small
admission/cache decision before any long full-host fallback.

## Measured baseline and target
Donor run 38223633711 took 49m22s for host Wine and 81m19s for the matched job.
Its compiler receipt recorded 1,246 hits, 95,248 misses and 4,727 link invocations.
The host cache restore missed. Packaging alone took 5m46s. These timings cannot
be replaced by a synthetic three-file result or promised warm-build time.
Current host configuration already disables Wine tests; i386 and x86_64 PE
architectures are intentional runtime coverage, not redundant test variants.
The retained make log is still needed for an actual target-category breakdown.

## Why a compiler cache alone is insufficient
build_host_wine.sh force-restages Wine, and any patch-content change invalidates
its configuration stamp and deletes its build directory. ccache can reuse some
compilation, but cannot preserve the complete Make DAG or avoid thousands of
links. Existing strict ccache partitioning is retained.

## Future checkpoint adapter acceptance contract
1. Authenticate a successful exact same-repository donor and archive hashes;
   bind full source inventory (hash/mode/observed timestamps), object/generated
   inventory and successful dependency/build/install receipts. Reject untrusted
   archive paths, symlinks outside the checkpoint, incomplete or partial donors.
2. Match compiler-content/toolchain/header/sysroot/package identities, flags,
   configure environment/results, pinned Wine, recipe hashes and absolute paths.
   GitHub PR merge-ref caches are not shared with sibling PRs. Use explicitly
   verified artifacts or trusted base/default-branch cache seeding.
3. Stage the entire desired source tree afresh. Compare exact membership, never
   overlay it onto old sources. Additions, removals, renames, mode changes,
   configuration, generators, global headers, recipes or unknown files go cold.
   Initial eligibility is an explicit small set of server/ntdll local files.
4. Verify the donor's actual source/object/generated timestamp relationships.
   The barrier must include every object/generated output. Preserve unchanged
   source timestamps only with matching bytes and mode; changed input timestamps
   must be strictly newer than that barrier on the actual filesystem. Equal,
   rounded, future or unpreservable timestamps go cold. Never sleep as proof.
   This helper assumes serialized exclusive access to the fresh staged tree.
5. Regenerate dependencies using pinned Wine's explicit make depend rule, then
   run normal full make and install/strip. tools/makedep.c at pinned commit
   490f6d5dcbb2a5047345b8af88d114bbcaad69a8 emits depend, Makefile/config.status
   and include/config.h.in rules. This proves the command exists; it does not
   establish arbitrary generated-input reuse correctness.
6. Keep full runtime DLL coverage and all existing source/ABI/install checks.
   Cache admission failure must select the normal verified cold build.

## Required real evidence before activation
Measure cold, unchanged, native-only, one allowed Wine C edit, allowed local
header edit, and config/toolchain change. Record affected compiler/link counts,
dependency regeneration, restoration/upload, install/strip, packaging and total
wall time. Native-only should compile zero host Wine units; a header edit must
rebuild every dependent unit. Compare each restored result against an independent
clean build and retained inventories. No-change is not sufficient proof.

The short hosted lane uses an original three-file C/shared-header Make DAG and
checks unchanged=0, native-only=0, one-C=1, local-header=2 compilations. It also
checks deletion, rename, configuration, toolchain and flags cold fallback and
byte-equivalent clean outputs. Its reports explicitly disclaim Wine speedups
and checkpoint transfer measurements.

## Early observability
The matched workflow times the host compiler-cache restore step (including
Actions step overhead), then retains exact hit/any-hit/matched key. Immediately
after admission it prints and uploads a bounded public decision with the guard
reason, elapsed admission, fallback requirement and runtime_build_complete=false.
Download URLs are removed. No environment or credentials are copied. Mocked
admission tests exercise receipt generation and enforce upload-before-full-build
ordering without starting Wine.
