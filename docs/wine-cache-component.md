# Bounded host compiler-cache component experiment

This opt-in CI lane measures one real pinned-Wine host C object. It does not build or install a runtime, execute the object, validate PS5 behavior, or establish a whole-Wine speedup.

## Input and admission

The original matched build is run 38241186538 attempt 1, candidate bbfa02476c6794538be1aad46886ec45976a4af9, compiled merge 7acf08abea63640a737c7cec0cae4c0da61b82f5. Its separate successful cache exporter is run 38252843457 attempt 1, head f683b8ff0d2813db4ec0c45b7f61b8fad3bac5b9, compiled merge 4c16c46b05e1921fbb73d93810d69d3770ae3640.

The importer pins artifact 11748513001 and its exact ZIP digest, the cache TAR digest, eight allowed ZIP members, complete regular-file inventory, original donor receipts, and opaque original host/source checkpoint. It verifies all cache TAR members before creating a fresh cache destination. Links, special files, duplicate/case-aliased paths, file-directory aliases and count/size overflows fail closed.

Fresh compiler identity is calculated by the existing cache helper on the actual runner. It must equal the donor's compiler/configuration/flags/header/package identity AND tracked source/build recipe map. Different hosted packages or headers cause rejection; the experiment must never relax this gate merely to obtain a hit. Fresh config and compiler launchers stay outside the imported cache.

The original save association is service-mediated provenance. Exporter-observed file hashes do not retroactively prove a donor-time file inventory.

## Bounded workload

The ordinary contract job runs without the benchmark label. After exact-head tests and independent review, the same-repository label `measure-wine-cache-component` permits the component job. It is incompatible with the heavy matched-build label.

The job has a 20-minute outer timeout. A shared 900-second budget covers prerequisites, pinned source fetch, current partition preparation, import, configure/tools-only build and all object measurements. Owned subprocesses run in separate process groups; timeout/cancel requests TERM, then KILL and bounded reap, with up to ten additional seconds reserved for cleanup. Repeat cancellation signals are masked during that bounded cleanup. Failure or uncertain cleanup stops the job. There is no full-build/install fallback.

The existing host builder is invoked only with `--tools-only`. Pinned Wine's server/Makefile.in names process.c and makedep uses an empty host architecture prefix, producing server/process.o. The actual generated rule must resolve to the staged server/process.c, and the object must be absent before the first measurement.

Measurements:
- Existing donor cache: require exactly one PID-bound compiler invocation for the exact selected source/output and a preprocessed cache hit, with zero misses. A dependency hit cannot substitute for target attribution.
- Unchanged make no-op: require make -q success, zero cache counter changes, identical object hash.
- Controlled staged C edit: append a used static data constant, verify actual timestamp ordering, require a miss and changed object hash.
- Uncached control: remove only that object and rebuild at the identical absolute path with identical flags, setting CCACHE_DISABLE after fresh cache environment construction. Its bytes must equal the edited cached-path result.

The original staged C source is restored afterward. Raw per-stage cache counters, PID-bound invocation logs and command logs are retained; hit counts are not claimed to equal all backend invocations. No-op scheduling and compiler-cache hits are reported separately.

## Limits

This does not prove shared-header invalidation, complete linking, object-tree checkpoint restoration, or whole-runtime build time. Those require later bounded dependency tests and real runtime acceptance. The existing inactive incremental-policy tests remain policy evidence only. Original matched runtime/install pins are unaffected.
