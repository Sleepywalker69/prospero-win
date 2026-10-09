# Experimental private AMD64 dispatcher ABI

`PW_WINE_PRIVATE_DISPATCH=1` selects a separate, experimental native AMD64
runtime build. It is off by default. It does not create processes, enable patch
0550, or establish console execution. The general release packager rejects a
report containing this experimental ABI before changing its output directory.
The existing diagnostic kit and native HELLO/FD probes are separate artifacts.

## Why a private slot is needed

The pinned Wine AMD64 syscall thunks call a native function pointer at
`0x7ffe1000`. Existing PS5 patches place that address in a shared 16 KiB
KUSER_SHARED_DATA mapping. A separately loaded native ntdll can have a different
function address. Instrumentation also changes the dispatcher locally, so equal
load addresses would not establish a correct shared-pointer contract.

Experimental ABI1 moves only the thunk's dispatcher operand to `0x7ffe4000`.
It keeps the 32-byte thunk shape and normal syscall-number field. The first
16 KiB page stays shared/read-only in the fixed client view; the next 16 KiB
page holds this process's private dispatcher data. The existing early Wine
reservation covers both pages. A separate reservation at the second page would
be rounded down by Wine's 64 KiB reservation alignment.

The early shared-data page remains committed because initialization diagnostics
can read its clock fields before the server section is installed. The checked
platform adapter replaces only that first page. It checks direct-memory
ownership before mapping and both the adopter's return and recorded release
failures afterward. Failure exits before guest entry; there is no rollback or
native cleanup claim. This is a narrow bootstrap adapter, not a general mapping
or allocator replacement.

The private page requests read/write protection without execute. Actual effective
protection and ownership still require a console observation. Shared-data writers
through the server and existing initialization alias are retained. ABI1 never
initializes the legacy dispatcher slot as a fallback.

## Matched module and architecture requirements

The explicit switch reaches Unix ntdll, AMD64 PE compilation and the checked
platform shim. Manual compiler definitions are rejected so a build cannot label
itself OFF while silently compiling ON code. The configure identity includes
the effective AMD64 flags. Native ntdll exports the ABI version when ON, and the
report binds actual PE and native ELF hashes to that declared build.

Before guest entry, the loader validates the actual loaded ntdll export/thunk.
It also validates win32u when mapped. Bounded image parsing rejects unreadable
or ambiguous export spans, forwarded/duplicate anchors and legacy operands.
Non-AMD64/hybrid images and PE `.so` builtin fallbacks are refused in ABI1.
This is a per-runtime AMD64 prerequisite; it cannot run a PE32 main executable.
An unmodified legacy native runtime cannot acquire these new checks, so manually
mixing ON PE modules into an OFF runtime remains outside the supported contract.

The standalone static checker accepts `--mode 0` or `--mode 1` and inspects both
ntdll.dll and win32u.dll without loading them. The general producer only admits
reports without an experimental declaration; it does not authenticate a manually
altered report or supply an ON installation path. A future experimental package
must validate the actual selected and overlaid PE/native identities separately.

## Validation boundaries

Pure tests materialize the exact new header and helper from patch 0910. They
exercise ordinary local byte arrays and counter values, without calling the
allocator, mapping APIs, Wine, a server or a native process provider. When
`PROSPERO_WINE_SOURCE` identifies the pinned Git source and Clang is available,
the suite additionally applies the actual selected patch hunks, compiles inert
COFF thunks, proves OFF bodies match the baseline and checks that ON changes
only the dispatcher operand. Those source-backed checks explicitly skip when
the source/tool prerequisites are absent.

The existing Wine PRX job has a separate `build-private-dispatch` opt-in label
and manual `build_private_dispatch` input. That selection builds an OFF/ON
matrix; the ordinary `build-wine-prxs` selection remains OFF. Each job uses
real host Wine tools, the supported LLVM18 SDK, pinned TLS dependencies and the
unchanged 14-module compile/link/conversion acceptance gate. It independently
checks actual PE operands, native/report hashes, and a visible defined native
ABI function only for ON. Artifacts identify their mode and carry exact source,
licenses and compiler/analyzer records. Bounded affected outputs and matching
source are also retained after a matrix build fails. This lane runs no Wine or
native runtime executable and never invokes general release packaging.
Compile/link/conversion cannot establish fixed-address allocation, effective
page protection, cross-process ownership, native cleanup or Windows children.
Authenticated descriptor transport, child-local thread control, authoritative
Wine startup and owned-child shutdown remain separate prerequisites.

The public source contract is the project's pinned
[Wine revision](https://github.com/wine-mirror/wine/tree/490f6d5dcbb2a5047345b8af88d114bbcaad69a8),
especially `include/wine/asm.h`, ntdll's Unix loader, virtual-memory and AMD64
signal code. [Development guidance](DEVELOPMENT.md) explains the source-backed
checks and supported host prerequisites.
