# Source-built D3D12 frontend and actual PE link check

This is a separate opt-in build-only producer. It does not modify or assemble
the frozen PS5 first-session kit. It builds upstream Windows PE64 d3d12.dll and
d3d12core.dll together, links the [original capability query](D3D12_QUERY.md), and inspects
their actual bytes. It does not execute any PE, Wine, vendor application, Vulkan
or GPU code. No capability override is set. Successful link inspection explicitly
keeps import-graph, console-package and runtime approval false.

The hosted-compatible query C source is SHA256
`c101938e6fbaad8d2e4c98bf880e19ab702a2a5a00506a33ac742cf22344f4d4`.
The sole delta from the prior source seal is the same typed numeric FL12_2 value,
[0xc200](https://learn.microsoft.com/en-us/windows/win32/api/d3dcommon/ne-d3dcommon-d3d_feature_level), in the requested-level array: [Noble MinGW 11 headers](https://github.com/mingw-w64/mingw-w64/blob/v11.0.1/mingw-w64-headers/include/d3dcommon.h) omit that enum name.
This changes neither the minimum feature level nor returned capabilities.
Its header remains `050b8e04e197a610c43157501a9d6e2e0d7e558673bda84a5b76bb98003e33fa`.
The query requests only FL11_0, reports actual max feature level and tiled/binding
tiers, and retains the reviewed failure, cleanup-marker and deadline logic. Its
25-second budget accounts for returning operations and supervises the worker
wait; it cannot guarantee termination of a stuck pre-main initializer, thread
creation, platform call or GPU driver. Self-termination may end the Wine title;
no independent native cleanup is established. The source reads two known
capability-override variables and refuses their nonempty values. A query result
does not establish graphics execution, full Agility or current Retail support.

## Exact producer inputs

The intentionally selected frontend is vkd3d-proton 2.14 at
`c965c1351fd6915a65bb7f647319536252a24a93`, not a claim of the newest version:
[pinned upstream source](https://github.com/HansKristian-Work/vkd3d-proton/tree/c965c1351fd6915a65bb7f647319536252a24a93).
The source-backed Windows recipe uses POSIX MinGW C/C++, Meson, Ninja, glslang
with Vulkan 1.3/depfile support, and an actual IDL compiler. The recipe's first
`widl` lookup is explicitly bound to the selected x64 MinGW widl by a private
wrapper, so it cannot accidentally select a different Wine IDL generator.

The sources phase creates separate clean checkouts of the following public commits at these paths
inside the main checkout. The sources phase fetches these exact commits from fixed public GitHub repositories. Do not use
recursive submodule initialization here: two unused nested gitlinks are
deliberately recorded but unpopulated for this bounded Meson target.

| Relative checkout | Repository | Commit |
| --- | --- | --- |
| . | HansKristian-Work/vkd3d-proton | c965c1351fd6915a65bb7f647319536252a24a93 |
| khronos/Vulkan-Headers | KhronosGroup/Vulkan-Headers | 29f979ee5aa58b7b005f805ea8df7a855c39ff37 |
| khronos/SPIRV-Headers | KhronosGroup/SPIRV-Headers | 8b246ff75c6615ba4532fe4fde20f1be090c3764 |
| subprojects/dxil-spirv | HansKristian-Work/dxil-spirv | 33cd5b2eee8a27da50ad7ed2762e56cca3a7b2c9 |
| subprojects/dxil-spirv/third_party/spirv-headers | KhronosGroup/SPIRV-Headers | ec59c77a3bb5c747a369931ef101ac7c14823f2f |

The last nested source's siblings SPIRV-Tools at
`d9c1aee6a609c6d6ec1caab4def80720c44bd08d` and SPIRV-Cross at
`476f384eb7d9e48613c45179e502a15ab95b6b49` are present as declared gitlinks.
The pinned dxil-spirv Meson static library compiles bundled bitcode/GLSL-SPIR-V
builder sources and consumes spirv-headers; it does not build those two sibling
projects. All used checkouts must match both their exact commits and complete
gitlink membership, with no dirty, untracked or ignored inputs. Full tracked
source archives, including their upstream license/notice files, are retained
before compilation. Optional proprietary DXILCONV is explicitly disabled;
tests, demos, extra programs, tracing, profiling and RenderDoc are also off.

The reusable graphics PE parser is copied unchanged from its accepted baseline,
SHA256 `e2532a45f885634546a2990df31783f8dcfec9b691c0e43943bb7d6e845154c2`.
The existing graphics-contracts parser is reused without modification.

## Bounded hosted build

The [workflow](../.github/workflows/d3d12-frontend.yml) uses Ubuntu 24.04, read-only repository permissions,
a 60-minute job cap, two Ninja workers and no Wine/PE execution step. It runs only
by manual dispatch or a same-repository pull request carrying the build-d3d12-frontend label.
Install build prerequisites only from the official Ubuntu distribution:

    sudo apt-get install --no-install-recommends build-essential git meson ninja-build \
      glslang-tools gcc-mingw-w64-x86-64-posix g++-mingw-w64-x86-64-posix \
      mingw-w64-tools binutils-mingw-w64-x86-64

The official package index provides the
[POSIX x64 compiler](https://packages.ubuntu.com/noble/gcc-mingw-w64-x86-64-posix),
[glslang tools](https://packages.ubuntu.com/noble/glslang-tools), and
[MinGW tools package](https://packages.ubuntu.com/mingw-w64-tools).
The final runner must check actual installed tool paths/versions; listing a
package does not establish that its generator accepts this pinned source.
The build script requires every selected executable and records its hash. It
retains installed compiler/runtime source-package identities, notices, full
license texts and the selected static runtime archive hashes. Compiler
executables and system DLLs are not bundled in the candidate.

Run the original pure/source controls and the new inert PE/command tests first:

    python3 tests/test_d3d12_query.py -v
    python3 tests/test_d3d12_frontend.py -v
    cc -std=c11 -Wall -Wextra -Werror -pedantic -Itests/fixtures \
      tests/fixtures/d3d12_query_contract_test.c -o /tmp/d3d12-query-contract
    /tmp/d3d12-query-contract

Only the final command executes an original host program with pure numeric
policy inputs. It contains no Windows, Wine, GPU, allocator or server code.

From a clean committed project checkout and a new directory outside that checkout:

    python3 tools/build_d3d12_frontend.py sources --work /new/d3d12-build --repository https://github.com/OWNER/prospero-win
    python3 tools/build_d3d12_frontend.py build --work /new/d3d12-build

The producer records argv arrays in COMMANDS.json. It runs the upstream Win32
cross recipe with `--wrap-mode=nodownload`, release build, explicit feature
options and retained relocations/ASLR/high-entropy/NX link flags. It uses private
compiler-name wrappers; no system compiler alternative is changed. It then
links the unchanged original fixture with `-std=c11 -O2 -Wall -Wextra -Werror`,
static compiler support, and `-ld3d12 -ldxgi -ldxguid`. A COFF object alone cannot
reach the final link report. The fixture's warning policy is unchanged; upstream
code keeps its own Meson warnings rather than imposing a new upstream patch.

SOURCE-CHECKPOINT.json, all used upstream sources/notices, full project source,
project commit/tree, LICENSE/NOTICE/THIRD_PARTY and tool identities exist before
compilation starts. The workflow uploads this checkpoint before the build.
Source archive membership must include every tracked blob, so export-ignore
cannot silently omit corresponding source or licenses. Outer source archives, copied fixtures and licence/notice files are normalized
to regular 0644 before inventory, with directories 0755. Original tracked modes
remain preserved inside each Git source archive. The build rechecks all
retained hashes and exact outer modes, project identity, source pins/cleanliness and tools before and
after compilation. An accepted artifact contains linked candidates only together
with corresponding sources/notices, command arrays and the PE link report.
Partial source archives, logs and original outputs are retained on failure.
This includes either DLL at its exact uninstalled Meson build path if the other
DLL fails before Ninja's install target. These are unaccepted failure evidence,
retained with corresponding source and notices; they do not gain a link report.
No artifact changes the accepted diagnostic kit or supplies a runnable overlay.

## Actual link-check contract and remaining consumer gate

The checker parses each resulting PE64 and requires a real entry point,
AMD64 architecture, DLL/EXE type, ASLR/high-entropy/NX flags, a bounded relocation
directory with actual DIR64 targets, and all original query API imports. It
records every direct normal/delay import and rejects unexpected DLL names for
review, including accidental dynamic compiler runtimes. The provisional
system-DLL allowlists are deliberately explicit; their presence is not an
assertion that a provider implements the imported functions. A full source
build can legitimately reveal an additional import and fail this gate.

Both frontend DLLs must export their expected function names as code RVAs.
The core's D3D12SDKVersion must be a nonforwarded, file-backed data export whose
actual UINT value is 614; Wine's stub or a function named SDKVersion fails.
An exported function RVA establishes a linked code address, not API semantics.
The DLLs are built in one clean source transaction and their hashes are bound
to that producer's source checkpoint. SDKVersion 614 does not establish
ID3D12SDKConfiguration or ID3D12SDKConfiguration1: this pin's core accepts its
private IVKD3DCoreInterface rather than implementing arbitrary Agility classes.

PE-LINK-REPORT.json always says `pe_import_graph_verified=false`,
`console_package_approved=false`, and `runtime_verified=false`. It does not
contain dxgi.dll or any Wine/native driver provider. A later separately reviewed
consumer must bind the accepted source-built DXVK 2.1+ dxgi.dll and exact Wine
base, then use the existing `verify_graph` parser for every imported name,
ordinal, API-set contract and forwarder. It must additionally root the
dynamically loaded matching d3d12core.dll/D3D12GetInterface and both pinned
Vulkan loader names; successful static imports alone miss these loads. The
accepted parser already roots winevulkan.dll and vulkan-1.dll for DXVK, but
its report label must be interpreted/extended for both frontend callers.
DXGI's D3D12 swapchain/interop interfaces remain later rendering contracts;
this headless query does not exercise presentation. Optional wineopenxr loading
is conditional and is not covered by this non-VR fixture.

The exact consumer then has to bind native PRX/provider identities and the
driver, preserve first-session files, and record a separate overlay manifest.
No producer link success admits that overlay automatically. The current RADV
source's absent strict sparse-residency semantics still cap this vkd3d feature
level path at at most 11_1 without forcing; real device creation may fail earlier.
No verified official current Retail minimum feature-level number was found.

## Validation performed here

The previous source/header and COFF identities were verified before integration.
The FL12_2 spelling compatibility delta compiles warning-clean with Clang 19 and
produces a byte-identical AMD64 COFF object to the prior source seal; source
controls preserve the requested query set and FL11_0 device minimum. Ten frontend host controls pass, including actual inert AMD64 PE-byte
parsing and negative controls for SDK data versus code/forwarders, missing
relocations/ASLR/NX, malformed targets, missing query APIs, unexpected CRT DLLs,
source pins/gitlink membership/cleanliness, complete source-archive membership,
checkpoint mutations, notice-mode tar round trips, workflow gating and build-only command generation.
The four query controls, including existing source/API mocks and pure C numeric contracts, pass.
These tests never run a generated PE or upstream graphics code.

Local tools currently provide Clang 19 and an i386 MinGW setup, but no x64 MinGW
linker/compiler, Meson, Ninja, glslang or widl on the checked build-tool path.
Thus the actual vkd3d build, executable link, emitted imports, full static graph,
Windows API execution, GPU execution and PS5 behavior remain untested. An exact
hosted build failure is an acceptable result and must be reported before any
console candidate can be proposed.
