# RADV archive prerequisite CI

The opt-in `RADV archive prerequisite` workflow builds one missing graphics
prerequisite using public sources. It does not produce a console-ready driver,
complete Wine runtime, or game compatibility result. The software-GDI
[diagnostic kit](DIAGNOSTIC_KIT.md) remains independent.

## Running the producer

A same-repository pull request with label `build-radv-archive`, or a manual run
of a reviewed workflow ref, can run it. It uses an ordinary Ubuntu 24.04 hosted
runner, read-only repository permissions, pinned actions and a 180-minute job
budget. Four build workers are enforced. Compilation time is unmeasured; a
time budget does not count as a successful prerequisite check.

The workflow runs the existing `tools/setup-native-dependencies.sh` and
`tools/build-radv.sh release` from the exact public PS5_Vulkan source. Its
native `mesa_clc` and `vtn_bindgen2` shader generators precede the cross build.
No console, account, vendor installer, or game executable is invoked.

## Sources and toolchain

Exact source pins are executable constants in
[`tools/package_radv_archive.py`](../tools/package_radv_archive.py):

- PS5_Vulkan `50daad6104db5072a2f3c95283d604d21684f0c2`
- PS5_Mesa `9d3cd417ff488bd1a7cc68c1f1c8e1df409c2a11`
- PS5_PayloadSDK platform fork `95c08f27386fc698f6bbe21dde3030140a41d10b`
- Public payload SDK source `4eb701204fc3f8d31e84cf8ca272974e2be9c867`

The public SDK v0.42 ZIP, bootstrap zlib 1.3.2, Mesa's zlib 1.3.1 source and
wrap patch have exact SHA-256 checks. They are copied into the upstream
scripts' cache locations only after verification. There are no shared warm
build caches or floating source branches.

The proposed Ubuntu build uses matching Clang/LLVM18, LLVM-SPIRV-Translator18.1
and SPIRV-Tools >=2024.1. The official `glslang-tools` package supplies host
`glslangValidator`; its checked `--version` preflight is retained, and pinned
Mesa requires glslang >=12.2 for AMD Vulkan BVH shader generation. Mesa's
configure version and API checks remain mandatory. Meson
1.7.2 and Python generator dependencies are pinned in an isolated environment;
Ubuntu 24.04's base Meson 1.3.2 would be too old. Installed system package and
Python versions are retained. Ubuntu adaptation is not an assertion that the
upstream project's documented Arch/CachyOS build has already passed here.

## Outputs and checks

Before compilation, `radv-sources-<sha>-<attempt>` checkpoints clean source
archives, project and dependency licences, original checked downloads, a
manifest of exact repository commit/tree identities and SHA256SUMS.

Only successful compilation and all checks produce
`radv-archive-prerequisite-<sha>-<attempt>`. Its tar preserves modes and adds:

- `producer/vulkan-source.tar`: exact source with the authoritative link recipe
  and its owned AGC stub sources
- `producer/radv-release/`: actual archive, Vulkan headers and PROVENANCE.txt
- `producer/ps5-payload-sdk/`: the exact SDK fork built by this producer
- `inspection/`: raw checked LLVM archive/header/symbol analyzer output
- `MANIFEST.json`: actual member count, archive hash and required definitions

The checker rejects thin archives, non-ELF members, non-AMD64 or non-relocatable
objects, malformed bounded tables and missing required global function
definitions. Every ordinary archive member is inspected, including long-name
formats. The required symbols are the ICD/device lookup and VideoOut helpers
actually consumed by `wine/ps5/pw_vulkan_radv.c`, not invented stubs. The source,
SDK and archive hashes must match the producer's exact provenance. All checked
analyzer processes must exit successfully. Private or external symlink targets
are rejected when packaging SDK outputs.

`radv-evidence-<run>-<attempt>` retains toolchain, build, configuration and
analyzer logs even after a later failure. Source/early artifacts are retained
for three days; checked prerequisites and raw logs for seven days. The tar is
an input to a future reviewed producer, not an installation kit.

## Remaining gates before accelerated rendering

The existing no-graphics checker intentionally accepts exactly 14 Wine modules.
This workflow does not change it. A future graphics variant needs a distinct,
strict 15-module graph check and authoritative graphics build report. Do not
filter that report or simply add `libvulkan` to an unchecked allowlist.

The existing Wine `--radv` route links the archive with the SDK platform/C++
runtime, Clang builtins and AGC providers. Before shipping, inspect actual
SONAMEs and all import providers, unresolved or private exports, data/TLS
imports and relocations, and raw syscalls. Reject WebKit/kernel-system providers
behind any filename alias. The existing link script permits unresolved-symbol
warnings, so successful linking alone is insufficient. Then inspect the final
SELF structure/integrity and extracted ELF metadata/LOAD bytes with the pinned
converter. These remain build-format checks, not native loading proof.

Only console observation establishes module loading, feature/limit exposure,
shader compilation, display presentation, x64/x86 D3D controls, stability and
shutdown for those exact bytes. DXVK DLLs still need this working driver; this
archive adds no DXVK, D3D12 or Retail-game guarantee. Keep exact artifact hashes
and the evidence requirements in [hardware validation](HARDWARE_VALIDATION.md).

## Licensing and source availability

Mesa is predominantly permissive-licensed, with component-specific notices in
its source. The SDK platform fork and PS5_Vulkan code carry GPL-3.0-or-later
terms. Their complete source archives and notices accompany the prerequisite;
the SDK release and both zlib sources/patch are retained. A later linked
`libvulkan.prx` includes GPL platform code and must preserve complete matching
source and licence provenance, as explained in [third-party notices](../THIRD_PARTY.md).
