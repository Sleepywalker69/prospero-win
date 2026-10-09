# Standalone RADV driver link and container checks

This optional job consumes the accepted RADV archive and produces a separate
`libvulkan.prx` with build-format evidence. It does not build or approve a
complete graphics runtime, deploy to a console, or establish DXVK/game support.
The existing exact 14-module [Wine checker](../tools/check_wine_prx_build.py)
and the software-GDI diagnostic kit remain unchanged.

## Fixed producer input

The job reads only RADV Actions run 37867691558, attempt 1, artifact 11589485912.
The producer head is `ab48410ea5b74e812e9276a908f84ae9ee2aa950`; its packaged
merge is `ad48a6b3558b5eee96e7df75e477660c528cd3a0`, source tree
`cede1918ae7e0cba67b555d58026aa3bd73cbf11`.

The outer ZIP SHA256 is
`130d03969a4f5ed4ff054db570cc61ca59133259dd295d7930626c3d7f0f6df8`.
The actual 701-member RADV archive SHA256 is
`f347c9955cf93d10886ab0751b99f49d7f4bc48fbcd33f43bc22ca13667863d9`.
It was built from PS5_Mesa `9d3cd417ff488bd1a7cc68c1f1c8e1df409c2a11`,
PS5_Vulkan `50daad6104db5072a2f3c95283d604d21684f0c2` and payload platform fork
`95c08f27386fc698f6bbe21dde3030140a41d10b`.

The consumer checks the successful run/artifact metadata, the outer checksum,
complete inner checksum coverage, source archive identities, SDK revision and
real static archive hash before linking. It reconstructs the existing documented
PS5_Vulkan layout from `producer/vulkan-source.tar`, `producer/ps5-payload-sdk`
and `producer/radv-release`. Old absolute paths in PROVENANCE.txt describe the
original build; the new `INPUTS-VERIFIED.json` explicitly records this restoration.
No old path-bound Wine/TLS report is repurposed.

## Bounded build

A same-repository PR label `build-radv-prx`, or manual reviewed workflow ref,
enables an ordinary Ubuntu 24.04 job with read-only contents/actions permissions
and a 35-minute limit. It neither rebuilds Wine nor recompiles Mesa.

It builds the public converter at foundation
`30597512539e7edfde079cbcaf4a626bc0a948c5` against that foundation's original
hash-pinned zlib 1.3.2, using its supported `--skip-sdk` bootstrap option. The
already verified RADV SDK remains the target SDK. Matched LLVM 18 tools and
`libclang-rt-18-dev` provide the exact Clang builtins archive required by the
upstream link recipe. Package versions, compiler versions and builtins digest
are retained in TOOLCHAIN.txt.

The unchanged `tools/link_radv_prx.sh` from the accepted source archive compiles
the owned wrapper, export descriptor and AGC import-stub sources, links the
verified Mesa/platform/C++ archives, then converts/signs the homebrew container.
The consumer first proves that the recipe, descriptor generator/header,
wrapper and unwind linker script match its current checkout. It does not
invent replacement stubs or rename providers to make the gate pass.

## Independent single-module gate

`tools/check_radv_prx.py` checks the actual linked objects rather than adding
`libvulkan` to the 14-module checker's membership list. It requires:

- ELF64 little-endian AMD64 shared-module identity and exact libvulkan SONAME
- real FUNC-typed module/loader/presenter exports from the reviewed descriptor
- every actual DT_NEEDED provider resolved by its real SONAME, including the
  source-built AGC/AGCDriver stubs, with visible dynamic exports
- exact ordinary kernel/libc stub hashes matching the existing checked Wine
  runtime; forbidden kernel-system/WebKit aliases always fail
- every function import bound to a FUNC in the first selected provider;
  unresolved or private exports and unsupported TLS/data imports fail
- the same four explicit SDK system-data globals and zero-addend R64/GLOB_DAT
  relocation rules, with writes inside writable LOAD memory; no extra data
  imports are automatically accepted
- nonempty checked disassembly with no syscall, sysenter or int 0x80 instruction
- successful checked converter/LLVM exits, no unresolved/error link diagnostics,
  signed-plaintext SELF structure/integrity, matching extracted digest and
  unchanged ELF metadata/program tables/LOAD bytes after documented OSABI
  normalization

The large graphics ELF reader has a 512 MiB bound because this producer starts
from a 258 MiB unstripped archive. It preserves the other bounded ELF checks.
The existing Wine checker's 128 MiB bound is unchanged.

Any extra system libraries appear explicitly in the manifest's provider graph.
Source-built stubs describe intended firmware imports; their export tables do
not demonstrate that the user's firmware grants those functions to the title.
An unexpected unresolved import, incompatible provider or forbidden instruction
stops the job. Do not waive a failed gate or silently alter the existing link
recipe to obtain an artifact.

## Output and remaining work

Only all-success produces `radv-driver-link-checked-<sha>-<attempt>`, containing:

- `driver/sce_module/libvulkan.prx`, plus its shared and converted ELF inputs,
  generated objects, GPU stubs and raw link log
- `inspection/`: every checked analyzer call, extracted ELF and CHECKS.json
- `sources/` and `LICENSES/`: retained verified RADV inputs and notices, exact
  converter source and consumer source archives
- `TOOLCHAIN.txt`, `INPUTS-VERIFIED.json`, MANIFEST.json and SHA256SUMS

Before packaging, all recorded shared/converted/extracted ELF, SELF, provider
and GPU-stub hashes are revalidated. Raw evidence is retained even if linking
or inspection fails, including bounded produced ELF/SELF/stub/object bytes and
the exact matching source/notices. A failure bundle is labelled unaccepted; it
does not become a successful driver artifact. This artifact is
not an approved drop-in update for the existing title. A later authoritative
graphics package must bind this driver to the matching Wine runtime and retain
its exact source/provider provenance. Converted export NIDs, platform
signature authentication and native loading are not proved by these checks.

Console testing must establish successful loading/import binding, device and
feature enumeration, shader compilation, VideoOut presentation, x64/x86 D3D
controls, stability and shutdown before any compatibility claim. No console or
vendor/account action is part of this workflow. See [hardware validation](HARDWARE_VALIDATION.md)
and [third-party licensing](../THIRD_PARTY.md); the linked platform code carries
GPL terms and its complete matching sources/notices remain bundled.
