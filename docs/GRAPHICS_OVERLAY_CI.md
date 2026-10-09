# Source-built D3D11 diagnostic overlay

This separate producer builds upstream DXVK 2.6.2's x64 Windows DLLs and an
original clear/readback executable. It combines their checked metadata with
one exact accepted Wine kit and one exact accepted RADV driver. A successful
job establishes build and file/import contracts. It does not establish console
loading, a visible frame, game compatibility or current Retail D3D11 support.

The software-GDI kit and its source hashes stay unchanged. This overlay has its
own manifest and source. There is no D3D12/vkd3d-proton component, vendor binary,
installer, game asset, account or console action in this job.

## Fixed inputs and build

The base is diagnostic-kit run 37861508535, artifact 11588549010. Its outer ZIP
SHA256 is `fcdbc6b853150618df471dac460744e40aab83dd7c0289963afa9ac0067a6cc0`.
The source commit is `578c593f7d8588c529f0c12413f71c8692817224`, tree
`93a62a15aff0376316b7504aba4e3dd35779750b`, with Wine
`490f6d5dcbb2a5047345b8af88d114bbcaad69a8`.

The driver is run 37877727299, artifact 11592264803. Its ZIP SHA256 is
`f7bb11abf687c57b024a3490d9c7b26a6a2be4f3300a09d3a7ea2340d4a0e260`.
Its consumer commit is `9de8e28b9944b72ac6dd0fd2da094f83be4f43b2`, tree
`3de8259f2eb0dfa0ec1c0b66a1b9db8f16797f49`. The actual PRX SHA256 is
`341318d3d89ddc78c56abd5666495e90ae44dbe6edfbdea7161c4446569d0183`.
Run/artifact metadata, archive boundaries, hashes and source identities are
checked before the inputs are used.

[DXVK 2.6.2 source](https://github.com/doitsujin/dxvk/tree/9d6f54a1ade20d1d27dd421024717a636f3d8c68)
is pinned at `9d6f54a1ade20d1d27dd421024717a636f3d8c68`. Its exact Vulkan/SPIR-V
headers, libdisplay-info and native DirectX header gitlinks are fetched by
explicit public URL/commit. Gitlink membership, clean source, corresponding
archives and licences are recorded. Source archives are reconstructed and
compared again before packaging. The producer's own commit/tree/source is
recorded separately from both older binary producers.

The optional `build-graphics-overlay` same-repository PR label or manual
workflow uses ordinary Ubuntu 24.04 with read-only contents/actions permissions
and a 60-minute cap. Official Ubuntu MinGW POSIX compilers, Meson, Ninja,
glslang and LLVM 18 are recorded. The upstream Windows cross file selects
Win32 WSI. Ninja uses two workers; Meson may not download undeclared wraps.
The selected static CRT, MinGW, pthread, GCC and C++ runtime archive hashes,
installed source-package versions, distribution copyright/exception notices
and their referenced full GPL/LGPL licence texts are retained. Compiler executables are not shipped. DXVK and its source
dependencies have complete corresponding archives; compiler/runtime provenance
identifies the official distribution source packages separately.
Only d3d11.dll and dxgi.dll are installed. Original upstream release hashes in
[pw_install.py](../tools/pw_install.py) are preserved; source-built DLLs have
new hashes and never impersonate an upstream release archive.

Source is uploaded before compilation. Partial DLLs, exact source, configure
metadata and raw logs remain available if a later gate fails. No Wine or PE
executable is run in this producer.

## What is checked

The exact base file manifest covers all original bytes and modes. A separately
pinned topology digest covers directories and relative internal links. All
destination parents must be ordinary owned directories before any copy or
write; added directory links cannot redirect writes into either input. Its 14 Wine
PRXs, native CPU companion, patched PE thunks and winevulkan provider graph are
bound to those unchanged files. The full kit already supplies winevulkan.dll,
winevulkan.prx, win32u and opengl32; no full Wine rebuild is needed here.

The standalone driver's original accepted SELF/converted/extracted hashes are
rechecked. Its ordinary SDK and source-built AGC providers are restored by
verified bytes, and the separate [driver checker](../tools/check_radv_prx.py)
reinspects the actual linked ELF/provider graph with new local paths. The five
providers are ordinary libc, ordinary kernel, VideoOut, AGC and AGCDriver.
The original 14-module checker and its data rules are unchanged. System stubs
and metadata still do not prove the user's firmware grants those imports.

The new AMD64 PE DLLs must export real code for the required D3D11/DXGI entry
points. A bounded parser resolves normal and delay imports, names and ordinals,
export forwarders and the exact Wine API-set namespace. Every reachable PE
provider is recorded by hash. DXVK's source-selected dynamic winevulkan.dll /
vulkan-1.dll lookup is explicitly checked for vkGetInstanceProcAddr. Exported
code and data are distinguished; an implementation may still be a Wine stub.
The graph check proves metadata resolution, not successful API behavior.

The original smoke creates a 1920x1080 window and requests hardware feature
level 11.0 without a software fallback. It queries, logs and requires an actual
1920x1080 RGBA8 back buffer with one sample, quality zero, one mip and one array
slice. It clears two colours, checks the mapped pointer and row pitch before
reading the centre pixel, and requires S_OK from each Present. Adapter IDs and
HRESULTs are logged. It includes no shader blobs or game assets.

The worker owns all GPU calls and COM/window cleanup. The main thread accounts
for one absolute 25-second budget starting before thread creation, rejects
backward clock samples, and requires normal zero thread exit and a marker set
after cleanup. Handle errors and the final clock sample after CloseHandle
prevent a success result. On timeout or uncertain completion it requests
self-termination without concurrently releasing worker objects; if that call
returns it logs the result and requests ExitProcess. This can end the hosting
Wine title. This is observed deadline accounting, not guaranteed interruption
of pre-main/configuration, thread creation, platform or GPU hangs. Those paths
still need hardware observation. A future passing run would not establish
arbitrary shader/draw workloads, long-term stability or that the user's TV
displayed a frame.

## Assemble a new diagnostic copy on a PC

Keep the verified base kit and overlay archives, source and licences. Extract
both into separate fresh directories. Obtain the graphics manifest SHA256 from
the independently verified producer result (`GRAPHICS_MANIFEST_SHA256` in its
package log), rather than trusting a digest inside an unknown archive.

The overlay's standalone Python helper creates a new copy and refuses to
modify either input or overwrite an existing output:

Use stable directories that you own, with no concurrent writers during assembly.
The checks do not make arbitrary external file changes atomic.

```sh
python3 graphics-overlay/assemble_graphics_copy.py \
  --base software-gdi-kit --overlay graphics-overlay --out graphics-diagnostic \
  --manifest-sha256 VERIFIED_PRODUCER_MANIFEST_SHA256
```

The only additions to the base runtime/data paths are:

- `PPSA99995/win/wine/lib/wine/x86_64-unix/libvulkan.prx`
- `pc/graphics-smoke/x64/d3d11.dll`, `dxgi.dll`, `d3d11-clear.exe`
- `pc/recipes/diagnostic-d3d11.yml`

The complete overlay evidence/source is retained in `graphics-evidence/`.
Original manifests describe the unchanged base files; the graphics manifest
separately describes the additions. Neither manifest claims a full tested
console graphics kit.

On a supported PC/WSL host, use the original kit's documented prefix preparation
with its matching bundled Wine:

```sh
python3 graphics-diagnostic/pc/tools/pw_install.py \
  graphics-diagnostic/pc/recipes/diagnostic-d3d11.yml \
  --library graphics-library \
  --wine graphics-diagnostic/pc/host-wine/usr/bin/wine
```

The recipe performs only create_prefix and local copy operations. It validates
local DLL/executable hashes via file URLs, disables Gecko/Mono downloads, and
sets native d3d11/dxgi overrides. `graphics: auto` preserves the existing runtime
selection while avoiding pw_install's release-downloader path; explicit
`graphics: dxvk` would fetch the old fixed release. The title's current auto
and dxvk modes use the same Vulkan path when these native DLLs are selected.
No fixture is launched during prefix preparation. A prefix is not included in
the overlay. This new recipe still needs a genuine supported-host prefix test
before its resulting prefix can be advertised as verified.

Use the existing kit's supported PC-to-console library push instructions only
when ready for a separately authorized hardware test. Preserve the exact base,
driver, DLL, executable and profile hashes and collect gap-free console logs.
Actual module binding, Vulkan features, shader behavior, presentation, input
and cleanup remain console gates. D3D12 and current Retail readiness remain
separate work; a D3D11 smoke result is not a game-support promise.
