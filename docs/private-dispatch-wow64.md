# Translated I386 with the private dispatcher

The experimental `PW_WINE_PRIVATE_DISPATCH=1` runtime now admits matched I386
PE modules through Wine's existing WoW64 translator. The AMD64 private ABI1
slot remains at `0x7ffe4000`. I386 thunks instead use their module-local writable
dispatcher, which WoW64 initializes with the translator's process-local BOP
addresses. No guest dispatcher is placed in shared user data.

Patch 0914 preserves the existing 0910 mapping and ownership checks. It requires
an AMD64 native host, 16 KiB host pages, a nonhybrid AMD64 or I386 image, and
architecture-specific checks of ntdll and win32u. The I386 check validates the
actual thunk, helper, zero-initialized dispatcher export, section permissions
and exact relocations. Private WoW64 selects `wowprospero.dll` and refuses a
missing or invalid backend instead of falling back to another CPU.

The source contract follows pinned Wine
[asm.h](https://github.com/wine-mirror/wine/blob/490f6d5dcbb2a5047345b8af88d114bbcaad69a8/include/wine/asm.h)
and [WoW64 initialization](https://github.com/wine-mirror/wine/blob/490f6d5dcbb2a5047345b8af88d114bbcaad69a8/dlls/wow64/syscall.c).
The original translator is in [cpu.c](../wine/wowprospero/cpu.c).

Both PE architectures receive the explicit build definition. The native ntdll
must publish `__wine_ps5_private_dispatch_wow64_abi` through its actual PRX
export descriptor alongside the unchanged base ABI1 export. The build report
retains `wow64_abi: 1`; the checker verifies real I386 bytes and the native
capability function and descriptor. `--require-wow64` rejects the old cohort.
All 22 patched PEs, native PRXs and the separately built CPU PE must come from
the matched build. This patch does not install a process provider or enable
service child creation by itself.

Pure byte controls, compiled source controls and artifact checks establish the
source and packaging contract. They do not establish PS5 execution, Battle.net
compatibility or child GUI support. The runtime remains experimental and its
manifest records `runtime_validated: false`. Default OFF behavior is preserved.
