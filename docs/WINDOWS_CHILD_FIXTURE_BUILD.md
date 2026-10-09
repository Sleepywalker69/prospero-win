# Matched Windows child-process build

This producer builds one matched experimental Wine cohort, an original AMD64
parent/child diagnostic, and a separate translated-I386 Battle.net installer
candidate. The vendor installer is supplied later by the operator. A successful hosted build establishes compilation,
conversion, import/provider identity, prefix preparation and archive integrity.
The console still has to establish full-CRT service startup, the inherited
wineserver endpoint, the Windows child result and cleanup. A native fd3 echo
probe or a Windows reference pass does not establish those boundaries.

The ordinary release packager continues to refuse private-dispatch runtimes.
This separate producer checks the actual private-ABI ntdll/win32u PE thunks and
native ntdll exports, then carries those exact files into its runtime and prefixes.
The new WoW64 capability is checked separately from the existing private ABI1;
an older ABI1-only runtime cannot enable the Battle.net profile.
It never combines earlier native-suite or graphics-kit binaries with this build.

## Inputs and build order

The opt-in workflow uses ordinary Windows Server 2022 and Ubuntu 24.04 hosted runners,
read-only repository permissions and commit-pinned actions. A same-repository
pull request needs the `build-windows-child-fixture` label; a manual run uses its
selected ref. No release publishing or console deployment occurs.

1. Build the original AMD64 PE using `build_windows_child_fixture.ps1` and the
   installed MSVC toolchain. Run the same bytes on Windows with the existing
   45-second outer deadline. Record project commit/tree, fixture/source recipe,
   compiler hash/version, result and both byte-identical PE hashes.
2. Run the unchanged host and sanitizer aggregates. Run the private dispatcher
   contract with the actual pinned Wine checkout and Clang, including its
   source-backed controls. Record every skip; source checks alone are not a
   compiled PRX result.
3. Apply the exact final patch series to a private reference checkout and run
   the existing owned-source staging commands. Build full host Wine and retain
   an early checkpoint with its corresponding source and notices.
4. Build the pinned public SDK/converters, TLS prerequisites and the complete
   private-ON Wine PE/PRX cohort with `PW_WINE_SERVICE_FIXTURE=1`. The existing 14-module checker remains required;
   its exact PE set contains 22 patched DLLs, including x64 wow64 and wow64win.
5. Build the distinct full-CRT service child, using unchanged app_crt and the
   high-address native layout. Its service-only converter copy adds a relocated
   pointer to the preload mask. The ordinary worker modes keep their original
   converter path.
6. Initialize a sterile host prefix through the existing `pw_install`
   create-prefix operation. Only Wine initialization runs here. The original
   parent/child diagnostic is added after the initialization audit and is never
   executed by the Linux producer.
7. Convert through the existing `pw_prefix` filesystem seam, then substitute
   all 22 matched PS5 PE DLLs with explicit before/after records. Check that all
   other exported files, directories and modes are unchanged, and recheck the
   selected ntdll/win32u private ABI. Assemble only after title, child, runtime,
   prefix, fixture and source identities agree.

The source cohort comparison includes actual staged source bytes. Equal Git
index trees alone are insufficient because the normal staging script modifies
tracked Wine files after patch application. The fresh reference contains the
same expected edits and the explicitly staged PS5-only bridge files.

## Full-CRT child and title records

`tools/build_wine_service_child.py` consumes:

- `--work`: the clean committed project checkout
- `--sdk`: the SDK under title foundation 9c0b994
- `--foundation`: converter foundation 3059751
- `--runtime`: the freshly checked Wine work directory
- `--llvm-bindir`: the actual SDK-selected LLVM 18 directory
- `--out`: a new owned child-output directory

The output `native-wine-child-build.json` uses `pw-wine-service-child/1`. It binds
the project, input sources, unchanged CRT/layout, ordinary libc/kernel stubs,
compiler/SDK, exact ntdll PRX, linked/converted/recovered bytes, import NIDs and
provider ranks, and preload metadata before signing and after recovery. The
entry must be the real `_start`; unwind metadata must exist. Unsupported data
imports, providers, relocations, raw trap instructions and undecoded analyzer
output fail.

The generated `wine-child-build.h` supplies the child's input-derived build ID
and expected ntdll hash, plus the checked `PW_WINE_CHILD_WOW64_ABI=1`. The separate `native-wine-child-build.h` supplies the
title with that ID and the final SELF hash/size, avoiding a circular build ID.

The `--check-title` operation additionally takes `--build`, `--app`,
`--service-work`, `--sdk-source-archive` and `--fixture`. Its
`native-wine-child-title.json` record requires the actual compiled project
identity, exactly one matching embedded child image, the four ordinary
SystemService bindings and the reviewed fixture-route marker/functions. It also
validates the original MSVC pair and requires the exact child PE SHA256 as a
standalone read-only title literal, matching the pre-compilation input record. Those
static facts do not establish that either route works on a console. The child
manifest lists AMD64 fixture and translated-I386 installer candidate modes
separately, with `runtime_validated:false` for both.

## Experimental translated-I386 admission

The target build enables both `PW_WINE_PRIVATE_DISPATCH=1` and
`PW_WINE_SERVICE_FIXTURE=1`; the full host Wine used for initialization enables
neither. Before `wineboot`, the installed host AMD64 ntdll/win32u thunks must
match the normal OFF contract. That check is retained in each exported prefix
report. The exact final ordered patch series is recorded; a previous source
checkpoint is not substituted for the final provider and WoW64 patches.

The translated-I386 checker compiles an inert host reader using the exact staged
pure validator header. It reads ordinary allocated byte buffers, checking actual
i386 ntdll/win32u thunk operands, module-local writable zero dispatcher slots and
HIGHLOW relocation coverage. It also checks the new native return-1 FUNC, the
actual relocated PRXDESC1 entry, preserved converted/SELF code bytes, and the
source/flag-bound private wow64 translator selection. The separate same-source
CPU producer binds its actual compiler, consumed Wine tools/headers/libraries
and `wowprospero.dll`; the runtime binds `wowprospero.prx`. No target instruction
is executed by these checks.

The second prefix is independently initialized and audited. It is not cloned
from the fixture prefix. Its fixed profile uses `battlenet-experimental-v1`,
`C:\installer\Battle.net-Setup.exe`, working directory `C:\installer`, `pe32`,
`wine-wow64`, `graphics=auto`, and `[runtime] cpu=translator`, with no arguments.
Because the installer is absent, this explicit profile template is tested by
the existing native profile parser; the normal installer profile generator
cannot truthfully derive an absent executable's architecture. The existing
`pw_install` create-prefix and `pw_prefix` conversion operations remain in use.
The exported installer directory must be empty. The consumer can later copy the
operator's supplied PE32 installer there after its own admission checks.

`provenance/battlenet-capability.json` binds the exact runtime check, CPU bytes,
profile and prefix report, with `installer_included:false` and
`runtime_validated:false`. `provenance/battlenet-prefix.json` retains the complete
second inventory and all22 PE substitutions. The top-level package manifest
admits the optional Battle roles only when these checks succeed.

## Prepared prefix and archive paths

The prepared profile is
`console/data/prospero-win/profiles/windows-child-fixture-v1.profile`.
Its prefix is
`console/data/prospero-win/prefixes/windows-child-fixture-v1`.
The application is `C:\windows-child-fixture\parent.exe` with working directory
`C:\windows-child-fixture`; it uses `wine-wow64`, `pe64` and `graphics=auto`.
The pair in `drive_c/windows-child-fixture` consists of identical original PE
bytes. This fresh slug does not replace an existing profile index.

The normal app location is `PPSA99995`, with:

- `eboot.bin`
- `native-wine-child.self` and `native-wine-child-build.json`
- `win/wine` containing the matched runtime, NLS and fonts
- the existing libc companion and pinned Lapy helper

The archive also contains `BUILD-INFO.txt`,
`provenance/windows-child-fixture.json`,
`provenance/private-dispatch-abi.json`, complete corresponding source/notices
and a SHA256SUMS covering all regular members except itself. Prefix symbolic
links are represented by the existing `.pw-symlinks` tables; the final archive
has no filesystem symlinks.

All assembly inputs and outputs must be stable owned directories with no
concurrent writers. Existing output paths and symlink destination parents are
refused. The prefix audit retains the reviewed strict generated-module/resource
rules, six exact fonts, eighteen known font-path substitutions and seven exact
registry-header exemptions. Unknown files or host text stop export; failure
artifacts retain bounded audit metadata without raw prefix/registry contents.
A separate always-run collector retains produced target PE/PRX, linked/converted
child/title, SELF, object and selected provider bytes plus matching public source
archives/notices. It labels these artifacts unaccepted and records original
modes, hashes and any limit-based omissions. Its bounds are256MiB per file,
2GiB total and10,000 files; it never scans a prefix, home or installer tree.

No vendor installer, account state, game files or private host data belong in
this archive. The candidate package does not establish Battle.net or game compatibility,
working graphics, TLS, arbitrary Windows child-process support or cleanup of
every possible descendant. Console results must name this exact artifact and
the observed boundary rather than borrowing success from an earlier cohort.

## Selecting and stopping this candidate

This experimental title lists only the two exact prepared profiles. Select
the original fixture or `battlenet-experimental-v1` with the controller; retained
ordinary game profiles and a command-line executable override are refused.
The original headless fixture requires no keyboard or mouse. The installer
uses the normal root-title USB keyboard/mouse route; this candidate does not
add controller mouse bindings or forward child windows and input.

Native environment is checked before ntdll construction. Owner activation
follows successful module and working-directory setup. The generated fixture
SHA256 is actually passed to fixture admission and checked against the staged
original child bytes. The separate Battle profile keeps its user-supplied
installer outside the distributed archive.

Options+Create requests ordinary root close and cancels new native child work.
Replacement remains blocked until owned native lifetimes settle. The main
presentation loop continues during a close-timeout hold. A saved
`PW_WINE_CHILD host_held` record names a pre-guest owner preparation, provider
installation or thread-start failure when applicable. Once the supervisor has
started, a failure before Wine entry has no genuine root-detach receipt, so
this candidate conservatively holds instead of claiming successful teardown.
Stop at that boundary and retain the log; do not repeat the attempt within the
same title. A bounded protocol deadline does not guarantee a synchronous OS
service call returns, nor does it authorize release of uncertain ownership.

`bootstrap_ready` acknowledges native preparation before guest entry.
`first_failure` carries the first API, raw result and native error.
`root_release_safe` permits host replacement after settlement, including a
settled failed run; it is not the fixture's `automated_pass` or a claim that the
installer works. Child logs and the actual lowercase
`/data/prospero-win/logs/session-N.log` should be inspected before sharing.
