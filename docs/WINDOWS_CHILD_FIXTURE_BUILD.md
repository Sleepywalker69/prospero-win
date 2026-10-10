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
   the existing owned-source staging commands. Build host tools and the pinned
   public SDK/converters/TLS prerequisites, then compile the complete
   experimental target units before starting the full host runtime.
4. Build full host Wine and retain its source checkpoint. Build and check the
   complete private-ON Wine PE/PRX cohort with `PW_WINE_SERVICE_FIXTURE=1`.
   The existing 14-module checker remains required; its exact PE set contains
   22 patched DLLs, including x64 wow64 and wow64win.
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

The workflow first builds Wine's existing host-tool target and compiles the
complete experimental target translation units before the full host runtime.
`build_host_wine.sh --tools-only` and `build_wine_ps5.sh --compile-check` emit
explicit partial-stage records; neither produces or validates a complete
runtime. The later full build, prefix and artifact checks remain mandatory.
Build concurrency is capped at four only when at least four CPUs and 12 GiB of
available memory remain after finite cgroup limits; smaller runners use at most
two jobs. The measured resources and chosen limit are retained in the evidence.

## Full-CRT child and title records

`tools/build_wine_service_child.py` consumes:

- `--work`: the clean committed project checkout
- `--sdk`: the SDK under title foundation 9c0b994
- `--foundation`: runtime PRX foundation 3059751 and its pinned zlib build
- `--runtime`: the freshly checked Wine work directory
- `--llvm-bindir`: the actual SDK-selected LLVM 18 directory
- `--out`: a new owned child-output directory

The output `native-wine-child-build.json` uses `pw-wine-service-child/1`. It binds
the project, input sources, unchanged CRT/layout, ordinary libc/kernel stubs,
compiler/SDK, exact ntdll PRX, linked/converted/recovered bytes, import NIDs and
provider ranks, and preload metadata before signing and after recovery. The
child uses the high-address executable converter from title foundation 9c0b994,
with only the two service preload edits. Its `converter_foundation` and source
hashes identify that selection; `prx_foundation` separately identifies the
runtime converter and retained source archive. The converter's existing
high-address LOAD mapping and strict `.data.rel.ro` requirement are preserved.
The zero-based probe converter retains its original source selection. The
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


## Native launch failures and service paths

A nonpositive `sceSystemServiceAddLocalProcess` result is a failed dispatch,
not evidence that the startup deadline expired. The owner preserves the raw
platform result before closing its passed descriptor. The Windows caller
receives a generic unsuccessful status; an observed cancellation still takes
priority and a genuine deadline without a failed dispatch remains a timeout.
The first-failure record remains first-publisher-wins across concurrent failures.
A rejected call does not prove that no native resource was created: uncertainty
still blocks replacement and there is no automatic second launch.

The parent verifies the exact helper bytes using either known readable alias.
The service call and `argv[0]` always use `/app0/native-wine-child.self` with the
checked owning application ID. A readable global sandbox alias is not assumed
to be a valid service launch path. The `launch_path` record carries the parent
read-alias index and the service-path index (always zero); the final cancellation
and deadline check follows that diagnostic callback and precedes dispatch.
The public [PS5 child-probe caller](https://github.com/mihawk-99/PS5_RetroArch/blob/33d61f4ddff906e0ca8584b7af74278e0459b451/frontends/child-probe/child_probe.c)
also uses `/app0` with this service API. Acceptance of this full-CRT helper from
an elevated parent remains a console test, not a consequence of the host mocks.

## Compiler-cache comparison

The Linux producer starts alongside `original-x64-reference`, with the same
trusted trigger and a separate workspace. It checks that the Windows job in the
exact run and attempt succeeded before the expensive complete host Wine build.
The artifact is downloaded and checked again immediately before its first use
in prefix export. The join uses the attempt-specific Actions jobs endpoint,
refuses incomplete or ambiguous responses, and has a 15-minute absolute budget.
The downloaded fixture must still match the current commit, tree, source and
recipe bytes, run ID, attempt, PE hashes and successful Windows reference.
Rerun the whole workflow when a new attempt needs a new Windows reference;
a Linux-only rerun cannot consume a previous attempt's fixture.

Only compiler results are cached. Each run freshly stages/configures Wine,
links, installs, creates its own prefixes and runs every artifact checker.
The MSVC recipe, host `make -j2 all`, `make sanitize`, and native i386 comparison
remain mandatory. TLS, SDK/foundation preparation, direct SDK adapter and
FreeType compilation, CPU packaging and title compilation are outside this
compiler cache.

Host Wine uses explicit Clang and MinGW launchers. PS5 Wine uses the SDK launcher
for Makefile-owned Unix units and explicit MinGW launchers for PE units. Their
triple-bearing names preserve Wine's compiler-target detection; no global
compiler masquerade changes SDK/TLS provider selection. Ccache uses content
checks, normal header validation, no sloppiness, and no hard links. A separate
fresh-cache control compiles original C twice through the actual SDK dispatcher,
requires a cold miss and warm hit, and compares the two object hashes without
executing target code. It runs before the complete host build.

The two Actions keys have no fallback restore keys. They bind the Wine pin,
ordered patches and staged sources, build/staging/cache recipes and workflow,
compiler versions and bytes, backend tools and resources, system/target headers,
installed package versions, flags and feature modes. The PS5 key also binds the
SDK and TLS inputs. Linked header directories are hashed through their real
targets, with cycle refusal. Project commit/tree, per-run compiler statistics,
Windows fixture metadata and runtime acceptance records remain fresh evidence
outside the cache. Only `RUNNER_TEMP/ccache-host` and `RUNNER_TEMP/ccache-ps5` are
uploaded by the cache actions, after their corresponding full build/check stage.

For the cold/warm hosted comparison, keep the same reviewed commit and run the
full workflow twice. Preserve the two run URLs and exact fixture identities.
Use `fixture-evidence/ccache-{host,ps5}/state.json`, `compatibility.json`, each
stage's JSON/config/stats files, and `ccache-sdk-control/RESULT.json` to distinguish
an Actions archive restore from real compiler hits. Stage records include the
requested key, restored key/status, command exit and elapsed time, direct plus
preprocessed hits, misses, hit rate and cache size. Actions step timings/logs
provide cache upload/download overhead; compare total job wall time as well as
compiler stages. A restored cache never substitutes for a missing build or
checker pass, and a statistics failure retains the original command outcome.

Fresh MSVC output and its embedded child hash can differ across runs, so compare
each archive against its own fixture/provenance records. Do not infer runtime
compatibility from cache hits or require unrelated complete archives to have
identical bytes. No hosted speedup is claimed until the cold and warm jobs and
all their normal checks have completed.

## Child bootstrap diagnostics

Before Wine entry, a matching child `FAILURE` retains the failing operation,
its raw result and immediate native errno when available. The parent's
`bootstrap_failure` event carries those three fields;
`bootstrap_failure_value` carries the two auxiliary values and `errno_valid`.
Operation IDs are defined in `native/pw_wine_child_wire.h`, starting at `0x100`
to distinguish them from the existing socket diagnostics. Directory failures
identify the required prefix or working directory; runtime failures identify
the attempted fixed runtime root. A permitted unreadable alias does not turn
an otherwise successful runtime selection into failure. Validation failures
do not invent an OS error.
The single final pre-Wine failure send can proceed when this child's logger
failed. It retains the original deadline and clock history, respects external
cancellation and earlier transport errors, and never retries uncertain delivery.

After a failed log-file open, the child makes at most one read-only `stat` of
`/data`, within its existing startup budget. The auxiliary fields distinguish
a visible directory, a non-directory, a failed `stat` with its own errno, or
an unavailable observation. This observation never replaces the original
log-open error, requests access, or retries the open. Parent access does not
establish the child's filesystem view. A missing child log alone therefore
cannot establish an access-denied or missing-directory diagnosis.

Where service cleanup is permitted, a nonzero `kill_return` is a cleanup
observation, not the bootstrap cause or proof that the child remains alive.
The ownership-uncertainty hold remains in force; no error code is treated as a
retirement receipt. Child-local data readiness adds the stricter pre-ACK hold
below, which prevents automatic cleanup of a possibly helper-targeted PID.

### Experimental child data readiness

The experimental native child checks `/data` after its session-bound BOOTSTRAP
and before creating a log or any Wine thread. Reuse requires both `stat` and
`lstat` to successfully observe a directory. Visibility from `stat` alone does
not skip the helper. The original log, prefix, CWD, runtime hash and ABI checks still run;
a later refusal never triggers a helper fallback.

If `stat` observes a directory or reports `ENOENT`, and `lstat` reports
`EPERM`, the child uses the same pinned one-shot
[Lapy helper release](https://github.com/mpereiraesaa/PS5-Lapy-JB-Daemon/releases/tag/v0.3.2-experimental)
already packaged by the title. Paired `stat`/`lstat` `ENOENT` also preserves
the original missing-directory helper path. It requests only its own PID and the existing
filesystem capability, and performs the existing local PREPARE operation in that
child. The distinction is supported by [upstream PR423](https://github.com/mpereiraesaa/prospero-win/pull/423):
`stat` may see `/data` while `lstat` returns `EPERM`. Other `lstat` errors,
non-directory results, and contradictory failed `stat` observations remain
explicit refusals. A successful `lstat` is not a privilege or prefix-access proof. The helper's title, one-thread and credential checks remain authoritative.
Status 7 alone does not identify which admission check refused the request.
The phase/status interpretation is bound to helper source contract
`b48b7d7236eca25c7b9dfd6c040c763ae05dde80`; the report explicitly makes no
source-to-binary reproducibility claim. The child hashes one bounded heap buffer
and uploads those exact bytes, after matching the packaged helper pin. It does
not hash and then reread a changing file.

Net is resolved after HELLO using the pinned SDK's ordinary module route:
`/system/common/lib/libSceSysmodule.sprx`, internal Net ID `0x8000001c`, and
successful `sceNetInit() == 0`. Modules remain loaded for the process lifetime.
The static child graph remains libc/kernel and the existing preload mask. The
builder separately verifies the SDK providers' 12 required function exports;
this is not proof that console firmware loads or initializes them successfully
inside this service. No helper request is sent after a failed resolution/init.
SceNet socket IDs and inherited native fd3 stay in separate descriptor domains.
Once data readiness observes a parent-control refusal, it suppresses the final
diagnostic send too, even when an earlier operation remains the primary error.

Before sending BOOTSTRAP, the owner logs `helper_possible` and latches possible
helper activity. Only the exact successful BOOTSTRAP_ACK clears that latch.
A pre-ACK refusal, cancellation, timeout or ambiguous transfer logs
`helper_unsettled` and permanently holds ownership, with no Kill or automatic
title restart. This intentionally also holds some conclusively refused children.
The child keeps its PID alive if a request might have reached the helper but no
recognized terminal response arrived. Closing a socket cannot recall remote
work. A terminal response means the pinned helper finished its synchronous
request, not that every failure restored access successfully. Status 8,
wrong-phase responses and contradictory OK after local PREPARE failure stay
unknown. The original 30-second deadline bounds admission to Wine; it cannot
prove remote helper work stopped. Successful helper use requires actual data
directory observations from both calls and the full measured 1,000 ms settle
inside that original deadline. After helper success, the same denied/absent
pairs may continue the existing bounded visibility polling; other errors remain
refusals.

The child log records `PW_WINE_CHILD_DATA` with `attempted`, `possible_apply`,
`terminal`, `data_before`, `data_after`, `settled_ms`, `lstat_before`,
`lstat_after`, and the raw return/errno of each observation. The
`observations_before/after` masks distinguish an actual sample (mask value1 for stat,
value2 for lstat) from an unobserved zero. Here `attempted` means one readiness
invocation; `possible_apply` marks possible helper-request delivery.
A reused directory has `data_before=1`, `lstat_before=1` and
`possible_apply=0`; its after-observation mask stays zero because no second
probe is invented. Terminal helper
success has `possible_apply=1`, `terminal=1`, `data_after=1`, `lstat_after=1` and a settle of at
least 1,000 ms. Neither record nor BOOTSTRAP_ACK proves Windows startup success.

FAILURE packets keep wire version 2 and 136 bytes. Data readiness uses stage 12
and the operation values starting at `0x200` in `pw_wine_child_data.h`. On every
bootstrap FAILURE, `returned_length` bits 16–21 hold possible-apply, terminal,
data-before, data-after, successful-directory-lstat-before and
successful-directory-lstat-after flags; its low 16 bits preserve the existing
operation auxiliary. `returned_value` retains the operation detail: CONTROL
uses the exact native poll revents mask, RESOLVE uses the following fixed index,
and other data operations use the observed helper status. Raw return and
immediate errno remain separate. Resolution indices are 1 Sysmodule load,
2 Sysmodule handle query, 3 NetInit, 4 NetSocket, 5 NetConnect, 6 NetSend,
7 NetRecv, 8 NetSetsockopt, 9 NetSocketClose and 10 NetErrnoLoc.

The compiler manifest binds the exact helper ELF, release record, helper
manifest, protocol, generated hash and dynamic SDK provider bytes. Title and
archive checks compare the packaged helper and retained metadata to that child
binding. Host controls mock native/filesystem/transport boundaries; they do not
execute the helper or establish service-console admission. A held result needs
manual recovery and remains inconclusive, never an automatic compatibility pass.
