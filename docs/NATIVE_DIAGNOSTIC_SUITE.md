# Native diagnostic suite

This optional native-only title has three independently selectable tests after
successful title startup. It does not run Windows programs. The four added
SystemService imports are resolved when the title loads, so their availability
is a startup gate for the combined title. Keep the earlier peer-only archive as
a rollback checkpoint. All packages use title ID `PPSA99995`; they do not install
as automatically independent applications.

Use the exact reviewed suite artifact and its `BUILD-INFO.txt`, checksum inventory
and `provenance/native-probe-suite.json`. The application directory contains
`eboot.bin`, `native-child.self` with `native-child-build.json`, and
`native-service.self` with `native-service-build.json`. Each helper is built from
original source and has a separate build identity. Preserve the complete archive
for the corresponding sources, dependency recipes, licenses and inspection data.

Select with the controller D-pad or keyboard arrows; Cross/Enter starts one
attempt. Square/Escape requests cancellation. A controller is sufficient.
Options shows the saved-log location. The actual directory is lowercase
`/data/prospero-win/logs` (for example `session-N.log`); use that spelling for FTP
even if the UI displays `LOGS`. The title stays on the menu and records
successful UI presentation ticks while the background test owns its work.

1. `SOCKET API MATRIX` collects ordinary API observations on fresh unused AF_UNIX
   stream sockets, AF_UNIX stream pairs, AF_INET stream sockets and AF_UNIX
   SEQPACKET pairs. Each topology uses a fresh descriptor set for each of three
   nonblocking methods: preserved-flags F_SETFL, FIONBIO, and SO_NBIO. SO_TYPE,
   F_GETFD, F_GETFL, FIOCLEX and before/after SO_NBIO reads are recorded. There is
   no bind, listener, connection, traffic or launch in this test. Collection
   completion does not mean every call worked or prove nonblocking I/O.
2. `SERVICE CHILD (HEADLESS)` makes at most one own-application service launch
   with the fixed packaged service helper. It exchanges fixed 96-byte packets,
   checks three echoes and a cooperative STOP acknowledgement, closes its owned
   endpoints, then observes the returned service ID. The worker uses inherited
   fd3, has its own entry deadline and requests exit after completion. Native
   PID/PPID, app ID and service ID are separate facts. No OS-parentage equality,
   native exit code, native reaping or Windows-child support is inferred.
3. `LEGACY PEER / EXIT` runs the existing elfldr-based peer/exit probe with the
   separate peer helper. Its credential, fresh nonce and kernel-event acceptance
   are unchanged. A submitted image without a complete successful bound exit
   observation prevents further suite attempts. See [the original probe
   contract](NATIVE_CHILD_PROBE.md) for its detailed limits.

Each test can be attempted once per title process. A running test excludes other
selections. Cancellation never closes a descriptor from the UI thread. An
ordinary unsupported result with settled ownership can leave unused tests
selectable. Any uncertain descriptor or child cleanup locks the entire menu;
retain the log and stop testing. There is no automatic retry or title restart.

## Reading the records

`PW_SOCKET_MATRIX` reports collection status, counts and cleanup uncertainty.
Each `PW_SOCKET_ROW` records case, topology (0–3 in the order above), method
(0–2), operation, attempted/skipped state, raw return and immediate error
validity. Getter rows include input capacity, returned length, all four before
and after buffer bytes, signed and hexadecimal value, unchanged sentinel and
length/control matches. Successful calls do not inherit stale errno. Failed
controls stay visible and never enable the operational peer test. F_SETFL is
skipped if that case's own baseline F_GETFL failed.

Operation numbers are create0, SO_TYPE1, baseline GETFD2/GETFL3/NBIO4,
FIOCLEX5, post-CLOEXEC GETFD6, selected setter7, final GETFL8/NBIO9 and close10.
Disposition0 means attempted; disposition1 means F_SETFL skipped because the
baseline GETFL was unavailable. The 32-bit getter is always shown both signed
and as exact hexadecimal bytes; an unchanged sentinel is not a true result.

The matrix has a five-second monotonic budget, at most 138 native descriptor
calls, 160 rows and two live owned descriptors. Stop, expiry and clock failure
prevent the next call except exact-once cleanup. Failed socketpair output
integers do not establish ownership and are never closed as if they did. Close
failure is uncertain and is never retried by descriptor number. Rows are logged
locally after descriptor cleanup, without the network logging lock or sends.
Local storage and synchronous platform calls can still take time to return.

`PW_SERVICE_PROGRESS` is a phase observation. `PW_SERVICE_FINAL` contains the
actual returned verdict after the final clock/cancellation check; an earlier
DONE progress record cannot override it. `PW_SERVICE_APP` retains raw app status
words, validity controls, list and kill outcomes. `PW_SERVICE_PATH` alias0 means
`/app0/native-service.self`; alias1 means the existing fixed sandbox alias
`/mnt/sandbox/PPSA99995_000/app0/native-service.self`. Both are checked against the
complete embedded worker bytes before dispatch. A readable mismatch refuses
launch. The first matching alias is selected before one service call; a failed
launch never causes an alternate-path retry. File preflight does not establish
the service's path namespace or eliminate later path changes. Build-ID and
correlation checks establish fixture consistency, not cryptographic image
authentication.

`PW_SERVICE_PACKET` retains ordinary packet return/error and ancillary cleanup
facts. `PW_SERVICE_PROTOCOL` reports native PID/PPID, echoes, STOP acknowledgement
and UI ticks. A zero receive with hangup and no end-of-record is a limited
channel observation. It is not native death. Complete-list absence retires the
owned service ID permanently, but is not a native wait/reap result. Absence
before validated HELLO remains inconclusive asynchronous startup. Without HELLO,
a bootstrap, inherited-fd3 or type-check failure cannot be distinguished from
other early termination by these parent records; do not infer a permission error.

The service attempt has one 15-second protocol endpoint and one 20-second outer
endpoint derived before preflight and launch; cleanup uses only the remaining
reserved time. This bounds protocol work, not the return time of an undocumented
synchronous service call. Unknown app/list output, zero/negative/duplicate launch
ID or a full list is refused or marked uncertain. Cleanup never targets a
reported native PID, baseline service ID or retired ID. One forced kill of the
still-observed owned ID may be attempted; forced cleanup cannot report
cooperative success. Generation-safe service IDs and the list-to-kill race are
not established by the available public interface.

## Build and evidence

The opt-in `build-native-diagnostics-suite` label, or workflow mode `suite`,
produces `native-diagnostics-suite.tar.gz`. Existing hello/FD/peer modes retain
their separate artifacts. The service-only converter source copy stores the
headless preload mask behind the correct relocated process-parameter pointer.
The build checks exact libkernel worker imports, entry/unwind/disassembly,
preload metadata before and after signing, reconstructed SELF bytes, embedded
images, title service-provider imports and package identities. A separate build
of the same default peer inputs must produce matching linked, converted and
SELF bytes. These are build checks; firmware support still requires the exact
console observations from each selected test.

The service ABI and preload layout are based on the pinned public
[RetroArch service caller](https://github.com/mihawk-99/PS5_RetroArch/blob/e98cca409ce8cd1dd77d4863e691b922cc95e608/frontends/child-probe/child_probe.c)
and its converter. This suite's implementation and tests are original. Its
finite fd3 helper differs from the reference's indefinitely idle helper, so
self-exit and cleanup remain independent hardware gates. No privilege,
credential, permission, kernel or security-setting change is performed by a test.
