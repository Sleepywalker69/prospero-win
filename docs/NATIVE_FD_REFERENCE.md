# Original native descriptor reference

This separate, opt-in Linux test checks the source for a future PS5 descriptor
capability probe. It does not change the HELLO-only native title or enable a
Windows child provider. No Wine server endpoint, vendor program, credentials,
custom mapping, loader code or security-setting change is involved.

The original module uses ordinary AF_UNIX sockets and SCM_RIGHTS. The parent
queues a pipe-shaped socket writer onto another socket endpoint before handing
that endpoint to the worker. The worker consumes the queued writer and sends
known bytes to the parent. It then creates and returns another writer in the
reverse direction. EOF is checked after sender duplicates close. This mirrors
the nested descriptor shape that Wine startup needs, using synthetic endpoints
only. It does not establish that Wine startup works.

## Source and ownership contracts

`native/pw_native_fd_probe.c` contains no process launch, Wine calls, SceNet
descriptor use, libc startup, errno dependency or raw syscall trampoline.
Its platform headers define the actual socket and ancillary layouts. Linux
uses MSG_NOSIGNAL; the SDK's BSD branch uses its declared SO_NOSIGPIPE and
sockaddr_un.sun_len. Every negative OS return is terminal, including interrupted
calls and nonblocking readiness races. This can produce conservative failures.

The caller supplies an absolute monotonic deadline and optional Stop callback.
The module rejects clock reversal, checks expiry after I/O, and closes delivered
ancillary descriptors before reporting a post-receive failure. Malformed,
missing, extra, wrongly tagged or truncated rights are rejected. Cleanup keeps
the first failure, records cleanup failures separately and never retries close.

A pathname must be absent within a fresh caller-owned directory. The module
never deletes an existing path to make bind succeed. Only a successful bind
establishes ownership for later unlink. It does not create directories, change
permissions or authenticate another actor. The PID/challenge exchange is
correlation only; `peer_identity_verified` remains zero. Parent-local and
peer-reported observations have distinct result fields.

## Explicit hosted reference

The `Original native descriptor reference` workflow runs only by manual dispatch
or the `test-native-fd-capability` label on a same-repository PR. It builds and
runs the actual original source on Ubuntu 24.04 with GCC and with Clang 18
ASan/UBSan. Each execution has a 20-second outer deadline and a two-second
forced-stop grace period; failures, missing
capabilities and timeouts cannot become a successful test result. Compiler
output, original source, exact exit status and hashes are retained.

The fixture covers distinct host PIDs, queued and reverse descriptor transfer,
known bytes, EOF, wrong correlation, extra/missing/wrong-tag/truncated rights,
unexpected rights on byte-only messages, timeout, cancellation, clock errors,
clock reversal, nonexistent paths and preservation of an existing file. It
checks descriptor counts in its controlled low descriptor range and waits for
its own original host children.
Those host-process results do not describe the PS5 loader's child ownership.

In an independently permitted Linux environment, the equivalent commands are:

    cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic \
      tests/fixtures/native_fd_capability.c -o /tmp/native-fd-reference
    timeout --kill-after=2s 20s /tmp/native-fd-reference

These runtime checks are deliberately outside `make test`: socket/process
permissions are an explicit requirement. A prior attempt in the restricted
development VM stopped with EPERM and is not a passing result. It must not be
repeated there or worked around. Actual SDK headers compile the module with a
PS5 target, but target compilation also does not prove runtime availability.

Default host checks run a separate pure mock suite. It replaces every socket,
descriptor and process boundary before including the real module, and covers
both roles, fragmented frames, cleanup, Stop/deadline boundaries and malformed
ancillary lengths. This structural coverage makes no runtime-capability claim.

## Remaining console and Windows gates

The [native HELLO probe](NATIVE_CHILD_PROBE.md) remains the first console
checkpoint. A separate future FD mode would need a fresh owned path, matched
worker/title artifacts, a bounded result frame and retained results from both
processes. Ordinary descriptors and SceNet socket IDs must never be interchanged.
Console namespace visibility, cross-context rights transfer and wrapper behavior
remain untested. No descriptor stage is wired into the title by this change.

A passed Linux reference cannot authorize or authenticate a real Wine endpoint.
Windows children additionally require one authoritative Wine server/startup
handshake, process-local dispatcher state, correct shared-section backing,
child-local thread control and owned-child shutdown before title restart.
Closed channels and peer reports are not native death/reap evidence. Existing
unsupported-process guards remain intact.

Public contracts: [SCM_RIGHTS ancillary data](https://pubs.opengroup.org/onlinepubs/9799919799/functions/recvmsg.html),
[socket descriptor transfer](https://pubs.opengroup.org/onlinepubs/9799919799/functions/sendmsg.html),
and [the pinned public SDK](https://github.com/ps5-payload-dev/sdk/tree/v0.42).
