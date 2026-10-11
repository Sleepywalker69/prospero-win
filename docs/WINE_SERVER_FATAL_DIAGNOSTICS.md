# In-process Wine server fatal diagnostics

Patch `0920-server-fatal-output-sink.patch` forwards fatal server messages into
ntdll's already installed title-output sink before the original `exit(1)`.
It is diagnostic-only: it does not change readiness, filesystem permissions,
helper requests, service ownership, child bootstrap, or exit status.

## What to look for

After loading the in-process server, before its first initialization call,
ntdll records `wine startup: server fatal sink installed`. If the server lacks
the setter or refuses it, ntdll records `server fatal sink unavailable` and
continues through the existing startup path. An unavailable sink is not a
successful diagnostic run. The matched PRX descriptor exports the setter.

The installed route does not use fd 1, fd 2, a socket, a Wine server request,
or a new allocation. It calls the existing title log callback. A typical
record is:

```text
wineserver: fatal errno_valid=1 errno=1 truncated=0 message=lstat /data/prospero-win/prefixes/example/.wineserver
```

`errno_valid=1` means the value was saved immediately after an errno-bearing
operation in the covered startup paths. The decimal value is native errno;
it is not a Windows error or evidence of a particular privilege state.
The covered operations are the `create_dir` and `create_server_dir` filesystem
failures, initial in-process socketpair, and wake pipe. Logical fatal errors
(and other existing callers of `fatal_error`) use `errno_valid=0 errno=0` so
that an unrelated stale errno cannot be mistaken for the failed operation.
Their original diagnostic message is still preserved, subject to the bound.

The operation and path are passed as data, including percent signs. Embedded
CR/LF become spaces so one fatal emits one record. A stack-only 768-byte message
buffer bounds path/text content. `truncated=1` identifies truncation or a
formatting failure; the latter emits `<format-error>`. The numeric errno is
outside that message buffer and remains intact. The callback is installed
once, permits an idempotent repeat of the same sink, and refuses replacement.
No callback points into temporary storage. Concurrent setter calls cannot
publish a partial pointer. Callback/formatting errno changes are restored
before the original `exit(1)`. When no sink is installed, ordinary stderr
formatting remains available, also preserving the original errno.

## Verification

Run `python3 tests/test_wine_server_fatal.py`. It compiles the actual added
production patch bodies and tests the sink, complete ntdll bridge, errno
preservation, fallback stderr, exit status, missing/refused sink, long paths,
formatting failure, CR/LF, percent-sign data, and concurrent installation.
The normal aggregate invokes this test. `--wine-source PATH` additionally
requires the tested blocks to equal an already composed Wine tree;
`--output PATH` retains the exact extracted C and a test receipt.

A host pass establishes these source-level contracts, not PS5 execution or a
confirmed explanation of the observed root exit. A console result needs the
matched ntdll/server/title cohort, the installed marker, and the fatal record.
An exit without that record remains unresolved. Fatal signals, aborts, failures
inside module constructors before sink installation, and lost title logging
are outside this diagnostic's guarantee.
