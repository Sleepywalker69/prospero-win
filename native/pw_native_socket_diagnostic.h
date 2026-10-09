/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_NATIVE_SOCKET_DIAGNOSTIC_H
#define PW_NATIVE_SOCKET_DIAGNOSTIC_H
#include <stdint.h>

enum { PW_SD_MAX_ROWS = 160, PW_SD_MAX_CALLS = 138, PW_SD_BUDGET_MS = 5000 };
enum { PW_SD_UNIX_STREAM, PW_SD_UNIX_PAIR, PW_SD_INET_STREAM, PW_SD_UNIX_SEQPACKET_PAIR };
enum { PW_SD_FCNTL, PW_SD_IOCTL, PW_SD_SOCKOPT };
enum { PW_SD_CREATE, PW_SD_TYPE, PW_SD_GETFD_BEFORE, PW_SD_GETFL_BEFORE,
       PW_SD_NBIO_BEFORE, PW_SD_CLEX, PW_SD_GETFD_AFTER, PW_SD_SET_NONBLOCK,
       PW_SD_GETFL_AFTER, PW_SD_NBIO_AFTER, PW_SD_CLOSE };
enum { PW_SD_OK, PW_SD_CANCELLED, PW_SD_TIMEOUT, PW_SD_CLOCK,
       PW_SD_LIMIT, PW_SD_OWNERSHIP, PW_SD_INVALID };
enum { PW_SD_EXECUTED, PW_SD_SKIP_GETFL };

typedef struct {
    unsigned case_id, topology, method, operation, disposition;
    int descriptor, companion, input_value;
    int64_t raw_return;
    unsigned errno_valid;
    int native_error;
    unsigned has_buffer, input_length, output_length;
    unsigned char input_bytes[4], output_bytes[4];
    int32_t output_value;
    uint32_t output_hex;
    unsigned buffer_unchanged, length_matches, type_control_matches;
} PwNativeSocketDiagnosticRow;

typedef struct {
    void *context;
    int (*clock_ms)(void *, uint64_t *);
    int (*cancelled)(void *);
} PwNativeSocketDiagnosticContext;

typedef struct {
    unsigned status, collection_complete, cleanup_uncertain;
    unsigned rows, native_calls, cases_started, cases_finished;
    unsigned failed_calls, malformed_readbacks, skipped_setters;
    uint64_t started, last_clock, deadline;
    PwNativeSocketDiagnosticRow row[PW_SD_MAX_ROWS];
} PwNativeSocketDiagnosticResult;

/* Parent-only, original no-traffic diagnostic on fresh owned sockets.
 * A completed collection is not proof of nonblocking I/O or peer capability.
 * No result may be used to bypass the separate operational peer predicate. */
int pw_native_socket_diagnostic_run(const PwNativeSocketDiagnosticContext *,
                                   PwNativeSocketDiagnosticResult *);
#endif
