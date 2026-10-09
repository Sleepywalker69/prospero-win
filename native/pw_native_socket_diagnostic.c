/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_native_socket_diagnostic.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

/* Ordinary PS5 socket option used by the pinned public native examples;
 * SDK v0.42 does not declare SO_NBIO. Runtime semantics are observations. */
enum { PW_SD_SO_NBIO = 0x1200 };
_Static_assert(CHAR_BIT == 8 && sizeof(int) == 4 && sizeof(socklen_t) == 4,
               "diagnostic records use the reviewed target integer ABI");

typedef struct {
    const PwNativeSocketDiagnosticContext *context;
    PwNativeSocketDiagnosticResult *result;
    unsigned case_id, topology, method;
} Run;

static int stop(Run *run, unsigned reason)
{
    if (!run->result->status) run->result->status = reason;
    return -1;
}

static int remaining(Run *run)
{
    uint64_t now;
    if (run->context->cancelled && run->context->cancelled(run->context->context))
        return stop(run, PW_SD_CANCELLED);
    if (run->context->clock_ms(run->context->context, &now) || now < run->result->last_clock)
        return stop(run, PW_SD_CLOCK);
    run->result->last_clock = now;
    if (now >= run->result->deadline) return stop(run, PW_SD_TIMEOUT);
    return 0;
}

static PwNativeSocketDiagnosticRow *row(Run *run, unsigned operation, int fd)
{
    PwNativeSocketDiagnosticResult *r = run->result;
    if (r->rows == PW_SD_MAX_ROWS) { stop(run, PW_SD_LIMIT); return NULL; }
    /* Reserve both cleanup calls before admitting another operation. */
    if (operation != PW_SD_CLOSE && r->native_calls >= PW_SD_MAX_CALLS - 2) {
        stop(run, PW_SD_LIMIT); return NULL;
    }
    PwNativeSocketDiagnosticRow *v = &r->row[r->rows++];
    v->case_id = run->case_id; v->topology = run->topology; v->method = run->method;
    v->operation = operation; v->descriptor = fd; v->companion = -1;
    return v;
}

/* Save errno before any clock, cancellation, logging or cleanup callback. */
static void returned(Run *run, PwNativeSocketDiagnosticRow *v, int rc, int error, int getter)
{
    v->raw_return = rc; v->errno_valid = rc < 0; v->native_error = rc < 0 ? error : 0;
    run->result->native_calls++;
    if (getter ? rc < 0 : rc != 0) run->result->failed_calls++;
}

static int flag_query(Run *run, int fd, unsigned operation, int command, int *value)
{
    if (remaining(run)) return -1;
    PwNativeSocketDiagnosticRow *v = row(run, operation, fd);
    if (!v) return -1;
    errno = 0;
    int rc = fcntl(fd, command, 0), error = errno;
    returned(run, v, rc, error, 1); *value = rc;
    return remaining(run);
}

/* Failed or malformed metadata is an independent observation. Only a
 * collection boundary stops subsequent no-traffic observations. */
static int option_query(Run *run, int fd, unsigned operation, int option, int expected_type)
{
    if (remaining(run)) return -1;
    PwNativeSocketDiagnosticRow *v = row(run, operation, fd);
    if (!v) return -1;
    int value; memset(&value, 0xa5, sizeof(value));
    socklen_t length = sizeof(value);
    v->has_buffer = 1; v->input_length = length;
    memcpy(v->input_bytes, &value, sizeof(value));
    errno = 0;
    int rc = getsockopt(fd, SOL_SOCKET, option, &value, &length), error = errno;
    returned(run, v, rc, error, 0);
    v->output_length = length; v->output_value = value;
    memcpy(&v->output_hex, &value, sizeof(value));
    memcpy(v->output_bytes, &value, sizeof(value));
    v->buffer_unchanged = !memcmp(v->input_bytes, v->output_bytes, sizeof(value));
    v->length_matches = length == sizeof(value);
    v->type_control_matches = expected_type && !rc && v->length_matches && value == expected_type;
    int malformed = !rc && (!v->length_matches || v->buffer_unchanged ||
                            (expected_type && value != expected_type));
    if (malformed) run->result->malformed_readbacks++;
    return remaining(run);
}

static int set_close_exec(Run *run, int fd)
{
    if (remaining(run)) return -1;
    PwNativeSocketDiagnosticRow *v = row(run, PW_SD_CLEX, fd);
    if (!v) return -1;
    errno = 0;
    int rc = ioctl(fd, FIOCLEX, (void *)0), error = errno;
    returned(run, v, rc, error, 0);
    return remaining(run);
}

static int set_nonblock(Run *run, int fd, int old_flags)
{
    if (remaining(run)) return -1;
    PwNativeSocketDiagnosticRow *v = row(run, PW_SD_SET_NONBLOCK, fd);
    if (!v) return -1;
    if (run->method == PW_SD_FCNTL && old_flags < 0) {
        v->disposition = PW_SD_SKIP_GETFL; run->result->skipped_setters++;
        return 0;
    }
    int one = 1, rc;
    v->input_value = run->method == PW_SD_FCNTL ? old_flags | O_NONBLOCK : one;
    errno = 0;
    if (run->method == PW_SD_FCNTL) rc = fcntl(fd, F_SETFL, old_flags | O_NONBLOCK);
    else if (run->method == PW_SD_IOCTL) rc = ioctl(fd, FIONBIO, &one);
    else rc = setsockopt(fd, SOL_SOCKET, PW_SD_SO_NBIO, &one, sizeof(one));
    int error = errno;
    returned(run, v, rc, error, 0);
    return remaining(run);
}

/* Cleanup is mandatory even after Stop/deadline. Never retry an uncertain
 * close or reuse a returned descriptor number after relinquishing it. */
static void dispose(Run *run, int *owned)
{
    if (*owned < 0) return;
    int fd = *owned; *owned = -1;
    PwNativeSocketDiagnosticRow *v = row(run, PW_SD_CLOSE, fd);
    errno = 0;
    int rc = close(fd), error = errno;
    if (v) returned(run, v, rc, error, 0);
    else run->result->native_calls++;
    if (rc || !v) {
        run->result->cleanup_uncertain = 1;
        stop(run, PW_SD_OWNERSHIP);
    }
    (void)remaining(run);
}

static void one_case(Run *run)
{
    int owned[2] = {-1, -1}, old_flags = -1, ignored;
    int pair = run->topology == PW_SD_UNIX_PAIR || run->topology == PW_SD_UNIX_SEQPACKET_PAIR;
    int type = run->topology == PW_SD_UNIX_SEQPACKET_PAIR ? SOCK_SEQPACKET : SOCK_STREAM;
    if (remaining(run)) return;
    PwNativeSocketDiagnosticRow *v = row(run, PW_SD_CREATE, -1);
    if (!v) return;
    run->result->cases_started++;
    errno = 0;
    int rc;
    if (pair) rc = socketpair(AF_UNIX, type, 0, owned);
    else { rc = socket(run->topology == PW_SD_UNIX_STREAM ? AF_UNIX : AF_INET, SOCK_STREAM, 0); owned[0] = rc; }
    int error = errno;
    returned(run, v, rc, error, !pair);
    v->descriptor = owned[0]; v->companion = owned[1];
    if (pair && rc) {
        /* A failed socketpair does not transfer ownership of output numbers.
         * They may name already-rolled-back or unrelated descriptors. */
        if (rc > 0 || owned[0] != -1 || owned[1] != -1) {
            run->result->cleanup_uncertain = 1; stop(run, PW_SD_OWNERSHIP);
        }
        owned[0] = owned[1] = -1;
        (void)remaining(run);
        goto cleanup;
    }
    if (pair && (owned[0] < 0 || owned[1] < 0 || owned[0] == owned[1])) {
        run->result->cleanup_uncertain = 1; stop(run, PW_SD_OWNERSHIP);
        if (owned[0] == owned[1]) owned[1] = -1;
        goto cleanup;
    }
    if (remaining(run) || owned[0] < 0) goto cleanup;
    if (option_query(run, owned[0], PW_SD_TYPE, SO_TYPE, type)) goto cleanup;
    if (flag_query(run, owned[0], PW_SD_GETFD_BEFORE, F_GETFD, &ignored) ||
        flag_query(run, owned[0], PW_SD_GETFL_BEFORE, F_GETFL, &old_flags) ||
        option_query(run, owned[0], PW_SD_NBIO_BEFORE, PW_SD_SO_NBIO, 0) ||
        set_close_exec(run, owned[0]) ||
        flag_query(run, owned[0], PW_SD_GETFD_AFTER, F_GETFD, &ignored) ||
        set_nonblock(run, owned[0], old_flags) ||
        flag_query(run, owned[0], PW_SD_GETFL_AFTER, F_GETFL, &ignored)) goto cleanup;
    (void)option_query(run, owned[0], PW_SD_NBIO_AFTER, PW_SD_SO_NBIO, 0);
cleanup:
    dispose(run, &owned[0]); dispose(run, &owned[1]);
    if (!run->result->status) run->result->cases_finished++;
}

int pw_native_socket_diagnostic_run(const PwNativeSocketDiagnosticContext *context,
                                   PwNativeSocketDiagnosticResult *result)
{
    if (!result) return -1;
    memset(result, 0, sizeof(*result));
    if (!context || !context->clock_ms) { result->status = PW_SD_INVALID; return -1; }
    Run run = {context, result, 0, 0, 0};
    uint64_t now;
    if (context->clock_ms(context->context, &now) || now > UINT64_MAX - PW_SD_BUDGET_MS)
        return stop(&run, PW_SD_CLOCK);
    result->started = result->last_clock = now; result->deadline = now + PW_SD_BUDGET_MS;
    for (run.topology = 0; run.topology < 4 && !result->status; ++run.topology)
        for (run.method = 0; run.method < 3 && !result->status; ++run.method) {
            run.case_id = run.topology * 3 + run.method;
            one_case(&run);
        }
    if (remaining(&run) || result->status) return -1;
    result->collection_complete = 1;
    return 0;
}
