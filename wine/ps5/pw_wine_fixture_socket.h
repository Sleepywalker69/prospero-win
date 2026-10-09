/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_WINE_FIXTURE_SOCKET_H
#define PW_WINE_FIXTURE_SOCKET_H
#include <stdint.h>
#define PW_WF_SOCKET_CLOEXEC 1u
#define PW_WF_SOCKET_NONBLOCK 2u
/* Ordinary socket option used by the public PS5 native callers and observed
 * on the original owned-socket matrix. SDK v0.42 does not name this option. */
#define PW_WF_SO_NBIO 0x1200

enum { PW_WF_SOCKET_ARGUMENT=1, PW_WF_SOCKET_TYPE, PW_WF_SOCKET_CLEX,
       PW_WF_SOCKET_NBIO_SET, PW_WF_SOCKET_NBIO_GET };
typedef struct PwWineFixtureSocketResult {
    int status, api, raw_result, native_error, errno_valid;
    uint32_t returned_length;
    int returned_value;
} PwWineFixtureSocketResult;
/* Only callers that already own a newly acquired ordinary stream may use
 * this operation. It never closes or substitutes the descriptor, and never
 * reads queued stream data. Caller owns all-path cleanup. */
int pw_wine_fixture_socket_prepare(int fd, unsigned flags, PwWineFixtureSocketResult *result);
typedef void (*PwWineFixtureSocketSink)(void *, const PwWineFixtureSocketResult *);
/* Install once before Wine threads. The sink must only record locally or
 * attempt one nonblocking control send; no wait/logging/server request. */
int pw_wine_fixture_socket_set_sink(PwWineFixtureSocketSink sink, void *context);
int pw_wine_fixture_socket_forward_sink(int (*install)(PwWineFixtureSocketSink, void *));
/* Immutable first failure snapshot. Returns1 only when a full record exists. */
int pw_wine_fixture_socket_failure(PwWineFixtureSocketResult *out);
/* Wine adapter: publish a failure and preserve its errno. No stdio/network logger. */
int pw_wine_fixture_socket(int fd, unsigned flags);
#endif
