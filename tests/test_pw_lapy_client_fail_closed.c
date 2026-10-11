/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Host-only, inert callbacks: no sockets, helpers, credentials or PS5 APIs. */
#include <stdio.h>
#include "pw_lapy_client.h"

struct mock {
    unsigned oversized, reads, frames, requests, prepared, cancels, prepare_calls;
    struct lapy_elevation_message request;
};
static unsigned failures;
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL line %u: %s\n", __LINE__, #condition); failures++; \
} } while (0)
static int remaining(void *context, int recovery, unsigned *left)
{ (void)context; (void)recovery; *left = 100; return 0; }
static long write_frame(void *context, const void *bytes, size_t size,
                        unsigned left, unsigned phase, int recovery, int *error)
{
    struct mock *m = context;
    (void)left; (void)phase; (void)recovery; (void)error;
    CHECK(size == sizeof(m->request));
    struct lapy_elevation_message frame;
    memcpy(&frame, bytes, sizeof(frame));
    if (frame.kind == LAPY_ELEVATION_REQUEST) { m->requests++; m->request = frame; }
    if (frame.kind == LAPY_ELEVATION_PREPARED) m->prepared++;
    if (frame.kind == LAPY_ELEVATION_CANCEL) m->cancels++;
    return (long)size;
}
static long read_frame(void *context, void *bytes, size_t size,
                       unsigned left, unsigned phase, int recovery, int *error)
{
    struct mock *m = context;
    (void)left; (void)phase; (void)recovery; (void)error;
    m->reads++;
    if (m->oversized && m->reads == 1) return (long)size + 1;
    struct lapy_elevation_message frame = m->request;
    frame.kind = m->frames ? LAPY_ELEVATION_RESPONSE : LAPY_ELEVATION_PREPARE;
    frame.status = m->frames && m->cancels ? LAPY_ELEVATION_CANCELLED : LAPY_ELEVATION_OK;
    CHECK(size == sizeof(frame));
    memcpy(bytes, &frame, sizeof(frame)); m->frames++;
    return (long)size;
}
static int prepare(void *context, int *error)
{ struct mock *m = context; (void)error; m->prepare_calls++; return 0; }
int main(void)
{
    struct mock m = { .oversized = 1 };
    PwLapyClient client = {0};
    PwLapyClientOps ops = { &m, remaining, write_frame, read_frame, prepare, NULL, 0, 0 };
    CHECK(pw_lapy_client_exchange(&client, &ops, 600, 123) == -1);
    CHECK(client.protocol_refused && !client.terminal && !client.settled_failure);
    CHECK(m.reads == 1 && m.cancels == 0 && m.prepare_calls == 0);
    CHECK(client.error == EPROTO);

    /* Refused invocation must not retain a previous transaction's receipt. */
    for (unsigned which = 0; which < 7; ++which) {
        PwLapyClientOps bad = ops;
        memset(&client, 0xa5, sizeof(client));
        if (which == 2) bad.remaining = NULL;
        if (which == 3) bad.send = NULL;
        if (which == 4) bad.receive = NULL;
        if (which == 5) bad.prepare = NULL;
        int rc = pw_lapy_client_exchange(&client, which == 1 ? NULL : &bad,
                                        which == 0 ? 1 : 600, which == 6 ? 0 : 123);
        CHECK(rc == -1);
        CHECK(!client.terminal && !client.settled_failure && !client.possible_apply);
        CHECK(client.no_request && client.error == EINVAL);
    }
    CHECK(pw_lapy_client_exchange(NULL, &ops, 600, 123) == -1);
    printf("portable client fail-closed regressions: %u failures\n", failures);
    return failures ? 1 : 0;
}
