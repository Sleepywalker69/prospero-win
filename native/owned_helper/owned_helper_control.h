#ifndef OWNED_HELPER_CONTROL_H
#define OWNED_HELPER_CONTROL_H
#include "lapy_elevation_protocol.h"
#include <stddef.h>
#include <stdint.h>

/* Single-thread, original connection only. A checkpoint is a cancellation
 * request; it never certifies cleanup and is forbidden inside a root move.
 * PID/transaction matching is correlation, not a process capability. The
 * native owner must retain its own process identities and certify cleanup;
 * transport loss or a valid CANCEL must never be treated as that receipt. */
enum lapy_control_result {
    LAPY_CTL_CONTINUE = 0, LAPY_CTL_CANCELLED = 1, LAPY_CTL_EOF = 2,
    LAPY_CTL_PROTOCOL = 3, LAPY_CTL_IO = 4, LAPY_CTL_TIMEOUT = 5
};
struct lapy_control_io {
    void *context;
    int (*clock_ms)(void *, uint64_t *);
    int (*wait)(void *, int writing, unsigned timeout_ms);
    long (*read)(void *, void *, size_t);
    long (*write)(void *, const void *, size_t);
};
struct lapy_helper_control {
    struct lapy_control_io io;
    struct lapy_elevation_message request;
    uint64_t last_clock, deadline;
    unsigned bound, prepared;
    enum lapy_control_result cancellation;
};
int lapy_control_init(struct lapy_helper_control *,
                      const struct lapy_control_io *, uint64_t deadline);
int lapy_control_bind(struct lapy_helper_control *,
                      const struct lapy_elevation_message *);
int lapy_control_matches(const struct lapy_elevation_message *,
                         const struct lapy_elevation_message *, unsigned kind);
/* The transfer retries zero-ready waits only while clock or byte progress
 * remains observable: 1024 consecutive zero-ready waits at one unchanged
 * clock value exhaust a work budget and return IO, not a synthetic timeout.
 * A same-millisecond EINTR storm may therefore fail conservatively. Clock
 * errors/deadlines take precedence; any clock advance or positive partial
 * transfer resets the budget. No total retry cap applies to advancing clocks.
 * With a frozen clock, the idle-wait bound depends on the initial byte count
 * (at most 1024 * (size + 1)); callbacks themselves must still return.
 * These outcomes never certify cleanup or peer receipt. */
enum lapy_control_result lapy_control_transfer(struct lapy_helper_control *,
                                               void *, size_t, int writing);
enum lapy_control_result lapy_control_checkpoint(struct lapy_helper_control *);
#endif
