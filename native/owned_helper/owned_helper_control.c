#include "owned_helper_control.h"
#include <string.h>

/* Work bound, not elapsed time: tolerate this many zero-ready waits with
 * neither millisecond-clock advancement nor byte progress. */
#define LAPY_CONTROL_STALL_LIMIT 1024U

static enum lapy_control_result remaining(struct lapy_helper_control *c,
                                          unsigned *left)
{
    uint64_t now;
    if (c->io.clock_ms(c->io.context, &now) || now < c->last_clock)
        return LAPY_CTL_IO;
    c->last_clock = now;
    if (now >= c->deadline) return LAPY_CTL_TIMEOUT;
    uint64_t n = c->deadline - now;
    *left = n > 100 ? 100 : (unsigned)n;
    return LAPY_CTL_CONTINUE;
}

int lapy_control_init(struct lapy_helper_control *c,
                      const struct lapy_control_io *io, uint64_t deadline)
{
    if (!c || !io || !io->clock_ms || !io->wait || !io->read || !io->write)
        return -1;
    memset(c, 0, sizeof(*c)); c->io = *io; c->deadline = deadline;
    unsigned left;
    return remaining(c, &left) == LAPY_CTL_CONTINUE ? 0 : -1;
}

/* This validates the wire tuple only. It is not process ownership proof. */
static int valid_request(const struct lapy_elevation_message *r)
{
    return r && r->magic == LAPY_ELEVATION_MAGIC &&
           r->version == LAPY_ELEVATION_VERSION && r->size == sizeof(*r) &&
           r->kind == LAPY_ELEVATION_REQUEST &&
           r->capability == LAPY_ELEVATION_FILESYSTEM &&
           r->pid > 1 && r->pid <= INT32_MAX &&
           !r->status && r->transaction_id;
}

int lapy_control_bind(struct lapy_helper_control *c,
                      const struct lapy_elevation_message *r)
{
    if (!c || c->bound || !valid_request(r)) return -1;
    c->request = *r; c->bound = 1;
    return 0;
}

int lapy_control_matches(const struct lapy_elevation_message *m,
                         const struct lapy_elevation_message *r, unsigned kind)
{
    return m && valid_request(r) && m->magic == r->magic &&
           m->version == r->version &&
           m->size == r->size && m->kind == kind &&
           m->capability == r->capability && m->pid == r->pid &&
           m->transaction_id && m->transaction_id == r->transaction_id;
}

enum lapy_control_result lapy_control_transfer(struct lapy_helper_control *c,
                                               void *buffer, size_t size,
                                               int writing)
{
    unsigned char *bytes = buffer;
    unsigned stalled_waits = 0;
    while (size) {
        uint64_t previous_clock = c->last_clock;
        unsigned left;
        enum lapy_control_result r = remaining(c, &left);
        if (r) return r;
        if (c->last_clock != previous_clock) stalled_waits = 0;
        if (stalled_waits >= LAPY_CONTROL_STALL_LIMIT) return LAPY_CTL_IO;
        int ready = c->io.wait(c->io.context, writing, left);
        if (ready < 0) return LAPY_CTL_IO;
        if (!ready) { ++stalled_waits; continue; }
        long n = writing ? c->io.write(c->io.context, bytes, size) :
                           c->io.read(c->io.context, bytes, size);
        if (n == 0 && !writing) return LAPY_CTL_EOF;
        if (n <= 0 || (unsigned long)n > size) return LAPY_CTL_IO;
        bytes += n; size -= (size_t)n;
        stalled_waits = 0;
    }
    return LAPY_CTL_CONTINUE;
}

enum lapy_control_result lapy_control_checkpoint(struct lapy_helper_control *c)
{
    if (!c || !c->bound) return LAPY_CTL_PROTOCOL;
    if (c->cancellation) return c->cancellation;
    unsigned left;
    enum lapy_control_result r = remaining(c, &left);
    if (!r) {
        int ready = c->io.wait(c->io.context, 0, 0);
        if (!ready) return LAPY_CTL_CONTINUE;
        if (ready < 0) r = LAPY_CTL_IO;
        else {
            struct lapy_elevation_message frame;
            memset(&frame, 0, sizeof(frame));
            r = lapy_control_transfer(c, &frame, sizeof(frame), 0);
            if (!r) r = lapy_control_matches(&frame, &c->request,
                                             LAPY_ELEVATION_CANCEL) && !frame.status ?
                        LAPY_CTL_CANCELLED : LAPY_CTL_PROTOCOL;
        }
    }
    c->cancellation = r;
    return r;
}
