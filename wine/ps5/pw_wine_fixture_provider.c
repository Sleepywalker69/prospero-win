/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_wine_fixture_provider.h"
#include <stdatomic.h>

/* Separate instances are linked into ntdll and the in-process server. Each
 * receives the immutable title-local callbacks before any Wine thread starts. */
static PwWineFixtureProvider installed;
static atomic_uint ready;

int pw_wine_fixture_install(const PwWineFixtureProvider *p)
{
    unsigned expected = 0;
    if (!p || p->abi != PW_WINE_FIXTURE_ABI || p->bytes != sizeof(*p) || !p->context ||
        !p->admit || !p->bind_process || !p->release_process || !p->spawn ||
        !p->startup_remaining_ms || !p->startup_result || !p->signal || !p->process_state || !p->root_exit || !p->root_detached)
        return -1;
    if (!atomic_compare_exchange_strong_explicit(&ready, &expected, 1,
                                                 memory_order_acq_rel, memory_order_acquire))
        return -1;
    installed = *p;
    atomic_store_explicit(&ready, 2, memory_order_release);
    return 0;
}
int pw_wineserver_fixture_install(const PwWineFixtureProvider *p)
{
    return pw_wine_fixture_install(p);
}
const PwWineFixtureProvider *pw_wine_fixture_get(void)
{
    return atomic_load_explicit(&ready, memory_order_acquire) == 2 ? &installed : 0;
}
