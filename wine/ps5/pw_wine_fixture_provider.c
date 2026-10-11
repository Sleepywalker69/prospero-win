/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_wine_fixture_provider.h"
#include "pw_wine_creation.h"
#include <stdatomic.h>

/* Separate instances are linked into ntdll and the in-process server. Each
 * receives the immutable title-local callbacks before any Wine thread starts. */
static PwWineFixtureProvider installed;
static atomic_uint ready;
static atomic_uint process_role; /* 1 owner, 2 child; selected once before Wine entry */

int pw_wine_fixture_install(const PwWineFixtureProvider *p)
{
    unsigned expected = 0;
    if (!p || p->abi != PW_WINE_FIXTURE_ABI || p->bytes != sizeof(*p) || !p->context ||
        !p->admit || !p->bind_process || !p->release_process || !p->spawn ||
        !p->startup_remaining_ms || !p->startup_result || !p->signal || !p->process_state || !p->root_exit || !p->root_detached)
        return -1;
    if (!atomic_compare_exchange_strong(&process_role, &expected, 1)) return -1;
    expected = 0;
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

static PwWineCreationProvider creation_provider;
static PwWineCreationChild creation_child;
static atomic_uint creation_ready, child_ready;

int pw_wine_creation_install(const PwWineCreationProvider *p)
{
    unsigned empty=0;
    if(!p||p->abi!=PW_WINE_CREATION_ABI||p->bytes!=sizeof(*p)||!p->context||
       !p->prepare||!p->query||!p->bind||!p->submit||!p->result||!p->abandon||
       !p->transport_failure||!p->origin_dead||!p->join||!pw_wine_fixture_get()||atomic_load(&process_role)!=1)return -1;
    if(!atomic_compare_exchange_strong_explicit(&creation_ready,&empty,1,
                                               memory_order_acq_rel,memory_order_acquire))return -1;
    creation_provider=*p;
    atomic_store_explicit(&creation_ready,2,memory_order_release);return 0;
}
int pw_wineserver_creation_install(const PwWineCreationProvider *p)
{ return pw_wine_creation_install(p); }
const PwWineCreationProvider *pw_wine_creation_get(void)
{ return atomic_load_explicit(&creation_ready,memory_order_acquire)==2?&creation_provider:0; }
int pw_wine_creation_child_install(const PwWineCreationChild *p)
{
    unsigned empty=0;
    if(!p||p->abi!=PW_WINE_CREATION_ABI||p->bytes!=sizeof(*p)||!p->generation||
       !p->wine_pid||!p->wine_tid||atomic_load(&ready)||atomic_load(&creation_ready)||
       (p->profile!=1&&p->profile!=2&&p->profile!=3)||
       (p->machine!=PW_WINE_FIXTURE_AMD64&&p->machine!=PW_WINE_FIXTURE_I386)||
       ((p->profile==1||p->profile==3)&&p->machine!=PW_WINE_FIXTURE_AMD64))return -1;
    if(!atomic_compare_exchange_strong(&process_role,&empty,2))return -1;
    empty=0;
    if(!atomic_compare_exchange_strong_explicit(&child_ready,&empty,1,
                                               memory_order_acq_rel,memory_order_acquire))return -1;
    creation_child=*p;
    atomic_store_explicit(&child_ready,2,memory_order_release);return 0;
}
const PwWineCreationChild *pw_wine_creation_child_get(void)
{ return atomic_load_explicit(&child_ready,memory_order_acquire)==2?&creation_child:0; }
unsigned __wine_ps5_creation_abi(void) { return PW_WINE_CREATION_ABI; }
