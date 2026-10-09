/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <assert.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../wine/ps5/pw_wine_fixture_provider.h"

static unsigned checks, publication_checks, reentrant;
static PwWineFixtureProvider candidate;
static void publication_hook(void);
static int compare_and_check(atomic_uint *object, unsigned *expected, unsigned desired,
                             memory_order success, memory_order failure)
{
    int result = atomic_compare_exchange_strong_explicit(object, expected, desired, success, failure);
    if (result) publication_hook();
    return result;
}
#undef atomic_compare_exchange_strong_explicit
#define atomic_compare_exchange_strong_explicit compare_and_check
#include "../wine/ps5/pw_wine_fixture_provider.c"
#undef atomic_compare_exchange_strong_explicit

#define CHECK(x) do { ++checks; assert(x); } while (0)
static uint32_t admit(void *c,uint32_t p,uint32_t t,uint32_t m,const char *s,uint64_t *g)
{ (void)c;(void)p;(void)t;(void)m;(void)s;*g=1;return 0; }
static uint32_t bind_process(void *c,uint32_t p,uint32_t t,uint32_t child,uint64_t *g)
{ (void)c;(void)p;(void)t;(void)child;*g=1;return 0; }
static void release_process(void *c,uint64_t g,uint32_t p) { (void)c;(void)g;(void)p; }
static uint32_t spawn(void *c,uint64_t g,int fd,uint32_t p,uint32_t t)
{ (void)c;(void)g;(void)fd;(void)p;(void)t;return 0; }
static uint32_t remaining(void *c,uint64_t g) { (void)c;(void)g;return 1; }
static void startup_result(void *c,uint64_t g,uint32_t ok,uint32_t status)
{ (void)c;(void)g;(void)ok;(void)status; }
static int signal_submit(void *c,uint64_t g,uint32_t p,int32_t native,int64_t t,int32_t sig)
{ (void)c;(void)g;(void)p;(void)native;(void)t;(void)sig;return PW_WF_SIGNAL_QUEUED; }
static uint32_t state(void *c,uint64_t g,uint32_t p,int32_t native,uint32_t cleanup)
{ (void)c;(void)g;(void)p;(void)native;(void)cleanup;return PW_WF_OWNED_ACTIVE; }
static uint32_t root_exit(void *c,uint32_t status) { CHECK(c==candidate.context);return status; }
static void root_detached(void *c,uint32_t ok,int32_t raw,int32_t error) { (void)c;(void)ok;(void)raw;(void)error; }
static void reset(void)
{
    static int context;
    atomic_init(&ready, 0); memset(&installed, 0, sizeof(installed)); reentrant=0;
    candidate=(PwWineFixtureProvider){PW_WINE_FIXTURE_ABI,sizeof(candidate),&context,
        admit,bind_process,release_process,spawn,remaining,startup_result,signal_submit,state,root_exit,root_detached};
}
static void publication_hook(void)
{
    ++publication_checks;
    CHECK(pw_wine_fixture_get()==NULL);
    if (!reentrant) {
        reentrant=1;
        CHECK(pw_wine_fixture_install(&candidate)==-1);
        CHECK(pw_wineserver_fixture_install(&candidate)==-1);
    }
}
int main(void)
{
    reset();CHECK(!pw_wine_fixture_get());CHECK(pw_wine_fixture_install(NULL)==-1);
    CHECK(!pw_wine_fixture_get());CHECK(!atomic_load(&ready));
    for(unsigned n=0;n<15;n++) {
        reset();PwWineFixtureProvider bad=candidate;
        switch(n) {
        case 0:bad.abi=0;break;case 1:bad.abi=2;break;
        case 2:bad.bytes--;break;case 3:bad.bytes++;break;case 4:bad.context=NULL;break;
        case 5:bad.admit=NULL;break;case 6:bad.bind_process=NULL;break;
        case 7:bad.release_process=NULL;break;case 8:bad.spawn=NULL;break;
        case 9:bad.startup_remaining_ms=NULL;break;case 10:bad.startup_result=NULL;break;
        case 11:bad.signal=NULL;break;case 12:bad.process_state=NULL;break;case 13:bad.root_exit=NULL;break;default:bad.root_detached=NULL;break;
        }
        CHECK(pw_wine_fixture_install(&bad)==-1);CHECK(!pw_wine_fixture_get());
        CHECK(!atomic_load(&ready));CHECK(!pw_wine_fixture_install(&candidate));
        const PwWineFixtureProvider *p=pw_wine_fixture_get();CHECK(p && p!=&candidate);
        CHECK(!memcmp(p,&candidate,sizeof(candidate)));
        CHECK(pw_wine_fixture_install(&candidate)==-1);
        CHECK(pw_wineserver_fixture_install(&candidate)==-1);
        PwWineFixtureProvider before=*p;
        memset(&candidate,0,sizeof(candidate));CHECK(!memcmp(p,&before,sizeof(before)));
        CHECK(pw_wine_fixture_install(&candidate)==-1);CHECK(pw_wine_fixture_get()==p);
    }
    reset();CHECK(pw_wineserver_fixture_install(&candidate)==0);CHECK(pw_wine_fixture_get()!=NULL);
    CHECK(publication_checks==16);
    const PwWineFixtureProvider *p=pw_wine_fixture_get();
    CHECK(p->root_exit(p->context,UINT32_C(0x80000100))==UINT32_C(0x80000100));
    printf("fixture provider installer: %u checks passed; incomplete publication/rebind/caller mutation rejected\n",checks);
    return 0;
}
