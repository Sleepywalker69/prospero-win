/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Actual immutable installer. Callback bodies are inert signature fixtures;
 * the publication interleaving is deterministic and does not run threads. */
#include <assert.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../wine/ps5/pw_wine_fixture_provider.h"
#include "../wine/ps5/pw_wine_creation.h"
static unsigned checks, publications, callbacks, in_hook;
#define CHECK(x) do { ++checks; assert(x); } while(0)
static void publication(atomic_uint *);
static int hooked_cas(atomic_uint *p,unsigned *e,unsigned n,memory_order a,memory_order b)
{
    int ok=atomic_compare_exchange_strong_explicit(p,e,n,a,b);
    if(ok&&!in_hook){in_hook=1;publication(p);in_hook=0;}
    return ok;
}
#undef atomic_compare_exchange_strong
#undef atomic_compare_exchange_strong_explicit
#define atomic_compare_exchange_strong(p,e,n) hooked_cas(p,e,n,memory_order_seq_cst,memory_order_seq_cst)
#define atomic_compare_exchange_strong_explicit hooked_cas
#include "../wine/ps5/pw_wine_fixture_provider.c"
#undef atomic_compare_exchange_strong
#undef atomic_compare_exchange_strong_explicit
static uint32_t f_admit(void*c,uint32_t p,uint32_t t,uint32_t m,const char*s,uint64_t*g)
{(void)c;(void)p;(void)t;(void)m;(void)s;(void)g;callbacks++;return 0;}
static uint32_t f_bind(void*c,uint32_t p,uint32_t t,uint32_t n,uint64_t*g)
{(void)c;(void)p;(void)t;(void)n;(void)g;callbacks++;return 0;}
static void f_release(void*c,uint64_t g,uint32_t p){(void)c;(void)g;(void)p;callbacks++;}
static uint32_t f_spawn(void*c,uint64_t g,int fd,uint32_t p,uint32_t t)
{(void)c;(void)g;(void)fd;(void)p;(void)t;callbacks++;return 0;}
static uint32_t f_left(void*c,uint64_t g){(void)c;(void)g;callbacks++;return 0;}
static void f_result(void*c,uint64_t g,uint32_t o,uint32_t s)
{(void)c;(void)g;(void)o;(void)s;callbacks++;}
static int f_signal(void*c,uint64_t g,uint32_t p,int32_t n,int64_t t,int32_t s)
{(void)c;(void)g;(void)p;(void)n;(void)t;(void)s;callbacks++;return 0;}
static uint32_t f_state(void*c,uint64_t g,uint32_t p,int32_t n,uint32_t r)
{(void)c;(void)g;(void)p;(void)n;(void)r;callbacks++;return 0;}
static uint32_t f_exit(void*c,uint32_t s){(void)c;(void)s;callbacks++;return 0;}
static void f_detach(void*c,uint32_t o,int32_t r,int32_t e)
{(void)c;(void)o;(void)r;(void)e;callbacks++;}
static uint32_t c_prepare(void*c,const PwWineCreationRequest*r,uint64_t*g)
{(void)c;(void)r;(void)g;callbacks++;return 0;}
static uint32_t c_query(void*c,uint64_t g,uint64_t l,uint64_t n,PwWineCreationStatus*s)
{(void)c;(void)g;(void)l;(void)n;(void)s;callbacks++;return 0;}
static uint32_t c_bind(void*c,uint64_t g,uint64_t l,uint64_t n,uint32_t p,uint32_t m,const void*i,uint32_t b)
{(void)c;(void)g;(void)l;(void)n;(void)p;(void)m;(void)i;(void)b;callbacks++;return 0;}
static uint32_t c_submit(void*c,uint64_t g,uint64_t l,uint64_t n,uint32_t p,uint32_t t,int*f)
{(void)c;(void)g;(void)l;(void)n;(void)p;(void)t;(void)f;callbacks++;return 0;}
static uint32_t c_result(void*c,uint64_t g,uint64_t l,uint32_t o,uint32_t s)
{(void)c;(void)g;(void)l;(void)o;(void)s;callbacks++;return 0;}
static void c_abandon(void*c,uint64_t g,uint64_t l){(void)c;(void)g;(void)l;callbacks++;}
static void c_transport(void*c,uint64_t g,uint64_t l,int32_t r,int32_t e)
{(void)c;(void)g;(void)l;(void)r;(void)e;callbacks++;}
static void c_dead(void*c,uint64_t g,uint32_t p){(void)c;(void)g;(void)p;callbacks++;}
static uint32_t c_join(void*c,uint64_t g,uint32_t p,uint32_t t,int32_t n)
{(void)c;(void)g;(void)p;(void)t;(void)n;callbacks++;return 0;}
static int context;
static PwWineFixtureProvider root;
static PwWineCreationProvider broker;
static PwWineCreationChild child;
static void reset(void)
{
    /* Independent scenarios only; production has no reset/rebind operation. */
    atomic_init(&ready,0);atomic_init(&process_role,0);
    atomic_init(&creation_ready,0);atomic_init(&child_ready,0);
    memset(&installed,0,sizeof(installed));memset(&creation_provider,0,sizeof(creation_provider));
    memset(&creation_child,0,sizeof(creation_child));
    root=(PwWineFixtureProvider){PW_WINE_FIXTURE_ABI,sizeof(root),&context,f_admit,f_bind,f_release,
        f_spawn,f_left,f_result,f_signal,f_state,f_exit,f_detach};
    broker=(PwWineCreationProvider){PW_WINE_CREATION_ABI,sizeof(broker),&context,c_prepare,c_query,
        c_bind,c_submit,c_result,c_abandon,c_transport,c_dead,c_join};
    child=(PwWineCreationChild){PW_WINE_CREATION_ABI,sizeof(child),123,44,45,2,PW_WINE_FIXTURE_AMD64};
    CHECK(!pw_wine_fixture_get()&&!pw_wine_creation_get()&&!pw_wine_creation_child_get());
}
static void publication(atomic_uint *p)
{
    publications++;
    if(p==&process_role||p==&ready){
        CHECK(!pw_wine_fixture_get()&&!pw_wine_creation_child_get());
        CHECK(pw_wine_fixture_install(&root)==-1);
        CHECK(pw_wine_creation_child_install(&child)==-1);
    }else if(p==&creation_ready){
        CHECK(pw_wine_fixture_get()!=NULL&&!pw_wine_creation_get());
        CHECK(pw_wine_creation_install(&broker)==-1);
        CHECK(pw_wine_creation_child_install(&child)==-1);
    }else{
        CHECK(p==&child_ready&&!pw_wine_creation_child_get());
        CHECK(!pw_wine_fixture_get()&&!pw_wine_creation_get());
        CHECK(pw_wine_creation_child_install(&child)==-1);
        CHECK(pw_wine_fixture_install(&root)==-1);
    }
}
static void child_controls(void)
{
    reset();CHECK(pw_wine_creation_child_install(NULL)==-1);
    for(unsigned n=0;n<12;n++){
        reset();PwWineCreationChild bad=child;
        switch(n){
        case 0:bad.abi=0;break;case 1:bad.abi++;break;case 2:bad.bytes--;break;
        case 3:bad.bytes++;break;case 4:bad.generation=0;break;case 5:bad.wine_pid=0;break;
        case 6:bad.wine_tid=0;break;case 7:bad.profile=0;break;case 8:bad.profile=4;break;
        case 9:bad.machine=0;break;case 10:bad.machine=0xaa64;break;
        default:bad.profile=1;bad.machine=PW_WINE_FIXTURE_I386;break;
        }
        CHECK(pw_wine_creation_child_install(&bad)==-1);
        CHECK(!pw_wine_creation_child_get()&&!atomic_load(&process_role));
        CHECK(!pw_wine_fixture_install(&root));
    }
    for(unsigned n=0;n<3;n++){
        reset();child.profile=n?2:1;child.machine=n==2?PW_WINE_FIXTURE_I386:PW_WINE_FIXTURE_AMD64;
        PwWineCreationChild before=child;
        CHECK(!pw_wine_creation_child_install(&child));
        const PwWineCreationChild *p=pw_wine_creation_child_get();
        CHECK(p&&p!=&child&&!memcmp(p,&before,sizeof(before)));
        CHECK(!pw_wine_fixture_get()&&!pw_wine_creation_get());
        CHECK(pw_wine_creation_child_install(&child)==-1);
        CHECK(pw_wine_fixture_install(&root)==-1);
        CHECK(pw_wineserver_fixture_install(&root)==-1);
        CHECK(pw_wine_creation_install(&broker)==-1);
        memset(&child,0,sizeof(child));CHECK(!memcmp(p,&before,sizeof(before)));
    }
}
static void broker_controls(void)
{
    reset();CHECK(pw_wine_creation_install(&broker)==-1);
    CHECK(!atomic_load(&process_role));CHECK(pw_wineserver_creation_install(&broker)==-1);
    CHECK(pw_wine_creation_install(NULL)==-1);
    for(unsigned n=0;n<14;n++){
        reset();CHECK(!pw_wine_fixture_install(&root));PwWineCreationProvider bad=broker;
        switch(n){
        case 0:bad.abi=0;break;case 1:bad.abi++;break;case 2:bad.bytes--;break;
        case 3:bad.bytes++;break;case 4:bad.context=NULL;break;case 5:bad.prepare=NULL;break;
        case 6:bad.query=NULL;break;case 7:bad.bind=NULL;break;case 8:bad.submit=NULL;break;
        case 9:bad.result=NULL;break;case 10:bad.abandon=NULL;break;case 11:bad.transport_failure=NULL;break;case 12:bad.origin_dead=NULL;break;
        default:bad.join=NULL;break;
        }
        CHECK(pw_wine_creation_install(&bad)==-1);CHECK(!pw_wine_creation_get());
        CHECK(!atomic_load(&creation_ready));CHECK(pw_wine_fixture_get()!=NULL);
        PwWineCreationProvider before=broker;
        CHECK(!pw_wineserver_creation_install(&broker));
        const PwWineCreationProvider *p=pw_wine_creation_get();
        CHECK(p&&p!=&broker&&!memcmp(p,&before,sizeof(before)));
        CHECK(pw_wine_creation_install(&broker)==-1);
        CHECK(pw_wineserver_creation_install(&broker)==-1);
        CHECK(pw_wine_creation_child_install(&child)==-1);
        memset(&broker,0,sizeof(broker));CHECK(!memcmp(p,&before,sizeof(before)));
    }
    reset();root.root_exit=NULL;CHECK(pw_wine_fixture_install(&root)==-1);
    CHECK(!atomic_load(&process_role));CHECK(!pw_wine_creation_child_install(&child));
}
int main(void)
{
    CHECK(__wine_ps5_creation_abi()==PW_WINE_CREATION_ABI);
    child_controls();broker_controls();CHECK(!callbacks);CHECK(publications>0);
    printf("creation installer: %u checks; %u deterministic publication boundaries; no native callbacks\n",checks,publications);
    return 0;
}
