/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _POSIX_C_SOURCE 200809L
#include "../wine/ps5/pw_wine_tagged_transport.h"
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

_Static_assert(sizeof(PwWineInput)==20,"legacy input unchanged");
_Static_assert(offsetof(PwWineInput,down)==16,"legacy input offset");
static PwTaggedInput event(unsigned source,uint64_t session,uint64_t epoch,uint64_t sequence)
{
    PwTaggedInput e={PW_TAGGED_ABI,sizeof(e),source,0,session,epoch,sequence,
                     {PW_WINE_INPUT_MOUSE_MOVE,source,(int32_t)(sequence%1000000),
                      -(int32_t)(sequence%1000000),(uint32_t)(sequence&1)},0};
    return e;
}
static void equal(const PwTaggedInput *a,const PwTaggedInput *b)
{
    assert(!memcmp(a,b,sizeof(*a)));
}
static void test_validation(void)
{
    PwTaggedTransport t;
    PwTaggedSourceConfig config[PW_TAGGED_SOURCES];
    for(unsigned i=0;i<PW_TAGGED_SOURCES;i++)config[i]=(PwTaggedSourceConfig){100+i,7+i};
    assert(pw_tagged_init(NULL,config,1)==PW_TAGGED_INVALID);
    assert(pw_tagged_init(&t,NULL,1)==PW_TAGGED_INVALID && !t.initialized);
    assert(pw_tagged_init(&t,config,0)==PW_TAGGED_INVALID && !t.initialized);
    assert(pw_tagged_init(&t,config,PW_TAGGED_SOURCES+1)==PW_TAGGED_INVALID);
    config[7].session=0;
    assert(pw_tagged_init(&t,config,PW_TAGGED_SOURCES)==PW_TAGGED_INVALID && !t.initialized);
    config[7].session=107;config[7].epoch=0;
    assert(pw_tagged_init(&t,config,PW_TAGGED_SOURCES)==PW_TAGGED_INVALID && !t.initialized);
    PwTaggedInput e=event(0,100,7,1),out;
    assert(pw_tagged_post(&t,&e)==PW_TAGGED_INVALID);
    assert(pw_tagged_destroy(&t)==PW_TAGGED_INVALID);
    config[7].epoch=14;
    assert(!pw_tagged_init(&t,config,PW_TAGGED_SOURCES));
    assert(pw_tagged_post(NULL,&e)==PW_TAGGED_INVALID);
    assert(pw_tagged_post(&t,NULL)==PW_TAGGED_INVALID);
    assert(pw_tagged_next(&t,NULL)==PW_TAGGED_INVALID);
    assert(pw_tagged_next_reset(&t,NULL)==PW_TAGGED_INVALID);
    PwTaggedInput bad[11];
    for(unsigned i=0;i<11;i++)bad[i]=e;
    bad[0].abi++;bad[1].size--;bad[2].source=PW_TAGGED_SOURCES;
    bad[3].reserved=1;bad[4].reserved_tail=1;bad[5].sequence=0;
    bad[6].event.type=0;
    bad[7].event=(PwWineInput){PW_WINE_INPUT_KEY,0,0,0,1};
    bad[8].event=(PwWineInput){PW_WINE_INPUT_KEY,256,0,0,1};
    bad[9].event=(PwWineInput){PW_WINE_INPUT_MOUSE_BUTTON,3,0,0,1};
    bad[10].event=(PwWineInput){PW_WINE_INPUT_WINDOW_CYCLE,0,0,0,1};
    for(unsigned i=0;i<11;i++)assert(pw_tagged_post(&t,&bad[i])==PW_TAGGED_INVALID);
    e.session=0;assert(pw_tagged_post(&t,&e)==PW_TAGGED_STALE);
    e.session=100;e.epoch=6;assert(pw_tagged_post(&t,&e)==PW_TAGGED_STALE);
    e.epoch=7;assert(!pw_tagged_post(&t,&e));
    assert(pw_tagged_post(&t,&e)==PW_TAGGED_STALE);
    assert(pw_tagged_next(&t,&out)==PW_TAGGED_DATA);equal(&e,&out);
    memset(&out,0xa5,sizeof(out));PwTaggedInput sentinel=out;
    assert(!pw_tagged_next(&t,&out));equal(&out,&sentinel);
    /* Every configured source boundary is usable; no alias with source zero. */
    e=event(7,107,14,1);assert(!pw_tagged_post(&t,&e));
    assert(pw_tagged_next(&t,&out)==PW_TAGGED_DATA);equal(&e,&out);
    assert(!pw_tagged_destroy(&t));
}
static void test_capacity_and_reset(void)
{
    PwTaggedTransport t;
    PwTaggedSourceConfig config[2]={{10,5},{20,8}};
    PwTaggedInput e,out,copy;
    PwTaggedReset reset,again;
    assert(!pw_tagged_init(&t,config,2));
    e=event(0,10,5,1);copy=e;
    assert(!pw_tagged_post(&t,&e));e.event.x=999;e.sequence=99;
    assert(pw_tagged_next(&t,&out)==PW_TAGGED_DATA);equal(&copy,&out);
    /* Pop has moved the head: repeated full wraps test slot reuse. */
    for(unsigned round=0;round<3;round++) {
        for(unsigned i=0;i<PW_TAGGED_CAPACITY;i++) {
            e=event(0,10,5,2+round*PW_TAGGED_CAPACITY+i);
            assert(!pw_tagged_post(&t,&e));
        }
        e.sequence++;assert(pw_tagged_post(&t,&e)==PW_TAGGED_FULL);
        for(unsigned i=0;i<PW_TAGGED_CAPACITY;i++) {
            assert(pw_tagged_next(&t,&out)==PW_TAGGED_DATA);
            copy=event(0,10,5,2+round*PW_TAGGED_CAPACITY+i);equal(&copy,&out);
        }
    }
    /* Failed FULL admission did not consume its sequence. */
    assert(!pw_tagged_post(&t,&e));
    assert(pw_tagged_next(&t,&out)==PW_TAGGED_DATA);equal(&e,&out);
    uint64_t base=e.sequence;
    for(unsigned i=0;i<PW_TAGGED_CAPACITY;i++) {
        unsigned s=i&1;
        e=event(s,s?20:10,s?8:5,s?i+1:base+i+1);
        assert(!pw_tagged_post(&t,&e));
    }
    assert(pw_tagged_close_source(&t,2,10,5,&reset)==PW_TAGGED_INVALID);
    assert(pw_tagged_close_source(&t,0,11,5,&reset)==PW_TAGGED_STALE);
    assert(pw_tagged_close_source(&t,0,10,4,&reset)==PW_TAGGED_STALE);
    assert(!pw_tagged_close_source(&t,0,10,5,&reset));
    assert(reset.source==0 && reset.session==10 && reset.old_epoch==5 &&
           reset.new_epoch==6 && !reset.exhausted &&
           reset.last_admitted_sequence==base+255);
    assert(!pw_tagged_close_source(&t,0,10,5,&again));
    assert(!memcmp(&reset,&again,sizeof(reset)));
    assert(pw_tagged_next_reset(&t,&again)==1);
    assert(!memcmp(&reset,&again,sizeof(reset)));
    assert(!pw_tagged_next_reset(&t,&again));
    assert(!pw_tagged_close_source(&t,0,10,5,&again));
    assert(!memcmp(&reset,&again,sizeof(reset)));
    assert(!pw_tagged_next_reset(&t,&again)); /* no duplicate publication */
    assert(pw_tagged_close_source(&t,0,10,6,&again)==PW_TAGGED_STALE);
    e=event(0,10,6,base+300);assert(pw_tagged_post(&t,&e)==PW_TAGGED_CLOSED);
    for(unsigned i=0;i<PW_TAGGED_CAPACITY;i++) {
        unsigned s=i&1;
        assert(pw_tagged_next(&t,&out)==(s?PW_TAGGED_DATA:PW_TAGGED_CANCELLED));
        e=event(s,s?20:10,s?8:5,s?i+1:base+i+1);equal(&e,&out);
    }
    /* Other source remains live, including maximum sequence and no wrap. */
    e=event(1,20,8,UINT64_MAX);e.event.x=0;e.event.y=0;
    assert(!pw_tagged_post(&t,&e));
    e.sequence=1;assert(pw_tagged_post(&t,&e)==PW_TAGGED_STALE);
    assert(pw_tagged_next(&t,&out)==PW_TAGGED_DATA && out.sequence==UINT64_MAX);
    assert(!pw_tagged_destroy(&t));
}
static void test_exhaustion_and_legacy(void)
{
    PwTaggedTransport t;
    PwTaggedSourceConfig config[PW_TAGGED_SOURCES];
    PwTaggedInput out;
    PwTaggedReset r;
    PwWineInput legacy={PW_WINE_INPUT_KEY,32,0,0,1},legacy_out;
    PwWineSinkStats before,after;
    pw_wine_sink_stats(&before);
    for(unsigned i=0;i<PW_TAGGED_SOURCES;i++)config[i]=(PwTaggedSourceConfig){i+1,UINT64_MAX-i};
    assert(!pw_tagged_init(&t,config,PW_TAGGED_SOURCES));
    for(unsigned i=0;i<PW_TAGGED_SOURCES;i++) {
        PwTaggedInput e=event(i,i+1,UINT64_MAX-i,1);
        assert(!pw_tagged_post(&t,&e));
    }
    assert(!pw_wine_post_input(&legacy));
    for(unsigned i=PW_TAGGED_SOURCES;i>0;i--)
        assert(!pw_tagged_close_source(&t,i-1,i,UINT64_MAX-(i-1),&r));
    for(unsigned i=0;i<PW_TAGGED_SOURCES;i++) {
        assert(pw_tagged_next_reset(&t,&r)==1 && r.source==i && r.session==i+1);
        assert(r.old_epoch==UINT64_MAX-i && r.last_admitted_sequence==1);
        assert(r.exhausted==(i==0) && r.new_epoch==UINT64_MAX-i+(i!=0));
        assert(pw_tagged_next(&t,&out)==PW_TAGGED_CANCELLED);
        PwTaggedInput e=event(i,i+1,UINT64_MAX-i,1);equal(&e,&out);
    }
    assert(pw_wine_next_input(&legacy_out)==1);
    assert(!memcmp(&legacy,&legacy_out,sizeof(legacy)));
    assert(!pw_wine_next_input(&legacy_out));
    pw_wine_sink_stats(&after);
    assert(after.inputs_posted==before.inputs_posted+1 &&
           after.inputs_delivered==before.inputs_delivered+1 &&
           after.inputs_dropped==before.inputs_dropped);
    assert(!pw_tagged_destroy(&t));
}

static void test_ordered_close(void)
{
    PwTaggedTransport t;
    PwTaggedSourceConfig config[2]={{9,3},{10,UINT64_MAX}};
    PwTaggedInput e=event(0,9,3,1),out,retained;
    PwTaggedReset r,duplicate;
    assert(!pw_tagged_init(&t,config,2));
    assert(!pw_tagged_post(&t,&e));
    assert(pw_tagged_next(&t,&out)==PW_TAGGED_DATA);retained=out;
    assert(!pw_tagged_close_source(&t,0,9,3,&r));
    equal(&out,&retained);equal(&out,&e); /* close cannot rewrite popped DATA */
    assert(pw_tagged_post(&t,&e)==PW_TAGGED_STALE);
    e.epoch=4;e.sequence=2;assert(pw_tagged_post(&t,&e)==PW_TAGGED_CLOSED);
    e=event(1,10,UINT64_MAX,1);assert(!pw_tagged_post(&t,&e));
    assert(!pw_tagged_close_source(&t,1,10,UINT64_MAX,&r));
    assert(r.exhausted && r.old_epoch==UINT64_MAX && r.new_epoch==UINT64_MAX);
    assert(pw_tagged_next(&t,&out)==PW_TAGGED_CANCELLED);equal(&out,&e);
    e.sequence=2;assert(pw_tagged_post(&t,&e)==PW_TAGGED_CLOSED);
    assert(pw_tagged_next_reset(&t,&duplicate)==1 && duplicate.source==0);
    assert(pw_tagged_next_reset(&t,&duplicate)==1 && duplicate.source==1);
    assert(!memcmp(&r,&duplicate,sizeof(r)));
    assert(!pw_tagged_close_source(&t,1,10,UINT64_MAX,&duplicate));
    assert(!memcmp(&r,&duplicate,sizeof(r)));
    assert(!pw_tagged_next_reset(&t,&duplicate));
    assert(!pw_tagged_destroy(&t));
}

enum { PRODUCERS=4, PER_PRODUCER=4000 };
typedef struct { PwTaggedTransport *t;unsigned source; } Producer;
static void *produce(void *arg)
{
    Producer *p=arg;
    for(unsigned n=1;n<=PER_PRODUCER;n++) {
        PwTaggedInput e=event(p->source,100+p->source,20+p->source,n);
        int result;
        while((result=pw_tagged_post(p->t,&e))==PW_TAGGED_FULL)sched_yield();
        assert(result==PW_TAGGED_OK);
        memset(&e,0,sizeof(e)); /* published slot owns a copy */
    }
    return NULL;
}
static void test_publication(void)
{
    PwTaggedTransport t;
    PwTaggedSourceConfig config[PRODUCERS];
    pthread_t threads[PRODUCERS];Producer p[PRODUCERS];
    unsigned seen[PRODUCERS]={0};
    for(unsigned i=0;i<PRODUCERS;i++)config[i]=(PwTaggedSourceConfig){100+i,20+i};
    assert(!pw_tagged_init(&t,config,PRODUCERS));
    for(unsigned i=0;i<PRODUCERS;i++) {
        p[i]=(Producer){&t,i};assert(!pthread_create(&threads[i],NULL,produce,&p[i]));
    }
    for(unsigned n=0;n<PRODUCERS*PER_PRODUCER;) {
        PwTaggedInput out;
        int result=pw_tagged_next(&t,&out);
        if(result==PW_TAGGED_EMPTY){sched_yield();continue;}
        assert(result==PW_TAGGED_DATA && out.source<PRODUCERS);
        unsigned s=out.source;
        PwTaggedInput expected=event(s,100+s,20+s,++seen[s]);equal(&expected,&out);n++;
    }
    for(unsigned i=0;i<PRODUCERS;i++) {
        assert(!pthread_join(threads[i],NULL));assert(seen[i]==PER_PRODUCER);
    }
    assert(!pw_tagged_destroy(&t));
}
typedef struct {
    PwTaggedTransport t;
    unsigned go;
    int posted,popped;
    PwTaggedInput output;
    PwTaggedReset resets[2];
} Race;
typedef struct { Race *race;unsigned index; } Closer;
static void start(Race *r)
{
    while(!__atomic_load_n(&r->go,__ATOMIC_ACQUIRE))sched_yield();
}
static void *race_post(void *arg)
{
    Race *r=arg;start(r);PwTaggedInput e=event(0,9,3,1);
    r->posted=pw_tagged_post(&r->t,&e);return NULL;
}
static void *race_pop(void *arg)
{
    Race *r=arg;start(r);r->popped=pw_tagged_next(&r->t,&r->output);return NULL;
}
static void *race_close(void *arg)
{
    Closer *c=arg;start(c->race);
    assert(!pw_tagged_close_source(&c->race->t,0,9,3,&c->race->resets[c->index]));
    return NULL;
}
static void test_reset_races(void)
{
    for(unsigned iteration=0;iteration<200;iteration++) {
        Race r;memset(&r,0,sizeof(r));
        PwTaggedSourceConfig config={9,3};pthread_t threads[4];
        Closer c[2]={{&r,0},{&r,1}};
        assert(!pw_tagged_init(&r.t,&config,1));
        assert(!pthread_create(&threads[0],NULL,race_post,&r));
        assert(!pthread_create(&threads[1],NULL,race_pop,&r));
        for(unsigned i=0;i<2;i++)assert(!pthread_create(&threads[2+i],NULL,race_close,&c[i]));
        __atomic_store_n(&r.go,1,__ATOMIC_RELEASE);
        for(unsigned i=0;i<4;i++)assert(!pthread_join(threads[i],NULL));
        assert(!memcmp(&r.resets[0],&r.resets[1],sizeof(PwTaggedReset)));
        assert(r.resets[0].old_epoch==3 && r.resets[0].new_epoch==4);
        unsigned accepted=r.posted==PW_TAGGED_OK;
        assert(accepted || r.posted==PW_TAGGED_STALE || r.posted==PW_TAGGED_CLOSED);
        assert(r.resets[0].last_admitted_sequence==accepted);
        PwTaggedInput out,expected=event(0,9,3,1);
        int tail=pw_tagged_next(&r.t,&out);
        if(!accepted)assert(r.popped==PW_TAGGED_EMPTY && tail==PW_TAGGED_EMPTY);
        else if(r.popped==PW_TAGGED_EMPTY) {
            assert(tail==PW_TAGGED_CANCELLED);equal(&expected,&out);
        } else {
            assert(r.popped==PW_TAGGED_DATA || r.popped==PW_TAGGED_CANCELLED);
            equal(&expected,&r.output);assert(tail==PW_TAGGED_EMPTY);
        }
        PwTaggedReset reset;
        assert(pw_tagged_next_reset(&r.t,&reset)==1);
        assert(!memcmp(&reset,&r.resets[0],sizeof(reset)));
        assert(!pw_tagged_next_reset(&r.t,&reset));
        assert(!pw_tagged_destroy(&r.t));
    }
}
int main(void)
{
    /* Bound all producer/start spins and joins: default SIGALRM fails the process. */
    alarm(60);
    test_validation();test_capacity_and_reset();test_exhaustion_and_legacy();
    test_ordered_close();
    test_publication();test_reset_races();
    alarm(0);
    puts("tagged transport: actual-source bounds, publication and reset tests passed");
    return 0;
}
