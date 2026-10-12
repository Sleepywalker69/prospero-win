/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* HOST-ONLY REFERENCE. Single serialized owner; exclusive use of the real
 * legacy sink is a fixture assumption, NOT a production multiplexing API.
 * USER completion below is supplied by tests, never inferred from enqueue. */
#ifndef PW_REFERENCE_TAGGED_SINK_H
#define PW_REFERENCE_TAGGED_SINK_H
#include <stdint.h>
#include <string.h>
#include "../wine/ps5/pw_wine_sink.h"
enum { REF_SOURCES=2, REF_CONTROLS=2 };
typedef struct {
    uint32_t abi,size,source,kind;
    uint64_t session,epoch,sequence;
    PwWineInput event;
    uint32_t reserved;
} RefEnvelope;
_Static_assert(sizeof(RefEnvelope)==64,"reference wire size");
typedef struct {
    uint64_t epoch,last_sequence;
    unsigned resetting;
} RefSource;
typedef struct {
    RefEnvelope meta[PW_WINE_INPUT_QUEUE], flight;
    unsigned head,count,inflight;
    uint64_t ticket,next_ticket,hwnd,generation;
    RefSource source[REF_SOURCES];
    unsigned held[REF_SOURCES][REF_CONTROLS];
    uint64_t held_hwnd[REF_SOURCES][REF_CONTROLS],held_generation[REF_SOURCES][REF_CONTROLS];
    uint64_t flight_hwnd,flight_generation;
} RefTaggedSink;
static void ref_init(RefTaggedSink *s)
{
    memset(s,0,sizeof(*s));
    for(unsigned i=0;i<REF_SOURCES;i++)s->source[i].epoch=1;
    s->hwnd=2;s->generation=1;
}
static int ref_control(PwWineInput e)
{
    if(e.type==PW_WINE_INPUT_KEY&&e.code==32&&e.down<=1)return 0;
    if(e.type==PW_WINE_INPUT_MOUSE_BUTTON&&e.code==0&&e.down<=1)return 1;
    return -1;
}
static int ref_admit(RefTaggedSink *s,const RefEnvelope *e)
{
    if(!e||e->abi!=1||e->size!=sizeof(*e)||e->session!=1||e->reserved||
       e->kind!=1||e->source>=REF_SOURCES||ref_control(e->event)<0)return -1;
    RefSource *p=&s->source[e->source];
    if(p->resetting||p->epoch==UINT64_MAX||e->epoch!=p->epoch||
       !e->sequence||e->sequence<=p->last_sequence||s->count==PW_WINE_INPUT_QUEUE)return -1;
    /* The serialized owner publishes metadata immediately after admission;
     * no callback or concurrent dequeue is permitted across these two writes. */
    if(pw_wine_post_input(&e->event))return -1;
    s->meta[(s->head+s->count)%PW_WINE_INPUT_QUEUE]=*e;
    s->count++;p->last_sequence=e->sequence;return 0;
}
static int ref_reset(RefTaggedSink *s,unsigned source)
{
    if(source>=REF_SOURCES)return -1;
    RefSource *p=&s->source[source];
    p->resetting=1;
    if(p->epoch==UINT64_MAX)return -1;
    p->epoch++;p->last_sequence=0;return 0;
}
/* 1: obligation published BEFORE any USER boundary call; 0: empty/busy.
 * Old queued records are cancelled, not reported applied. */
static int ref_take(RefTaggedSink *s)
{
    if(s->inflight)return 0;
    while(s->count) {
        PwWineInput e;
        if(!pw_wine_next_input(&e))return -1;
        RefEnvelope m=s->meta[s->head];
        s->head=(s->head+1)%PW_WINE_INPUT_QUEUE;s->count--;
        if(memcmp(&e,&m.event,sizeof(e)))return -1;
        if(m.epoch!=s->source[m.source].epoch)continue;
        if(s->next_ticket==UINT64_MAX)return -1;
        int k=ref_control(m.event);
        s->flight=m;s->ticket=++s->next_ticket;
        s->flight_hwnd=m.event.down?s->hwnd:s->held_hwnd[m.source][k];
        s->flight_generation=m.event.down?s->generation:s->held_generation[m.source][k];
        s->inflight=1;return 1;
    }
    return 0;
}
/* Only aggregate transitions require a USER attempt. The caller must settle
 * suppressed source-only transitions explicitly with a successful logical
 * completion. Target identities belong to obligations, never current focus. */
static int ref_needs_hardware(const RefTaggedSink *s)
{
    if(!s->inflight)return -1;
    unsigned source=s->flight.source;int k=ref_control(s->flight.event);
    unsigned own=s->held[source][k],other=0;
    if(own&&s->flight.event.down&&(s->held_hwnd[source][k]!=s->flight_hwnd||
       s->held_generation[source][k]!=s->flight_generation))return -1;
    for(unsigned i=0;i<REF_SOURCES;i++)
        if(i!=source&&s->held_hwnd[i][k]==s->flight_hwnd&&
           s->held_generation[i][k]==s->flight_generation)other|=s->held[i][k];
    return s->flight.event.down?!(own||other):(own&&!other);
}
/* Exact mock completion settles the old obligation even after reset. It
 * cannot ACK the new epoch barrier; a late applied DOWN must be released. */
static int ref_complete(RefTaggedSink *s,uint64_t ticket,uint64_t epoch,int applied)
{
    if(!s->inflight||ticket!=s->ticket||epoch!=s->flight.epoch)return -1;
    if(applied<0||(applied&&ref_needs_hardware(s)<0))return -1; /* unknown/timeout retains ownership */
    if(applied){
        unsigned source=s->flight.source;int k=ref_control(s->flight.event);
        s->held[source][k]=s->flight.event.down;
        s->held_hwnd[source][k]=s->flight_hwnd;
        s->held_generation[source][k]=s->flight_generation;
    }
    s->inflight=0;return 0;
}
static unsigned ref_effective(const RefTaggedSink *s,unsigned control)
{
    unsigned held=0;
    for(unsigned i=0;i<REF_SOURCES;i++)held|=s->held[i][control];
    return held;
}
/* 0: no obligation, 1: source-only relinquish (another source owns it),
 * 2: physical UP needed, -1: identity mismatch/unknown completion.
 * A real implementation needs a separate release ticket/receipt. This
 * narrow fixture synchronously supplies that completion under its owner. */
static int ref_release(RefTaggedSink *s,unsigned source,unsigned control,
                       uint64_t hwnd,uint64_t generation,int applied)
{
    if(source>=REF_SOURCES||control>=REF_CONTROLS||
       !s->source[source].resetting||s->inflight)return -1;
    if(!s->held[source][control])return 0;
    if(hwnd!=s->held_hwnd[source][control]||generation!=s->held_generation[source][control])return -1;
    unsigned other=0;
    for(unsigned i=0;i<REF_SOURCES;i++)if(i!=source&&s->held_hwnd[i][control]==hwnd&&
        s->held_generation[i][control]==generation)other|=s->held[i][control];
    if(other){s->held[source][control]=0;return 1;}
    if(applied!=1)return -1;
    s->held[source][control]=0;return 2;
}
static int ref_source_cleared(RefTaggedSink *s,unsigned source,uint64_t epoch)
{
    if(source>=REF_SOURCES||!s->source[source].resetting||
       epoch!=s->source[source].epoch||epoch==UINT64_MAX)return -1;
    if(s->inflight&&s->flight.source==source)return -1;
    for(unsigned i=0;i<s->count;i++)
        if(s->meta[(s->head+i)%PW_WINE_INPUT_QUEUE].source==source)return -1;
    for(unsigned k=0;k<REF_CONTROLS;k++)if(s->held[source][k])return -1;
    /* Admission remains blocked until a separate neutral-rearm policy.
     * SOURCE_CLEARED makes no global desktop-neutral claim. */
    return 0;
}
#endif
