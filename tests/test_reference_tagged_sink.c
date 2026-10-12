/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Actual legacy sink admission + reference metadata/ledger. USER is mocked. */
#include <assert.h>
#include <stdio.h>
#include "reference_tagged_sink.h"
static RefEnvelope event(unsigned source,uint64_t sequence,unsigned down)
{
    RefEnvelope e={.abi=1,.size=sizeof(e),.source=source,.kind=1,
        .session=1,.epoch=1,.sequence=sequence,
        .event={PW_WINE_INPUT_KEY,32,0,0,down}};
    return e;
}
static void empty_sink(void)
{
    PwWineInput e;while(pw_wine_next_input(&e)){}
}
static void complete(RefTaggedSink *s,int applied)
{
    assert(!ref_complete(s,s->ticket,s->flight.epoch,applied));
}
static void admission_and_barrier(void)
{
    RefTaggedSink s;ref_init(&s);empty_sink();
    RefEnvelope e=event(0,1,1);
    for(unsigned i=0;i<PW_WINE_INPUT_QUEUE;i++){
        e.sequence=i+1;assert(!ref_admit(&s,&e));
    }
    e.sequence++;assert(ref_admit(&s,&e)==-1);
    assert(!ref_effective(&s,0)); /* ADMITTED is not APPLIED */
    assert(!ref_reset(&s,0)); /* control cannot be starved by a full ring */
    assert(ref_source_cleared(&s,0,2)==-1);
    assert(!ref_take(&s)); /* all old queued records cancelled */
    assert(!s.count&&!s.inflight&&!ref_effective(&s,0));
    assert(!ref_source_cleared(&s,0,2));
    assert(ref_source_cleared(&s,0,1)==-1);
    e.epoch=2;e.sequence=1;assert(ref_admit(&s,&e)==-1); /* no implicit rearm */
}
static void late_completion_and_identity(void)
{
    RefTaggedSink s;ref_init(&s);empty_sink();RefEnvelope e=event(0,1,1);
    assert(!ref_admit(&s,&e)&&ref_take(&s)==1);
    uint64_t ticket=s.ticket;
    assert(!ref_reset(&s,0));
    assert(ref_source_cleared(&s,0,2)==-1);
    assert(ref_complete(&s,ticket+1,1,1)==-1);
    assert(ref_complete(&s,ticket,2,1)==-1);
    assert(ref_complete(&s,ticket,1,-1)==-1&&s.inflight);
    complete(&s,1); /* reset raced with actual applied DOWN */
    assert(ref_effective(&s,0)&&ref_source_cleared(&s,0,2)==-1);
    assert(ref_complete(&s,ticket,1,1)==-1);
    assert(ref_release(&s,0,0,3,1,1)==-1);
    s.generation=2;
    assert(ref_release(&s,0,0,2,2,1)==-1); /* reused HWND */
    assert(ref_release(&s,0,0,2,1,0)==-1&&ref_effective(&s,0));
    assert(ref_release(&s,0,0,2,1,1)==2);
    assert(!ref_source_cleared(&s,0,2));
    assert(!ref_reset(&s,0)&&ref_source_cleared(&s,0,2)==-1);
    assert(!ref_source_cleared(&s,0,3));
}
static void shared_control_and_cancel(void)
{
    RefTaggedSink s;ref_init(&s);empty_sink();
    for(unsigned source=0;source<2;source++){
        RefEnvelope e=event(source,1,1);
        assert(!ref_admit(&s,&e)&&ref_take(&s)==1);complete(&s,1);
    }
    assert(!ref_reset(&s,0));
    assert(ref_release(&s,0,0,2,1,-1)==1); /* NO physical UP */
    assert(!ref_source_cleared(&s,0,2)&&ref_effective(&s,0));
    assert(!ref_reset(&s,1));
    assert(ref_release(&s,1,0,2,1,-1)==-1);
    assert(ref_release(&s,1,0,2,1,1)==2&&!ref_effective(&s,0));
    assert(!ref_source_cleared(&s,1,2));
    ref_init(&s);RefEnvelope e=event(0,1,1);
    assert(!ref_admit(&s,&e)&&ref_take(&s)==1);
    assert(!ref_reset(&s,0));complete(&s,0); /* factual refusal */
    assert(!ref_effective(&s,0)&&!ref_source_cleared(&s,0,2));
}
static void changed_target_duplicate(void)
{
    RefTaggedSink s;ref_init(&s);empty_sink();RefEnvelope e=event(0,1,1);
    assert(!ref_admit(&s,&e)&&ref_take(&s)==1);complete(&s,1);
    s.generation=2;e.sequence=2;
    assert(!ref_admit(&s,&e)&&ref_take(&s)==1);
    assert(ref_needs_hardware(&s)==-1);
    assert(ref_complete(&s,s.ticket,s.flight.epoch,1)==-1&&s.inflight);
    complete(&s,0);
    assert(s.held[0][0]&&s.held_generation[0][0]==1);
    assert(!ref_reset(&s,0)&&ref_release(&s,0,0,2,2,1)==-1);
    assert(ref_release(&s,0,0,2,1,1)==2&&!ref_source_cleared(&s,0,2));
}
static void aggregate_normal_up(void)
{
    RefTaggedSink s;ref_init(&s);empty_sink();
    RefEnvelope e=event(0,1,1);
    assert(!ref_admit(&s,&e)&&ref_take(&s)==1&&ref_needs_hardware(&s)==1);complete(&s,1);
    e=event(1,1,1);
    assert(!ref_admit(&s,&e)&&ref_take(&s)==1&&!ref_needs_hardware(&s));complete(&s,1);
    e=event(0,2,0);
    assert(!ref_admit(&s,&e)&&ref_take(&s)==1&&!ref_needs_hardware(&s));complete(&s,1);
    assert(ref_effective(&s,0));
    e=event(1,2,0);
    assert(!ref_admit(&s,&e)&&ref_take(&s)==1&&ref_needs_hardware(&s)==1);
    assert(s.flight_hwnd==2&&s.flight_generation==1);complete(&s,1);
    assert(!ref_effective(&s,0));
}
static void refusal_and_fifo(void)
{
    RefTaggedSink s;ref_init(&s);empty_sink();RefEnvelope e=event(0,1,1),bad=e;
    bad.abi=2;assert(ref_admit(&s,&bad)==-1);
    bad=e;bad.reserved=1;assert(ref_admit(&s,&bad)==-1);
    bad=e;bad.size--;assert(ref_admit(&s,&bad)==-1);
    bad=e;bad.source=2;assert(ref_admit(&s,&bad)==-1);
    assert(!s.count&&!s.source[0].last_sequence);
    /* A real sink rejection must not advance the reference owner's cursor. */
    for(unsigned i=0;i<PW_WINE_INPUT_QUEUE;i++)assert(!pw_wine_post_input(&e.event));
    assert(ref_admit(&s,&e)==-1&&!s.count&&!s.source[0].last_sequence);
    empty_sink();
    assert(!ref_admit(&s,&e));assert(ref_admit(&s,&e)==-1);
    e=event(1,1,1);e.event.type=PW_WINE_INPUT_MOUSE_BUTTON;e.event.code=0;
    assert(!ref_admit(&s,&e));
    assert(!ref_reset(&s,0));
    assert(ref_take(&s)==1&&s.flight.source==1);
    complete(&s,1);assert(s.held[1][1]&&!s.held[0][0]);
    assert(!ref_take(&s)&&!ref_source_cleared(&s,0,2));
    assert(!ref_reset(&s,1)&&ref_release(&s,1,1,2,1,1)==2);
    s.source[0].epoch=UINT64_MAX;
    assert(ref_reset(&s,0)==-1&&ref_source_cleared(&s,0,UINT64_MAX)==-1);
}
int main(void)
{
    admission_and_barrier();late_completion_and_identity();
    shared_control_and_cancel();changed_target_duplicate();aggregate_normal_up();refusal_and_fifo();
    puts("actual sink admission + reference tagged barrier passed; mocked completion only");
    return 0;
}
