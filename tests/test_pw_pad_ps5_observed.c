/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Actual native reader/tracker with mocked platform input. Only admission
 * into the separately labelled reference stream is modeled: no production
 * title caller, USER completion or XInput queue is activated/proved here. */
#include "../native/pw_pad_ps5.h"
#include "reference_controller_stream.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static PwPadPs5Data raw[PW_PAD_PS5_BATCH];
static int reported, observed_status;
static PwPadPs5ObservedBatch batch, another, saved;
static int user_init(const void *p) { assert(!p); return 0; }
static int user_get(int32_t *u) { *u=42; return 0; }
static int end(void) { return 0; }
static int pad_init(void) { return 0; }
static int pad_open(int32_t u,int32_t t,int32_t i,const void *p)
{ assert(u==42 && !t && !i && !p); return 7; }
static int pad_read(int32_t h,PwPadPs5Data *out,int32_t capacity)
{
    assert(h==7 && capacity==PW_PAD_PS5_BATCH);
    unsigned count=reported>PW_PAD_PS5_BATCH ? PW_PAD_PS5_BATCH :
                   reported>0 ? (unsigned)reported : 0;
    memcpy(out,raw,count*sizeof(*out));
    return reported;
}
static int pad_close(int32_t h) { assert(h==7); return 0; }
static const PwPadPs5Ops ops={user_init,user_get,end,pad_init,pad_open,pad_read,pad_close,NULL};
static const PwPadKeyMap map[]={{1,0x20,0,0,"button"}};

static void prepare(unsigned count,uint64_t first)
{
    memset(raw,0,sizeof(raw));
    for(unsigned i=0;i<count;i++) {
        raw[i].connected=1;raw[i].connected_count=1;raw[i].timestamp=first+i;
        raw[i].left_stick=raw[i].right_stick=(PwPadPs5Stick){128,128};
    }
    reported=(int)count;
}
static void compare_read(PwPadPs5 *legacy,PwPadPs5 *observed)
{
    int expected=pw_pad_ps5_read(legacy);
    observed_status=pw_pad_ps5_read_observed(observed,&batch);
    assert(observed_status==expected);
    /* Both structs are zero-initialized by the real open path and share the
     * same immutable ops/map. Existing struct layouts are unchanged. */
    assert(!memcmp(legacy,observed,sizeof(*legacy)));
    assert(batch.count<=PW_PAD_PS5_BATCH && batch.native_read_rc==reported);
}
static int reference_admit(PwRefStream *stream,const PwPadPs5ObservedBatch *input,int read_status)
{
    uint32_t buttons[PW_PAD_PS5_BATCH];
    if(read_status!=PW_OK)return PW_REF_INVALID;
    assert(input->count<=PW_PAD_PS5_BATCH);
    if(input->loss_flags) { (void)pw_ref_reset(stream); return PW_REF_RESET; }
    for(uint32_t i=0;i<input->count;i++)buttons[i]=input->records[i].sample.buttons;
    return pw_ref_publish(stream,buttons,input->count);
}
static void ack_both(PwRefStream *s)
{
    PwRefRecord r;
    for(unsigned i=0;i<PW_REF_CONSUMERS;i++) {
        assert(pw_ref_take(s,i,&r)==PW_REF_RESET);
        assert(pw_ref_ack_reset(s,i,r.epoch)==PW_REF_RECORD);
    }
}
static void drain(PwRefStream *s,unsigned count,const uint32_t *expected)
{
    PwRefRecord r;
    for(unsigned c=0;c<PW_REF_CONSUMERS;c++) {
        for(unsigned i=0;i<count;i++) {
            assert(pw_ref_take(s,c,&r)==PW_REF_RECORD);
            assert(r.buttons==expected[i]);
        }
        assert(pw_ref_take(s,c,&r)==PW_REF_EMPTY);
    }
}
static void test_actual_history(void)
{
    PwPadPs5 legacy,observed;
    assert(pw_pad_ps5_open(&legacy,&ops,map,1)==PW_OK);
    assert(pw_pad_ps5_open(&observed,&ops,map,1)==PW_OK);
    prepare(4,1);
    for(unsigned i=0;i<4;i++)raw[i].buttons=i%2?0:1;
    raw[0].left_stick.x=255;raw[0].r2=255;
    raw[0].touch_data.fingers=1;raw[0].touch_data.touch[0].x=500;
    compare_read(&legacy,&observed);
    assert(batch.count==4 && !batch.loss_flags);
    assert(batch.records[0].left_stick.x==255 && batch.records[0].r2==255);
    assert(batch.records[0].touch_data.touch[0].x==500);
    assert(batch.records[3].left_stick.x==128 && !batch.records[3].r2);
    assert(observed.left_stick.x==128 && !observed.r2);
    PwRefStream stream; assert(!pw_ref_init(&stream));
    assert(reference_admit(&stream,&batch,observed_status)==PW_REF_RECORD);
    const uint32_t taps[]={1,0,1,0};drain(&stream,4,taps);
    saved=batch;
    prepare(2,5);raw[0].buttons=2;
    assert(pw_pad_ps5_read_observed(&observed,&another)==PW_OK);
    assert(!memcmp(&batch,&saved,sizeof(batch))); /* owned, not stack-backed */
    assert(pw_pad_ps5_read(&legacy)==PW_OK);
    assert(!memcmp(&legacy,&observed,sizeof(legacy)));

    /* Mix stale records with two genuinely fresh records; stale state must
     * neither enter the observed history nor change compatibility output. */
    prepare(4,5);
    raw[0].timestamp=6;raw[0].buttons=1;
    raw[1].timestamp=7;raw[1].buttons=2;
    raw[2].timestamp=3;raw[2].buttons=1;
    raw[3].timestamp=8;
    compare_read(&legacy,&observed);
    assert(batch.count==2 && batch.records[0].sample.timestamp_us==7 &&
           batch.records[0].sample.buttons==2 && batch.records[1].sample.timestamp_us==8);
    prepare(0,0);compare_read(&legacy,&observed);
    assert(!batch.count && !batch.loss_flags);

    /* Zero timestamps are accepted in read order, exactly as the old reader. */
    prepare(2,0);raw[1].timestamp=0;raw[0].buttons=1;
    compare_read(&legacy,&observed);
    assert(batch.count==2 && !batch.loss_flags &&
           !batch.records[0].sample.timestamp_us && !batch.records[1].sample.timestamp_us);

    prepare(PW_PAD_PS5_BATCH,100);
    for(unsigned i=0;i<PW_PAD_PS5_BATCH;i++)raw[i].buttons=i%2;
    compare_read(&legacy,&observed);
    assert(batch.count==PW_PAD_PS5_BATCH && !batch.loss_flags);
    for(unsigned i=0;i<PW_PAD_PS5_BATCH;i++)
        assert(batch.records[i].sample.timestamp_us==100+i && batch.records[i].sample.buttons==i%2);
    /* The reference ring is deliberately smaller: failure is atomic. */
    assert(reference_admit(&stream,&batch,observed_status)==PW_REF_OVERFLOW);
    ack_both(&stream);
    assert(!pw_ref_snapshot(&stream) && stream.blocked);
    prepare(PW_PAD_PS5_BATCH,200);reported=PW_PAD_PS5_BATCH+1;
    compare_read(&legacy,&observed);
    assert(!batch.count && batch.loss_flags==PW_PAD_OBS_INVALID_COUNT);
    assert(reference_admit(&stream,&batch,observed_status)==PW_REF_RESET);
    pw_ref_destroy(&stream);
    assert(pw_pad_ps5_close(&legacy)==PW_OK && pw_pad_ps5_close(&observed)==PW_OK);
}
static void test_loss_positions(void)
{
    for(unsigned reason=0;reason<3;reason++) for(unsigned position=0;position<3;position++) {
        PwPadPs5 legacy,observed;PwRefStream stream;
        assert(pw_pad_ps5_open(&legacy,&ops,map,1)==PW_OK);
        assert(pw_pad_ps5_open(&observed,&ops,map,1)==PW_OK);
        assert(!pw_ref_init(&stream));
        prepare(1,1);compare_read(&legacy,&observed);
        assert(!batch.loss_flags); /* first generation is not a discontinuity */
        prepare(3,2);raw[0].buttons=1;
        uint32_t flag=reason==0?PW_PAD_OBS_INTERCEPTED:
                      reason==1?PW_PAD_OBS_DISCONNECTED:PW_PAD_OBS_GENERATION;
        if(reason==0)raw[position].buttons|=0x80000000u;
        if(reason==1)raw[position].connected=0;
        if(reason==2)for(unsigned i=position;i<3;i++)raw[i].connected_count=2;
        compare_read(&legacy,&observed);
        assert(batch.count==3 && (batch.loss_flags&flag));
        if(reason!=2) {
            assert(batch.records[position].left_stick.x==128);
            assert(!batch.records[position].r2 && !batch.records[position].touch_data.fingers);
        }
        assert(reference_admit(&stream,&batch,observed_status)==PW_REF_RESET);
        ack_both(&stream);
        assert(stream.blocked && !pw_ref_snapshot(&stream));
        /* Neutral at the end of a loss batch cannot rearm. Only a later
         * usable batch can. Empty calls and held input stay suppressed. */
        prepare(0,0);compare_read(&legacy,&observed);
        assert(reference_admit(&stream,&batch,observed_status)==PW_REF_RECORD && stream.blocked);
        prepare(1,5);raw[0].buttons=1;
        if(reason==2)raw[0].connected_count=2;
        compare_read(&legacy,&observed);
        assert(!batch.loss_flags && reference_admit(&stream,&batch,observed_status)==PW_REF_RECORD && stream.blocked);
        raw[0].buttons=0;raw[0].timestamp=6;
        compare_read(&legacy,&observed);
        assert(reference_admit(&stream,&batch,observed_status)==PW_REF_RECORD && !stream.blocked);
        pw_ref_destroy(&stream);
        assert(pw_pad_ps5_close(&legacy)==PW_OK && pw_pad_ps5_close(&observed)==PW_OK);
    }
}
static void test_error_and_preconditions(void)
{
    PwPadPs5 legacy,observed;
    assert(pw_pad_ps5_open(&legacy,&ops,map,1)==PW_OK);
    assert(pw_pad_ps5_open(&observed,&ops,map,1)==PW_OK);
    prepare(1,1);raw[0].buttons=1;compare_read(&legacy,&observed);
    reported=-9;compare_read(&legacy,&observed);
    assert(!batch.count && batch.loss_flags==PW_PAD_OBS_READ_ERROR && !observed.core.connected);
    memset(&batch,0xff,sizeof(batch));
    observed_status=pw_pad_ps5_read_observed(NULL,&batch);
    assert(observed_status==PW_ERR_PRECONDITION);
    assert(!batch.count && !batch.loss_flags && !batch.native_read_rc);
    PwRefStream stream;assert(!pw_ref_init(&stream));
    assert(reference_admit(&stream,&batch,observed_status)==PW_REF_INVALID);
    assert(stream.epoch==1 && !stream.write && !stream.blocked);
    pw_ref_destroy(&stream);
    assert(pw_pad_ps5_close(&legacy)==PW_OK && pw_pad_ps5_close(&observed)==PW_OK);
}
int main(void)
{
    test_actual_history();test_loss_positions();test_error_and_preconditions();
    puts("observed native reader passed; reference admission only, no production delivery proof");
    return 0;
}
