/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Original pure codec controls: no credentials, events, RNG or native I/O. */
#include "../native/pw_native_peer_protocol.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

static PwNativeChildFrame session(void)
{
    PwNativeChildFrame s={0};
    s.kind=PW_NC_ECHO;s.sequence=3;s.parent_pid=101;s.child_pid=202;s.child_ppid=303;
    s.correlation=UINT64_C(0x1122334455667788);
    memcpy(s.build_id,"0123456789abcdef0123456789abcdef01234567",40);
    return s;
}
static PwNativePeerRecord record(const PwNativeChildFrame *s,unsigned kind)
{
    PwNativePeerRecord r;
    memset(&r,0xa5,sizeof(r));pw_native_peer_record(&r,s,kind);
    if(kind==PW_NP_WORKER_RESULT)r.observations=7;
    if(kind==PW_NP_CHALLENGE||kind==PW_NP_WORKER_ECHO)
        for(unsigned i=0;i<PW_NP_CHALLENGE_BYTES;i++)r.challenge[i]=(uint8_t)(0x81u+i);
    return r;
}
static void rejected_wire(const uint8_t *wire,const PwNativeChildFrame *s)
{
    PwNativePeerRecord before,after;
    memset(&before,0x5a,sizeof(before));memcpy(&after,&before,sizeof(after));
    assert(pw_native_peer_decode(&after,wire,s)==-1);
    assert(!memcmp(&before,&after,sizeof(before)));
}
static void rejected_record(const PwNativePeerRecord *r)
{
    uint8_t before[PW_NP_RECORD_BYTES],after[PW_NP_RECORD_BYTES];
    memset(before,0xa5,sizeof(before));memcpy(after,before,sizeof(after));
    assert(pw_native_peer_encode(after,r)==-1&&!memcmp(before,after,sizeof(before)));
    assert(!pw_native_peer_worker_success(r));
}
static void round_trip(const PwNativePeerRecord *r,const PwNativeChildFrame *s)
{
    struct { uint8_t before[16],wire[PW_NP_RECORD_BYTES],after[16]; } guarded;
    PwNativePeerRecord decoded;uint8_t second[PW_NP_RECORD_BYTES];
    memset(&guarded,0xa5,sizeof(guarded));
    assert(!pw_native_peer_encode(guarded.wire,r));
    for(unsigned i=0;i<16;i++)assert(guarded.before[i]==0xa5&&guarded.after[i]==0xa5);
    assert(!pw_native_peer_decode(&decoded,guarded.wire,s));
    assert(!pw_native_peer_encode(second,&decoded)&&!memcmp(second,guarded.wire,sizeof(second)));
    assert(decoded.kind==r->kind&&decoded.status==r->status&&decoded.raw_result==r->raw_result);
    assert(decoded.observations==r->observations&&decoded.phase==r->phase);
    assert(!memcmp(decoded.challenge,r->challenge,PW_NP_CHALLENGE_BYTES));
}
static void exact_layout_and_kind_contract(void)
{
    PwNativeChildFrame s=session();PwNativePeerRecord r=record(&s,PW_NP_WORKER_RESULT);
    uint8_t wire[PW_NP_RECORD_BYTES],expected[PW_NP_RECORD_BYTES]={
        'P','W','P','E',1,0,0,0,5,0,0,0,0,0,0,0,
        101,0,0,0,202,0,0,0,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,
        5,0,0,0,7,0,0,0
    };
    assert(PW_NP_RECORD_BYTES==128&&PW_NP_CHALLENGE_BYTES==32&&PW_NC_BUILD_BYTES==48);
    assert(PW_NP_REPORT_RESERVE_MS==750&&PW_NP_SUCCESS_EXIT==37);
    memcpy(expected+40,s.build_id,48);
    assert(!pw_native_peer_encode(wire,&r)&&!memcmp(wire,expected,sizeof(wire)));
    assert(pw_native_peer_worker_success(&r));
    for(unsigned kind=PW_NP_WORKER_READY;kind<=PW_NP_WORKER_RESULT;kind++){
        r=record(&s,kind);round_trip(&r,&s);
        assert(!!pw_native_peer_worker_success(&r)==(kind==PW_NP_WORKER_RESULT));
        for(unsigned phase=0;phase<=PW_NP_COMPLETE+1;phase++){
            if(phase==r.phase)continue;
            PwNativePeerRecord bad=r;bad.phase=phase;rejected_record(&bad);
        }
        if(kind==PW_NP_CHALLENGE||kind==PW_NP_WORKER_ECHO){
            /* Shape validation does not pretend to measure entropy quality. */
            memset(r.challenge,0,sizeof(r.challenge));round_trip(&r,&s);
            memset(r.challenge,0xff,sizeof(r.challenge));round_trip(&r,&s);
        }else for(unsigned i=0;i<32;i++){
            PwNativePeerRecord bad=r;bad.challenge[i]=1;rejected_record(&bad);
        }
    }
}
static void every_success_bit_and_session_binding(void)
{
    PwNativeChildFrame s=session();PwNativePeerRecord r=record(&s,PW_NP_WORKER_RESULT);
    uint8_t wire[PW_NP_RECORD_BYTES],bad[PW_NP_RECORD_BYTES];
    assert(!pw_native_peer_encode(wire,&r));
    for(unsigned byte=0;byte<sizeof(wire);byte++)for(unsigned bit=0;bit<8;bit++){
        memcpy(bad,wire,sizeof(bad));bad[byte]^=(uint8_t)(1u<<bit);rejected_wire(bad,&s);
    }
    for(unsigned field=0;field<5;field++){
        PwNativeChildFrame changed=s;
        if(field==0)changed.parent_pid++;
        if(field==1)changed.child_pid++;
        if(field==2)changed.correlation^=UINT64_C(1)<<63;
        if(field==3)changed.build_id[0]='z';
        if(field==4){changed.parent_pid=s.child_pid;changed.child_pid=s.parent_pid;}
        rejected_wire(wire,&changed);
    }
    rejected_wire(wire,NULL);rejected_wire(NULL,&s);
    assert(pw_native_peer_decode(NULL,wire,&s)==-1);
    assert(pw_native_peer_encode(NULL,&r)==-1);rejected_record(NULL);
}
static void invalid_ids_builds_and_success_fields(void)
{
    PwNativeChildFrame s=session();PwNativePeerRecord good=record(&s,PW_NP_WORKER_RESULT),r;
    const uint32_t invalid[]={0,1,UINT32_C(0x80000000),UINT32_MAX};
    for(unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++){
        r=good;r.parent_pid=invalid[i];rejected_record(&r);
        r=good;r.child_pid=invalid[i];rejected_record(&r);
    }
    r=good;r.parent_pid=r.child_pid;rejected_record(&r);
    r=good;r.correlation=0;rejected_record(&r);
    for(unsigned bit=0;bit<32;bit++){
        r=good;r.observations^=UINT32_C(1)<<bit;rejected_record(&r);
    }
    r=good;r.kind=0;rejected_record(&r);r.kind=UINT32_MAX;rejected_record(&r);
    r=good;r.raw_result=1;rejected_record(&r);r.raw_result=-1;rejected_record(&r);
    r=good;r.status=1;rejected_record(&r);r.status=PW_NP_EXIT-1;rejected_record(&r);
    r=good;r.build_id[0]=0;rejected_record(&r);
    const unsigned char invalid_build[]={1,9,10,32,127,128,255};
    for(unsigned i=0;i<sizeof(invalid_build);i++){
        r=good;r.build_id[7]=(char)invalid_build[i];rejected_record(&r);
    }
    r=good;memset(r.build_id,'a',sizeof(r.build_id));rejected_record(&r);
    r=good;r.build_id[47]='x';rejected_record(&r);
    r=good;r.build_id[3]=0;rejected_record(&r);
    for(unsigned length=1;length<PW_NC_BUILD_BYTES;length++){
        PwNativeChildFrame changed=s;memset(changed.build_id,0,sizeof(changed.build_id));
        memset(changed.build_id,'a',length);r=record(&changed,PW_NP_WORKER_RESULT);round_trip(&r,&changed);
    }
    s.parent_pid=2;s.child_pid=INT32_MAX;s.correlation=UINT64_MAX;r=record(&s,PW_NP_WORKER_RESULT);round_trip(&r,&s);
    s.parent_pid=INT32_MAX;s.child_pid=2;s.correlation=1;r=record(&s,PW_NP_WORKER_RESULT);round_trip(&r,&s);
}
static void failure_diagnostics_are_never_success(void)
{
    PwNativeChildFrame s=session();
    const int64_t raw[]={INT64_MIN,-37,-1,0,1,37,INT64_MAX};
    for(int status=PW_NP_EXIT;status<PW_NP_OK;status++)for(unsigned i=0;i<sizeof(raw)/sizeof(raw[0]);i++){
        PwNativePeerRecord r=record(&s,PW_NP_WORKER_RESULT);
        r.status=status;r.raw_result=raw[i];r.observations=PW_NP_WORKER_CREDENTIAL|PW_NP_WORKER_CLOSED;
        assert(!pw_native_peer_worker_success(&r));round_trip(&r,&s);
    }
    for(unsigned mask=0;mask<256;mask++){
        PwNativePeerRecord r=record(&s,PW_NP_WORKER_RESULT);r.status=PW_NP_OS;r.raw_result=-37;r.observations=mask;
        if(mask==0||mask==1||mask==3||mask==4||mask==5||mask==7){
            round_trip(&r,&s);assert(!pw_native_peer_worker_success(&r));
        }else rejected_record(&r);
    }
    for(unsigned phase=0;phase<=PW_NP_COMPLETE+1;phase++){
        PwNativePeerRecord r=record(&s,PW_NP_WORKER_RESULT);r.status=PW_NP_OS;r.phase=phase;r.observations=0;
        if(phase==PW_NP_ARM||phase>PW_NP_REPORT)rejected_record(&r);
        else {round_trip(&r,&s);assert(!pw_native_peer_worker_success(&r));}
    }
    for(unsigned kind=PW_NP_WORKER_READY;kind<PW_NP_WORKER_RESULT;kind++){
        PwNativePeerRecord good=record(&s,kind),r;
        r=good;r.status=PW_NP_OS;rejected_record(&r);
        r=good;r.raw_result=-1;rejected_record(&r);
        r=good;r.observations=1;rejected_record(&r);
    }
}
static void constructor_clears_private_material(void)
{
    PwNativeChildFrame s=session();PwNativePeerRecord r;
    for(unsigned kind=PW_NP_WORKER_READY;kind<=PW_NP_WORKER_RESULT;kind++){
        memset(&r,0x99,sizeof(r));pw_native_peer_record(&r,&s,kind);
        assert(r.kind==kind&&r.parent_pid==s.parent_pid&&r.child_pid==s.child_pid&&r.correlation==s.correlation);
        assert(!memcmp(r.build_id,s.build_id,48)&&!r.status&&!r.raw_result&&!r.observations);
        for(unsigned i=0;i<32;i++)assert(!r.challenge[i]);
        assert(!pw_native_peer_worker_success(&r));
    }
}
int main(void)
{
    exact_layout_and_kind_contract();every_success_bit_and_session_binding();
    invalid_ids_builds_and_success_fields();failure_diagnostics_are_never_success();constructor_clears_private_material();
    puts("native peer codec: 128-byte canonical binding, 1024 success-bit mutations, zero unused nonce, signed failures and no false worker success passed; model only, no native capability verified");
    return 0;
}
