/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Pure fixed-record/path controls. No socket, filesystem or process operation. */
#include "../native/pw_native_fd_report.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

static const uint32_t parent=17,child=42;
static const uint64_t token=UINT64_C(0x8877665544332211);
static PwNativeFdResult completed(int worker)
{
    PwNativeFdResult r={0};
    r.status=PW_NATIVE_FD_OK;r.stage=PW_NATIVE_FD_COMPLETE;r.api=PW_NATIVE_FD_API_NONE;
    r.local_pid=worker?child:parent;r.reported_peer_pid=worker?parent:child;
    r.observations=PW_NATIVE_FD_CONNECTED|PW_NATIVE_FD_HELLO_OK|PW_NATIVE_FD_QUEUED_RIGHT_OK|
        PW_NATIVE_FD_FORWARD_OK|PW_NATIVE_FD_REVERSE_OK|PW_NATIVE_FD_COMPLETED|
        (worker?PW_NATIVE_FD_REVERSE_EOF:PW_NATIVE_FD_FORWARD_EOF);
    r.peer_observations=worker?0:PW_NATIVE_FD_REVERSE_EOF;
    return r;
}
static void unchanged_failure(const uint8_t *wire,uint32_t p,uint32_t c,uint64_t id)
{
    PwNativeFdResult before,after;
    memset(&before,0xa5,sizeof(before));memcpy(&after,&before,sizeof(after));
    assert(pw_native_fd_report_decode(&after,wire,p,c,id)==-1);
    assert(!memcmp(&after,&before,sizeof(after)));
}
static void invalid_encode(const PwNativeFdResult *r,uint32_t p,uint32_t c,uint64_t id)
{
    uint8_t wire[PW_NATIVE_FD_REPORT_BYTES],before[PW_NATIVE_FD_REPORT_BYTES];
    memset(wire,0xa5,sizeof(wire));memcpy(before,wire,sizeof(wire));
    assert(pw_native_fd_report_encode(wire,p,c,id,r)==-1&&!memcmp(wire,before,sizeof(wire)));
}
static void test_success_and_every_bit(void)
{
    PwNativeFdResult input=completed(1),out;
    uint8_t wire[PW_NATIVE_FD_REPORT_BYTES],bad[PW_NATIVE_FD_REPORT_BYTES],other[PW_NATIVE_FD_REPORT_BYTES];
    assert(PW_NATIVE_FD_REPORT_BYTES==80&&PW_NATIVE_FD_REPORT_RESERVE_MS==750);
    assert(pw_native_fd_result_matches(&input,child,parent,1));
    assert(!pw_native_fd_result_matches(&input,parent,child,0));
    assert(!pw_native_fd_report_encode(wire,parent,child,token,&input));
    assert(!memcmp(wire,"PFDR",4)&&wire[4]==1&&wire[8]==80&&wire[12]==2&&wire[24]==4);
    assert(wire[16]==17&&wire[20]==42&&wire[32]==0x11&&wire[39]==0x88);
    assert(!pw_native_fd_report_decode(&out,wire,parent,child,token));
    assert(pw_native_fd_result_matches(&out,child,parent,1));
    assert(!out.peer_identity_verified&&!out.clock_observed&&!out.last_clock_ms);
    /* Every single-bit change to the canonical success record is rejected. */
    for(unsigned byte=0;byte<sizeof(wire);++byte)for(unsigned bit=0;bit<8;++bit){
        memcpy(bad,wire,sizeof(bad));bad[byte]^=(uint8_t)(1u<<bit);unchanged_failure(bad,parent,child,token);
    }
    unchanged_failure(wire,parent+1,child,token);unchanged_failure(wire,parent,child+1,token);
    unchanged_failure(wire,child,parent,token);unchanged_failure(wire,parent,child,token^1);
    unchanged_failure(wire,parent,child,token^(UINT64_C(1)<<63));unchanged_failure(wire,parent,child,0);
    unchanged_failure(NULL,parent,child,token);
    assert(pw_native_fd_report_decode(NULL,wire,parent,child,token)==-1);
    /* A peer's clock history is deliberately absent from the wire. */
    input.last_clock_ms=UINT64_MAX;input.clock_observed=1;
    assert(!pw_native_fd_report_encode(other,parent,child,token,&input)&&!memcmp(wire,other,sizeof(wire)));
}
static void test_no_false_success_or_role_confusion(void)
{
    PwNativeFdResult w=completed(1),p=completed(0),bad;
    assert(pw_native_fd_result_matches(&p,parent,child,0));
    invalid_encode(&p,parent,child,token);invalid_encode(NULL,parent,child,token);
    for(unsigned bit=0;bit<32;++bit){
        bad=w;bad.observations^=UINT32_C(1)<<bit;
        assert(!pw_native_fd_result_matches(&bad,child,parent,1));invalid_encode(&bad,parent,child,token);
        bad=w;bad.peer_observations=UINT32_C(1)<<bit;invalid_encode(&bad,parent,child,token);
    }
    bad=w;bad.cleanup_failed=1;invalid_encode(&bad,parent,child,token);
    bad=w;bad.peer_identity_verified=1;invalid_encode(&bad,parent,child,token);
    bad=w;bad.raw_result=-1;invalid_encode(&bad,parent,child,token);
    bad=w;bad.api=PW_NATIVE_FD_API_CLOSE;invalid_encode(&bad,parent,child,token);
    bad=w;bad.stage=PW_NATIVE_FD_FINISH;invalid_encode(&bad,parent,child,token);
    bad=w;bad.local_pid=0;invalid_encode(&bad,parent,child,token);
    bad=w;bad.reported_peer_pid=0;invalid_encode(&bad,parent,child,token);
    for(unsigned i=0;i<4;++i){
        const uint32_t invalid[]={0,1,UINT32_C(0x80000000),UINT32_MAX};
        invalid_encode(&w,invalid[i],child,token);invalid_encode(&w,parent,invalid[i],token);
    }
    invalid_encode(&w,parent,parent,token);invalid_encode(&w,parent,child,0);
    assert(pw_native_fd_report_encode(NULL,parent,child,token,&w)==-1);
}
static void test_failure_diagnostics(void)
{
    const int64_t raw[]={INT64_MIN,-37,-1,0,1,INT64_MAX};
    for(int status=PW_NATIVE_FD_EOF;status<PW_NATIVE_FD_OK;++status)for(unsigned i=0;i<sizeof(raw)/sizeof(raw[0]);++i){
        PwNativeFdResult input={0},output;uint8_t wire[PW_NATIVE_FD_REPORT_BYTES];
        input.status=(PwNativeFdStatus)status;input.stage=PW_NATIVE_FD_REVERSE;
        input.api=PW_NATIVE_FD_API_RECVMSG;input.raw_result=raw[i];input.local_pid=child;input.reported_peer_pid=parent;
        input.observations=PW_NATIVE_FD_CONNECTED|PW_NATIVE_FD_HELLO_OK;input.cleanup_failed=i&1;
        assert(!pw_native_fd_report_encode(wire,parent,child,token,&input));
        assert(!pw_native_fd_report_decode(&output,wire,parent,child,token));
        assert(output.status==input.status&&output.stage==input.stage&&output.api==input.api&&output.raw_result==raw[i]);
        assert(output.cleanup_failed==input.cleanup_failed&&output.observations==input.observations);
        assert(!pw_native_fd_result_matches(&output,child,parent,1));
        input.stage=PW_NATIVE_FD_COMPLETE;invalid_encode(&input,parent,child,token);
        input.stage=PW_NATIVE_FD_REVERSE;input.observations|=PW_NATIVE_FD_COMPLETED;invalid_encode(&input,parent,child,token);
    }
    {
        PwNativeFdResult early={0},decoded;uint8_t wire[PW_NATIVE_FD_REPORT_BYTES];
        early.status=PW_NATIVE_FD_CLOCK;early.api=PW_NATIVE_FD_API_CLOCK;early.raw_result=-37;
        assert(!pw_native_fd_report_encode(wire,parent,child,token,&early));
        assert(!pw_native_fd_report_decode(&decoded,wire,parent,child,token));
        assert(!decoded.local_pid&&!decoded.reported_peer_pid&&!decoded.peer_identity_verified);
        early.status=(PwNativeFdStatus)1;invalid_encode(&early,parent,child,token);
        early.status=(PwNativeFdStatus)(PW_NATIVE_FD_EOF-1);invalid_encode(&early,parent,child,token);
        early.status=PW_NATIVE_FD_CLOCK;early.stage=(PwNativeFdStage)-1;invalid_encode(&early,parent,child,token);
        early.stage=(PwNativeFdStage)(PW_NATIVE_FD_COMPLETE+1);invalid_encode(&early,parent,child,token);
        early.stage=PW_NATIVE_FD_VALIDATE;early.api=(PwNativeFdApi)-1;invalid_encode(&early,parent,child,token);
        early.api=(PwNativeFdApi)(PW_NATIVE_FD_API_UNLINK+1);invalid_encode(&early,parent,child,token);
        early.api=PW_NATIVE_FD_API_CLOCK;early.cleanup_failed=2;invalid_encode(&early,parent,child,token);
    }
}
static void test_failure_progress_binding(void)
{
    const uint32_t prefixes[]={0,1,3,7,15,111};
    for(unsigned mask=0;mask<128;++mask){
        PwNativeFdResult r={0};r.status=PW_NATIVE_FD_OS;r.stage=PW_NATIVE_FD_REVERSE;r.api=PW_NATIVE_FD_API_RECVMSG;
        r.local_pid=child;r.reported_peer_pid=parent;r.observations=mask;
        int valid=0;for(unsigned i=0;i<sizeof(prefixes)/sizeof(prefixes[0]);++i)if(mask==prefixes[i])valid=1;
        if(!valid)invalid_encode(&r,parent,child,token);
    }
    for(unsigned i=2;i<sizeof(prefixes)/sizeof(prefixes[0]);++i){
        PwNativeFdResult r={0},bad;uint8_t wire[PW_NATIVE_FD_REPORT_BYTES];
        r.status=PW_NATIVE_FD_OS;r.stage=PW_NATIVE_FD_REVERSE;r.api=PW_NATIVE_FD_API_RECVMSG;
        r.local_pid=child;r.reported_peer_pid=parent;r.observations=prefixes[i];
        assert(!pw_native_fd_report_encode(wire,parent,child,token,&r));
        bad=r;bad.local_pid=0;invalid_encode(&bad,parent,child,token);
        bad=r;bad.reported_peer_pid=0;invalid_encode(&bad,parent,child,token);
        memset(wire+72,0,4);unchanged_failure(wire,parent,child,token);
        assert(!pw_native_fd_report_encode(wire,parent,child,token,&r));
        memset(wire+76,0,4);unchanged_failure(wire,parent,child,token);
    }
}
static void test_paths(void)
{
    struct Guarded { unsigned char before[16];char data[PW_NATIVE_FD_PATH_CAP];unsigned char after[16]; } d,s;
    char expected[PW_NATIVE_FD_PATH_CAP],socket_expected[PW_NATIVE_FD_PATH_CAP];
    const uint32_t pids[]={2,17,INT32_MAX};const uint64_t tokens[]={1,token,UINT64_MAX};
    for(unsigned i=0;i<3;++i)for(unsigned j=0;j<3;++j){
        memset(&d,0xa5,sizeof(d));memset(&s,0xa5,sizeof(s));
        assert(!pw_native_fd_paths(pids[i],tokens[j],d.data,s.data));
        assert(snprintf(expected,sizeof(expected),"/data/prospero-win/fd-%08x-%016llx",pids[i],(unsigned long long)tokens[j])>0);
        assert(snprintf(socket_expected,sizeof(socket_expected),"%s/s",expected)>0);
        assert(!strcmp(d.data,expected)&&!strcmp(s.data,socket_expected));
        assert(strlen(s.data)<PW_NATIVE_FD_PATH_CAP&&!strstr(s.data,".."));
        for(unsigned k=0;k<16;++k)assert(d.before[k]==0xa5&&d.after[k]==0xa5&&s.before[k]==0xa5&&s.after[k]==0xa5);
    }
    const uint32_t invalid[]={0,1,UINT32_C(0x80000000),UINT32_MAX};
    for(unsigned i=0;i<4;++i){
        memset(&d,0xa5,sizeof(d));memset(&s,0xa5,sizeof(s));
        struct Guarded old_d,old_s;memcpy(&old_d,&d,sizeof(d));memcpy(&old_s,&s,sizeof(s));
        assert(pw_native_fd_paths(invalid[i],token,d.data,s.data)==-1);
        assert(!memcmp(&d,&old_d,sizeof(d))&&!memcmp(&s,&old_s,sizeof(s)));
    }
    assert(pw_native_fd_paths(parent,0,d.data,s.data)==-1);
    assert(pw_native_fd_paths(parent,token,NULL,s.data)==-1);
    assert(pw_native_fd_paths(parent,token,d.data,NULL)==-1);
}
int main(void)
{
    test_success_and_every_bit();test_no_false_success_or_role_confusion();test_failure_diagnostics();test_failure_progress_binding();test_paths();
    puts("native FD report/path: canonical 80-byte binding, 640 bit mutations, exact observations, signed errors and bounded names passed; no transport executed");return 0;
}
