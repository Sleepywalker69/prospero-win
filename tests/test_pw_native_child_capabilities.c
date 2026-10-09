/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Ordered capability phase over scripted bytes; no native descriptor APIs. */
#include "../native/pw_native_child_protocol.h"
#include "../native/pw_native_fd_report.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

enum { NORMAL, FAIL_EXPLICIT, FAIL_NO_ERROR, EXPIRE_STAGE, EXPIRE_TOTAL, STOP,
       ALTER_STAGE, ALTER_TOTAL };
typedef struct {
    uint8_t input[6*PW_NC_FRAME_BYTES+PW_NATIVE_FD_REPORT_BYTES];
    uint8_t output[6*PW_NC_FRAME_BYTES+PW_NATIVE_FD_REPORT_BYTES];
    size_t input_size,position,output_size,chunk;
    uint64_t now;
    int worker,mode,cancelled,calls,capability_progress;
} Fixture;
static const uint64_t token=UINT64_C(0x8877665544332211);
static int clock_ms(void *context,uint64_t *value) { *value=((Fixture *)context)->now;return 0; }
static int cancelled(void *context) { return ((Fixture *)context)->cancelled; }
static int wait_ms(void *context,unsigned value) { ((Fixture *)context)->now+=value;return 0; }
static void progress(void *context,unsigned stage)
{ if(stage==PW_NC_CAPABILITIES)++((Fixture *)context)->capability_progress; }
static long read_bytes(void *context,void *bytes,size_t size,unsigned timeout)
{
    Fixture *f=context;assert(timeout>0&&timeout<=PW_NC_STAGE_MS);
    if(size>f->input_size-f->position)size=f->input_size-f->position;
    if(f->chunk&&size>f->chunk)size=f->chunk;
    memcpy(bytes,f->input+f->position,size);f->position+=size;return (long)size;
}
static long write_bytes(void *context,const void *bytes,size_t size,unsigned timeout)
{
    Fixture *f=context;assert(timeout>0&&timeout<=PW_NC_STAGE_MS);
    if(f->chunk&&size>f->chunk)size=f->chunk;
    assert(size<=sizeof(f->output)-f->output_size);memcpy(f->output+f->output_size,bytes,size);f->output_size+=size;return (long)size;
}
static PwNativeFdResult successful_report(void)
{
    PwNativeFdResult r={0};r.status=PW_NATIVE_FD_OK;r.stage=PW_NATIVE_FD_COMPLETE;
    r.local_pid=42;r.reported_peer_pid=17;r.observations=239;return r;
}
static int capability(void *context,PwNativeChildIo *io,const PwNativeChildFrame *frame)
{
    Fixture *f=context;uint8_t report[PW_NATIVE_FD_REPORT_BYTES];PwNativeFdResult r=successful_report();
    ++f->calls;assert(f->calls==1&&f->capability_progress==1);
    assert(frame->sequence==3&&frame->parent_pid==17&&frame->child_pid==42&&frame->child_ppid==7&&frame->correlation==token);
    assert(!strcmp(frame->build_id,"capability-fixture"));
    assert(frame->kind==(f->worker?PW_NC_ECHO_REPLY:PW_NC_ECHO));
    assert(f->position==(size_t)(f->worker?3:4)*PW_NC_FRAME_BYTES);
    assert(f->output_size==(size_t)(f->worker?4:3)*PW_NC_FRAME_BYTES);
    if(f->mode==FAIL_EXPLICIT){errno=EACCES;return -1;}
    if(f->mode==FAIL_NO_ERROR){errno=0;return -1;}
    if(f->worker){
        assert(!pw_native_fd_report_encode(report,17,42,token,&r));
        if(pw_native_child_send(io,report,sizeof(report)))return -1;
    }else{
        if(pw_native_child_receive(io,report,sizeof(report)))return -1;
        if(pw_native_fd_report_decode(&r,report,17,42,token)){errno=EPROTO;return -1;}
        if(!pw_native_fd_result_matches(&r,42,17,1)){errno=EIO;return -1;}
    }
    if(f->mode==EXPIRE_STAGE)f->now=io->stage_end;
    if(f->mode==EXPIRE_TOTAL)f->now=io->total_end;
    if(f->mode==STOP)f->cancelled=1;
    if(f->mode==ALTER_STAGE)++io->stage_end;
    if(f->mode==ALTER_TOTAL)++io->total_end;
    return 0;
}
static PwNativeChildIo io_for(Fixture *f,int enabled)
{
    PwNativeChildIo io={0};io.context=f;io.clock_ms=clock_ms;io.receive=read_bytes;io.send=write_bytes;
    io.wait_ms=wait_ms;io.cancelled=cancelled;io.progress=progress;io.capabilities=enabled?capability:NULL;return io;
}
static void frame(Fixture *f,uint32_t kind,uint32_t sequence)
{
    PwNativeChildFrame value={0};value.kind=kind;value.sequence=sequence;value.child_pid=42;value.child_ppid=7;
    if(kind!=PW_NC_HELLO){value.parent_pid=17;value.correlation=token;}
    memcpy(value.build_id,"capability-fixture",sizeof("capability-fixture"));
    assert(!pw_native_child_encode(f->input+f->input_size,&value));f->input_size+=PW_NC_FRAME_BYTES;
}
static Fixture fixture(int worker,int enabled)
{
    Fixture f={0};f.worker=worker;f.now=100;
    if(!worker)frame(&f,PW_NC_HELLO,0);
    for(unsigned i=1;i<=3;++i)frame(&f,worker?PW_NC_ECHO:PW_NC_ECHO_REPLY,i);
    if(enabled&&!worker){
        PwNativeFdResult report=successful_report();
        assert(!pw_native_fd_report_encode(f.input+f.input_size,17,42,token,&report));f.input_size+=PW_NATIVE_FD_REPORT_BYTES;
    }
    frame(&f,worker?PW_NC_STOP:PW_NC_STOP_ACK,4);return f;
}
static int run(Fixture *f,int enabled,PwNativeChildResult *result)
{
    PwNativeChildIo io=io_for(f,enabled);errno=0;
    return f->worker?pw_native_child_worker(&io,42,7,"capability-fixture"):
        pw_native_child_parent(&io,17,token,"capability-fixture",result);
}
static void no_stop_or_ack(const Fixture *f)
{
    const size_t before=(size_t)(f->worker?4:3)*PW_NC_FRAME_BYTES;
    assert(f->output_size==before||(f->worker&&f->output_size==before+PW_NATIVE_FD_REPORT_BYTES));
}
static void test_order_and_legacy(void)
{
    for(int worker=0;worker<2;++worker)for(unsigned chunk=1;chunk<=PW_NC_FRAME_BYTES+1;++chunk){
        Fixture f=fixture(worker,1);f.chunk=chunk;PwNativeChildResult r={0};
        assert(!run(&f,1,&r)&&f.calls==1&&f.capability_progress==1&&f.position==f.input_size);
        if(worker){
            PwNativeFdResult report;PwNativeChildFrame ack;
            assert(!pw_native_fd_report_decode(&report,f.output+4*PW_NC_FRAME_BYTES,17,42,token));
            assert(pw_native_fd_result_matches(&report,42,17,1));
            assert(!pw_native_child_decode(&ack,f.output+4*PW_NC_FRAME_BYTES+PW_NATIVE_FD_REPORT_BYTES)&&ack.kind==PW_NC_STOP_ACK);
        }else assert(r.echoes==3&&r.capabilities_complete&&r.stop_ack&&r.stream_closed&&r.stage==PW_NC_CLOSED);
        f=fixture(worker,0);f.chunk=chunk;memset(&r,0,sizeof(r));
        assert(!run(&f,0,&r)&&!f.calls&&!f.capability_progress);
        if(!worker)assert(!r.capabilities_complete&&r.stop_ack&&r.stream_closed);
    }
}
static void test_failure_deadlines_and_cancellation(void)
{
    const int errors[]={0,EACCES,EIO,ETIMEDOUT,ETIMEDOUT,ECANCELED,EPROTO,EPROTO};
    for(int worker=0;worker<2;++worker)for(int mode=FAIL_EXPLICIT;mode<=ALTER_TOTAL;++mode){
        Fixture f=fixture(worker,1);f.mode=mode;f.chunk=7;PwNativeChildResult r={0};
        assert(run(&f,1,&r)==-1&&errno==errors[mode]&&f.calls==1);no_stop_or_ack(&f);
        if(!worker)assert(r.echoes==3&&r.stage==PW_NC_CAPABILITIES&&r.error==errors[mode]&&!r.capabilities_complete&&!r.stop_ack&&!r.stream_closed);
    }
}
static void test_report_truncation_and_failure_cannot_pass(void)
{
    for(unsigned cut=0;cut<PW_NATIVE_FD_REPORT_BYTES;++cut){
        Fixture f=fixture(0,1);f.input_size=4*PW_NC_FRAME_BYTES+cut;f.chunk=3;PwNativeChildResult r={0};
        assert(run(&f,1,&r)==-1&&r.error==ECONNRESET&&f.calls==1);no_stop_or_ack(&f);
        assert(!r.capabilities_complete&&!r.stop_ack&&!r.stream_closed);
    }
    {
        Fixture f=fixture(0,1);PwNativeChildResult r={0};f.input[4*PW_NC_FRAME_BYTES+32]^=1;
        assert(run(&f,1,&r)==-1&&r.error==EPROTO&&!r.capabilities_complete);no_stop_or_ack(&f);
        f=fixture(0,1);PwNativeFdResult failure={0};failure.status=PW_NATIVE_FD_OS;failure.stage=PW_NATIVE_FD_CONNECT;failure.api=PW_NATIVE_FD_API_CONNECT;failure.raw_result=-1;
        assert(!pw_native_fd_report_encode(f.input+4*PW_NC_FRAME_BYTES,17,42,token,&failure));
        assert(run(&f,1,&r)==-1&&r.error==EIO&&!r.capabilities_complete&&!r.stop_ack);no_stop_or_ack(&f);
    }
}
int main(void)
{
    test_order_and_legacy();test_failure_deadlines_and_cancellation();test_report_truncation_and_failure_cannot_pass();
    puts("native capability callback: after echo 3, before STOP, bounded reports/failures and unchanged HELLO-only mode passed; no sockets executed");return 0;
}
