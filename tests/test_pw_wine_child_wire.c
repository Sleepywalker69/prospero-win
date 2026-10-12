/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* All socket/clock/close boundaries are original mocks; no native IO. */
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "../native/pw_wine_child_wire.h"
static int fake_poll(struct pollfd*,nfds_t,int);
static int fake_type(int,int,int,void*,socklen_t*);
static ssize_t fake_send(int,const struct msghdr*,int);
static ssize_t fake_receive(int,struct msghdr*,int);
static int fake_close(int);
#define poll fake_poll
#define getsockopt fake_type
#define sendmsg fake_send
#define recvmsg fake_receive
#define close fake_close
#include "../native/pw_wine_child_wire.c"
#undef poll
#undef getsockopt
#undef sendmsg
#undef recvmsg
#undef close
static struct {
    uint64_t now,advance;
    int recv_cancel,cancelled,clock_error,clock_reverse,poll_rc,type_rc,stream_type,close_rc;
    unsigned no_wait;
    unsigned polls,sends,receives,types,closes;int closed[20],sent_right;
    short revents;ssize_t received,sent;int flags;
    unsigned char bytes[PW_WC_WIRE_BYTES],sent_bytes[PW_WC_WIRE_BYTES];
    _Alignas(struct cmsghdr) unsigned char control[CMSG_SPACE(16*sizeof(int))];size_t controls;
} m;
static PwNativeChildIo io;static PwWineChildWireResult r;
static PwWineChildFrame hello(void)
{
    PwWineChildFrame f={.kind=PW_WC_HELLO,.child_pid=600,.child_ppid=53};
    memcpy(f.build_id,"0123456789012345678901234567890123456789",41);return f;
}
static PwWineChildFrame boot(void)
{
    PwWineChildFrame f=hello();f.kind=PW_WC_BOOTSTRAP;f.generation=1;f.sequence=1;
    f.parent_pid=599;f.wine_pid=20;f.wine_tid=24;f.profile=PW_WC_PROFILE_FIXTURE;f.machine=PW_WC_MACHINE_AMD64;return f;
}
static int tick(void *p,uint64_t *now){(void)p;*now=m.clock_reverse?0:m.now;return m.clock_error;}
static int cancel(void *p){(void)p;return m.cancelled;}
static void reset(PwWineChildFrame f)
{
    memset(&m,0,sizeof(m));memset(&r,0,sizeof(r));m.now=100;m.poll_rc=1;m.revents=POLLIN;
    m.received=m.sent=PW_WC_WIRE_BYTES;m.stream_type=SOCK_STREAM;m.sent_right=-1;
    io=(PwNativeChildIo){.clock_ms=tick,.cancelled=cancel,.ready=1,.last_clock=100,.stage_end=500,.total_end=1000};
    assert(!pw_wine_child_wire_encode(m.bytes,&f));
}
static int fake_poll(struct pollfd*p,nfds_t n,int timeout)
{assert(n==1&&p->fd==3&&(m.no_wait?timeout==0:timeout>0&&timeout<=25));m.polls++;p->revents=m.poll_rc==1?(p->events==POLLOUT?POLLOUT:m.revents):0;
 if(m.poll_rc<0)errno=13;
 return m.poll_rc;}
static int fake_type(int fd,int level,int option,void *value,socklen_t *length)
{assert(fd>=0&&level==SOL_SOCKET&&option==SO_TYPE&&*length==4);m.types++;
 *(int*)value=fd==3?SOCK_SEQPACKET:m.stream_type;*length=4;m.now+=m.advance;if(m.type_rc<0)errno=22;return m.type_rc;}
static ssize_t fake_send(int fd,const struct msghdr *msg,int flags)
{assert(fd==3&&flags==(MSG_DONTWAIT|MSG_NOSIGNAL)&&msg->msg_iovlen==1&&msg->msg_iov[0].iov_len==PW_WC_WIRE_BYTES);
 m.sends++;memcpy(m.sent_bytes,msg->msg_iov[0].iov_base,PW_WC_WIRE_BYTES);
 if(msg->msg_controllen){assert(msg->msg_controllen==CMSG_SPACE(sizeof(int)));struct cmsghdr *h=msg->msg_control;
 assert(h->cmsg_level==SOL_SOCKET&&h->cmsg_type==SCM_RIGHTS&&h->cmsg_len==CMSG_LEN(sizeof(int)));
 memcpy(&m.sent_right,CMSG_DATA(h),4);}m.now+=m.advance;if(m.sent<0)errno=45;return m.sent;}
static ssize_t fake_receive(int fd,struct msghdr *msg,int flags)
{assert(fd==3&&flags==MSG_DONTWAIT&&msg->msg_iovlen==1&&msg->msg_iov[0].iov_len==PW_WC_WIRE_BYTES);m.receives++;
 memcpy(msg->msg_iov[0].iov_base,m.bytes,PW_WC_WIRE_BYTES);size_t n=m.controls;if(n>msg->msg_controllen)n=msg->msg_controllen;
 memcpy(msg->msg_control,m.control,n);msg->msg_controllen=(socklen_t)m.controls;msg->msg_flags=m.flags;
 m.now+=m.advance;if(m.recv_cancel)m.cancelled=1;if(m.received<0)errno=22;return m.received;}
static int fake_close(int fd){assert(fd>=0&&fd!=3&&m.closes<20);m.closed[m.closes++]=fd;if(m.close_rc<0)errno=9;return m.close_rc;}
static void rights(const int *fds,unsigned count)
{struct cmsghdr *h=(struct cmsghdr*)m.control;h->cmsg_level=SOL_SOCKET;h->cmsg_type=SCM_RIGHTS;
 h->cmsg_len=CMSG_LEN(count*sizeof(int));memcpy(CMSG_DATA(h),fds,count*sizeof(int));m.controls=CMSG_SPACE(count*sizeof(int));}
static int receive(unsigned kind,int *fd)
{PwWineChildFrame got;return pw_wine_child_wire_receive_step(&io,3,PW_WC_KIND(kind),&got,fd,&r);}
static void progress_wire_tests(void)
{
    PwWineChildFrame f=boot(),decoded;unsigned char bytes[PW_WC_WIRE_BYTES];int fd=-1;
    f.kind=PW_WC_PROGRESS;
    for(unsigned profile=1;profile<=4;profile++)for(unsigned stage=1;stage<=PW_WC_PROGRESS_LAST;stage++){
        f.profile=profile;f.failure_api=stage;
        assert(!pw_wine_child_wire_encode(bytes,&f)&&!pw_wine_child_wire_decode(&decoded,bytes));
        assert(decoded.kind==PW_WC_PROGRESS&&decoded.failure_api==stage&&pw_wine_child_wire_same_session(&f,&decoded));
        reset(f);assert(receive(PW_WC_PROGRESS,&fd)==PW_WC_RECORD&&fd==-1&&!m.closes);
    }
    for(unsigned mutation=0;mutation<11;mutation++){
        f=boot();f.kind=PW_WC_PROGRESS;f.failure_api=1;
        if(mutation==0)f.failure_api=0;
        if(mutation==1)f.failure_api=PW_WC_PROGRESS_LAST+1;
        if(mutation==2)f.sequence=2;
        if(mutation==3)f.status=-1;
        if(mutation==4)f.native_error=EACCES;
        if(mutation==5)f.failure_raw=1;
        if(mutation==6)f.returned_length=1;
        if(mutation==7)f.returned_value=1;
        if(mutation==8)f.errno_valid=1;
        if(mutation==9)f.target_tid=1;
        if(mutation==10)f.signal=PW_WC_SIGNAL_QUIT;
        assert(pw_wine_child_wire_encode(bytes,&f));
    }
    f=boot();f.kind=PW_WC_PROGRESS;f.failure_api=1;
    reset(f);int descriptor=9;rights(&descriptor,1);
    assert(receive(PW_WC_PROGRESS,&fd)==PW_WC_ERROR&&fd==-1&&m.closes==1);
    reset(f);assert(receive(PW_WC_SIGNAL_ACK,&fd)==PW_WC_ERROR&&fd==-1);
    reset(f);assert(!pw_wine_child_wire_try_send(3,&f,-1,&r)&&m.sends==1);
    reset(f);assert(pw_wine_child_wire_try_send(3,&f,9,&r)<0&&!m.sends);
}

static void net_targets_wire_tests(void)
{
    static const uint64_t values[]={0,1,UINT64_C(0x7fffffffffffffff),
        UINT64_C(0x8000000000000000),UINT64_MAX,UINT64_C(0x0123456789abcdef)};
    PwWineChildFrame f,decoded;unsigned char bytes[PW_WC_WIRE_BYTES];
    _Static_assert(PW_WC_WIRE_BYTES==136,"diagnostics keep the original frame size");
    for(unsigned i=0;i<sizeof(values)/sizeof(values[0]);i++){
        f=boot();f.kind=PW_WC_PROGRESS;f.failure_api=PW_WCP_NET_SOCKET_BEGIN;
        f.net_socket_target=values[i];f.net_errno_target=values[(i+1)%6];f.data_prepare_anchor=values[(i+2)%6];
        assert(!pw_wine_child_wire_encode(bytes,&f)&&!pw_wine_child_wire_decode(&decoded,bytes));
        assert(decoded.net_socket_target==f.net_socket_target&&decoded.net_errno_target==f.net_errno_target&&
               decoded.data_prepare_anchor==f.data_prepare_anchor&&pw_wine_child_wire_same_session(&f,&decoded));
        assert(!decoded.target_tid&&!decoded.signal&&!decoded.status&&!decoded.native_error&&
               !decoded.failure_raw&&!decoded.returned_length&&!decoded.returned_value&&!decoded.errno_valid);
        assert(get64(bytes+48)==f.data_prepare_anchor&&get32(bytes+56)==(uint32_t)f.net_socket_target&&
               get32(bytes+112)==(uint32_t)(f.net_socket_target>>32)&&get64(bytes+116)==f.net_errno_target);
        for(unsigned j=0;j<3;j++){
            unsigned offset=j==0?60:j==1?64:124;
            bytes[offset]=1;assert(pw_wine_child_wire_decode(&decoded,bytes));bytes[offset]=0;
        }
    }
    for(unsigned kind=PW_WC_HELLO;kind<=PW_WC_CANCEL;kind++)for(unsigned field=0;field<3;field++){
        f=kind==PW_WC_HELLO?hello():boot();f.kind=kind;
        if(kind==PW_WC_SIGNAL||kind==PW_WC_SIGNAL_ACK){f.sequence=2;f.target_tid=12;f.signal=PW_WC_SIGNAL_QUIT;}
        if(kind==PW_WC_FAILURE)f.status=-1;
        if(kind==PW_WC_PROGRESS)f.failure_api=1;
        assert(!pw_wine_child_wire_encode(bytes,&f));
        if(field==0)f.net_socket_target=1;
        if(field==1)f.net_errno_target=1;
        if(field==2)f.data_prepare_anchor=1;
        assert(pw_wine_child_wire_encode(bytes,&f));
    }
    for(unsigned stage=1;stage<=PW_WC_PROGRESS_LAST;stage++)if(stage!=PW_WCP_NET_SOCKET_BEGIN){
        f=boot();f.kind=PW_WC_PROGRESS;f.failure_api=stage;f.net_socket_target=UINT64_MAX;
        assert(pw_wine_child_wire_encode(bytes,&f));
    }
    for(unsigned field=0;field<8;field++){
        f=boot();f.kind=PW_WC_PROGRESS;f.failure_api=PW_WCP_NET_SOCKET_BEGIN;
        if(field==0)f.target_tid=1;
        if(field==1)f.signal=1;
        if(field==2)f.status=-1;
        if(field==3)f.native_error=1;
        if(field==4)f.failure_raw=1;
        if(field==5)f.returned_length=1;
        if(field==6)f.returned_value=1;
        if(field==7)f.errno_valid=1;
        assert(pw_wine_child_wire_encode(bytes,&f));
    }
    f=boot();f.kind=PW_WC_PROGRESS;f.failure_api=PW_WCP_NET_SOCKET_BEGIN;
    f.net_socket_target=UINT64_MAX;f.net_errno_target=UINT64_C(0x8000000000000000);
    reset(f);int descriptor=9,fd=-1;rights(&descriptor,1);
    assert(receive(PW_WC_PROGRESS,&fd)==PW_WC_ERROR&&fd==-1&&m.closes==1&&m.closed[0]==9);
    reset(f);assert(receive(PW_WC_PROGRESS,&fd)==PW_WC_RECORD&&fd==-1&&!m.closes);
}

static void cancel_wire_tests(void)
{
    PwWineChildFrame f=boot(),decoded;unsigned char bytes[PW_WC_WIRE_BYTES];int fd=-1;
    f.kind=PW_WC_CANCEL;
    for(unsigned profile=1;profile<=4;profile++){
        f.profile=profile;assert(!pw_wine_child_wire_encode(bytes,&f));
        assert(!pw_wine_child_wire_decode(&decoded,bytes)&&decoded.kind==PW_WC_CANCEL);
        reset(f);assert(receive(PW_WC_CANCEL,&fd)==PW_WC_RECORD&&fd==-1);
        reset(f);assert(!pw_wine_child_wire_try_send(3,&f,-1,&r)&&m.sends==1);
    }
    for(unsigned field=0;field<10;field++){
        f=boot();f.kind=PW_WC_CANCEL;
        if(field==0)f.sequence=2;
        if(field==1)f.status=-1;
        if(field==2)f.native_error=1;
        if(field==3)f.failure_api=1;
        if(field==4)f.failure_raw=1;
        if(field==5)f.returned_length=1;
        if(field==6)f.returned_value=1;
        if(field==7)f.errno_valid=1;
        if(field==8)f.signal=3;
        if(field==9)f.target_tid=1;
        assert(pw_wine_child_wire_encode(bytes,&f));
    }
    f=boot();f.kind=PW_WC_CANCEL;reset(f);int descriptor=9;rights(&descriptor,1);
    assert(receive(PW_WC_CANCEL,&fd)==PW_WC_ERROR&&fd==-1&&m.closes==1);
    reset(f);assert(receive(PW_WC_SIGNAL,&fd)==PW_WC_ERROR);
    reset(f);assert(pw_wine_child_wire_try_send(3,&f,9,&r)<0&&!m.sends);
}

int main(void)
{
    net_targets_wire_tests();
    cancel_wire_tests();
    progress_wire_tests();
    PwWineChildFrame f=boot(),decoded;unsigned char bytes[PW_WC_WIRE_BYTES];
    assert(!pw_wine_child_wire_encode(bytes,&f));assert(!pw_wine_child_wire_decode(&decoded,bytes));
    assert(pw_wine_child_wire_same_session(&f,&decoded));bytes[127]=1;assert(pw_wine_child_wire_decode(&decoded,bytes));
    f=boot();f.profile=PW_WC_PROFILE_BATTLENET;f.machine=PW_WC_MACHINE_I386;
    assert(!pw_wine_child_wire_encode(bytes,&f)&&!pw_wine_child_wire_decode(&decoded,bytes));
    assert(decoded.profile==2&&decoded.machine==0x14c&&bytes[8]==2&&bytes[128]==2&&bytes[132]==0x4c);
    decoded.machine=PW_WC_MACHINE_AMD64;assert(!pw_wine_child_wire_same_session(&f,&decoded));
    decoded=f;decoded.profile=PW_WC_PROFILE_FIXTURE;assert(!pw_wine_child_wire_same_session(&f,&decoded));
    f.profile=3;assert(pw_wine_child_wire_encode(bytes,&f));
    f=boot();f.machine=PW_WC_MACHINE_I386;assert(pw_wine_child_wire_encode(bytes,&f));
    f=boot();f.machine=0xaa64;assert(pw_wine_child_wire_encode(bytes,&f));
    f=hello();f.profile=1;assert(pw_wine_child_wire_encode(bytes,&f));
    f=boot();assert(!pw_wine_child_wire_encode(bytes,&f));bytes[8]=1;assert(pw_wine_child_wire_decode(&decoded,bytes));
    f=boot();f.signal=10;assert(pw_wine_child_wire_encode(bytes,&f));f=boot();f.kind=PW_WC_SIGNAL;f.sequence=2;f.target_tid=12;f.signal=30;
    assert(!pw_wine_child_wire_encode(bytes,&f));f.signal=10;assert(pw_wine_child_wire_encode(bytes,&f));
    reset(hello());assert(!pw_wine_child_wire_validate(&io,3,&r));int fd=-1;assert(receive(PW_WC_HELLO,&fd)==PW_WC_RECORD&&fd==-1);
    reset(boot());int descriptors[]={9};rights(descriptors,1);m.flags=MSG_EOR|MSG_DONTWAIT;
    assert(receive(PW_WC_BOOTSTRAP,&fd)==PW_WC_RECORD&&fd==9&&!m.closes);pw_wine_child_wire_close(&fd,&r);assert(fd==-1&&m.closes==1);
    reset(boot());descriptors[0]=0;rights(descriptors,1);assert(receive(PW_WC_BOOTSTRAP,&fd)==PW_WC_RECORD&&fd==0);pw_wine_child_wire_close(&fd,&r);
    reset(hello());descriptors[0]=9;rights(descriptors,1);assert(receive(PW_WC_HELLO,&fd)<0&&m.closes==1&&fd==-1);
    reset(boot());assert(receive(PW_WC_BOOTSTRAP,&fd)<0&&!m.closes);
    reset(boot());int extra[]={9,10};rights(extra,2);assert(receive(PW_WC_BOOTSTRAP,&fd)<0&&m.closes==2);
    reset(boot());int duplicate[]={9,9};rights(duplicate,2);assert(receive(PW_WC_BOOTSTRAP,&fd)<0&&m.closes==1&&r.ownership_uncertain);
    reset(boot());descriptors[0]=3;rights(descriptors,1);assert(receive(PW_WC_BOOTSTRAP,&fd)<0&&!m.closes&&r.ownership_uncertain);
    reset(boot());descriptors[0]=9;rights(descriptors,1);((struct cmsghdr*)m.control)->cmsg_len=4096;
    assert(receive(PW_WC_BOOTSTRAP,&fd)<0&&!m.closes&&r.ownership_uncertain);
    reset(boot());rights(descriptors,1);m.flags=MSG_CTRUNC;assert(receive(PW_WC_BOOTSTRAP,&fd)<0&&m.closes==1&&r.ownership_uncertain);
    reset(boot());rights(descriptors,1);m.flags=MSG_TRUNC;assert(receive(PW_WC_BOOTSTRAP,&fd)<0&&m.closes==1);
    reset(boot());rights(descriptors,1);m.received=128;assert(receive(PW_WC_BOOTSTRAP,&fd)<0&&m.closes==1);
    reset(boot());rights(descriptors,1);m.received=135;assert(receive(PW_WC_BOOTSTRAP,&fd)<0&&m.closes==1);
    reset(boot());rights(descriptors,1);m.received=127;assert(receive(PW_WC_BOOTSTRAP,&fd)<0&&m.closes==1);
    reset(boot());rights(descriptors,1);m.stream_type=SOCK_SEQPACKET;assert(receive(PW_WC_BOOTSTRAP,&fd)<0&&m.closes==1);
    reset(boot());rights(descriptors,1);m.type_rc=-1;assert(receive(PW_WC_BOOTSTRAP,&fd)<0&&m.closes==1&&r.native_error==22&&r.api==PW_WC_API_TYPE);
    reset(boot());rights(descriptors,1);m.advance=400;assert(receive(PW_WC_BOOTSTRAP,&fd)<0&&m.closes==1&&!m.types&&r.status==PW_WC_BUDGET);
    reset(boot());rights(descriptors,1);m.recv_cancel=1;assert(receive(PW_WC_BOOTSTRAP,&fd)<0&&m.closes==1&&!m.types&&r.status==PW_WC_BUDGET);
    reset(boot());rights(descriptors,1);m.advance=201;assert(receive(PW_WC_BOOTSTRAP,&fd)<0&&m.closes==1&&r.status==PW_WC_BUDGET);
    reset(boot());rights(descriptors,1);m.received=127;m.close_rc=-1;
    assert(receive(PW_WC_BOOTSTRAP,&fd)<0&&m.closes==1&&r.status==PW_WC_PROTOCOL&&r.cleanup_failed&&r.cleanup_native_error==9);
    reset(hello());m.received=0;assert(receive(PW_WC_HELLO,&fd)<0&&r.channel_zero_observed&&!r.hangup_observed);
    reset(hello());m.received=0;m.revents=POLLIN|POLLHUP;assert(receive(PW_WC_HELLO,&fd)==PW_WC_CHANNEL_CLOSED);
    reset(hello());m.received=0;m.revents=POLLHUP;m.flags=MSG_EOR;assert(receive(PW_WC_HELLO,&fd)<0);
    reset(hello());m.poll_rc=0;assert(receive(PW_WC_HELLO,&fd)==PW_WC_IDLE&&!m.receives&&io.stage_end==500);
    reset(hello());m.clock_reverse=1;assert(receive(PW_WC_HELLO,&fd)<0&&!m.polls);
    reset(hello());m.poll_rc=-1;assert(receive(PW_WC_HELLO,&fd)<0&&r.errno_valid&&r.native_error==13);
    reset(hello());m.received=-1;assert(receive(PW_WC_HELLO,&fd)<0&&r.native_error==22&&!m.closes);
    reset(boot());f=boot();assert(!pw_wine_child_wire_try_send(3,&f,9,&r)&&m.sent_right==9&&!m.polls);
    reset(hello());f=hello();assert(pw_wine_child_wire_try_send(3,&f,9,&r)<0&&!m.sends);
    reset(boot());f=boot();m.sent=-1;assert(pw_wine_child_wire_try_send(3,&f,9,&r)<0&&r.delivery_uncertain&&r.native_error==45&&!m.closes);
    reset(boot());f=boot();m.sent=127;assert(pw_wine_child_wire_try_send(3,&f,9,&r)<0&&r.delivery_uncertain);
    reset(boot());f=boot();m.advance=400;assert(pw_wine_child_wire_send(&io,3,&f,9,&r)<0&&r.delivery_uncertain&&r.status==PW_WC_BUDGET);
    reset(hello());m.no_wait=1;m.poll_rc=0;fd=-1;
    assert(pw_wine_child_wire_receive_nowait(&io,3,PW_WC_KIND(PW_WC_HELLO),&decoded,&fd,&r)==PW_WC_IDLE);
    assert(m.polls==1&&!m.receives&&io.stage_end==500&&fd==-1);
    m.poll_rc=1;
    assert(pw_wine_child_wire_receive_nowait(&io,3,PW_WC_KIND(PW_WC_HELLO),&decoded,&fd,&r)==PW_WC_RECORD);
    assert(m.polls==2&&m.receives==1&&fd==-1);
    reset(boot());m.no_wait=1;m.poll_rc=0;f=boot();
    assert(pw_wine_child_wire_send_step(&io,3,&f,9,&r)==PW_WC_IDLE&&!m.sends&&m.polls==1);
    assert(io.stage_end==500);m.poll_rc=1;
    assert(pw_wine_child_wire_send_step(&io,3,&f,9,&r)==PW_WC_RECORD&&m.sends==1&&m.sent_right==9);
    reset(boot());m.no_wait=1;f=boot();m.advance=400;
    assert(pw_wine_child_wire_send_step(&io,3,&f,9,&r)==PW_WC_ERROR&&r.delivery_uncertain&&m.sends==1);
    puts("wine child wire: all mocked controls passed");return 0;
}
