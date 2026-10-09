/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Pure syscall-boundary mocks: no socket or process operation is performed. */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <unistd.h>
static int fake_socket(int,int,int);
static int fake_socketpair(int,int,int,int[2]);
static int fake_bind(int,const struct sockaddr *,socklen_t);
static int fake_listen(int,int);
static int fake_accept(int,struct sockaddr *,socklen_t *);
static int fake_connect(int,const struct sockaddr *,socklen_t);
static int fake_close(int);
static int fake_unlink(const char *);
static int fake_fcntl(int,int,...);
static int fake_poll(struct pollfd *,nfds_t,int);
static ssize_t fake_sendmsg(int,const struct msghdr *,int);
static ssize_t fake_recvmsg(int,struct msghdr *,int);
static pid_t fake_getpid(void);
static int fake_shutdown(int,int);
#define socket fake_socket
#define socketpair fake_socketpair
#define bind fake_bind
#define listen fake_listen
#define accept fake_accept
#define connect fake_connect
#define close fake_close
#define unlink fake_unlink
#define fcntl fake_fcntl
#define poll fake_poll
#define sendmsg fake_sendmsg
#define recvmsg fake_recvmsg
#define getpid fake_getpid
#define shutdown fake_shutdown
#include "../native/pw_native_fd_probe.c"
#undef socket
#undef socketpair
#undef bind
#undef listen
#undef accept
#undef connect
#undef close
#undef unlink
#undef fcntl
#undef poll
#undef sendmsg
#undef recvmsg
#undef getpid
#undef shutdown

static struct {
    uint64_t now, deadline, io_step;
    int stop, clock_fail, poll_stop, poll_expire, receive_stop, receive_expire;
    int open[256], closed[256], close_fail, unlink_fail, unlink_calls;
    int fcntl_calls, fcntl_fail_at, socket_calls, bind_calls, bind_fail, listen_fail;
    int send_calls, receive_calls, poll_calls, poll_fail, recv_fail, send_fail;
    int count, want_flags, wrong_type, short_control, short_payload;
    int connect_ok, accept_ok, next_pair, script_count, script_at, rights_sent;
    struct { int fd, right; size_t size, position; unsigned char bytes[HELLO_BYTES]; } script[12];
    unsigned char tag, input[128], output[128];
    size_t length, position, output_size, chunk;
} m;
static void reset(void)
{
    memset(&m,0,sizeof(m));m.now=10;m.deadline=100;m.open[17]=1;m.tag=TAG_ENDPOINT;m.next_pair=20;
}
static int clock_value(void *context,uint64_t *value)
{ (void)context;if(m.clock_fail)return -37;*value=m.now;return 0; }
static int is_cancelled(void *context) { (void)context;return m.stop; }
static PwNativeFdContext context(void)
{ PwNativeFdContext c={NULL,clock_value,is_cancelled,m.deadline};return c; }
static int fake_socket(int d,int t,int p)
{ assert(d==AF_UNIX&&t==SOCK_STREAM&&!p);++m.socket_calls;m.open[10]=1;return 10; }
static int fake_socketpair(int d,int t,int p,int pair[2])
{ assert(d==AF_UNIX&&t==SOCK_STREAM&&!p);pair[0]=m.next_pair++;pair[1]=m.next_pair++;m.open[pair[0]]=m.open[pair[1]]=1;return 0; }
static int fake_bind(int fd,const struct sockaddr *a,socklen_t size)
{ assert(fd==10&&a&&size>0);++m.bind_calls;return m.bind_fail?-17:0; }
static int fake_listen(int fd,int n) { assert(fd==10&&n==1);return m.listen_fail?-18:0; }
static int fake_accept(int fd,struct sockaddr *a,socklen_t *size)
{ (void)a;(void)size;assert(fd==10);if(m.accept_ok){m.open[30]=1;return 30;}return -19; }
static int fake_connect(int fd,const struct sockaddr *a,socklen_t size)
{ assert(fd==10&&a&&size);return m.connect_ok?0:-20; }
static int fake_close(int fd)
{ assert(fd>=0&&fd<256&&m.open[fd]);m.open[fd]=0;++m.closed[fd];return m.close_fail?-23:0; }
static int fake_unlink(const char *path)
{ assert(!strcmp(path,"/original-fixture/r"));++m.unlink_calls;return m.unlink_fail?-24:0; }
static int fake_fcntl(int fd,int command,...)
{
    assert(fd>=0&&fd<256&&m.open[fd]);++m.fcntl_calls;
    assert(command==F_GETFD||command==F_SETFD||command==F_GETFL||command==F_SETFL);
    if(m.fcntl_calls==m.fcntl_fail_at)return -27;
    return 0;
}
static int fake_poll(struct pollfd *p,nfds_t count,int timeout)
{
    assert(count==1&&timeout>0&&timeout<=25&&m.open[p->fd]);++m.poll_calls;
    if(m.poll_stop)m.stop=1;
    if(m.poll_expire)m.now=m.deadline;
    if(m.poll_fail)return -29;
    p->revents=p->events;return 1;
}
static ssize_t fake_sendmsg(int fd,const struct msghdr *msg,int flags)
{
    assert(m.open[fd]&&msg->msg_iovlen==1&&flags==MSG_NOSIGNAL);++m.send_calls;
    if(m.send_fail)return -31;
    if(msg->msg_controllen){
        struct cmsghdr *h=CMSG_FIRSTHDR((struct msghdr *)(void *)msg);
        assert(h&&h->cmsg_level==SOL_SOCKET&&h->cmsg_type==SCM_RIGHTS&&h->cmsg_len==CMSG_LEN(sizeof(int)));
        int right=*(int *)(void *)CMSG_DATA(h);assert(right>=0&&right<256&&m.open[right]);++m.rights_sent;
    }
    size_t count=msg->msg_iov[0].iov_len;
    if(m.chunk&&count>m.chunk)count=m.chunk;
    assert(m.output_size+count<=sizeof(m.output));
    memcpy(m.output+m.output_size,msg->msg_iov[0].iov_base,count);m.output_size+=count;m.now+=m.io_step;
    return (ssize_t)count;
}
static ssize_t fake_recvmsg(int fd,struct msghdr *msg,int flags)
{
    assert(m.open[fd]&&!flags&&msg->msg_iovlen==1);++m.receive_calls;
    if(m.recv_fail)return -32;
    if(m.script_count){
        assert(m.script_at<m.script_count);
        int i=m.script_at;assert(m.script[i].fd==fd);
        size_t count=m.script[i].size-m.script[i].position;
        if(count>msg->msg_iov[0].iov_len)count=msg->msg_iov[0].iov_len;
        if(m.chunk&&count>m.chunk)count=m.chunk;
        memcpy(msg->msg_iov[0].iov_base,m.script[i].bytes+m.script[i].position,count);
        m.script[i].position+=count;msg->msg_flags=0;msg->msg_controllen=0;
        if(m.script[i].right>=0){
            assert(count==1);int right=m.script[i].right;assert(!m.open[right]);m.open[right]=1;
            struct cmsghdr *h=msg->msg_control;h->cmsg_len=CMSG_LEN(sizeof(int));h->cmsg_level=SOL_SOCKET;h->cmsg_type=SCM_RIGHTS;
            *(int *)(void *)CMSG_DATA(h)=right;msg->msg_controllen=CMSG_SPACE(sizeof(int));
        }
        if(m.script[i].position==m.script[i].size)++m.script_at;
        return (ssize_t)count;
    }
    if(m.count){
        struct cmsghdr *h=msg->msg_control;assert(m.count<=CONTROL_FDS);
        h->cmsg_len=CMSG_LEN((size_t)m.count*sizeof(int))-(unsigned)m.short_payload;
        h->cmsg_level=SOL_SOCKET;h->cmsg_type=m.wrong_type?0:SCM_RIGHTS;
        for(int i=0;i<m.count;++i){((int *)(void *)CMSG_DATA(h))[i]=64+i;m.open[64+i]=1;}
        msg->msg_controllen=CMSG_SPACE((size_t)m.count*sizeof(int));
    }else msg->msg_controllen=m.short_control?(size_t)m.short_control:0;
    msg->msg_flags=m.want_flags;
    size_t count=msg->msg_iov[0].iov_len;
    if(m.count){count=1;*(unsigned char *)msg->msg_iov[0].iov_base=m.tag;}
    else{
        if(count>m.length-m.position)count=m.length-m.position;
        if(m.chunk&&count>m.chunk)count=m.chunk;
        memcpy(msg->msg_iov[0].iov_base,m.input+m.position,count);m.position+=count;
    }
    if(m.receive_stop)m.stop=1;
    if(m.receive_expire)m.now=m.deadline;
    m.now+=m.io_step;return (ssize_t)count;
}
static pid_t fake_getpid(void) { return 17; }
static int fake_shutdown(int fd,int direction)
{ assert(m.open[fd]&&(direction==SHUT_RD||direction==SHUT_WR));return 0; }

static void receive_control(int fds,int wanted,int flags,int wrong_tag,int expected)
{
    reset();m.count=fds;m.want_flags=flags;if(wrong_tag)m.tag=TAG_REPLY;
    m.length=1;m.input[0]=TAG_ENDPOINT;
    PwNativeFdContext c=context();PwNativeFdResult r={0};int right=-1;unsigned char byte;
    int got=wanted?receive_right(17,TAG_ENDPOINT,&right,&c,&r):(int)receive_chunk(17,&byte,1,0,NULL,&c,&r);
    assert((expected?got<0:got==0)&&r.status==expected);
    if(!expected){assert(right==64&&m.open[64]);close_owned(&right,&r);}
    assert(right==-1);
    for(int i=0;i<fds;++i)assert(!m.open[64+i]&&m.closed[64+i]==1);
}
static void ancillary_and_cleanup(void)
{
    receive_control(1,1,0,0,PW_NATIVE_FD_OK);
    receive_control(0,1,0,0,PW_NATIVE_FD_PROTOCOL);
    receive_control(2,1,0,0,PW_NATIVE_FD_PROTOCOL);
    receive_control(1,1,0,1,PW_NATIVE_FD_PROTOCOL);
    receive_control(1,0,0,0,PW_NATIVE_FD_PROTOCOL);
    receive_control(8,1,MSG_CTRUNC,0,PW_NATIVE_FD_PROTOCOL);
    receive_control(1,1,MSG_TRUNC,0,PW_NATIVE_FD_PROTOCOL);
    for(int failure=1;failure<=4;++failure){
        reset();m.count=1;m.fcntl_fail_at=failure;
        PwNativeFdContext c=context();PwNativeFdResult r={0};int right=-1;
        assert(receive_right(17,TAG_ENDPOINT,&right,&c,&r)<0);
        assert(r.status==PW_NATIVE_FD_OS&&r.api==PW_NATIVE_FD_API_FCNTL&&r.raw_result==-27);
        assert(right==-1&&m.closed[64]==1&&!r.peer_identity_verified);
    }
    reset();m.count=2;m.close_fail=1;
    PwNativeFdContext c=context();PwNativeFdResult r={0};int right=-1;
    assert(receive_right(17,TAG_ENDPOINT,&right,&c,&r)<0);
    assert(r.status==PW_NATIVE_FD_PROTOCOL&&r.api==PW_NATIVE_FD_API_RECVMSG&&r.cleanup_failed);
    assert(m.closed[64]==1&&m.closed[65]==1);
}
static void deadline_and_stop(void)
{
    for(int when=0;when<2;++when)for(int stop=0;stop<2;++stop){
        reset();m.count=1;
        if(when){m.receive_stop=stop;m.receive_expire=!stop;}
        else{m.poll_stop=stop;m.poll_expire=!stop;}
        PwNativeFdContext c=context();PwNativeFdResult r={0};int right=-1;
        assert(receive_right(17,TAG_ENDPOINT,&right,&c,&r)<0);
        assert(r.status==(stop?PW_NATIVE_FD_CANCELLED:PW_NATIVE_FD_TIMEOUT)&&right==-1);
        assert(m.receive_calls==when&&m.closed[64]==when);
    }
    reset();m.poll_stop=1;PwNativeFdContext c=context();PwNativeFdResult r={0};
    assert(send_right(17,TAG_ENDPOINT,17,&c,&r)<0&&r.status==PW_NATIVE_FD_CANCELLED&&!m.send_calls);
    reset();m.chunk=1;m.io_step=10;c=context();memset(&r,0,sizeof(r));
    assert(send_data(17,"0123456789abcdef",16,&c,&r)<0&&r.status==PW_NATIVE_FD_TIMEOUT);
    assert(m.send_calls==9&&m.now==100&&m.output_size==9);
}
static void fragmentation_and_eof(void)
{
    for(unsigned chunk=1;chunk<=DATA_BYTES+1;++chunk){
        reset();m.chunk=chunk;data_frame(m.input,123,1);m.length=DATA_BYTES;
        PwNativeFdContext c=context();PwNativeFdResult r={0};
        assert(!data_and_eof(17,123,1,&c,&r)&&!r.status&&!r.observations);
        assert(!send_data(17,m.input,DATA_BYTES,&c,&r));
        assert(m.output_size==DATA_BYTES&&!memcmp(m.input,m.output,DATA_BYTES));
    }
    for(unsigned cut=0;cut<DATA_BYTES;++cut){
        reset();data_frame(m.input,123,1);m.length=cut;m.chunk=3;
        PwNativeFdContext c=context();PwNativeFdResult r={0};
        assert(data_and_eof(17,123,1,&c,&r)<0&&r.status==PW_NATIVE_FD_EOF);
    }
    reset();data_frame(m.input,123,1);m.length=DATA_BYTES+1;
    PwNativeFdContext c=context();PwNativeFdResult r={0};
    assert(data_and_eof(17,123,1,&c,&r)<0&&r.status==PW_NATIVE_FD_PROTOCOL);
    for(unsigned cut=0;cut<HELLO_BYTES;++cut){
        reset();m.length=cut;m.chunk=2;
        put32(m.input,0x31444650);put32(m.input+4,1);put64(m.input+8,123);put32(m.input+16,42);
        c=context();memset(&r,0,sizeof(r));
        assert(hello(17,123,&c,&r)<0&&r.status==PW_NATIVE_FD_EOF&&!r.peer_identity_verified);
    }
}
static void setup_dispose_and_failures(void)
{
    for(int setup=0;setup<7;++setup){
        reset();if(setup<4)m.fcntl_fail_at=setup+1;if(setup==4)m.bind_fail=1;if(setup==5)m.listen_fail=1;
        PwNativeFdContext c=context();PwNativeFdResult r={0};PwNativeFdListener l;
        int rc=pw_native_fd_parent_open(&l,"/original-fixture/r",&c,&r);
        if(setup<6){assert(rc==PW_NATIVE_FD_OS&&l.fd==-1&&!l.bound&&m.closed[10]==1);assert(m.unlink_calls==(setup==5));}
        else{
            assert(!rc);m.close_fail=m.unlink_fail=1;pw_native_fd_dispose(&l,&r);
            assert(r.status==PW_NATIVE_FD_OS&&r.raw_result==-23&&r.api==PW_NATIVE_FD_API_CLOSE&&r.cleanup_failed);
            pw_native_fd_dispose(&l,&r);assert(m.closed[10]==1&&m.unlink_calls==1);
        }
    }
    reset();PwNativeFdContext c=context();PwNativeFdResult r={0};
    m.clock_fail=1;assert(check(&c,&r,NULL)<0&&r.status==PW_NATIVE_FD_CLOCK&&r.raw_result==-37);
    reset();c=context();memset(&r,0,sizeof(r));assert(!check(&c,&r,NULL));--m.now;
    assert(check(&c,&r,NULL)<0&&r.status==PW_NATIVE_FD_CLOCK);
}
static void packet(int fd,int right,const void *bytes,size_t size)
{
    assert(m.script_count<12&&size<=HELLO_BYTES);int i=m.script_count++;
    m.script[i].fd=fd;m.script[i].right=right;m.script[i].size=size;
    if(size)memcpy(m.script[i].bytes,bytes,size);
}
static void both_complete_paths(void)
{
    for(int worker=0;worker<2;++worker)for(unsigned chunk=1;chunk<=HELLO_BYTES+1;++chunk){
        reset();m.chunk=chunk;m.connect_ok=m.accept_ok=1;
        unsigned char greeting[HELLO_BYTES]={0},frame[DATA_BYTES],tag;
        put32(greeting,0x31444650);put32(greeting+4,1);put64(greeting+8,123);put32(greeting+16,42);
        packet(worker?10:30,-1,greeting,sizeof(greeting));
        if(worker){
            tag=TAG_ENDPOINT;packet(10,64,&tag,1);tag=TAG_QUEUED;packet(64,65,&tag,1);
            data_frame(frame,123,2);packet(20,-1,frame,sizeof(frame));packet(20,-1,NULL,0);
        }else{
            data_frame(frame,123,1);packet(22,-1,frame,sizeof(frame));packet(22,-1,NULL,0);
            tag=TAG_REPLY;packet(21,64,&tag,1);data_frame(frame,123,3);packet(30,-1,frame,sizeof(frame));
        }
        PwNativeFdContext c=context();PwNativeFdResult r={0};PwNativeFdListener l;
        int rc;
        if(worker)rc=pw_native_fd_worker("/original-fixture/r",123,&c,&r);
        else{assert(!pw_native_fd_parent_open(&l,"/original-fixture/r",&c,&r));rc=pw_native_fd_parent(&l,123,&c,&r);}
        assert(!rc&&r.stage==PW_NATIVE_FD_COMPLETE&&!r.cleanup_failed&&!r.peer_identity_verified);
        assert(r.local_pid==17&&r.reported_peer_pid==42&&m.script_at==m.script_count);
        assert(m.rights_sent==(worker?1:2)&&m.unlink_calls==!worker);
        assert(r.observations==(worker?239u:191u));
        assert(r.peer_observations==(worker?0u:PW_NATIVE_FD_REVERSE_EOF));
        for(int fd=0;fd<256;++fd)if(fd!=17)assert(!m.open[fd]&&m.closed[fd]<=1);
    }
}
static void malformed_short_control(void)
{
    reset();m.short_control=1;m.length=1;m.input[0]=7;
    PwNativeFdContext c=context();PwNativeFdResult r={0};unsigned char byte;
    assert(receive_chunk(17,&byte,1,0,NULL,&c,&r)<0&&r.status==PW_NATIVE_FD_PROTOCOL);
}
int main(int argc,char **argv)
{
    if(argc==2&&!strcmp(argv[1],"--short-control"))malformed_short_control();
    else{assert(argc==1||(argc==2&&!strcmp(argv[1],"--baseline")));ancillary_and_cleanup();deadline_and_stop();fragmentation_and_eof();setup_dispose_and_failures();both_complete_paths();if(argc==1)malformed_short_control();}
    puts("Pure native FD mocks passed; no sockets, processes, Wine startup or native reaping executed.");return 0;
}
