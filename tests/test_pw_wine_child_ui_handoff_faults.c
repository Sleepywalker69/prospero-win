/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../native/pw_wine_child_ui_handoff.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
static int fake_type(int,int,int,void *,socklen_t *);
static int fake_poll(struct pollfd *,nfds_t,int);
static int fake_stat(int,struct stat *);
static int fake_fcntl(int,int,...);
static ssize_t fake_send(int,const struct msghdr *,int);
static ssize_t fake_receive(int,struct msghdr *,int);
static void fake_close(int *,PwWineChildWireResult *);
#define getsockopt fake_type
#define poll fake_poll
#define fstat fake_stat
#define fcntl fake_fcntl
#define sendmsg fake_send
#define recvmsg fake_receive
#define pw_wine_child_wire_close fake_close
#include "../native/pw_wine_child_ui_handoff.c"
#undef getsockopt
#undef poll
#undef fstat
#undef fcntl
#undef sendmsg
#undef recvmsg
#undef pw_wine_child_wire_close
static struct {
    uint64_t now,advance;int cancelled,after_cancel,clock_bad,poll_bad,poll_idle,type_bad,stat_bad,zero_inode,same_inode;
    int fcntl_bad,close_bad,send_error,recv_error,flags,send_partial;
    unsigned receives,sends,closes;int closed[20];
    size_t controls;ssize_t received;
    unsigned char bytes[PW_WCU_HANDOFF_BYTES];
    _Alignas(struct cmsghdr) unsigned char ancillary[CMSG_SPACE(16*sizeof(int))];
} m;
static PwWineChildUiHandoff h;
static PwNativeChildIo budget_io;
static PwWineChildFrame local,bootstrap;
static int clock_cb(void *unused,uint64_t *out){(void)unused;*out=m.now;return m.clock_bad;}
static int stop_cb(void *unused){(void)unused;return m.cancelled;}
static int fake_type(int fd,int level,int op,void *p,socklen_t *n)
{assert(fd>=0&&level==SOL_SOCKET&&op==SO_TYPE&&*n==sizeof(int));*(int*)p=fd==3?SOCK_SEQPACKET:SOCK_STREAM;if(m.type_bad)*n=0;return 0;}
static int fake_poll(struct pollfd *p,nfds_t n,int timeout)
{assert(n==1&&p->fd==3&&timeout==0);if(m.poll_bad){errno=EINTR;return -1;}p->revents=m.poll_idle?0:p->events;return m.poll_idle?0:1;}
static int fake_stat(int fd,struct stat *s)
{assert(fd==9||fd==10);memset(s,0,sizeof(*s));s->st_dev=1;s->st_ino=m.zero_inode?0:m.same_inode?99:(unsigned)fd;if(m.stat_bad){errno=EIO;return -1;}return 0;}
static int fake_fcntl(int fd,int op,...)
{assert(fd==9||fd==10);if(m.fcntl_bad==op){errno=EIO;return -1;}assert(op==F_GETFD||op==F_SETFD);return 0;}
static ssize_t fake_send(int fd,const struct msghdr *msg,int flags)
{
    assert(fd==3&&flags==(MSG_NOSIGNAL|MSG_DONTWAIT)&&msg->msg_iovlen==1&&msg->msg_iov[0].iov_len==PW_WCU_HANDOFF_BYTES);
    assert(msg->msg_controllen==CMSG_SPACE(2*sizeof(int)));struct cmsghdr *c=msg->msg_control;int rights[2];
    assert(c->cmsg_level==SOL_SOCKET&&c->cmsg_type==SCM_RIGHTS&&c->cmsg_len==CMSG_LEN(sizeof(rights)));
    memcpy(rights,CMSG_DATA(c),sizeof(rights));assert(rights[0]==9&&rights[1]==10);
    assert(((const unsigned char *)msg->msg_iov[0].iov_base)[8]==3);m.sends++;m.now+=m.advance;
    if(m.send_error){errno=m.send_error;return -1;}return m.send_partial?3:PW_WCU_HANDOFF_BYTES;
}
static ssize_t fake_receive(int fd,struct msghdr *msg,int flags)
{
    assert(fd==3&&flags==MSG_DONTWAIT&&msg->msg_iovlen==1&&msg->msg_iov[0].iov_len==PW_WCU_HANDOFF_BYTES);m.receives++;
    if(m.recv_error){errno=m.recv_error;return -1;}
    memcpy(msg->msg_iov[0].iov_base,m.bytes,sizeof(m.bytes));size_t n=m.controls;
    if(n>msg->msg_controllen)n=msg->msg_controllen;
    memcpy(msg->msg_control,m.ancillary,n);
    msg->msg_controllen=m.controls;msg->msg_flags=m.flags;m.now+=m.advance;if(m.after_cancel)m.cancelled=1;return m.received;
}
static void fake_close(int *fd,PwWineChildWireResult *r)
{
    assert(fd&&*fd>=0&&*fd!=3&&m.closes<20);m.closed[m.closes++]=*fd;*fd=-1;
    if(m.close_bad){r->cleanup_failed=r->ownership_uncertain=r->cleanup_errno_valid=1;r->cleanup_native_error=EINTR;}
    else r->rights_closed++;
}
static void reset(void)
{
    memset(&m,0,sizeof(m));memset(&h,0,sizeof(h));m.now=100;m.received=PW_WCU_HANDOFF_BYTES;
    budget_io=(PwNativeChildIo){.ready=1,.clock_ms=clock_cb,.cancelled=stop_cb,.last_clock=100,.stage_end=500,.total_end=1000};
    local=(PwWineChildFrame){.kind=PW_WC_HELLO,.child_pid=600,.child_ppid=500};
    memcpy(local.build_id,"0123456789012345678901234567890123456789",41);
    bootstrap=local;bootstrap.kind=PW_WC_BOOTSTRAP;bootstrap.sequence=1;bootstrap.generation=81;
    bootstrap.parent_pid=599;bootstrap.wine_pid=80;bootstrap.wine_tid=84;bootstrap.profile=2;bootstrap.machine=PW_WC_MACHINE_AMD64;
    assert(!encode(m.bytes,&bootstrap,80));
    struct cmsghdr *c=(struct cmsghdr*)m.ancillary;c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;
    c->cmsg_len=CMSG_LEN(2*sizeof(int));int rights[]={9,10};memcpy(CMSG_DATA(c),rights,sizeof(rights));m.controls=CMSG_SPACE(sizeof(rights));
}
static int receive(void){int server=-1,ui=-1;int rc=pw_wine_child_ui_handoff_receive(&h,&budget_io,3,&local,&server,&ui);
    if(rc==PW_WC_RECORD)assert(server==9&&ui==10);else assert(server==-1&&ui==-1);return rc;}
int main(void)
{
    reset();assert(receive()==PW_WC_RECORD&&!m.closes);assert(receive()==PW_WC_ERROR&&m.receives==1);
    for(unsigned mode=0;mode<17;mode++){
        reset();struct cmsghdr *c=(struct cmsghdr*)m.ancillary;
        unsigned expected=2;
        if(mode==0){int alias=9;memcpy((unsigned char*)CMSG_DATA(c)+sizeof(int),&alias,sizeof(alias));expected=1;}
        if(mode==1)m.flags=MSG_CTRUNC;
        if(mode==2)m.flags=MSG_TRUNC;
        if(mode==3)m.advance=400;
        if(mode==4)m.after_cancel=1;
        if(mode==5)m.stat_bad=1;
        if(mode==6)m.zero_inode=1;
        if(mode==7)m.same_inode=1;
        if(mode==8)m.fcntl_bad=F_GETFD;
        if(mode==9)m.fcntl_bad=F_SETFD;
        if(mode==10){c->cmsg_len=4096;expected=0;}
        if(mode==11){c->cmsg_type=999;expected=0;}
        if(mode==12){m.controls=sizeof(m.ancillary)+1;/* collect valid rights, mark uncertain */}
        if(mode==13){m.bytes[151]=1;m.close_bad=1;}
        if(mode==14){c->cmsg_len=CMSG_LEN(sizeof(int)+1);expected=1;}
        if(mode==15){m.controls=CMSG_LEN(sizeof(int)+1);expected=0;}
        if(mode==16){c->cmsg_len=4096;m.controls=CMSG_SPACE(sizeof(int));
            memset((unsigned char*)CMSG_DATA(c)+sizeof(int),0,m.controls-CMSG_LEN(sizeof(int)));expected=0;}
        assert(receive()==PW_WC_ERROR&&h.state==PW_WCU_HANDOFF_FAILED&&m.closes==expected);
        assert(receive()==PW_WC_ERROR&&m.receives==1&&m.closes==expected);
        if(mode==13)assert(h.result.cleanup_failed&&h.result.ownership_uncertain);
    }
    reset();m.poll_idle=1;assert(receive()==PW_WC_IDLE&&!m.receives&&h.state==PW_WCU_HANDOFF_NEW);
    m.poll_idle=0;assert(receive()==PW_WC_RECORD);
    for(unsigned mode=0;mode<5;mode++){
        reset();if(mode==0)m.now=99;if(mode==1)m.now=500;if(mode==2)m.cancelled=1;if(mode==3)m.clock_bad=1;if(mode==4)m.poll_bad=1;
        assert(receive()==PW_WC_ERROR&&!m.receives&&!m.closes);
    }
    for(unsigned mode=0;mode<4;mode++){
        reset();if(mode==1)m.send_error=EINTR;if(mode==2)m.send_partial=1;if(mode==3)m.advance=400;
        int rc=pw_wine_child_ui_handoff_send(&h,&budget_io,3,&bootstrap,80,9,10);
        assert(rc==(mode?PW_WC_ERROR:PW_WC_RECORD)&&m.sends==1&&!m.closes);
        if(mode)assert(h.result.delivery_uncertain);
        assert(pw_wine_child_ui_handoff_send(&h,&budget_io,3,&bootstrap,80,9,10)==PW_WC_ERROR&&m.sends==1);
    }
    puts("child UI handoff: malformed ancillary, cancellation, identity capability, IO and cleanup faults passed");return 0;
}
