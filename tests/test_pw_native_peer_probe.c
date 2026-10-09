/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Production transport, deterministic target-ABI mocks only. No real sockets,
 * events, RNG, process observation or filesystem operations are performed. */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "native_peer_fixture/peer_abi.h"
/* Target SDK 4eb7012 sys/fcntl.h. Host Linux O_NONBLOCK is different. */
_Static_assert(F_GETFD==1 && F_SETFD==2 && F_GETFL==3 && F_SETFL==4, "target fcntl commands");
_Static_assert(FD_CLOEXEC==1, "target descriptor close-on-exec flag");
#undef O_NONBLOCK
#define O_NONBLOCK 0x0004
#include "../native/pw_native_peer_probe.h"
static int mock_close(int),mock_socket(int,int,int),mock_fcntl(int,int,...);
static int mock_ioctl(int,unsigned long,...);
static int mock_setsockopt(int,int,int,const void *,socklen_t);
static int mock_bind(int,const struct sockaddr *,socklen_t),mock_listen(int,int);
static int mock_accept(int,struct sockaddr *,socklen_t *),mock_connect(int,const struct sockaddr *,socklen_t);
static int mock_poll(struct pollfd *,nfds_t,int),mock_unlink(const char *),mock_kqueue(void);
static ssize_t mock_sendmsg(int,const struct msghdr *,int),mock_recvmsg(int,struct msghdr *,int);
static int mock_kevent(int,const struct kevent *,int,struct kevent *,int,const struct timespec *);
static int mock_sysctl(const int *,unsigned,void *,size_t *,const void *,size_t);
#define PW_NATIVE_PEER_TEST_ABI 1
#define TEST_HAS_PRESTOP 1
#define close mock_close
#define socket mock_socket
#define fcntl mock_fcntl
#define ioctl mock_ioctl
#define setsockopt mock_setsockopt
#define bind mock_bind
#define listen mock_listen
#define accept mock_accept
#define connect mock_connect
#define poll mock_poll
#define unlink mock_unlink
#define kqueue mock_kqueue
#define sendmsg mock_sendmsg
#define recvmsg mock_recvmsg
#define kevent(...) mock_kevent(__VA_ARGS__)
#define sysctl mock_sysctl
#include "../native/pw_native_peer_probe.c"
#undef close
#undef socket
#undef fcntl
#undef ioctl
#undef setsockopt
#undef bind
#undef listen
#undef accept
#undef connect
#undef poll
#undef unlink
#undef kqueue
#undef sendmsg
#undef recvmsg
#undef kevent
#undef sysctl

enum { CT_NORMAL, CT_NONE, CT_DUP, CT_RIGHTS, CT_WRONG_LEVEL, CT_WRONG_TYPE,
 CT_SMALL, CT_SHORT_PAYLOAD, CT_LONG_PAYLOAD, CT_OVER_CAP, CT_BAD_LENGTH,
 CT_WRONG_PID, CT_NEG_GROUP, CT_MANY_GROUP, CT_LATE, CT_EVERY, CT_RIGHTS_FIRST };
static struct {
 PwNativeChildFrame session; PwNativeChildIo io; PwNativePeerProbe probe; PwNativePeerResult result;
 uint64_t now; int cancel,clock_fail; unsigned clocks,chunk,recv_at,recv_record;
 int worker,control_type,control_flags,control_small,recv_return,send_return;
 int eof_after,wire_bad,echo_bit,control_eof;int credential_pid_override,credential_pid_set;
 int socket_fail,accept_fail,connect_fail,bind_fail,listen_fail,prepare_fail,unlink_fail,queue_fail;
 int close_fail,close_effect,close_count[256],sockets,accepts,sends,receives,unlinks,queues;
 int fcntl_calls,close_errno,ioctl_calls[256],fd_flags[256],file_flags[256];
 int ioctl_fail_fd,ioctl_fail_result,setsockopt_fail_fd,connects,worker_reports;
 unsigned long ioctl_fail_request;PwNativePeerRecord sent_worker_report;
 int setsockopt_calls,bind_calls,listen_calls,prepare_effect;
 int poll_effect,control_poll,control_short; unsigned control_at,control_sent;
 int event_step,receipt_case,early_case,event_case,rng_return,rng_size,rng_calls,receipt_calls;
 int rng_effect,send_effect,recv_effect,event_effect; unsigned max_slice;
 struct kevent registration; uint8_t nonce[32]; PwNativePeerRecord outbound[4];
 unsigned outbound_count; unsigned sequence,receipt_order,entropy_order,challenge_order;
} m;
static unsigned checks;
#define CHECK(x) do { checks++; if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);return 1;} }while(0)
static void effect(int value)
{ if(value==1)m.now=m.io.stage_end<m.io.total_end?m.io.stage_end:m.io.total_end;
  if(value==2)m.cancel=1;
  if(value==3)m.now=0;
  if(value==4)m.clock_fail=1; }
static int clock_cb(void *p,uint64_t *v){(void)p;m.clocks++;*v=m.now;return m.clock_fail?-1:0;}
static int cancel_cb(void *p){(void)p;return m.cancel;}
static PwNativePeerRecord record(unsigned kind)
{ PwNativePeerRecord r;pw_native_peer_record(&r,&m.session,kind);
  if(kind==PW_NP_WORKER_RESULT)r.observations=7;
  if(kind==PW_NP_CHALLENGE||kind==PW_NP_WORKER_ECHO)memcpy(r.challenge,m.nonce,32);
  return r; }
static long control_receive(void *p,void *out,size_t n,unsigned ms)
{
 (void)p;assert(ms>0&&ms<=25);uint8_t wire[128];
 PwNativePeerRecord r=record(m.worker?PW_NP_CHALLENGE:PW_NP_WORKER_RESULT);
 assert(!pw_native_peer_encode(wire,&r));if(m.control_eof>=0&&m.control_at>=(unsigned)m.control_eof)return 0;size_t amount=128-m.control_at;if(amount>n)amount=n;
 if(m.control_short&&amount>(unsigned)m.control_short)amount=(unsigned)m.control_short;
 if(m.control_eof>=0&&amount>(unsigned)m.control_eof-m.control_at)amount=(unsigned)m.control_eof-m.control_at;
 memcpy(out,wire+m.control_at,amount);m.control_at+=(unsigned)amount;return (long)amount;
}
static long control_send(void *p,const void *in,size_t n,unsigned ms)
{
 (void)p;assert(ms>0&&ms<=25);static uint8_t wire[128];size_t amount=n;
 if(m.control_short&&amount>(unsigned)m.control_short)amount=(unsigned)m.control_short;
 assert(m.control_sent+amount<=128);memcpy(wire+m.control_sent,in,amount);m.control_sent+=(unsigned)amount;
 if(m.control_sent==128){PwNativePeerRecord r;assert(!pw_native_peer_decode(&r,wire,&m.session));
  if(!m.worker){assert(r.kind==PW_NP_CHALLENGE&&m.rng_calls==1&&m.receipt_calls==1);
   assert(!memcmp(r.challenge,m.nonce,32));m.challenge_order=++m.sequence;}
  else {assert(r.kind==PW_NP_WORKER_RESULT);m.worker_reports++;m.sent_worker_report=r;for(unsigned i=0;i<32;i++)assert(!r.challenge[i]);}}
 return (long)amount;
}
static void reset(void)
{
 memset(&m,0,sizeof(m));m.now=100;m.chunk=128;m.recv_return=-999;m.send_return=128;m.rng_size=32;m.ioctl_fail_fd=-1;m.ioctl_fail_result=-1;m.setsockopt_fail_fd=-1;
 m.close_fail=-1;m.eof_after=-1;m.control_eof=-1;m.echo_bit=-1;m.session.parent_pid=101;m.session.child_pid=202;m.session.child_ppid=303;
 m.session.correlation=UINT64_C(0x1020304050607080);memcpy(m.session.build_id,"peer-model-test",16);
 m.io=(PwNativeChildIo){.clock_ms=clock_cb,.receive=control_receive,.send=control_send,
   .cancelled=cancel_cb,.stage_end=5000,.total_end=15000,.last_clock=100,.ready=1};
 m.probe.listener=m.probe.stream=m.probe.queue=-1;
 for(unsigned i=0;i<32;i++)m.nonce[i]=(uint8_t)(i*7+3);
}
static int mock_close(int fd)
{ assert(fd>=0&&fd<256);m.close_count[fd]++;assert(m.close_count[fd]==1);
 if(fd==40)effect(m.close_effect);
 if(m.close_errno)errno=m.close_errno;
 if(fd==m.close_fail){errno=5;return -1;}return 0; }
static int mock_socket(int family,int type,int protocol)
{ assert(family==AF_UNIX&&type==SOCK_STREAM&&!protocol);m.sockets++;return m.socket_fail?-1:20; }
static int mock_fcntl(int fd,int cmd,...)
{ (void)fd;(void)cmd;m.fcntl_calls++;errno=EINVAL;return -1; }
static int mock_ioctl(int fd,unsigned long request,...)
{
 assert(fd==20||fd==30);int step=m.ioctl_calls[fd]++;
 assert(request==(step==0?FIOCLEX:FIONBIO));assert(step<2);
 va_list args;va_start(args,request);
 if(request==FIOCLEX){assert(va_arg(args,void *)==NULL);}
 else {int *one=va_arg(args,int *);assert(one&&*one==1);}
 va_end(args);
 if(m.prepare_fail||(fd==m.ioctl_fail_fd&&request==m.ioctl_fail_request)){
  errno=EINVAL;return m.ioctl_fail_result;
 }
 if(request==FIOCLEX)m.fd_flags[fd]|=FD_CLOEXEC;
 else m.file_flags[fd]|=O_NONBLOCK;
 return 0;
}
static int mock_setsockopt(int fd,int level,int name,const void *value,socklen_t n)
{ m.setsockopt_calls++;assert(fd==20||fd==30);assert(level==SOL_SOCKET&&name==SO_NOSIGPIPE&&n==sizeof(int)&&*(const int *)value==1);assert(m.ioctl_calls[fd]==2);if(fd==m.setsockopt_fail_fd){errno=EINVAL;return -1;}effect(m.prepare_effect);return 0; }
static int mock_bind(int fd,const struct sockaddr *a,socklen_t n)
{ m.bind_calls++;assert(fd==20&&a&&n>2&&a->sa_len==n&&a->sa_family==AF_UNIX);return m.bind_fail?-1:0; }
static int mock_listen(int fd,int backlog){m.listen_calls++;assert(fd==20&&backlog==1);return m.listen_fail?-1:0;}
static int mock_accept(int fd,struct sockaddr *a,socklen_t *n)
{ assert(fd==20&&!a&&!n);m.accepts++;return m.accept_fail?-1:30; }
static int mock_connect(int fd,const struct sockaddr *a,socklen_t n)
{ m.connects++;assert(fd==20&&a&&n>2&&a->sa_len==n&&a->sa_family==AF_UNIX);return m.connect_fail?-1:0; }
static int mock_unlink(const char *p){assert(strstr(p,"/peer-"));m.unlinks++;return m.unlink_fail?-1:0;}
static int mock_poll(struct pollfd *p,nfds_t n,int timeout)
{
 assert(n==1&&timeout>=0&&timeout<=25);
 if(timeout==0&&p->fd==STDIN_FILENO){p->revents=(short)m.control_poll;return !!p->revents;}
 if((unsigned)timeout>m.max_slice)m.max_slice=(unsigned)timeout;
 p->revents=p->events;effect(m.poll_effect);return 1;
}
static ssize_t mock_sendmsg(int fd,const struct msghdr *msg,int flags)
{
 assert((fd==20||fd==30)&&!flags&&msg->msg_iovlen==1&&msg->msg_iov[0].iov_len==128);
 assert(msg->msg_controllen==CMSG_SPACE(sizeof(struct cmsgcred)));
 struct cmsghdr *h=CMSG_FIRSTHDR(msg);assert(h&&h->cmsg_level==SOL_SOCKET&&h->cmsg_type==SCM_CREDS&&h->cmsg_len==CMSG_LEN(sizeof(struct cmsgcred)));
 for(unsigned i=0;i<sizeof(struct cmsgcred);i++)assert(!CMSG_DATA(h)[i]);
 assert(m.outbound_count<4);assert(!pw_native_peer_decode(&m.outbound[m.outbound_count++],msg->msg_iov[0].iov_base,&m.session));
 m.sends++;effect(m.send_effect);return m.send_return;
}
static size_t add_control(unsigned char *p,int type,uint32_t pid)
{
 struct cmsghdr *h=(struct cmsghdr *)(void *)p;h->cmsg_level=SOL_SOCKET;h->cmsg_type=type;
 if(type==SCM_CREDS){struct cmsgcred c={0};c.cmcred_pid=m.credential_pid_set?m.credential_pid_override:(int32_t)pid;c.cmcred_uid=1000;c.cmcred_euid=2000;c.cmcred_gid=3000;c.cmcred_ngroups=16;
  h->cmsg_len=CMSG_LEN(sizeof(c));memcpy(CMSG_DATA(h),&c,sizeof(c));return CMSG_SPACE(sizeof(c));}
 int values[]={70,71,70,-1};h->cmsg_len=CMSG_LEN(sizeof(values));memcpy(CMSG_DATA(h),values,sizeof(values));return CMSG_SPACE(sizeof(values));
}
static ssize_t mock_recvmsg(int fd,struct msghdr *msg,int flags)
{
 assert((fd==20||fd==30)&&!flags&&msg->msg_iovlen==1);m.receives++;
 uint8_t wire[128];PwNativePeerRecord r=record(m.worker?PW_NP_PARENT_READY:(m.recv_record?PW_NP_WORKER_ECHO:PW_NP_WORKER_READY));
 if(m.recv_record&&m.echo_bit>=0)r.challenge[m.echo_bit/8]^=(uint8_t)(1u<<(m.echo_bit%8));
 assert(!pw_native_peer_encode(wire,&r));if(m.wire_bad)wire[m.wire_bad-1]^=1;
 size_t amount=128-m.recv_at;
 if(amount>m.chunk)amount=m.chunk;
 if(amount>msg->msg_iov[0].iov_len)amount=msg->msg_iov[0].iov_len;
 if(m.eof_after>=0){if(m.recv_at>=(unsigned)m.eof_after)amount=0;else if(amount>(unsigned)m.eof_after-m.recv_at)amount=(unsigned)m.eof_after-m.recv_at;}
 memcpy(msg->msg_iov[0].iov_base,wire+m.recv_at,amount);unsigned char *p=msg->msg_control;
 size_t capacity=msg->msg_controllen,n=0;uint32_t pid=m.worker?m.session.parent_pid:m.session.child_pid;
 if((m.recv_at==0&&m.control_type!=CT_NONE&&m.control_type!=CT_LATE)||
    (m.recv_at!=0&&(m.control_type==CT_LATE||m.control_type==CT_EVERY))){
  if(m.control_type==CT_RIGHTS_FIRST)n+=add_control(p,SCM_RIGHTS,pid);
  n+=add_control(p+n,SCM_CREDS,pid);
  if(m.control_type==CT_DUP)n+=add_control(p+n,SCM_CREDS,pid);
  if(m.control_type==CT_RIGHTS)n+=add_control(p+n,SCM_RIGHTS,pid);
  struct cmsghdr *h=(struct cmsghdr *)(void *)p;struct cmsgcred c;memcpy(&c,CMSG_DATA(h),sizeof(c));
  switch(m.control_type){
  case CT_WRONG_LEVEL:h->cmsg_level=0;break;case CT_WRONG_TYPE:h->cmsg_type=99;break;
  case CT_SMALL:n=(size_t)m.control_small;break;case CT_SHORT_PAYLOAD:h->cmsg_len--;break;
  case CT_LONG_PAYLOAD:h->cmsg_len++;break;case CT_OVER_CAP:n=capacity+1;break;
  case CT_BAD_LENGTH:h->cmsg_len=UINT32_MAX;break;
  case CT_WRONG_PID:c.cmcred_pid++;memcpy(CMSG_DATA(h),&c,sizeof(c));break;
  case CT_NEG_GROUP:c.cmcred_ngroups=-1;memcpy(CMSG_DATA(h),&c,sizeof(c));break;
  case CT_MANY_GROUP:c.cmcred_ngroups=17;memcpy(CMSG_DATA(h),&c,sizeof(c));break;
  default:break;}
 }
 msg->msg_controllen=(socklen_t)n;msg->msg_flags=m.control_flags;m.recv_at+=(unsigned)amount;
 if(m.recv_at==128){m.recv_at=0;m.recv_record++;}effect(m.recv_effect);
 return m.recv_return==-999?(ssize_t)amount:m.recv_return;
}
static int mock_kqueue(void){m.queues++;return m.queue_fail?-1:40;}
static void make_exit(struct kevent *event)
{ *event=m.registration;event->flags=EV_EOF;event->fflags=NOTE_EXIT;event->data=W_EXITCODE(37,0); }
static int mock_kevent(int fd,const struct kevent *change,int nchange,struct kevent *event,int nevent,const struct timespec *timeout)
{
 assert(fd==40&&event&&nevent==1&&timeout&&timeout->tv_sec==0&&timeout->tv_nsec>=0&&timeout->tv_nsec<=25000000);
 if(change){assert(nchange==1&&!timeout->tv_nsec&&change->ident==m.session.child_pid&&change->filter==EVFILT_PROC&&change->flags==(EV_ADD|EV_ENABLE|EV_RECEIPT)&&change->fflags==NOTE_EXIT&&!change->data);
  m.receipt_calls++;assert(m.receipt_calls==1);m.registration=*change;*event=*change;event->flags=EV_ERROR;event->data=0;m.receipt_order=++m.sequence;
  switch(m.receipt_case){case 1:return 0;case 2:return 2;case 3:event->ident++;break;case 4:event->filter++;break;case 5:event->udata=NULL;break;case 6:event->flags=0;break;case 7:event->data=3;break;case 8:event->fflags=0;break;case 9:event->flags|=EV_EOF;break;case 10:errno=3;return -1;default:break;}
  return 1;
 }
 assert(!nchange);m.event_step++;
 if(!timeout->tv_nsec){if(m.early_case==m.event_step){make_exit(event);return 1;}return 0;}
 make_exit(event);effect(m.event_effect);
 switch(m.event_case){case 1:event->ident++;break;case 2:event->filter++;break;case 3:event->udata=NULL;break;case 4:event->flags|=EV_ERROR;break;case 5:event->flags=0;break;case 6:event->fflags=0;break;case 7:event->data=37;break;case 8:event->data=W_EXITCODE(2,0);break;case 9:event->data=W_EXITCODE(3,0);break;case 10:event->data=W_EXITCODE(4,0);break;case 11:event->data=9;break;case 12:return 2;case 13:errno=5;return -1;default:break;}
 return 1;
}
static int mock_sysctl(const int *mib,unsigned count,void *out,size_t *bytes,const void *newp,size_t newlen)
{
 assert(mib&&count==2&&mib[0]==CTL_KERN&&mib[1]==KERN_ARND&&out&&bytes&&*bytes==32&&!newp&&!newlen);
 assert(m.receipt_calls==1&&m.event_step==1);m.rng_calls++;assert(m.rng_calls==1);m.entropy_order=++m.sequence;
 memcpy(out,m.nonce,32);*bytes=(size_t)m.rng_size;effect(m.rng_effect);return m.rng_return;
}
static int open_parent(void)
{ char dir[100],path[100];assert(!pw_native_peer_paths(m.session.parent_pid,m.session.correlation,dir,path));return pw_native_peer_parent_open(&m.probe,path,&m.io,&m.result); }
static int exchange_parent(void)
{ int rc=pw_native_peer_parent_exchange(&m.probe,&m.io,&m.session,&m.result);
#ifdef TEST_HAS_PRESTOP
 if(!rc)rc=pw_native_peer_pre_stop(&m.probe,&m.io,&m.result);
#endif
 return rc; }
static void armed(void)
{ m.probe.queue=40;m.probe.armed=1;m.probe.peer_pid=m.session.child_pid;m.result.prestop_empty=1;
 EV_SET(&m.registration,m.session.child_pid,EVFILT_PROC,EV_ADD|EV_ENABLE|EV_RECEIPT,NOTE_EXIT,0,&m.probe); }
static int test_receipt(void)
{ reset();CHECK(!open_parent());CHECK(!exchange_parent());CHECK(m.result.receipt_ok&&m.result.initial_empty&&m.result.nonce_match&&m.result.worker_report_valid);
 CHECK(m.receipt_order<m.entropy_order&&m.entropy_order<m.challenge_order);CHECK(m.io.stage_end==5000);
 CHECK(!pw_native_peer_observe(&m.probe,&m.io,1,&m.result));CHECK(m.result.phase==PW_NP_COMPLETE&&m.result.exit_status_match);CHECK(m.close_count[20]==1&&m.close_count[30]==1&&m.close_count[40]==1&&m.unlinks==1);return 0; }
static int test_reserve(void)
{ reset();m.worker=1;m.now=m.io.last_clock=2300;m.io.total_end=3000;
 CHECK(pw_native_peer_worker_exchange(&m.io,&m.session,&m.result)<0);CHECK(m.result.status==PW_NP_TIMEOUT&&m.sockets==0&&m.sends==0);return 0; }
static int test_close_budget(void)
{ reset();armed();CHECK(!pw_native_peer_observe(&m.probe,&m.io,1,&m.result));CHECK(m.result.phase==PW_NP_COMPLETE);
 for(int e=1;e<=4;e++){reset();armed();m.close_effect=e;
 CHECK(pw_native_peer_observe(&m.probe,&m.io,1,&m.result)<0);CHECK(m.result.phase!=PW_NP_COMPLETE&&m.close_count[40]==1);}
 return 0; }
static int test_credentials(void)
{
 for(unsigned chunk=1;chunk<=128;chunk++){reset();m.chunk=chunk;PwNativePeerRecord r;PwNativePeerCredential c={0};
 CHECK(!receive_credential(30,&r,&m.session,202,&c,0,0,&m.io,&m.result));CHECK(c.pid==202&&c.uid==1000&&c.euid==2000&&c.groups==16);}
 for(int t=CT_NONE;t<=CT_RIGHTS_FIRST;t++){reset();m.control_type=t;m.chunk=1;m.control_small=1;PwNativePeerRecord r;PwNativePeerCredential c={0};
 CHECK(receive_credential(30,&r,&m.session,202,&c,0,0,&m.io,&m.result)<0);CHECK(m.result.status==PW_NP_PROTOCOL);
 if(t==CT_RIGHTS||t==CT_RIGHTS_FIRST)CHECK(m.close_count[70]==1&&m.close_count[71]==1);}
 for(int n=1;n<(int)CMSG_LEN(0);n++){reset();m.control_type=CT_SMALL;m.control_small=n;PwNativePeerRecord r;PwNativePeerCredential c={0};CHECK(receive_credential(30,&r,&m.session,202,&c,0,0,&m.io,&m.result)<0);}
 for(int pid=-1;pid<=1;pid++){reset();m.credential_pid_set=1;m.credential_pid_override=pid;PwNativePeerRecord r;PwNativePeerCredential c={0};CHECK(receive_credential(30,&r,&m.session,202,&c,0,0,&m.io,&m.result)<0);}
 reset();m.control_type=CT_RIGHTS;m.close_fail=70;{PwNativePeerRecord r;PwNativePeerCredential c={0};CHECK(receive_credential(30,&r,&m.session,202,&c,0,0,&m.io,&m.result)<0);CHECK(m.result.status==PW_NP_PROTOCOL&&m.result.raw_result==128&&m.result.cleanup_failed);CHECK(m.close_count[70]==1&&m.close_count[71]==1);}
 for(int offset=1;offset<=40;offset++){reset();m.wire_bad=offset;PwNativePeerRecord r;PwNativePeerCredential c={0};CHECK(receive_credential(30,&r,&m.session,202,&c,0,0,&m.io,&m.result)<0);}
 for(int flag=MSG_TRUNC;flag<=MSG_CTRUNC;flag*=2){reset();m.control_flags=flag;PwNativePeerRecord r;PwNativePeerCredential c={0};CHECK(receive_credential(30,&r,&m.session,202,&c,0,0,&m.io,&m.result)<0);}
 for(int n=-1;n<=129;n++){if(n==128)continue;reset();m.send_return=n;PwNativePeerRecord r=record(PW_NP_WORKER_READY);CHECK(send_credential(30,&r,0,0,&m.io,&m.result)<0);CHECK(m.sends==1);}
 for(int cut=0;cut<128;cut++){reset();m.eof_after=cut;PwNativePeerRecord r;PwNativePeerCredential c={0};CHECK(receive_credential(30,&r,&m.session,202,&c,0,0,&m.io,&m.result)<0);CHECK(m.result.status==PW_NP_EOF);}
 for(int n=0;n<2;n++){reset();m.recv_return=n?-1:129;PwNativePeerRecord r;PwNativePeerCredential c={0};CHECK(receive_credential(30,&r,&m.session,202,&c,0,0,&m.io,&m.result)<0);}
 for(int e=1;e<=4;e++){reset();m.recv_effect=e;PwNativePeerRecord r;PwNativePeerCredential c={0};CHECK(receive_credential(30,&r,&m.session,202,&c,0,0,&m.io,&m.result)<0);}
 for(int e=1;e<=4;e++){reset();m.send_effect=e;PwNativePeerRecord r=record(PW_NP_WORKER_READY);CHECK(send_credential(30,&r,0,0,&m.io,&m.result)<0);CHECK(m.sends==1);}
 for(int e=1;e<=4;e++){reset();m.poll_effect=e;PwNativePeerRecord r=record(PW_NP_WORKER_READY);CHECK(send_credential(30,&r,0,0,&m.io,&m.result)<0);CHECK(!m.sends);}
 return 0;
}
static int test_events_entropy(void)
{
 for(int e=1;e<=10;e++){reset();m.receipt_case=e;CHECK(!open_parent());CHECK(exchange_parent()<0);CHECK(!m.rng_calls&&!m.challenge_order);pw_native_peer_parent_cleanup(&m.probe,&m.result);}
 for(int e=1;e<=2;e++){reset();m.early_case=e;CHECK(!open_parent());CHECK(exchange_parent()<0);CHECK(m.result.status==PW_NP_EXIT);if(e==1)CHECK(!m.rng_calls);pw_native_peer_parent_cleanup(&m.probe,&m.result);}
 for(int n=-1;n<=33;n++){if(n==32)continue;reset();m.rng_size=n;CHECK(!open_parent());CHECK(exchange_parent()<0);CHECK(m.rng_calls==1&&!m.challenge_order);pw_native_peer_parent_cleanup(&m.probe,&m.result);}
 for(int n=-1;n<=1;n+=2){reset();m.rng_return=n;CHECK(!open_parent());CHECK(exchange_parent()<0);CHECK(m.rng_calls==1&&!m.challenge_order);pw_native_peer_parent_cleanup(&m.probe,&m.result);}
 for(int e=1;e<=4;e++){reset();m.rng_effect=e;CHECK(!open_parent());CHECK(exchange_parent()<0);CHECK(m.rng_calls==1&&!m.challenge_order);pw_native_peer_parent_cleanup(&m.probe,&m.result);}
 for(int bit=0;bit<256;bit++){reset();m.echo_bit=bit;CHECK(!open_parent());CHECK(exchange_parent()<0);CHECK(!m.result.nonce_match);pw_native_peer_parent_cleanup(&m.probe,&m.result);}
 for(unsigned n=1;n<=128;n++){reset();m.chunk=n;m.control_short=(int)n;CHECK(!open_parent());CHECK(!exchange_parent());CHECK(m.result.prestop_empty&&m.result.reciprocal_ok);pw_native_peer_parent_cleanup(&m.probe,&m.result);}
 for(int cut=0;cut<128;cut++){reset();m.control_eof=cut;CHECK(!open_parent());CHECK(exchange_parent()<0);CHECK(!m.result.worker_report_valid);pw_native_peer_parent_cleanup(&m.probe,&m.result);}
 reset();memset(m.nonce,0,32);CHECK(!open_parent());CHECK(!exchange_parent());pw_native_peer_parent_cleanup(&m.probe,&m.result);
 for(int e=1;e<=13;e++){reset();armed();m.event_case=e;CHECK(pw_native_peer_observe(&m.probe,&m.io,1,&m.result)<0);CHECK(m.result.phase!=PW_NP_COMPLETE&&m.close_count[40]==1);}
 reset();armed();CHECK(pw_native_peer_observe(&m.probe,&m.io,0,&m.result)<0);CHECK(m.result.exit_observed&&m.result.exit_status_match&&m.result.status==PW_NP_PROTOCOL);
 reset();armed();m.result.status=PW_NP_ENTROPY;m.result.raw_result=-45;CHECK(pw_native_peer_observe(&m.probe,&m.io,1,&m.result)<0);CHECK(m.result.status==PW_NP_ENTROPY&&m.result.raw_result==-45&&m.result.exit_observed);
 for(int e=1;e<=4;e++){reset();armed();m.event_effect=e;CHECK(pw_native_peer_observe(&m.probe,&m.io,1,&m.result)<0);CHECK(m.close_count[40]==1);}
 return 0;
}
static int test_paths_deadlines(void)
{
 char d[100],p[100];reset();CHECK(!pw_native_peer_paths(101,UINT64_C(0x1020304050607080),d,p));
 CHECK(!strcmp(d,"/data/prospero-win/peer-00000065-1020304050607080"));CHECK(!strcmp(p,"/data/prospero-win/peer-00000065-1020304050607080/s"));
 CHECK(pw_native_peer_paths(0,1,d,p)<0&&pw_native_peer_paths(1,1,d,p)<0&&pw_native_peer_paths(UINT32_MAX,1,d,p)<0&&pw_native_peer_paths(2,0,d,p)<0);
 const char *bad[]={"relative","/data//x","/data/./x","/data/../x","/data/x/","/data/x\n"};
 for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++){reset();CHECK(pw_native_peer_parent_open(&m.probe,bad[i],&m.io,&m.result)<0);CHECK(!m.sockets&&!m.unlinks);}
 reset();armed();m.io.stage_end=101;CHECK(!pw_native_peer_observe(&m.probe,&m.io,1,&m.result));
 for(int i=0;i<2;i++){reset();armed();if(i)m.io.total_end=100;else m.io.stage_end=100;CHECK(pw_native_peer_observe(&m.probe,&m.io,1,&m.result)<0);CHECK(m.result.status==PW_NP_TIMEOUT&&!m.event_step);}
 reset();armed();m.result.prestop_empty=0;CHECK(pw_native_peer_observe(&m.probe,&m.io,1,&m.result)<0);CHECK(m.result.status==PW_NP_PROTOCOL);
 return 0;
}
static int test_worker_cleanup(void)
{
 for(int stage=0;stage<3;stage++){reset();CHECK(!open_parent());if(stage==0)m.accept_fail=1;if(stage==1)m.queue_fail=1;if(stage==2)m.close_fail=30;CHECK(exchange_parent()<0);pw_native_peer_parent_cleanup(&m.probe,&m.result);CHECK(m.close_count[20]==1&&m.close_count[30]==(stage!=0)&&m.close_count[40]==(stage==2));}
 reset();m.worker=1;m.connect_fail=1;CHECK(pw_native_peer_worker_exchange(&m.io,&m.session,&m.result)<0);CHECK(m.close_count[20]==1&&!m.sends);
 for(unsigned chunk=1;chunk<=128;chunk++){reset();m.worker=1;m.chunk=chunk;m.control_short=(int)chunk;CHECK(!pw_native_peer_worker_exchange(&m.io,&m.session,&m.result));CHECK(m.sends==2&&m.close_count[20]==1&&m.control_sent==128);CHECK(m.outbound[0].kind==PW_NP_WORKER_READY&&m.outbound[1].kind==PW_NP_WORKER_ECHO);CHECK(!memcmp(m.outbound[1].challenge,m.nonce,32));}
 for(int p=1;p<=3;p++){reset();m.worker=1;m.control_poll=p==1?POLLHUP:p==2?POLLERR:POLLNVAL;CHECK(pw_native_peer_worker_exchange(&m.io,&m.session,&m.result)<0);CHECK(m.close_count[20]==1&&!m.sends);}
 reset();m.worker=1;m.close_fail=20;CHECK(pw_native_peer_worker_exchange(&m.io,&m.session,&m.result)<0);CHECK(m.result.cleanup_failed&&m.close_count[20]==1);
 for(int i=0;i<5;i++){reset();if(i==0)m.socket_fail=1;if(i==1)m.prepare_fail=1;if(i==2)m.bind_fail=1;if(i==3)m.listen_fail=1;if(i==4){m.cancel=1;}
 CHECK(open_parent()<0);pw_native_peer_parent_cleanup(&m.probe,&m.result);CHECK(m.close_count[20]==(i>0&&i<4));CHECK(m.unlinks==(i==3));}
 reset();CHECK(!open_parent());m.unlink_fail=1;pw_native_peer_parent_cleanup(&m.probe,&m.result);CHECK(m.result.cleanup_failed&&m.unlinks==1);pw_native_peer_parent_cleanup(&m.probe,&m.result);CHECK(m.unlinks==1&&m.close_count[20]==1);
 reset();armed();m.close_fail=40;CHECK(pw_native_peer_observe(&m.probe,&m.io,1,&m.result)<0);CHECK(m.result.cleanup_failed&&m.close_count[40]==1);
 return 0;
}
static int test_ioctl_contract(void)
{
 const unsigned expected_api[]={PW_NP_API_IOCTL_FIOCLEX,PW_NP_API_IOCTL_FIONBIO};
 CHECK(expected_api[0]==24&&expected_api[1]==25);
 /* Model only the documented bit-specific effect; this is no target kernel proof. */
 for(int role=0;role<3;role++)for(int already=0;already<2;already++){
  reset();m.fd_flags[20]=m.fd_flags[30]=0x40|(already?FD_CLOEXEC:0);
  m.file_flags[20]=m.file_flags[30]=2|8|(already?O_NONBLOCK:0);
  int rc;if(role==2){m.worker=1;rc=pw_native_peer_worker_exchange(&m.io,&m.session,&m.result);}
  else {rc=open_parent();if(!rc&&role==1)rc=exchange_parent();}
  CHECK(!m.fcntl_calls);CHECK(!rc);
  int fd=role==1?30:20;CHECK(m.ioctl_calls[fd]==2);
  CHECK(m.fd_flags[fd]==(0x40|FD_CLOEXEC)&&m.file_flags[fd]==(2|8|O_NONBLOCK));
  CHECK(m.setsockopt_calls==(role==1?2:1));
  if(role!=2)pw_native_peer_parent_cleanup(&m.probe,&m.result);
  CHECK(m.close_count[20]==1);if(role==1)CHECK(m.close_count[30]==1);
 }
 for(int role=0;role<3;role++)for(int command=0;command<2;command++)
 for(int close_error=0;close_error<2;close_error++)for(int positive=0;positive<2;positive++){
  reset();if(role==1)CHECK(!open_parent());if(role==2)m.worker=1;
  int fd=role==1?30:20;m.fd_flags[fd]=0x40;m.file_flags[fd]=2|8;
  m.ioctl_fail_fd=fd;m.ioctl_fail_request=command?FIONBIO:FIOCLEX;m.ioctl_fail_result=positive?1:-1;
  m.close_errno=EBADF;if(close_error)m.close_fail=fd;
  int rc=role==0?open_parent():role==1?exchange_parent():pw_native_peer_worker_exchange(&m.io,&m.session,&m.result);
  CHECK(rc<0&&m.result.status==PW_NP_OS);CHECK(m.result.phase==(role==1?PW_NP_READY:PW_NP_SETUP));
  CHECK(m.result.api==expected_api[command]&&m.result.raw_result==m.ioctl_fail_result);
  CHECK(m.result.native_error==(positive?0:EINVAL));CHECK(!m.fcntl_calls);
  CHECK(m.ioctl_calls[fd]==command+1&&m.close_count[fd]==1);
  CHECK(m.fd_flags[fd]==(0x40|(command?FD_CLOEXEC:0))&&m.file_flags[fd]==(2|8));
  CHECK(m.setsockopt_calls==(role==1?1:0)&&m.bind_calls==(role==1?1:0)&&m.listen_calls==(role==1?1:0));
  CHECK(!m.connects&&!m.sends&&!m.receives&&!m.queues&&!m.rng_calls);
  CHECK(m.result.cleanup_failed==(unsigned)close_error);
  if(role==2){CHECK(m.worker_reports==1&&!pw_native_peer_worker_success(&m.sent_worker_report));
   CHECK(m.sent_worker_report.status==PW_NP_OS&&m.sent_worker_report.phase==PW_NP_SETUP);
   CHECK(m.sent_worker_report.observations==(close_error?0u:PW_NP_WORKER_CLOSED));}
  else {pw_native_peer_parent_cleanup(&m.probe,&m.result);CHECK(m.close_count[20]==1);
   CHECK(m.unlinks==(role==1));if(role==1)CHECK(m.close_count[30]==1);}
  CHECK(m.result.api==expected_api[command]&&m.result.raw_result==m.ioctl_fail_result);
  CHECK(m.result.native_error==(positive?0:EINVAL));
 }
 /* Both flags remain required if the later SIGPIPE setup fails. */
 for(int role=0;role<3;role++){
  reset();if(role==1)CHECK(!open_parent());if(role==2)m.worker=1;
  int fd=role==1?30:20;m.setsockopt_fail_fd=fd;
  int rc=role==0?open_parent():role==1?exchange_parent():pw_native_peer_worker_exchange(&m.io,&m.session,&m.result);
  CHECK(rc<0&&m.result.api==PW_NP_API_SETSOCKOPT&&m.result.native_error==EINVAL);
  CHECK(m.ioctl_calls[fd]==2&&m.close_count[fd]==1&&!m.fcntl_calls);
  CHECK(!m.connects&&!m.sends&&!m.receives&&!m.queues);
  if(role!=2)pw_native_peer_parent_cleanup(&m.probe,&m.result);
 }
 return 0;
}
static int test_prepare_boundary(int worker,int cancelled)
{
 reset();m.prepare_effect=cancelled?2:1;int rc;
 if(worker){m.worker=1;rc=pw_native_peer_worker_exchange(&m.io,&m.session,&m.result);}
 else rc=open_parent();
 CHECK(rc<0);CHECK(m.result.status==(cancelled?PW_NP_CANCELLED:PW_NP_TIMEOUT));
 CHECK(m.close_count[20]==1);CHECK(!m.sends&&!m.receives&&!m.queues);
 fprintf(stderr,"boundary worker=%d cancel=%d bind=%d listen=%d connect=%d close=%d status=%d\n",
   worker,cancelled,m.bind_calls,m.listen_calls,m.connects,m.close_count[20],m.result.status);
 if(worker)CHECK(!m.connects);else CHECK(!m.bind_calls&&!m.listen_calls&&!m.unlinks);
 return 0;
}
int main(int argc,char **argv)
{
 (void)mock_ioctl;(void)mock_fcntl;
 if(argc>1){
  if(!strcmp(argv[1],"prepare-parent-expiry"))return test_prepare_boundary(0,0);
  if(!strcmp(argv[1],"prepare-parent-cancel"))return test_prepare_boundary(0,1);
  if(!strcmp(argv[1],"prepare-worker-expiry"))return test_prepare_boundary(1,0);
  if(!strcmp(argv[1],"prepare-worker-cancel"))return test_prepare_boundary(1,1);
  if(!strcmp(argv[1],"ioctl"))return test_ioctl_contract();
  if(!strcmp(argv[1],"receipt"))return test_receipt();
  if(!strcmp(argv[1],"reserve"))return test_reserve();
  if(!strcmp(argv[1],"close-budget"))return test_close_budget();
  return 2;
 }
 if(test_prepare_boundary(0,0)||test_prepare_boundary(0,1)||test_prepare_boundary(1,0)||test_prepare_boundary(1,1)||
    test_ioctl_contract()||test_receipt()||test_reserve()||test_close_budget()||test_credentials()||test_events_entropy()||test_paths_deadlines()||test_worker_cleanup())return 1;
 printf("native peer target-ABI pure mocks: %u checks passed; no native capabilities verified\n",checks);return 0;
}
