/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_wine_child_wire.h"
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#ifdef __PROSPERO__
_Static_assert(SIGQUIT == PW_WC_SIGNAL_QUIT && SIGUSR1 == PW_WC_SIGNAL_USR1, "signal ABI");
#endif
enum { MAX_RIGHTS = 16, POLL_SLICE = 25 };
static const unsigned char magic[8] = {'P','W','W','C','H','L','D',0};
static void put32(unsigned char *p, uint32_t n) { for (unsigned i=0;i<4;i++) p[i]=(unsigned char)(n>>(8*i)); }
static void put64(unsigned char *p, uint64_t n) { for (unsigned i=0;i<8;i++) p[i]=(unsigned char)(n>>(8*i)); }
static uint32_t get32(const unsigned char *p) { uint32_t n=0; for(unsigned i=0;i<4;i++) n|=(uint32_t)p[i]<<(8*i); return n; }
static uint64_t get64(const unsigned char *p) { uint64_t n=0; for(unsigned i=0;i<8;i++) n|=(uint64_t)p[i]<<(8*i); return n; }
static int valid(const PwWineChildFrame *f)
{
    if (!f || f->kind<PW_WC_HELLO || f->kind>PW_WC_FAILURE ||
        !f->child_pid || f->child_pid>INT32_MAX || !f->child_ppid || f->child_ppid>INT32_MAX ||
        f->parent_pid>INT32_MAX || f->target_tid<0 || f->native_error<0 || f->build_id[40]) return 0;
    for(unsigned i=0;i<40;i++) if (!((f->build_id[i]>='0'&&f->build_id[i]<='9')||
                                    (f->build_id[i]>='a'&&f->build_id[i]<='f'))) return 0;
    if(f->errno_valid>1)return 0;
    if(f->kind!=PW_WC_FAILURE&&(f->failure_api||f->failure_raw||f->returned_length||f->returned_value||f->errno_valid))return 0;
    if(f->kind==PW_WC_HELLO)
        return !f->generation&&!f->sequence&&!f->parent_pid&&!f->wine_pid&&!f->wine_tid&&
               !f->target_tid&&!f->signal&&!f->status&&!f->native_error&&!f->profile&&!f->machine;
    if((f->profile!=PW_WC_PROFILE_FIXTURE&&f->profile!=PW_WC_PROFILE_BATTLENET)||
       (f->machine!=PW_WC_MACHINE_AMD64&&f->machine!=PW_WC_MACHINE_I386)||
       (f->profile==PW_WC_PROFILE_FIXTURE&&f->machine!=PW_WC_MACHINE_AMD64))return 0;
    if(!f->generation||!f->parent_pid||f->parent_pid==f->child_pid||!f->wine_pid||!f->wine_tid) return 0;
    if(f->kind==PW_WC_BOOTSTRAP||f->kind==PW_WC_BOOTSTRAP_ACK)
        return f->sequence==1&&!f->target_tid&&!f->signal&&!f->status&&!f->native_error;
    if(f->kind==PW_WC_FAILURE)
        return f->sequence>=1&&!f->target_tid&&!f->signal&&f->status<0&&
               (f->errno_valid?f->native_error>0:!f->native_error);
    if(f->sequence<2||!f->target_tid ||
       (f->signal!=PW_WC_SIGNAL_QUIT&&f->signal!=PW_WC_SIGNAL_USR1)) return 0;
    if(f->kind==PW_WC_SIGNAL) return !f->status&&!f->native_error;
    return (f->status==0&&!f->native_error)||(f->status==-1&&f->native_error>0);
}
int pw_wine_child_wire_encode(unsigned char out[PW_WC_WIRE_BYTES], const PwWineChildFrame *f)
{
    if(!out||!valid(f)) return -1;
    memset(out,0,PW_WC_WIRE_BYTES); memcpy(out,magic,8); put32(out+8,2); put32(out+12,f->kind);
    put64(out+16,f->generation); put32(out+24,f->sequence); put32(out+28,f->parent_pid);
    put32(out+32,f->child_pid); put32(out+36,f->child_ppid); put32(out+40,f->wine_pid);
    put32(out+44,f->wine_tid); put64(out+48,(uint64_t)f->target_tid);
    put32(out+56,(uint32_t)f->signal); put32(out+60,(uint32_t)f->status);
    put32(out+64,(uint32_t)f->native_error); memcpy(out+68,f->build_id,40);
    put32(out+108,f->failure_api);put32(out+112,(uint32_t)f->failure_raw);
    put32(out+116,f->returned_length);put32(out+120,(uint32_t)f->returned_value);
    put32(out+124,f->errno_valid);put32(out+128,f->profile);put32(out+132,f->machine);return 0;
}
int pw_wine_child_wire_decode(PwWineChildFrame *f, const unsigned char in[PW_WC_WIRE_BYTES])
{
    PwWineChildFrame v={0};
    if(!f||!in||memcmp(in,magic,8)||get32(in+8)!=2) return -1;
    v.kind=get32(in+12); v.generation=get64(in+16); v.sequence=get32(in+24);
    v.parent_pid=get32(in+28); v.child_pid=get32(in+32); v.child_ppid=get32(in+36);
    v.wine_pid=get32(in+40); v.wine_tid=get32(in+44); v.target_tid=(int64_t)get64(in+48);
    v.signal=(int32_t)get32(in+56); v.status=(int32_t)get32(in+60); v.native_error=(int32_t)get32(in+64);
    memcpy(v.build_id,in+68,40);v.failure_api=get32(in+108);v.failure_raw=(int32_t)get32(in+112);
    v.returned_length=get32(in+116);v.returned_value=(int32_t)get32(in+120);v.errno_valid=get32(in+124);v.profile=get32(in+128);v.machine=get32(in+132);
    if(!valid(&v)) return -1;
    *f=v; return 0;
}
int pw_wine_child_wire_same_session(const PwWineChildFrame *a,const PwWineChildFrame *b)
{
    return a&&b&&a->generation==b->generation&&a->parent_pid==b->parent_pid&&
        a->child_pid==b->child_pid&&a->child_ppid==b->child_ppid&&a->wine_pid==b->wine_pid&&
        a->wine_tid==b->wine_tid&&a->profile==b->profile&&a->machine==b->machine&&!memcmp(a->build_id,b->build_id,41);
}
static int fail(PwWineChildWireResult *r,int status,int api,int64_t raw,int error)
{
    if(r&&!r->status){r->status=status;r->api=api;r->raw_result=raw;
        if(error){r->native_error=error;r->errno_valid=1;}}
    return PW_WC_ERROR;
}
static int budget(PwNativeChildIo *io,PwWineChildWireResult *r,unsigned *left)
{
    unsigned n;
    if(!io||!io->ready||!io->clock_ms||!r) return fail(r,PW_WC_INVALID,PW_WC_API_NONE,0,0);
    if(r->status) return -1;
    if(pw_native_child_remaining(io,&n)) return fail(r,PW_WC_BUDGET,PW_WC_API_CLOCK,-1,0);
    if(left) *left=n;
    return 0;
}
void pw_wine_child_wire_close(int *slot,PwWineChildWireResult *r)
{
    if(!slot||*slot<0) return;
    int fd=*slot; *slot=-1; int rc=close(fd),error=rc<0?errno:0;
    if(rc){if(r){if(!r->cleanup_failed&&rc<0){r->cleanup_native_error=error;r->cleanup_errno_valid=1;}
                   r->cleanup_failed=1;r->ownership_uncertain=1;}
        fail(r,PW_WC_OS,PW_WC_API_CLOSE,rc,error);}
    else if(r) r->rights_closed++;
}
static int socket_type(int fd,int expected,PwWineChildWireResult *r)
{
    int type=0; socklen_t len=sizeof(type);
    int rc=getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&len),error=rc<0?errno:0;
    if(rc) return fail(r,PW_WC_OS,PW_WC_API_TYPE,rc,error);
    if(len!=sizeof(type)||type!=expected) return fail(r,PW_WC_PROTOCOL,PW_WC_API_TYPE,type,0);
    return 0;
}
int pw_wine_child_wire_validate(PwNativeChildIo *io,int fd,PwWineChildWireResult *r)
{
    if(fd<0) return fail(r,PW_WC_INVALID,PW_WC_API_TYPE,fd,0);
    if(budget(io,r,NULL)||socket_type(fd,SOCK_SEQPACKET,r)) return -1;
    return budget(io,r,NULL);
}
static int poll_once(PwNativeChildIo *io,int fd,int writing,PwWineChildWireResult *r)
{
    unsigned left;
    if(fd<0)return fail(r,PW_WC_INVALID,PW_WC_API_POLL,fd,0);
    if(budget(io,r,&left)) return -1;
    struct pollfd p={fd,writing?POLLOUT:POLLIN,0};
    int rc=poll(&p,1,(int)(left<POLL_SLICE?left:POLL_SLICE)),error=rc<0?errno:0;
    r->poll_revents=(uint32_t)(unsigned short)p.revents;
    if(rc<0) return fail(r,PW_WC_OS,PW_WC_API_POLL,rc,error);
    if(rc>1||(!rc&&p.revents)) return fail(r,PW_WC_PROTOCOL,PW_WC_API_POLL,rc,0);
    if(budget(io,r,NULL)) return -1;
    if(!rc) return PW_WC_IDLE;
    if(p.revents&(POLLERR|POLLNVAL)) return fail(r,PW_WC_OS,PW_WC_API_POLL,p.revents,0);
    if((p.revents&~(POLLIN|POLLOUT|POLLHUP))||
       !(p.revents&(writing?POLLOUT:POLLIN|POLLHUP))||(writing&&(p.revents&POLLHUP)))
        return fail(r,PW_WC_PROTOCOL,PW_WC_API_POLL,p.revents,0);
    return PW_WC_RECORD;
}
int pw_wine_child_wire_try_send(int fd,const PwWineChildFrame *f,int right,PwWineChildWireResult *r)
{
    unsigned char bytes[PW_WC_WIRE_BYTES];
    union{struct cmsghdr align;unsigned char bytes[CMSG_SPACE(sizeof(int))];} control;
    if(!r||r->status||fd<0||right< -1||!f||pw_wine_child_wire_encode(bytes,f)||
       ((f->kind==PW_WC_BOOTSTRAP)!=(right>=0))||right==fd)
        return fail(r,PW_WC_INVALID,PW_WC_API_SEND,-1,0);
    struct iovec part={bytes,sizeof(bytes)};struct msghdr m={0};m.msg_iov=&part;m.msg_iovlen=1;
    if(right>=0){memset(&control,0,sizeof(control));struct cmsghdr *h=&control.align;
        h->cmsg_level=SOL_SOCKET;h->cmsg_type=SCM_RIGHTS;h->cmsg_len=CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(h),&right,sizeof(right));m.msg_control=control.bytes;m.msg_controllen=sizeof(control.bytes);}
    ssize_t sent=sendmsg(fd,&m,MSG_DONTWAIT|MSG_NOSIGNAL);int error=sent<0?errno:0;
    if(sent!=PW_WC_WIRE_BYTES){r->delivery_uncertain=1;
        return fail(r,sent<0?PW_WC_OS:PW_WC_PROTOCOL,PW_WC_API_SEND,sent,error);}
    return 0;
}
int pw_wine_child_wire_send(PwNativeChildIo *io,int fd,const PwWineChildFrame *f,int right,PwWineChildWireResult *r)
{
    int rc;do{rc=poll_once(io,fd,1,r);}while(rc==PW_WC_IDLE);
    if(rc<0||pw_wine_child_wire_try_send(fd,f,right,r)) return -1;
    if(budget(io,r,NULL)){r->delivery_uncertain=1;return -1;}return 0;
}
/* Parse only complete bounds-checked records as descriptor ownership. The
 * caller settles every collected unique descriptor before any refusal. */
static unsigned collect(int channel,const unsigned char *p,size_t cap,size_t reported,
                        int out[MAX_RIGHTS],PwWineChildWireResult *r,int *valid_control)
{
    size_t used=reported,at=0;unsigned count=0,records=0;*valid_control=1;
    if(used>cap){used=cap;r->ownership_uncertain=1;*valid_control=0;}
    while(at<used){struct cmsghdr h;
        if(used-at<sizeof(h)){r->ownership_uncertain=1;*valid_control=0;break;}
        memcpy(&h,p+at,sizeof(h));size_t len=h.cmsg_len,head=CMSG_LEN(0);
        if(len<head||len>used-at){r->ownership_uncertain=1;*valid_control=0;break;}
        size_t payload=len-head;records++;
        if(h.cmsg_level!=SOL_SOCKET||h.cmsg_type!=SCM_RIGHTS){*valid_control=0;r->ownership_uncertain=1;}
        else if(!payload||payload%sizeof(int)){*valid_control=0;r->ownership_uncertain=1;}
        else for(size_t n=0;n<payload;n+=sizeof(int)){int fd,duplicate=0;memcpy(&fd,p+at+head+n,sizeof(fd));
            for(unsigned i=0;i<count;i++) if(out[i]==fd) duplicate=1;
            if(fd<0||fd==channel||duplicate||count==MAX_RIGHTS){*valid_control=0;r->ownership_uncertain=1;}
            else out[count++]=fd;}
        if(len==used-at)break;
        size_t next=CMSG_SPACE(payload);
        if(next>used-at){for(size_t n=len;n<used-at;n++)if(p[at+n]){*valid_control=0;r->ownership_uncertain=1;}break;}
        at+=next;
    }
    if(records!=1||count!=1)*valid_control=0;
    return count;
}
int pw_wine_child_wire_receive_step(PwNativeChildIo *io,int fd,uint32_t kinds,
                                   PwWineChildFrame *f,int *right,PwWineChildWireResult *r)
{
    if(!r||!f||!right||*right!=-1||!kinds||kinds&~0x7eu) return fail(r,PW_WC_INVALID,PW_WC_API_RECEIVE,0,0);
    int rc=poll_once(io,fd,0,r);if(rc!=PW_WC_RECORD)return rc;
    unsigned char bytes[PW_WC_WIRE_BYTES];
    union{struct cmsghdr align;unsigned char bytes[CMSG_SPACE(MAX_RIGHTS*sizeof(int))];} control;
    struct iovec part={bytes,sizeof(bytes)};struct msghdr m={0};memset(&control,0,sizeof(control));
    m.msg_iov=&part;m.msg_iovlen=1;m.msg_control=control.bytes;m.msg_controllen=sizeof(control.bytes);
    ssize_t got=recvmsg(fd,&m,MSG_DONTWAIT);int error=got<0?errno:0;
    r->received_bytes=got;r->message_flags=(uint32_t)m.msg_flags;r->control_bytes=m.msg_controllen;
    if(got<0)return fail(r,PW_WC_OS,PW_WC_API_RECEIVE,got,error);
    int rights[MAX_RIGHTS],control_valid=0;unsigned count=0;
    if(m.msg_controllen)count=collect(fd,control.bytes,sizeof(control.bytes),m.msg_controllen,rights,r,&control_valid);
    if(m.msg_flags&MSG_CTRUNC)r->ownership_uncertain=1;
    PwWineChildFrame frame={0};int okay=got==PW_WC_WIRE_BYTES&&!pw_wine_child_wire_decode(&frame,bytes)&&
        (kinds&PW_WC_KIND(frame.kind))&&!(m.msg_flags&~(MSG_EOR|MSG_DONTWAIT));
    if(okay)okay=frame.kind==PW_WC_BOOTSTRAP?control_valid&&count==1:!m.msg_controllen;
    int closed=got==0&&!m.msg_controllen&&!(m.msg_flags&~MSG_DONTWAIT)&&
               (r->poll_revents&POLLHUP);
    if(got==0){r->channel_zero_observed=1;r->hangup_observed=(r->poll_revents&POLLHUP)!=0;}
    if(!okay&&!closed)fail(r,PW_WC_PROTOCOL,PW_WC_API_RECEIVE,got,0);
    if(budget(io,r,NULL))okay=closed=0; /* own/clean received rights before further native work */
    if(okay&&frame.kind==PW_WC_BOOTSTRAP&&socket_type(rights[0],SOCK_STREAM,r))okay=0;
    if(budget(io,r,NULL))okay=closed=0;
    if(!okay||r->status){for(unsigned i=0;i<count;i++)pw_wine_child_wire_close(&rights[i],r);
        return closed&&!r->status?PW_WC_CHANNEL_CLOSED:PW_WC_ERROR;}
    if(count)*right=rights[0];
    *f=frame;return PW_WC_RECORD;
}
int pw_wine_child_wire_receive(PwNativeChildIo *io,int fd,uint32_t kinds,
                              PwWineChildFrame *f,int *right,PwWineChildWireResult *r)
{
    int rc;do{rc=pw_wine_child_wire_receive_step(io,fd,kinds,f,right,r);}while(rc==PW_WC_IDLE);return rc;
}
