/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_wine_child_ui_handoff.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
enum { RIGHTS_CAP=16 };
static int fail(PwWineChildUiHandoff *h,int status,int api,int64_t raw,int error)
{
    if(h){h->state=PW_WCU_HANDOFF_FAILED;
        if(!h->result.status){h->result.status=status;h->result.api=api;h->result.raw_result=raw;
            h->result.errno_valid=error>0;h->result.native_error=error>0?error:0;}}
    return PW_WC_ERROR;
}
static int budget(PwWineChildUiHandoff *h,PwNativeChildIo *io)
{
    unsigned left;
    if(!h||h->state!=PW_WCU_HANDOFF_NEW||!io||!io->ready||!io->clock_ms)return -1;
    if(pw_native_child_remaining(io,&left))return fail(h,PW_WC_BUDGET,PW_WC_API_CLOCK,-1,0);
    return 0;
}
static int type(int fd,int expected)
{
    int actual=0;socklen_t bytes=sizeof(actual);
    return fd<0||getsockopt(fd,SOL_SOCKET,SO_TYPE,&actual,&bytes)||
           bytes!=sizeof(actual)||actual!=expected?-1:0;
}
/* Standard descriptor inspection, deliberately no target-specific guesses.
 * A platform without useful socket inode identity must not enable this mode. */
static int distinct_streams(int first,int second)
{
    struct stat a,b;
    return first==second||type(first,SOCK_STREAM)||type(second,SOCK_STREAM)||
           fstat(first,&a)||fstat(second,&b)||!a.st_ino||!b.st_ino||
           (a.st_dev==b.st_dev&&a.st_ino==b.st_ino)?-1:0;
}
static int ready(PwWineChildUiHandoff *h,PwNativeChildIo *io,int fd,int writing)
{
    if(budget(h,io))return PW_WC_ERROR;
    if(type(fd,SOCK_SEQPACKET))return fail(h,PW_WC_INVALID,PW_WC_API_TYPE,fd,0);
    struct pollfd p={fd,writing?POLLOUT:POLLIN,0};
    int rc=poll(&p,1,0),error=rc<0?errno:0;
    h->result.poll_revents=(unsigned short)p.revents;
    if(rc<0)return fail(h,PW_WC_OS,PW_WC_API_POLL,rc,error);
    if(rc>1||(!rc&&p.revents)||p.revents&~(POLLIN|POLLOUT|POLLHUP)||
       (rc&&!(p.revents&(writing?POLLOUT:POLLIN)))||p.revents&POLLHUP)
        return fail(h,PW_WC_PROTOCOL,PW_WC_API_POLL,p.revents,0);
    if(budget(h,io))return PW_WC_ERROR;
    return rc?PW_WC_RECORD:PW_WC_IDLE;
}
static int encode(unsigned char bytes[PW_WCU_HANDOFF_BYTES],const PwWineChildFrame *f,uint64_t session)
{
    if(!session||!f||f->kind!=PW_WC_BOOTSTRAP||pw_wine_child_wire_encode(bytes,f))return -1;
    bytes[8]=3;
    for(unsigned n=0;n<8;n++)bytes[136+n]=(unsigned char)(session>>(8*n));
    memset(bytes+144,0,8);return 0;
}
static int decode(PwWineChildFrame *f,uint64_t *session,unsigned char bytes[PW_WCU_HANDOFF_BYTES])
{
    if(bytes[8]!=3||bytes[9]||bytes[10]||bytes[11])return -1;
    for(unsigned n=144;n<PW_WCU_HANDOFF_BYTES;n++)if(bytes[n])return -1;
    bytes[8]=2;
    if(pw_wine_child_wire_decode(f,bytes)||f->kind!=PW_WC_BOOTSTRAP)return -1;
    *session=0;for(unsigned n=0;n<8;n++)*session|=(uint64_t)bytes[136+n]<<(8*n);
    return *session?0:-1;
}
int pw_wine_child_ui_handoff_send(PwWineChildUiHandoff *h,PwNativeChildIo *io,int control,
                                const PwWineChildFrame *f,uint64_t session,int server,int ui)
{
    unsigned char bytes[PW_WCU_HANDOFF_BYTES];
    if(!h||h->state!=PW_WCU_HANDOFF_NEW)return PW_WC_ERROR;
    if(server==control||ui==control||encode(bytes,f,session)||distinct_streams(server,ui))
        return fail(h,PW_WC_INVALID,PW_WC_API_SEND,-1,0);
    int rc=ready(h,io,control,1);if(rc!=PW_WC_RECORD)return rc;
    union {struct cmsghdr align;unsigned char bytes[CMSG_SPACE(2*sizeof(int))];} ancillary;
    memset(&ancillary,0,sizeof(ancillary));
    struct cmsghdr *c=&ancillary.align;c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;
    c->cmsg_len=CMSG_LEN(2*sizeof(int));int rights[2]={server,ui};memcpy(CMSG_DATA(c),rights,sizeof(rights));
    struct iovec part={bytes,sizeof(bytes)};struct msghdr message={0};
    message.msg_iov=&part;message.msg_iovlen=1;message.msg_control=ancillary.bytes;
    message.msg_controllen=sizeof(ancillary.bytes);
    ssize_t sent=sendmsg(control,&message,MSG_DONTWAIT|MSG_NOSIGNAL);int error=sent<0?errno:0;
    if(sent!=PW_WCU_HANDOFF_BYTES){h->result.delivery_uncertain=1;
        return fail(h,sent<0?PW_WC_OS:PW_WC_PROTOCOL,PW_WC_API_SEND,sent,error);}
    if(budget(h,io)){h->result.delivery_uncertain=1;return PW_WC_ERROR;}
    h->bootstrap=*f;h->session=session;h->state=PW_WCU_HANDOFF_DONE;return PW_WC_RECORD;
}
/* One authoritative ancillary parser, collect before any semantic refusal.
 * For malformed native lengths, only complete bounded SCM_RIGHTS entries are
 * known owned. Unknown/truncated ownership is recorded, never guessed/closed. */
static unsigned collect(PwWineChildUiHandoff *h,int channel,const unsigned char *p,size_t capacity,
                        size_t reported,int rights[RIGHTS_CAP],int *valid)
{
    unsigned count=0,records=0;size_t at=0,used=reported;*valid=1;
    if(used>capacity){used=capacity;*valid=0;h->result.ownership_uncertain=1;}
    while(at<used){struct cmsghdr c;
        if(used-at<sizeof(c)){*valid=0;h->result.ownership_uncertain=1;break;}
        memcpy(&c,p+at,sizeof(c));size_t len=c.cmsg_len,head=CMSG_LEN(0);
        /* If length escapes the returned envelope, apparent ints may be
         * alignment padding. There is no safe payload boundary to harvest. */
        if(len<head||len>used-at){*valid=0;h->result.ownership_uncertain=1;break;}
        size_t payload=len-head;records++;
        if(!payload||payload%sizeof(int)){*valid=0;h->result.ownership_uncertain=1;}
        if(c.cmsg_level!=SOL_SOCKET||c.cmsg_type!=SCM_RIGHTS){
            *valid=0;h->result.ownership_uncertain=1;
        }else for(size_t offset=0;offset+sizeof(int)<=payload;offset+=sizeof(int)){
            int fd,duplicate=0;memcpy(&fd,p+at+head+offset,sizeof(fd));
            for(unsigned n=0;n<count;n++)if(rights[n]==fd)duplicate=1;
            if(fd<0||fd==channel||duplicate||count==RIGHTS_CAP){*valid=0;h->result.ownership_uncertain=1;}
            else rights[count++]=fd;
        }
        if(len==used-at)break;
        size_t next=CMSG_SPACE(payload);
        if(next>used-at){for(size_t n=len;n<used-at;n++)if(p[at+n]){*valid=0;h->result.ownership_uncertain=1;}break;}
        at+=next;
    }
    if(records!=1||count!=2)*valid=0;
    return count;
}
int pw_wine_child_ui_handoff_receive(PwWineChildUiHandoff *h,PwNativeChildIo *io,int control,
                                   const PwWineChildFrame *hello,int *server,int *ui)
{
    unsigned char hello_bytes[PW_WC_WIRE_BYTES];
    if(!h||h->state!=PW_WCU_HANDOFF_NEW)return PW_WC_ERROR;
    if(!server||!ui||server==ui||*server!=-1||*ui!=-1||!hello||hello->kind!=PW_WC_HELLO||
       pw_wine_child_wire_encode(hello_bytes,hello))return fail(h,PW_WC_INVALID,PW_WC_API_RECEIVE,-1,0);
    int rc=ready(h,io,control,0);if(rc!=PW_WC_RECORD)return rc;
    unsigned char bytes[PW_WCU_HANDOFF_BYTES];
    union {struct cmsghdr align;unsigned char bytes[CMSG_SPACE(RIGHTS_CAP*sizeof(int))];} ancillary;
    memset(&ancillary,0,sizeof(ancillary));struct iovec part={bytes,sizeof(bytes)};struct msghdr message={0};
    message.msg_iov=&part;message.msg_iovlen=1;message.msg_control=ancillary.bytes;message.msg_controllen=sizeof(ancillary.bytes);
    ssize_t got=recvmsg(control,&message,MSG_DONTWAIT);int error=got<0?errno:0;
    h->result.received_bytes=got;h->result.message_flags=(uint32_t)message.msg_flags;
    h->result.control_bytes=message.msg_controllen;
    if(got<0)return fail(h,PW_WC_OS,PW_WC_API_RECEIVE,got,error);
    int rights[RIGHTS_CAP],valid=0;unsigned count=0;
    if(message.msg_controllen)count=collect(h,control,ancillary.bytes,sizeof(ancillary.bytes),message.msg_controllen,rights,&valid);
    if(message.msg_flags&MSG_CTRUNC)h->result.ownership_uncertain=1;
    PwWineChildFrame frame;uint64_t session=0;
    int okay=got==PW_WCU_HANDOFF_BYTES&&valid&&count==2&&
        !(message.msg_flags&~(MSG_EOR|MSG_DONTWAIT))&&!decode(&frame,&session,bytes);
    if(okay)okay=frame.child_pid==hello->child_pid&&frame.child_ppid==hello->child_ppid&&
        !memcmp(frame.build_id,hello->build_id,41);
    if(!okay)fail(h,PW_WC_PROTOCOL,PW_WC_API_RECEIVE,got,0);
    if(okay&&budget(h,io))okay=0;
    if(okay&&distinct_streams(rights[0],rights[1])){
        fail(h,PW_WC_PROTOCOL,PW_WC_API_TYPE,-1,0);okay=0;}
    /* Received rights must not survive a subsequent exec into another child.
     * This is before Wine or any producer thread starts. No fcntl retry. */
    for(unsigned n=0;okay&&n<count;n++){
        int flags=fcntl(rights[n],F_GETFD),native_error=flags<0?errno:0;
        if(flags<0){fail(h,PW_WC_OS,PW_WC_API_TYPE,flags,native_error);okay=0;break;}
        int set=fcntl(rights[n],F_SETFD,flags|FD_CLOEXEC);native_error=set<0?errno:0;
        if(set){fail(h,PW_WC_OS,PW_WC_API_TYPE,set,native_error);okay=0;}
    }
    if(okay&&budget(h,io))okay=0;
    if(!okay){for(unsigned n=0;n<count;n++)pw_wine_child_wire_close(&rights[n],&h->result);
        h->state=PW_WCU_HANDOFF_FAILED;return PW_WC_ERROR;}
    h->bootstrap=frame;h->session=session;h->state=PW_WCU_HANDOFF_DONE;
    *server=rights[0];*ui=rights[1];return PW_WC_RECORD;
}
int pw_wine_child_ui_handoff_identity(const PwWineChildUiHandoff *h,const PwWineChildFrame *accepted,
                                    PwWineChildUiIdentity *out)
{
    if(!h||!out||h->state!=PW_WCU_HANDOFF_DONE||!h->session||!accepted||
       accepted->kind!=PW_WC_BOOTSTRAP||accepted->sequence!=1||
       !pw_wine_child_wire_same_session(&h->bootstrap,accepted))return -1;
    *out=(PwWineChildUiIdentity){h->session,accepted->generation,accepted->child_pid};return 0;
}
