/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_native_peer_probe.h"
#include <sys/types.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>
#ifndef PW_NATIVE_PEER_WORKER_ONLY
#include <errno.h>
#ifndef PW_NATIVE_PEER_TEST_ABI
#include <sys/event.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#endif
#endif
#if !defined(__FreeBSD__) && !defined(__PROSPERO__) && !defined(PW_NATIVE_PEER_TEST_ABI)
#error "This diagnostic requires the reviewed BSD credential/event ABI"
#endif

enum { CONTROL_BYTES = 2*CMSG_SPACE(sizeof(struct cmsgcred)) + CMSG_SPACE(8*sizeof(int)),
       MAX_RIGHTS = CONTROL_BYTES / sizeof(int) };
static int fail(PwNativePeerResult *r, int status, int64_t raw)
{
    if(!r->status){
        r->status=status;r->raw_result=raw;
#ifndef PW_NATIVE_PEER_WORKER_ONLY
        if(status==PW_NP_OS && raw<0)r->native_error=errno;
#endif
    }
    return -1;
}
static void phase(PwNativePeerResult *r, unsigned value) { if(!r->status)r->phase=value; }
static void api(PwNativePeerResult *r, unsigned value) { if(!r->status)r->api=value; }
static void close_owned(int *fd, PwNativePeerResult *r)
{
    if(*fd<0)return;
    int owned=*fd;*fd=-1;api(r,PW_NP_API_CLOSE);
    int rc=close(owned);
    if(rc){r->cleanup_failed=1;fail(r,PW_NP_OS,rc);}
}
static int remaining(PwNativeChildIo *io, PwNativePeerResult *r, unsigned *slice)
{
    uint64_t now,end;
    if(!io || !io->ready || !io->clock_ms)return fail(r,PW_NP_INVALID,0);
    if(io->cancelled && io->cancelled(io->context))return fail(r,PW_NP_CANCELLED,0);
    api(r,PW_NP_API_CLOCK);
    int rc=io->clock_ms(io->context,&now);
    if(rc || now<io->last_clock)return fail(r,PW_NP_CLOCK,rc);
    io->last_clock=now;end=io->stage_end<io->total_end?io->stage_end:io->total_end;
    if(now>=end)return fail(r,PW_NP_TIMEOUT,0);
    if(slice)*slice=(unsigned)(end-now>25?25:end-now);
    return 0;
}
static int control_lost(int worker, int challenge_pending, PwNativePeerResult *r)
{
    if(!worker)return 0;
    struct pollfd p={STDIN_FILENO,POLLIN,0};api(r,PW_NP_API_POLL);
    int rc=poll(&p,1,0);
    if(rc<0)return fail(r,PW_NP_OS,rc);
    if(rc>1 || p.revents & (POLLNVAL|POLLERR|POLLHUP))return fail(r,PW_NP_CANCELLED,p.revents);
    if(p.revents & ~POLLIN)return fail(r,PW_NP_PROTOCOL,p.revents);
    if((p.revents&POLLIN) && !challenge_pending)return fail(r,PW_NP_PROTOCOL,p.revents);
    return 0;
}
static int ready(int fd, short events, int worker, int challenge_pending,
                  PwNativeChildIo *io, PwNativePeerResult *r)
{
    for(;;){
        unsigned slice;struct pollfd p={fd,events,0};
        if(remaining(io,r,&slice) || control_lost(worker,challenge_pending,r))return -1;
        api(r,PW_NP_API_POLL);int rc=poll(&p,1,(int)slice);
        if(rc<0)return fail(r,PW_NP_OS,rc);
        if(remaining(io,r,NULL) || control_lost(worker,challenge_pending,r))return -1;
        api(r,PW_NP_API_POLL);
        if(!rc)continue;
        if(rc!=1 || p.revents&POLLNVAL)return fail(r,PW_NP_PROTOCOL,p.revents);
        if(p.revents&(events|POLLHUP|POLLERR))return 0;
        return fail(r,PW_NP_PROTOCOL,p.revents);
    }
}
static int prepare(int fd, PwNativePeerResult *r)
{
    /* BSD setters change only these bits, without a flag read/modify/write.
     * This ordinary descriptor API is separate from SceNet's socket IDs. */
    api(r,PW_NP_API_IOCTL_FIOCLEX);int rc=ioctl(fd,FIOCLEX,(void *)0);
    if(rc)return fail(r,PW_NP_OS,rc);
    int one=1;api(r,PW_NP_API_IOCTL_FIONBIO);rc=ioctl(fd,FIONBIO,&one);
    if(rc)return fail(r,PW_NP_OS,rc);
#if defined(__FreeBSD__) || defined(__PROSPERO__) || defined(PW_NATIVE_PEER_TEST_ABI)
    api(r,PW_NP_API_SETSOCKOPT);
    rc=setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));
    if(rc<0)return fail(r,PW_NP_OS,rc);
#endif
    return 0;
}
static int socket_new(PwNativePeerResult *r)
{
    api(r,PW_NP_API_SOCKET);int fd=socket(AF_UNIX,SOCK_STREAM,0);
    if(fd<0){fail(r,PW_NP_OS,fd);return -1;}
    if(prepare(fd,r))close_owned(&fd,r);
    return fd;
}
static int address(const char *path, struct sockaddr_un *a, socklen_t *size, PwNativePeerResult *r)
{
    size_t n=0;
    if(!path || *path!='/')return fail(r,PW_NP_INVALID,0);
    while(n<PW_NP_PATH_CAP && path[n])n++;
    if(!n || n>=PW_NP_PATH_CAP || n+1>sizeof(a->sun_path))return fail(r,PW_NP_INVALID,0);
    for(size_t i=0;i<n;i++){
        if((unsigned char)path[i]<32 || path[i]==127)return fail(r,PW_NP_INVALID,0);
        if(path[i]=='/' && (path[i+1]=='/' || !path[i+1] ||
           (path[i+1]=='.' && (!path[i+2] || path[i+2]=='/' ||
            (path[i+2]=='.' && (!path[i+3] || path[i+3]=='/'))))))return fail(r,PW_NP_INVALID,0);
    }
    memset(a,0,sizeof(*a));a->sun_family=AF_UNIX;memcpy(a->sun_path,path,n+1);
    *size=(socklen_t)(offsetof(struct sockaddr_un,sun_path)+n+1);
#if defined(__FreeBSD__) || defined(__PROSPERO__) || defined(PW_NATIVE_PEER_TEST_ABI)
    a->sun_len=(unsigned char)*size;
#endif
    return 0;
}
int pw_native_peer_paths(uint32_t pid, uint64_t token, char directory[PW_NP_PATH_CAP], char path[PW_NP_PATH_CAP])
{
    static const char prefix[]="/data/prospero-win/peer-",hex[]="0123456789abcdef";
    enum{PREFIX=sizeof(prefix)-1,LENGTH=PREFIX+8+1+16};
    _Static_assert(LENGTH+3<=PW_NP_PATH_CAP,"peer path is bounded");
    if(!directory || !path || pid<=1 || pid>INT32_MAX || !token)return -1;
    memcpy(directory,prefix,PREFIX);
    for(unsigned i=0;i<8;i++)directory[PREFIX+i]=hex[(pid>>((7-i)*4))&15];
    directory[PREFIX+8]='-';
    for(unsigned i=0;i<16;i++)directory[PREFIX+9+i]=hex[(token>>((15-i)*4))&15];
    directory[LENGTH]=0;memcpy(path,directory,LENGTH);path[LENGTH]='/';path[LENGTH+1]='s';path[LENGTH+2]=0;return 0;
}
static int control_record(PwNativeChildIo *io, PwNativePeerRecord *record,
                          const PwNativeChildFrame *session, int writing, PwNativePeerResult *r)
{
    uint8_t bytes[PW_NP_RECORD_BYTES];size_t at=0;
    if(writing && pw_native_peer_encode(bytes,record))return fail(r,PW_NP_PROTOCOL,0);
    while(at<sizeof(bytes)){
        unsigned slice;if(remaining(io,r,&slice))return -1;
        api(r,PW_NP_API_CONTROL);
        long n=writing?io->send(io->context,bytes+at,sizeof(bytes)-at,slice):
                       io->receive(io->context,bytes+at,sizeof(bytes)-at,slice);
        if(n<0)return fail(r,PW_NP_OS,n);
        if(!n)return fail(r,PW_NP_EOF,0);
        if((unsigned long)n>sizeof(bytes)-at)return fail(r,PW_NP_PROTOCOL,n);
        at+=(size_t)n;if(remaining(io,r,NULL))return -1;
    }
    if(!writing && pw_native_peer_decode(record,bytes,session))return fail(r,PW_NP_PROTOCOL,0);
    return 0;
}
static int send_credential(int fd, const PwNativePeerRecord *record, int worker, int challenge_pending,
                            PwNativeChildIo *io, PwNativePeerResult *r)
{
    uint8_t bytes[PW_NP_RECORD_BYTES];
    union{struct cmsghdr align;unsigned char bytes[CMSG_SPACE(sizeof(struct cmsgcred))];}control;
    struct iovec iov={bytes,sizeof(bytes)};struct msghdr msg;
    if(pw_native_peer_encode(bytes,record))return fail(r,PW_NP_PROTOCOL,0);
    if(ready(fd,POLLOUT,worker,challenge_pending,io,r))return -1;
    memset(&control,0,sizeof(control));memset(&msg,0,sizeof(msg));
    msg.msg_iov=&iov;msg.msg_iovlen=1;msg.msg_control=control.bytes;msg.msg_controllen=sizeof(control.bytes);
    struct cmsghdr *h=CMSG_FIRSTHDR(&msg);h->cmsg_level=SOL_SOCKET;h->cmsg_type=SCM_CREDS;h->cmsg_len=CMSG_LEN(sizeof(struct cmsgcred));
    /* Sender credentials stay entirely zero. Only the kernel may fill them. */
    api(r,PW_NP_API_SENDMSG);ssize_t n=sendmsg(fd,&msg,0);
    if(n<0)return fail(r,PW_NP_OS,n);
    if(n!=(ssize_t)sizeof(bytes))return fail(r,PW_NP_PROTOCOL,n); /* never resend an ambiguous envelope */
    return remaining(io,r,NULL);
}
static int receive_credential(int fd, PwNativePeerRecord *record, const PwNativeChildFrame *session,
                               uint32_t expected_pid, PwNativePeerCredential *credential,
                               int worker, int challenge_pending, PwNativeChildIo *io, PwNativePeerResult *r)
{
    uint8_t bytes[PW_NP_RECORD_BYTES];size_t at=0;unsigned credential_seen=0;
    while(at<sizeof(bytes)){
        union{struct cmsghdr align;unsigned char bytes[CONTROL_BYTES];}control;
        struct iovec iov={bytes+at,sizeof(bytes)-at};struct msghdr msg;
        int rights[MAX_RIGHTS],right_count=0,bad=0;unsigned creds=0;
        struct cmsgcred received;memset(&received,0,sizeof(received));
        if(ready(fd,POLLIN,worker,challenge_pending,io,r))return -1;
        memset(&control,0,sizeof(control));memset(&msg,0,sizeof(msg));
        msg.msg_iov=&iov;msg.msg_iovlen=1;msg.msg_control=control.bytes;msg.msg_controllen=sizeof(control.bytes);
        api(r,PW_NP_API_RECVMSG);ssize_t n=recvmsg(fd,&msg,0);
        if(n<0)return fail(r,PW_NP_OS,n);
        size_t limit=msg.msg_controllen;
        if(limit>sizeof(control.bytes)){bad=1;limit=sizeof(control.bytes);}
        if(limit && limit<CMSG_LEN(0))bad=1;
        struct msghdr inspect=msg;inspect.msg_control=control.bytes;inspect.msg_controllen=limit;
        for(struct cmsghdr *h=CMSG_FIRSTHDR(&inspect);h;h=CMSG_NXTHDR(&inspect,h)){
            size_t offset=(size_t)((unsigned char *)(void *)h-control.bytes);
            if(offset>limit || limit-offset<sizeof(*h) || h->cmsg_len<CMSG_LEN(0) || h->cmsg_len>limit-offset){bad=1;break;}
            size_t payload=h->cmsg_len-CMSG_LEN(0);
            if(h->cmsg_level==SOL_SOCKET && h->cmsg_type==SCM_RIGHTS){
                bad=1;
                for(size_t i=0;i<payload/sizeof(int);i++){
                    int value=((int *)(void *)CMSG_DATA(h))[i],duplicate=0;
                    if(value<0)continue;
                    for(int j=0;j<right_count;j++)if(rights[j]==value)duplicate=1;
                    if(!duplicate && right_count<MAX_RIGHTS)rights[right_count++]=value;
                }
            }else if(h->cmsg_level==SOL_SOCKET && h->cmsg_type==SCM_CREDS && payload==sizeof(struct cmsgcred)){
                if(++creds==1)memcpy(&received,CMSG_DATA(h),sizeof(received));
            }else bad=1;
        }
        if(msg.msg_flags&(MSG_CTRUNC|MSG_TRUNC))bad=1;
        if((size_t)n>sizeof(bytes)-at || creds!=(at?0u:1u))bad=1;
        if(creds){
            if(received.cmcred_pid<=1 || (uint32_t)received.cmcred_pid!=expected_pid ||
               received.cmcred_ngroups<0 || received.cmcred_ngroups>CMGROUP_MAX)bad=1;
        }
        if(bad){fail(r,PW_NP_PROTOCOL,n);for(int i=0;i<right_count;i++)close_owned(&rights[i],r);return -1;}
        if(remaining(io,r,NULL))return -1;
        if(!n)return fail(r,PW_NP_EOF,0);
        if(creds){
            credential_seen++;
            credential->pid=(uint32_t)received.cmcred_pid;credential->uid=(uint32_t)received.cmcred_uid;
            credential->euid=(uint32_t)received.cmcred_euid;credential->gid=(uint32_t)received.cmcred_gid;
            credential->groups=(uint32_t)received.cmcred_ngroups;
        }
        at+=(size_t)n;
    }
    if(credential_seen!=1 || pw_native_peer_decode(record,bytes,session))return fail(r,PW_NP_PROTOCOL,0);
    return 0;
}

#ifndef PW_NATIVE_PEER_WORKER_ONLY
static void close_rendezvous(PwNativePeerProbe *p, PwNativePeerResult *r)
{
    close_owned(&p->stream,r);close_owned(&p->listener,r);
    if(p->bound){p->bound=0;api(r,PW_NP_API_UNLINK);int rc=unlink(p->path);
        if(rc){r->cleanup_failed=1;fail(r,PW_NP_OS,rc);}}
}
void pw_native_peer_parent_cleanup(PwNativePeerProbe *p, PwNativePeerResult *r)
{ if(p && r){close_rendezvous(p,r);close_owned(&p->queue,r);} }
int pw_native_peer_parent_open(PwNativePeerProbe *p, const char *path, PwNativeChildIo *io, PwNativePeerResult *r)
{
    struct sockaddr_un a;socklen_t length;
    if(!p || !r)return -1;
    memset(p,0,sizeof(*p));p->listener=p->stream=p->queue=-1;memset(r,0,sizeof(*r));
    if(remaining(io,r,NULL) || address(path,&a,&length,r))return -1;
    p->listener=socket_new(r);if(p->listener<0)return -1;
    if(remaining(io,r,NULL))goto failed;
    api(r,PW_NP_API_BIND);int rc=bind(p->listener,(struct sockaddr *)(void *)&a,length);
    if(rc){fail(r,PW_NP_OS,rc);goto failed;}
    p->bound=1;memcpy(p->path,path,strlen(path)+1);
    api(r,PW_NP_API_LISTEN);rc=listen(p->listener,1);if(rc){fail(r,PW_NP_OS,rc);goto failed;}
    if(remaining(io,r,NULL))goto failed;
    return 0;
failed:close_rendezvous(p,r);return -1;
}
static void event_fields(const struct kevent *event, PwNativePeerProbe *p, PwNativePeerResult *r)
{
    r->event_ident=(uint64_t)event->ident;r->event_filter=event->filter;r->event_tag_matches=event->udata==p;
    r->exit_flags=event->flags;r->exit_fflags=event->fflags;r->exit_data=event->data;
}
static int event_matches(const struct kevent *event, PwNativePeerProbe *p)
{ return event->ident==p->peer_pid && event->filter==EVFILT_PROC && event->udata==p; }
static int exit_event(const struct kevent *event, PwNativePeerProbe *p, PwNativePeerResult *r)
{
    if(!event_matches(event,p) || event->flags&EV_ERROR ||
       !(event->flags&EV_EOF) || !(event->fflags&NOTE_EXIT))return 0;
    r->exit_observed=1;r->exit_status_match=event->data==W_EXITCODE(PW_NP_SUCCESS_EXIT,0);
    return 1;
}
static int empty_queue(PwNativePeerProbe *p, PwNativeChildIo *io, PwNativePeerResult *r)
{
    struct kevent event;struct timespec timeout={0,0};memset(&event,0,sizeof(event));
    if(remaining(io,r,NULL))return -1;
    api(r,PW_NP_API_PENDING);int rc=kevent(p->queue,NULL,0,&event,1,&timeout);
    if(rc<0)return fail(r,PW_NP_OS,rc);
    if(rc){event_fields(&event,p,r);if(rc==1)(void)exit_event(&event,p,r);return fail(r,PW_NP_EXIT,rc);}
    return remaining(io,r,NULL);
}
int pw_native_peer_parent_exchange(PwNativePeerProbe *p, PwNativeChildIo *io,
                                    const PwNativeChildFrame *session, PwNativePeerResult *r)
{
    PwNativePeerRecord record;struct kevent change,event;struct timespec timeout={0,0};
    uint8_t nonce[PW_NP_CHALLENGE_BYTES]={0};uint64_t outer=io->stage_end;
    phase(r,PW_NP_READY);
    if(p->listener<0 || !p->bound)return fail(r,PW_NP_INVALID,0);
    if(remaining(io,r,NULL))return -1;
    uint64_t effective=outer<io->total_end?outer:io->total_end;
    if(effective-io->last_clock<=PW_NP_REPORT_RESERVE_MS)return fail(r,PW_NP_TIMEOUT,0);
    io->stage_end=effective-PW_NP_REPORT_RESERVE_MS;
    p->peer_pid=session->child_pid;
    if(ready(p->listener,POLLIN,0,0,io,r))goto finish;
    api(r,PW_NP_API_ACCEPT);p->stream=accept(p->listener,NULL,NULL);
    if(p->stream<0){fail(r,PW_NP_OS,p->stream);goto finish;}
    if(prepare(p->stream,r) || receive_credential(p->stream,&record,session,p->peer_pid,&r->initial_credential,0,0,io,r))goto finish;
    if(record.kind!=PW_NP_WORKER_READY){fail(r,PW_NP_PROTOCOL,0);goto finish;}r->credential_ok=1;
    pw_native_peer_record(&record,session,PW_NP_PARENT_READY);
    if(send_credential(p->stream,&record,0,0,io,r))goto finish;
    phase(r,PW_NP_ARM);api(r,PW_NP_API_KQUEUE);p->queue=kqueue();
    if(p->queue<0){fail(r,PW_NP_OS,p->queue);goto finish;}
    /* Queue remains private, tagged by this stable owned record; no PID relookup. */
    memset(&change,0,sizeof(change));memset(&event,0,sizeof(event));
    EV_SET(&change,p->peer_pid,EVFILT_PROC,EV_ADD|EV_ENABLE|EV_RECEIPT,NOTE_EXIT,0,p);
    if(remaining(io,r,NULL))goto finish;
    api(r,PW_NP_API_ARM);int rc=kevent(p->queue,&change,1,&event,1,&timeout);
    if(rc<0){fail(r,PW_NP_OS,rc);goto finish;}
    r->receipt_flags=event.flags;r->receipt_fflags=event.fflags;r->receipt_data=event.data;
    if(rc!=1 || !event_matches(&event,p) || event.flags!=EV_ERROR || event.data || event.fflags!=NOTE_EXIT){
        fail(r,PW_NP_REGISTRATION,rc);goto finish;
    }
    p->armed=1;r->receipt_ok=1;
    if(remaining(io,r,NULL) || empty_queue(p,io,r))goto finish;
    r->initial_empty=1;
    phase(r,PW_NP_CHALLENGE_PHASE);api(r,PW_NP_API_ENTROPY);
    int mib[2]={CTL_KERN,KERN_ARND};size_t bytes=sizeof(nonce);
    rc=sysctl(mib,2,nonce,&bytes,NULL,0);r->entropy_return=rc;r->entropy_bytes=(unsigned)bytes;
    if(rc || bytes!=sizeof(nonce)){fail(r,PW_NP_ENTROPY,rc);goto finish;}r->entropy_ok=1;
    if(remaining(io,r,NULL))goto finish;
    pw_native_peer_record(&record,session,PW_NP_CHALLENGE);memcpy(record.challenge,nonce,sizeof(nonce));
    if(control_record(io,&record,session,1,r))goto finish;
    phase(r,PW_NP_ECHO_PHASE);
    if(receive_credential(p->stream,&record,session,p->peer_pid,&r->post_arm_credential,0,0,io,r))goto finish;
    if(record.kind!=PW_NP_WORKER_ECHO || memcmp(record.challenge,nonce,sizeof(nonce))){fail(r,PW_NP_PROTOCOL,0);goto finish;}
    r->nonce_match=1;
finish:
    /* Restore only the original bound; reporting cannot extend the stage. */
    io->stage_end=outer;memset(nonce,0,sizeof(nonce));memset(record.challenge,0,sizeof(record.challenge));
    phase(r,PW_NP_REPORT);
    if(!control_record(io,&record,session,0,r)){
        if(record.kind!=PW_NP_WORKER_RESULT)fail(r,PW_NP_PROTOCOL,0);
        else {r->worker_report=record;r->worker_report_valid=1;
            if(!pw_native_peer_worker_success(&record))fail(r,PW_NP_PROTOCOL,record.raw_result);
            else r->reciprocal_ok=1;}
    }
    close_rendezvous(p,r);
    return r->status?-1:0;
}
int pw_native_peer_pre_stop(PwNativePeerProbe *p, PwNativeChildIo *io, PwNativePeerResult *r)
{
    if(r->status)return -1;
    if(!p->armed || p->queue<0 || p->listener>=0 || p->stream>=0 || p->bound ||
       !r->worker_report_valid || !r->nonce_match)return fail(r,PW_NP_INVALID,0);
    if(empty_queue(p,io,r))return -1;
    r->prestop_empty=1;return 0;
}
int pw_native_peer_observe(PwNativePeerProbe *p, PwNativeChildIo *io, int cooperative, PwNativePeerResult *r)
{
    if(!p->armed || p->queue<0)return fail(r,PW_NP_REGISTRATION,0);
    phase(r,PW_NP_EXIT_PHASE);
    for(;!r->exit_observed;){
        unsigned slice;struct kevent event;memset(&event,0,sizeof(event));
        if(remaining(io,r,&slice))break;
        struct timespec timeout={0,(long)slice*1000000};api(r,PW_NP_API_EVENT);
        int rc=kevent(p->queue,NULL,0,&event,1,&timeout);
        if(rc<0){fail(r,PW_NP_OS,rc);break;}
        if(rc){
            event_fields(&event,p,r);
            if(rc!=1 || !exit_event(&event,p,r)){fail(r,PW_NP_EXIT,rc);break;}
            if(!r->exit_status_match)fail(r,PW_NP_EXIT,event.data);
            if(remaining(io,r,NULL))break;
            if(!cooperative)fail(r,PW_NP_PROTOCOL,0);
            break;
        }
        if(remaining(io,r,NULL))break;
    }
    if(!cooperative || !r->prestop_empty)fail(r,PW_NP_PROTOCOL,0);
    close_owned(&p->queue,r);
    (void)remaining(io,r,NULL);
    if(!r->status && r->exit_observed && r->exit_status_match){r->phase=PW_NP_COMPLETE;r->api=PW_NP_API_NONE;}
    return r->status?-1:0;
}
#endif

int pw_native_peer_worker_exchange(PwNativeChildIo *io, const PwNativeChildFrame *session, PwNativePeerResult *r)
{
    char directory[PW_NP_PATH_CAP],path[PW_NP_PATH_CAP];struct sockaddr_un a;socklen_t length;
    PwNativePeerRecord record;int fd=-1;uint64_t outer=io->stage_end;unsigned observations=0;
    memset(r,0,sizeof(*r));
    if(remaining(io,r,NULL))return -1;
    uint64_t effective=outer<io->total_end?outer:io->total_end;
    if(effective-io->last_clock<=PW_NP_REPORT_RESERVE_MS)return fail(r,PW_NP_TIMEOUT,0);
    io->stage_end=effective-PW_NP_REPORT_RESERVE_MS;
    if(pw_native_peer_paths(session->parent_pid,session->correlation,directory,path) || address(path,&a,&length,r)){fail(r,PW_NP_INVALID,0);goto finish;}
    fd=socket_new(r);if(fd<0)goto finish;
    if(remaining(io,r,NULL))goto finish;
    api(r,PW_NP_API_CONNECT);int rc=connect(fd,(struct sockaddr *)(void *)&a,length);
    if(rc){fail(r,PW_NP_OS,rc);goto finish;}
    phase(r,PW_NP_READY);pw_native_peer_record(&record,session,PW_NP_WORKER_READY);
    if(send_credential(fd,&record,1,1,io,r) ||
       receive_credential(fd,&record,session,session->parent_pid,&r->initial_credential,1,1,io,r))goto finish;
    if(record.kind!=PW_NP_PARENT_READY){fail(r,PW_NP_PROTOCOL,0);goto finish;}
    r->credential_ok=1;observations|=PW_NP_WORKER_CREDENTIAL;
    phase(r,PW_NP_CHALLENGE_PHASE);
    if(control_record(io,&record,session,0,r))goto finish;
    if(record.kind!=PW_NP_CHALLENGE){fail(r,PW_NP_PROTOCOL,0);goto finish;}
    phase(r,PW_NP_ECHO_PHASE);record.kind=PW_NP_WORKER_ECHO;record.phase=PW_NP_ECHO_PHASE;
    if(send_credential(fd,&record,1,0,io,r))goto finish;
    observations|=PW_NP_WORKER_ECHO_SENT;r->nonce_match=1;
finish:
    phase(r,PW_NP_REPORT);close_owned(&fd,r);
    if(!r->cleanup_failed)observations|=PW_NP_WORKER_CLOSED;
    io->stage_end=outer;
    pw_native_peer_record(&record,session,PW_NP_WORKER_RESULT);record.status=r->status;
    record.phase=r->status?r->phase:PW_NP_REPORT;record.observations=observations;record.raw_result=r->raw_result;
    if(control_record(io,&record,session,1,r))return -1;
    return r->status?-1:0;
}
