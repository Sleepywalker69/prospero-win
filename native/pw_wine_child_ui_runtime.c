/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#include "pw_wine_child_ui_runtime.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
static int close_once(PwWineChildUiOwner *u,int *slot)
{
    if(*slot<0)return 0;
    int fd=*slot;*slot=-1;
    if(close(fd)){u->close_uncertain=1;return -1;}return 0;
}
int pw_wine_child_ui_owner_retire(PwWineChildUiOwner *u)
{
    if(!u||!u->initialized)return -1;
    if(!u->retired){u->retired=1;(void)pw_wine_child_ui_end(&u->rx);
        (void)close_once(u,&u->passed_fd);(void)close_once(u,&u->fd);}
    return u->close_uncertain?-1:0;
}
int pw_wine_child_ui_owner_init(PwWineChildUiOwner *u,PwWineChildUiIdentity id,PwWinePresentSink sink,void *context)
{
    if(!u||u->initialized||!id.session||!id.generation||!id.native_pid||!sink)return -1;
    u->fd=u->passed_fd=-1;u->initialized=1;
    int pair[2]={-1,-1};int rc=socketpair(AF_UNIX,SOCK_STREAM,0,pair);
    if(rc||pair[0]<0||pair[1]<0||pair[0]==pair[1]){
        if(pair[0]>=0)u->fd=pair[0];
        if(pair[1]>=0&&pair[1]!=pair[0])u->passed_fd=pair[1];
        if(rc>0||(rc<0&&(pair[0]>=0||pair[1]>=0))||(!rc&&(pair[0]<0||pair[1]<0||pair[0]==pair[1])))u->close_uncertain=1;
        (void)pw_wine_child_ui_owner_retire(u);return -1;
    }
    u->fd=pair[0];u->passed_fd=pair[1];
    for(unsigned i=0;i<2;i++){
        int flags=fcntl(pair[i],F_GETFD);
        if(flags<0||fcntl(pair[i],F_SETFD,flags|FD_CLOEXEC)){
            (void)pw_wine_child_ui_owner_retire(u);return -1;}
    }
    void *storage=mmap(NULL,PW_WCU_MAX_BYTES,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    if(storage==MAP_FAILED){(void)pw_wine_child_ui_owner_retire(u);return -1;}
    u->storage=storage;
    if(pw_wine_child_ui_rx_init(&u->rx,id,PW_WCU_FRAME,u->storage,PW_WCU_MAX_BYTES,sink,NULL,context)){
        (void)pw_wine_child_ui_owner_retire(u);return -1;}
    return 0;
}
int pw_wine_child_ui_owner_send(PwWineChildUiOwner *u,PwNativeChildIo *io,int control,
                               const PwWineChildFrame *bootstrap,uint64_t session,int server)
{
    if(!u||!u->initialized||u->retired||session!=u->rx.identity.session||!bootstrap||
       bootstrap->generation!=u->rx.identity.generation||bootstrap->child_pid!=u->rx.identity.native_pid)return -1;
    int rc=pw_wine_child_ui_handoff_send(&u->handoff,io,control,bootstrap,session,server,u->passed_fd);
    if(rc==PW_WC_IDLE)return rc;
    (void)close_once(u,&u->passed_fd);
    if(rc!=PW_WC_RECORD||u->close_uncertain){(void)pw_wine_child_ui_owner_retire(u);return PW_WC_ERROR;}
    return PW_WC_RECORD;
}
/* UI carries bytes only. Kernel-delivered rights are still owned before a
 * protocol refusal and must be closed. No reuse after uncertain metadata. */
static int refuse_rights(PwWineChildUiOwner *u,struct msghdr *m,size_t capacity)
{
    if(!m->msg_controllen&&!(m->msg_flags&MSG_CTRUNC))return 0;
    size_t used=m->msg_controllen,at=0;unsigned n=0;int owned[16];
    if(used>capacity){used=capacity;u->close_uncertain=1;}
    if(m->msg_flags&MSG_CTRUNC)u->close_uncertain=1;
    while(at<used){struct cmsghdr c;
        if(used-at<sizeof(c)){u->close_uncertain=1;break;}
        memcpy(&c,(unsigned char *)m->msg_control+at,sizeof(c));size_t head=CMSG_LEN(0),len=c.cmsg_len;
        /* An over-reported length cannot distinguish delivered ints from
         * alignment padding. Preserve uncertainty rather than guess fds. */
        if(len<head||len>used-at){u->close_uncertain=1;break;}
        size_t payload=len-head;
        if(payload%sizeof(int)||!payload)u->close_uncertain=1;
        if(c.cmsg_level!=SOL_SOCKET||c.cmsg_type!=SCM_RIGHTS)u->close_uncertain=1;
        else for(size_t offset=0;offset+sizeof(int)<=payload;offset+=sizeof(int)){
            int fd,duplicate=0;memcpy(&fd,(unsigned char *)m->msg_control+at+head+offset,sizeof(fd));
            for(unsigned j=0;j<n;j++)if(owned[j]==fd)duplicate=1;
            if(fd<0||fd==u->fd||fd==u->passed_fd||duplicate||n==16)u->close_uncertain=1;
            else owned[n++]=fd;
        }
        if(len==used-at)break;
        size_t next=CMSG_SPACE(payload);if(next>used-at)break;at+=next;
    }
    for(unsigned i=0;i<n;i++)(void)close_once(u,&owned[i]);
    return -1;
}
int pw_wine_child_ui_owner_pump(PwWineChildUiOwner *u)
{
    if(!u||!u->initialized||u->retired||u->handoff.state!=PW_WCU_HANDOFF_DONE)return -1;
    for(unsigned attempt=0;attempt<8;attempt++){
        unsigned char bytes[65536];union{struct cmsghdr align;unsigned char bytes[CMSG_SPACE(16*sizeof(int))];} ancillary;
        struct iovec part={bytes,sizeof(bytes)};struct msghdr m={0};memset(&ancillary,0,sizeof(ancillary));
        m.msg_iov=&part;m.msg_iovlen=1;m.msg_control=ancillary.bytes;m.msg_controllen=sizeof(ancillary.bytes);
        ssize_t got=recvmsg(u->fd,&m,MSG_DONTWAIT);int error=got<0?errno:0;
        if(got<0&&(error==EAGAIN||error==EWOULDBLOCK))return 0;
        int bad=got<0;
        if(got>=0&&refuse_rights(u,&m,sizeof(ancillary.bytes)))bad=1;
        if(got<=0||bad||(size_t)got>sizeof(bytes)||(m.msg_flags&~(MSG_EOR|MSG_DONTWAIT))||pw_wine_child_ui_feed(&u->rx,bytes,(size_t)got)){
            (void)pw_wine_child_ui_owner_retire(u);return -1;}
    }
    return 1;
}
