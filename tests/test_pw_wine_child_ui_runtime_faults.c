/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../native/pw_wine_child_ui_runtime.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
static int mock_close(int);
static int mock_pair(int,int,int,int *);
static ssize_t mock_receive(int,struct msghdr *,int);
#define close mock_close
#define socketpair mock_pair
#define recvmsg mock_receive
#include "../native/pw_wine_child_ui_runtime.c"
#undef close
#undef socketpair
#undef recvmsg
static unsigned closes;
static int closed[20],pair_mode;
static ssize_t got;
static int mock_close(int fd){assert(fd>=0&&closes<20);closed[closes++]=fd;return 0;}
static int mock_pair(int domain,int type,int protocol,int *pair)
{
    assert(domain==AF_UNIX&&type==SOCK_STREAM&&!protocol);
    if(pair_mode==1||pair_mode==2){pair[0]=9;pair[1]=10;}
    if(pair_mode==3)pair[0]=pair[1]=9;
    if(pair_mode==4)pair[0]=9;
    errno=EIO;return pair_mode==2?1:pair_mode>=3?0:-1;
}
static ssize_t mock_receive(int fd,struct msghdr *m,int flags)
{assert(fd==5&&flags==MSG_DONTWAIT);m->msg_controllen=0;m->msg_flags=0;return got;}
static int sink(void *c,const void *p,uint32_t w,uint32_t h,uint32_t s)
{(void)c;(void)p;(void)w;(void)h;(void)s;return 0;}
static void ancillary(void)
{
    for(unsigned mode=0;mode<8;mode++){
        PwWineChildUiOwner u={.initialized=1,.fd=5,.passed_fd=-1};closes=0;
        union{struct cmsghdr align;unsigned char bytes[CMSG_SPACE(2*sizeof(int))];} a;
        memset(&a,0,sizeof(a));a.align.cmsg_level=SOL_SOCKET;a.align.cmsg_type=SCM_RIGHTS;
        a.align.cmsg_len=CMSG_LEN(2*sizeof(int));int rights[2]={9,10};memcpy(CMSG_DATA(&a.align),rights,sizeof(rights));
        struct msghdr m={0};m.msg_control=a.bytes;m.msg_controllen=sizeof(a.bytes);unsigned expected=2;
        if(mode==1){a.align.cmsg_len=CMSG_LEN(sizeof(int)+1);expected=1;}
        if(mode==2){a.align.cmsg_len=4096;expected=0;}
        if(mode==3){m.msg_controllen=CMSG_LEN(sizeof(int)+1);expected=0;}
        if(mode==4){a.align.cmsg_type=999;expected=0;}
        if(mode==5){a.align.cmsg_len=sizeof(struct cmsghdr)-1;expected=0;}
        if(mode==6){m.msg_flags=MSG_CTRUNC;}
        if(mode==7){ /* padding zero is not descriptor zero */
            a.align.cmsg_len=4096;m.msg_controllen=CMSG_SPACE(sizeof(int));
            memset((unsigned char*)CMSG_DATA(&a.align)+sizeof(int),0,m.msg_controllen-CMSG_LEN(sizeof(int)));expected=0;
        }
        assert(refuse_rights(&u,&m,sizeof(a.bytes))<0&&closes==expected);
        for(unsigned i=0;i<closes;i++)assert(closed[i]==(int)i+9);
        assert(u.close_uncertain==(mode!=0));
    }
}
int main(void)
{
    ancillary();
    for(pair_mode=0;pair_mode<5;pair_mode++){
        PwWineChildUiOwner u={0};closes=0;
        assert(pw_wine_child_ui_owner_init(&u,(PwWineChildUiIdentity){1,2,3},sink,NULL)<0);
        assert(u.retired&&u.fd==-1&&u.passed_fd==-1);
        assert(closes==(pair_mode==0?0:pair_mode<3?2:1));assert(u.close_uncertain==(pair_mode!=0));
    }
    /* A malformed native return cannot cause an oversized stack-buffer feed. */
    PwWineChildUiOwner u={.initialized=1,.fd=5,.passed_fd=-1,.handoff={.state=PW_WCU_HANDOFF_DONE}};
    closes=0;got=65537;assert(pw_wine_child_ui_owner_pump(&u)<0&&u.retired&&closes==1&&closed[0]==5);
    puts("child UI runtime faults: bounded partial ancillary prefixes, unknown metadata, ambiguous pair and oversized read refused");return 0;
}
