/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _POSIX_C_SOURCE 200809L
#include "../native/pw_wine_child_ui_runtime.h"
#include "../native/pw_wine_child_ui_channel.h"
#include "../native/pw_wine_child_ui_preview.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
static uint64_t now_ms=100;
static PwWineChildUiMailbox mailbox;
static PwWineChildUiIdentity id={80,81,600};
static int tick(void *unused,uint64_t *out){(void)unused;*out=now_ms;return 0;}
static int frame(void *context,const void *pixels,uint32_t w,uint32_t h,uint32_t stride)
{assert(context==&mailbox);return pw_wine_child_ui_mailbox_put(&mailbox,id,pixels,w,h,stride);}
static int detach(void *unused){(void)unused;pw_wine_set_present_sink(NULL,NULL);return 0;}
static int fds(void){DIR *d=opendir("/proc/self/fd");assert(d);struct dirent *e;int count=0;while((e=readdir(d)))if(e->d_name[0]!='.')count++;closedir(d);return count;}
static void transport(void)
{
    for(unsigned bad=0;bad<3;bad++){
        int initial=fds(),control[2],server[2];assert(!socketpair(AF_UNIX,SOCK_SEQPACKET,0,control));
        assert(!socketpair(AF_UNIX,SOCK_STREAM,0,server));
        PwWineChildUiOwner owner={0};assert(!pw_wine_child_ui_owner_init(&owner,id,frame,&mailbox));
        int owner_fd=owner.fd,passed_fd=owner.passed_fd;
        PwWineChildFrame hello={.kind=PW_WC_HELLO,.child_pid=600,.child_ppid=500};
        memcpy(hello.build_id,"0123456789012345678901234567890123456789",41);
        PwWineChildFrame boot=hello;boot.kind=PW_WC_BOOTSTRAP;boot.sequence=1;boot.generation=81;
        boot.parent_pid=599;boot.wine_pid=80;boot.wine_tid=84;boot.profile=2;boot.machine=PW_WC_MACHINE_AMD64;
        PwNativeChildIo io={.ready=1,.clock_ms=tick,.last_clock=100,.stage_end=500,.total_end=1000};
        /* Correlation must match the original admitted owner before transfer. */
        PwWineChildFrame wrong=boot;wrong.generation++;
        assert(pw_wine_child_ui_owner_send(&owner,&io,control[0],&wrong,80,server[1])<0);
        wrong=boot;wrong.child_pid++;
        assert(pw_wine_child_ui_owner_send(&owner,&io,control[0],&wrong,80,server[1])<0);
        assert(pw_wine_child_ui_owner_send(&owner,&io,control[0],&boot,81,server[1])<0);
        assert(owner.passed_fd==passed_fd&&owner.handoff.state==PW_WCU_HANDOFF_NEW);
        assert(pw_wine_child_ui_owner_send(&owner,&io,control[0],&boot,80,server[1])==PW_WC_RECORD);
        assert(owner.fd==owner_fd&&owner.passed_fd==-1);errno=0;assert(fcntl(passed_fd,F_GETFD)<0&&errno==EBADF);
        PwWineChildUiHandoff received={0};int child_server=-1,child_ui=-1;
        assert(pw_wine_child_ui_handoff_receive(&received,&io,control[1],&hello,&child_server,&child_ui)==PW_WC_RECORD);
        assert(!close(server[1]));assert(!close(child_server));assert(!close(server[0]));
        if(bad==2){ /* ancillary on UI is refused and the delivered fd closed */
            int extra[2];assert(!socketpair(AF_UNIX,SOCK_STREAM,0,extra));
            union{struct cmsghdr align;unsigned char bytes[CMSG_SPACE(sizeof(int))];} c;
            memset(&c,0,sizeof(c));c.align.cmsg_level=SOL_SOCKET;c.align.cmsg_type=SCM_RIGHTS;c.align.cmsg_len=CMSG_LEN(sizeof(int));
            memcpy(CMSG_DATA(&c.align),&extra[1],sizeof(int));char byte=0;struct iovec part={&byte,1};struct msghdr m={0};
            m.msg_iov=&part;m.msg_iovlen=1;m.msg_control=c.bytes;m.msg_controllen=sizeof(c.bytes);
            assert(sendmsg(child_ui,&m,MSG_NOSIGNAL)==1);int before=fds();
            assert(pw_wine_child_ui_owner_pump(&owner)<0&&owner.retired&&owner.fd==-1);
            assert(fds()==before-1);assert(!close(extra[0]));assert(!close(extra[1]));assert(!close(child_ui));
        }else{
            PwWineChildUiIdentity sent=id;if(bad)sent.generation++;
            unsigned char storage[128];PwWineChildUiChannel q={0};
            assert(!pw_wine_child_ui_channel_init(&q,&child_ui,sent,PW_WCU_FRAME,storage,sizeof(storage),1000,50,tick,NULL,NULL));
            pw_wine_set_present_sink(pw_wine_child_ui_channel_present,&q);uint32_t color=0xff102030;
            assert(!pw_wine_present(&color,1,1,4));while(q.queued)assert(pw_wine_child_ui_channel_pump(&q)>=0);
            int rc=pw_wine_child_ui_owner_pump(&owner);
            if(bad)assert(rc<0&&owner.retired);else{
                assert(rc==0&&!owner.retired);PwWineChildUiPreview snapshot={0};assert(pw_wine_child_ui_mailbox_take(&mailbox,&snapshot));
                assert(snapshot.valid&&snapshot.identity.generation==id.generation&&snapshot.pixels[0]==color);
            }
            assert(!pw_wine_child_ui_channel_retire(&q,detach,NULL));assert(!pthread_mutex_destroy(&q.lock));
        }
        assert(!pw_wine_child_ui_owner_retire(&owner));
        /* UI rejection never closes the independent control endpoint. */
        assert(fcntl(control[0],F_GETFD)>=0&&fcntl(control[1],F_GETFD)>=0);
        assert(!close(control[0]));assert(!close(control[1]));
        /* Test-only release after all callbacks and the simulated owner end. */
        assert(!munmap(owner.storage,PW_WCU_MAX_BYTES));assert(fds()==initial);
    }
}
static void preview(void)
{
    PwWineChildUiPreview snapshot={0};uint32_t color=0xff445566;
    assert(!pw_wine_child_ui_mailbox_put(&mailbox,id,&color,1,1,4));
    assert(pw_wine_child_ui_mailbox_take(&mailbox,&snapshot)==1&&snapshot.valid&&snapshot.pixels[0]==color);
    assert(pw_wine_child_ui_mailbox_take(&mailbox,&snapshot)==0);
    assert(!pthread_mutex_lock(&mailbox.lock));
    assert(!pw_wine_child_ui_mailbox_put(&mailbox,id,&color,1,1,4));
    assert(!pw_wine_child_ui_mailbox_take(&mailbox,&snapshot));
    assert(!pthread_mutex_unlock(&mailbox.lock));
    assert(!pw_wine_child_ui_mailbox_take(&mailbox,&snapshot)); /* busy put was dropped whole */
    PwWineChildUiIdentity other=id;other.generation++;
    pw_wine_child_ui_mailbox_retire(&mailbox,other);assert(!pw_wine_child_ui_mailbox_take(&mailbox,&snapshot));
    enum { W=120,H=90,N=W*H };
    uint32_t root[N],out[N+4];for(unsigned i=0;i<N;i++)root[i]=0xff00ff00;memset(out,0xa5,sizeof(out));
    assert(!pw_wine_child_ui_preview_overlay(&snapshot,root,W,H,W*4,out,N*4));
    assert(out[0]==root[0]&&out[N]==0xa5a5a5a5);unsigned changes=0;
    for(unsigned i=0;i<N;i++){assert(root[i]==0xff00ff00);changes+=out[i]!=root[i];}assert(changes>100&&changes<N/3);
    assert(pw_wine_child_ui_preview_overlay(&snapshot,root,W,H,W*4,out,N*4-1)<0);
    pw_wine_child_ui_mailbox_retire(&mailbox,id);assert(pw_wine_child_ui_mailbox_take(&mailbox,&snapshot)&&!snapshot.valid);
    assert(pw_wine_child_ui_preview_overlay(&snapshot,root,W,H,W*4,out,N*4)<0);
    /* Retirement invalidates even at the no-wrap sequence ceiling. */
    mailbox.preview.sequence=UINT64_MAX;mailbox.preview.valid=1;mailbox.preview.identity=id;
    snapshot=mailbox.preview;pw_wine_child_ui_mailbox_retire(&mailbox,id);
    assert(pw_wine_child_ui_mailbox_take(&mailbox,&snapshot)&&!snapshot.valid);
    assert(pw_wine_child_ui_mailbox_put(&mailbox,id,&color,1,1,4)<0);
}
int main(void)
{alarm(10);assert(!pw_wine_child_ui_mailbox_init(&mailbox));transport();preview();assert(!pthread_mutex_destroy(&mailbox.lock));puts("child UI runtime: owned-role handoff, framed preview, ancillary refusal, identity/retirement and root isolation passed");return 0;}
