/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _POSIX_C_SOURCE 200809L
#include "../native/pw_wine_child_ui_handoff.h"
#include "../native/pw_wine_child_ui_channel.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static int tick(void *unused,uint64_t *out)
{
    struct timespec t;(void)unused;assert(!clock_gettime(CLOCK_MONOTONIC,&t));
    *out=(uint64_t)t.tv_sec*1000+(uint64_t)t.tv_nsec/1000000;return 0;
}
static PwNativeChildIo io(void)
{
    uint64_t now;tick(NULL,&now);
    return (PwNativeChildIo){.ready=1,.clock_ms=tick,.last_clock=now,.stage_end=now+3000,.total_end=now+3000};
}
static PwWineChildFrame hello(uint32_t pid,uint32_t ppid)
{
    PwWineChildFrame h={.kind=PW_WC_HELLO,.child_pid=pid,.child_ppid=ppid};
    memcpy(h.build_id,"0123456789012345678901234567890123456789",41);return h;
}
static PwWineChildFrame boot(PwWineChildFrame h)
{
    h.kind=PW_WC_BOOTSTRAP;h.sequence=1;h.generation=801;h.parent_pid=777;
    if(h.parent_pid==h.child_pid)h.parent_pid++;
    h.wine_pid=80;h.wine_tid=84;h.profile=PW_WC_PROFILE_BATTLENET;h.machine=PW_WC_MACHINE_AMD64;return h;
}
static void close_pair(int p[2]){assert(!close(p[0]));assert(!close(p[1]));}
static int count_fds(void)
{
    DIR *d=opendir("/proc/self/fd");assert(d);int count=0;struct dirent *e;
    while((e=readdir(d)))if(e->d_name[0]!='.')count++;
    assert(!closedir(d));return count;
}
static void raw_send(int control,PwWineChildFrame b,uint64_t session,const int *fds,unsigned count,int mutation)
{
    unsigned char bytes[PW_WCU_HANDOFF_BYTES];memset(bytes,0,sizeof(bytes));
    assert(!pw_wine_child_wire_encode(bytes,&b));bytes[8]=3;
    for(unsigned n=0;n<8;n++)bytes[136+n]=(unsigned char)(session>>(8*n));
    size_t length=sizeof(bytes);
    if(mutation==1)bytes[8]=2;
    if(mutation==2)bytes[151]=1;
    if(mutation==3)length--;
    if(mutation==4)bytes[32]^=1;
    union {struct cmsghdr align;unsigned char bytes[CMSG_SPACE(20*sizeof(int))];} ancillary;
    memset(&ancillary,0,sizeof(ancillary));struct iovec part={bytes,length};struct msghdr m={0};m.msg_iov=&part;m.msg_iovlen=1;
    if(count){struct cmsghdr *c=&ancillary.align;c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;
        c->cmsg_len=CMSG_LEN(count*sizeof(int));memcpy(CMSG_DATA(c),fds,count*sizeof(int));
        m.msg_control=ancillary.bytes;m.msg_controllen=CMSG_SPACE(count*sizeof(int));}
    assert(sendmsg(control,&m,MSG_NOSIGNAL)==(ssize_t)length);
}
static void negatives(void)
{
    for(unsigned which=0;which<11;which++){
        int control[2],server[2],ui[2];assert(!socketpair(AF_UNIX,SOCK_SEQPACKET,0,control));
        assert(!socketpair(AF_UNIX,SOCK_STREAM,0,server));assert(!socketpair(AF_UNIX,which==7?SOCK_SEQPACKET:SOCK_STREAM,0,ui));
        int fds[20];for(unsigned n=0;n<20;n++)fds[n]=n&1?ui[1]:server[1];
        unsigned count=2;int mutation=0;uint64_t session=800;
        if(which==0)count=0;
        if(which==1)count=1;
        if(which==2)count=3;
        if(which==3)fds[1]=server[1]; /* kernel installs two distinct numbers for same object */
        if(which==4)mutation=1;
        if(which==5)mutation=2;
        if(which==6)mutation=3;
        if(which==8)mutation=4;
        if(which==9)session=0;
        if(which==10)count=20; /* native MSG_CTRUNC: collect and close all delivered rights */
        PwWineChildFrame local=hello(600,500),b=boot(local);int before=count_fds();
        raw_send(control[0],b,session,fds,count,mutation);
        PwWineChildUiHandoff h={0};PwNativeChildIo budget=io();int server_fd=-1,ui_fd=-1;
        assert(pw_wine_child_ui_handoff_receive(&h,&budget,control[1],&local,&server_fd,&ui_fd)==PW_WC_ERROR);
        assert(server_fd==-1&&ui_fd==-1&&h.state==PW_WCU_HANDOFF_FAILED);
        assert(count_fds()==before); /* every kernel-delivered rejected right was closed */
        if(which==10)assert(h.result.ownership_uncertain);
        assert(pw_wine_child_ui_handoff_receive(&h,&budget,control[1],&local,&server_fd,&ui_fd)==PW_WC_ERROR);
        close_pair(control);close_pair(server);close_pair(ui);
    }
    /* Old v2 receiver explicitly refuses v3/two rights, retaining compatibility. */
    int c[2],s[2],u[2];assert(!socketpair(AF_UNIX,SOCK_SEQPACKET,0,c));
    assert(!socketpair(AF_UNIX,SOCK_STREAM,0,s));assert(!socketpair(AF_UNIX,SOCK_STREAM,0,u));
    PwWineChildFrame local=hello(600,500),b=boot(local),got;
    int before=count_fds(),fds[]={s[1],u[1]},right=-1;raw_send(c[0],b,800,fds,2,0);
    PwWineChildWireResult result={0};PwNativeChildIo budget=io();
    assert(pw_wine_child_wire_receive_nowait(&budget,c[1],PW_WC_KIND(PW_WC_BOOTSTRAP),&got,&right,&result)==PW_WC_ERROR);
    assert(right==-1&&result.rights_closed==2&&count_fds()==before);
    /* Sender refuses duplicate aliases too, without ever emitting a record. */
    PwWineChildUiHandoff h={0};int alias=dup(s[1]);assert(alias>=0);
    assert(pw_wine_child_ui_handoff_send(&h,&budget,c[0],&b,800,s[1],alias)==PW_WC_ERROR);
    struct pollfd p={c[1],POLLIN,0};assert(poll(&p,1,0)==0);assert(!close(alias));
    close_pair(c);close_pair(s);close_pair(u);
}
static int detach_sink(void *unused)
{(void)unused;pw_wine_set_present_sink(NULL,NULL);return 0;}
static int detached_input(void *unused){(void)unused;return 0;}
static int input_callback(void *unused,const PwWineInput *e)
{(void)unused;return pw_wine_post_input(e);}
static void receive_record(int fd,PwWineChildUiRx *rx)
{
    uint64_t start;tick(NULL,&start);uint64_t next=rx->next;
    while(rx->next==next){uint64_t now;tick(NULL,&now);assert(now-start<2000);
        struct pollfd p={fd,POLLIN,0};int rc=poll(&p,1,10);assert(rc>=0);
        if(!rc)continue;
        unsigned char bytes[7];ssize_t count=recv(fd,bytes,sizeof(bytes),MSG_DONTWAIT);
        assert(count>0);assert(!pw_wine_child_ui_feed(rx,bytes,(size_t)count));
    }
}
static void drain(PwWineChildUiChannel *q)
{
    while(q->queued)assert(pw_wine_child_ui_channel_pump(q)>=0);
}
static unsigned frames;
static int frame_callback(void *unused,const void *bytes,uint32_t w,uint32_t h,uint32_t stride)
{
    (void)unused;const unsigned char expected[]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    assert(w==2&&h==2&&stride==8&&!memcmp(bytes,expected,16));frames++;return 0;
}
static void real_child(int control)
{
    PwNativeChildIo budget=io();PwWineChildWireResult wire={0};
    PwWineChildFrame local=hello((uint32_t)getpid(),(uint32_t)getppid());
    assert(!pw_wine_child_wire_send(&budget,control,&local,-1,&wire));
    PwWineChildUiHandoff h={0};int server=-1,ui=-1,rc;
    do {rc=pw_wine_child_ui_handoff_receive(&h,&budget,control,&local,&server,&ui);}while(rc==PW_WC_IDLE);
    assert(rc==PW_WC_RECORD&&server>=0&&ui>=0&&server!=ui);
    assert(fcntl(server,F_GETFD)&FD_CLOEXEC);assert(fcntl(ui,F_GETFD)&FD_CLOEXEC);
    PwWineChildUiIdentity identity;assert(!pw_wine_child_ui_handoff_identity(&h,&h.bootstrap,&identity));
    assert(identity.native_pid==(uint32_t)getpid()&&identity.session==800&&identity.generation==801);
    assert(send(server,"SERVER",6,MSG_NOSIGNAL)==6);assert(!close(server));
    unsigned char storage[128],input_storage[20];PwWineChildUiChannel queue={0};
    assert(!pw_wine_child_ui_channel_init(&queue,&ui,identity,PW_WCU_FRAME,storage,sizeof(storage),budget.total_end,500,tick,NULL,NULL));
    assert(ui==-1);pw_wine_set_present_sink(pw_wine_child_ui_channel_present,&queue);
    unsigned char pixels[]={1,2,3,4,5,6,7,8,90,90,90,90,9,10,11,12,13,14,15,16,90,90,90,90};
    assert(!pw_wine_present(pixels,2,2,12));drain(&queue);
    PwWineChildUiRx input;assert(!pw_wine_child_ui_rx_init(&input,identity,PW_WCU_INPUT,input_storage,sizeof(input_storage),NULL,input_callback,NULL));
    receive_record(queue.fd,&input);receive_record(queue.fd,&input);
    PwWineInput event;assert(pw_wine_next_input(&event)==1&&event.code==65&&event.down==1);
    assert(pw_wine_next_input(&event)==1&&event.code==65&&event.down==0);assert(!pw_wine_next_input(&event));
    assert(!pw_wine_child_ui_channel_retire(&queue,detach_sink,NULL));
    assert(pw_wine_present(pixels,2,2,12)==-1);assert(!close(control));_exit(0);
}
static void inherited_flow(void)
{
    int control[2];assert(!socketpair(AF_UNIX,SOCK_SEQPACKET,0,control));
    pid_t pid=fork();assert(pid>=0);
    if(!pid){assert(!close(control[0]));real_child(control[1]);}
    assert(!close(control[1]));PwNativeChildIo budget=io();PwWineChildFrame local;
    PwWineChildWireResult wire={0};int no_right=-1;
    assert(pw_wine_child_wire_receive(&budget,control[0],PW_WC_KIND(PW_WC_HELLO),&local,&no_right,&wire)==PW_WC_RECORD);
    assert(local.child_pid==(uint32_t)pid&&local.child_ppid==(uint32_t)getpid()&&no_right==-1);
    PwWineChildFrame b=boot(local);b.parent_pid=(uint32_t)getpid();
    /* Created AFTER fork: the child can access these only through rights. */
    int server[2],ui[2];assert(!socketpair(AF_UNIX,SOCK_STREAM,0,server));assert(!socketpair(AF_UNIX,SOCK_STREAM,0,ui));
    PwWineChildUiHandoff h={0};int rc;
    do {rc=pw_wine_child_ui_handoff_send(&h,&budget,control[0],&b,800,server[1],ui[1]);}while(rc==PW_WC_IDLE);
    assert(rc==PW_WC_RECORD);assert(!close(server[1]));assert(!close(ui[1]));
    assert(pw_wine_child_ui_handoff_send(&h,&budget,control[0],&b,800,server[0],ui[0])==PW_WC_ERROR);
    char marker[6];assert(recv(server[0],marker,sizeof(marker),MSG_WAITALL)==6&&!memcmp(marker,"SERVER",6));assert(!close(server[0]));
    PwWineChildUiIdentity identity;assert(!pw_wine_child_ui_handoff_identity(&h,&b,&identity));
    PwWineChildFrame wrong=b;wrong.generation++;assert(pw_wine_child_ui_handoff_identity(&h,&wrong,&identity));
    assert(!pw_wine_child_ui_handoff_identity(&h,&b,&identity));
    unsigned char storage[128];PwWineChildUiRx frames_rx;
    assert(!pw_wine_child_ui_rx_init(&frames_rx,identity,PW_WCU_FRAME,storage,sizeof(storage),frame_callback,NULL,NULL));
    receive_record(ui[0],&frames_rx);assert(frames==1);
    unsigned char tx_storage[128];PwWineChildUiChannel input={0};
    assert(!pw_wine_child_ui_channel_init(&input,&ui[0],identity,PW_WCU_INPUT,tx_storage,sizeof(tx_storage),budget.total_end,500,tick,NULL,NULL));
    PwWineInput e={PW_WINE_INPUT_KEY,65,0,0,1};assert(!pw_wine_child_ui_channel_input(&input,&e));drain(&input);
    e.down=0;assert(!pw_wine_child_ui_channel_input(&input,&e));drain(&input);
    int status;assert(waitpid(pid,&status,0)==pid&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
    /* Both input edges were consumed before child exit, our test's explicit
     * input settlement certificate. A socket EOF alone would not suffice. */
    assert(!pw_wine_child_ui_channel_retire(&input,detached_input,NULL));assert(!close(control[0]));
}
static atomic_uint callback_entered,callback_release,retire_entered;
static PwWineChildUiChannel lifetime_queue;
static int held_callback(void *context,const void *bytes,uint32_t w,uint32_t h,uint32_t stride)
{
    atomic_store(&callback_entered,1);
    while(!atomic_load(&callback_release)){struct timespec delay={0,1000000};nanosleep(&delay,NULL);}
    return pw_wine_child_ui_channel_present(context,bytes,w,h,stride);
}
static void *produce(void *unused)
{(void)unused;unsigned char pixel[4]={0};assert(pw_wine_present(pixel,1,1,4)<0);return NULL;}
static void *retire_thread(void *unused)
{(void)unused;atomic_store(&retire_entered,1);assert(!pw_wine_child_ui_channel_retire(&lifetime_queue,detach_sink,NULL));return NULL;}
static void callback_lifetime(void)
{
    int pair[2];assert(!socketpair(AF_UNIX,SOCK_STREAM,0,pair));int original=pair[0];
    unsigned char storage[128];PwNativeChildIo budget=io();PwWineChildUiIdentity id={10,11,12};
    assert(!pw_wine_child_ui_channel_init(&lifetime_queue,&pair[0],id,PW_WCU_FRAME,storage,sizeof(storage),budget.total_end,500,tick,NULL,NULL));
    pw_wine_set_present_sink(held_callback,&lifetime_queue);pthread_t producer,retirer;
    assert(!pthread_create(&producer,NULL,produce,NULL));
    while(!atomic_load(&callback_entered)){struct timespec delay={0,1000000};nanosleep(&delay,NULL);}
    assert(!pthread_create(&retirer,NULL,retire_thread,NULL));
    while(!atomic_load(&retire_entered)||!atomic_load(&lifetime_queue.cancelled)){struct timespec delay={0,1000000};nanosleep(&delay,NULL);}
    /* Retire is waiting for the real Wine setter to detach this callback.
     * Closing or reusing its fd before the callback exits would violate this. */
    assert(fcntl(original,F_GETFD)>=0);atomic_store(&callback_release,1);
    assert(!pthread_join(producer,NULL));assert(!pthread_join(retirer,NULL));
    errno=0;assert(fcntl(original,F_GETFD)<0&&errno==EBADF);assert(!close(pair[1]));
    assert(!pthread_mutex_destroy(&lifetime_queue.lock));
}
int main(void)
{
    alarm(10);int before=count_fds();negatives();assert(count_fds()==before);
    inherited_flow();callback_lifetime();assert(count_fds()==before);puts("child UI handoff: host fork, rights isolation, identity and rejection controls passed");return 0;
}
