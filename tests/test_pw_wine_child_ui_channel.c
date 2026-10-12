/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Deterministic IO fault boundaries; no descriptors are opened by this suite. */
#include "../native/pw_wine_child_ui_channel.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
static ssize_t fake_send(int,const void *,size_t,int);
static int fake_type(int,int,int,void *,socklen_t *);
static int fake_fcntl(int,int,...);
static int fake_close(int);
#define send fake_send
#define getsockopt fake_type
#define fcntl fake_fcntl
#define close fake_close
#include "../native/pw_wine_child_ui_channel.c"
#undef send
#undef getsockopt
#undef fcntl
#undef close
static struct {
    uint64_t now,advance;int clock_bad,stopped,type_bad,fcntl_bad,close_bad,send_error;
    size_t send_max;unsigned sends,closes,detaches;int detach_fail;
    unsigned char bytes[256];size_t bytes_used;
} m;
static PwWineChildUiChannel q;
static unsigned char storage[256];
static int clock_cb(void *unused,uint64_t *value){(void)unused;*value=m.now;return m.clock_bad;}
static int stop_cb(void *unused){(void)unused;return m.stopped;}
static int fake_type(int fd,int level,int option,void *p,socklen_t *n)
{assert(fd==9&&level==SOL_SOCKET&&option==SO_TYPE&&*n==sizeof(int));*(int *)p=m.type_bad?SOCK_SEQPACKET:SOCK_STREAM;return 0;}
static int fake_fcntl(int fd,int op,...)
{assert(fd==9&&(op==F_GETFD||op==F_SETFD));if(m.fcntl_bad){errno=EIO;return -1;}return 0;}
static int fake_close(int fd){assert(fd==9);m.closes++;if(m.close_bad){errno=EINTR;return -1;}return 0;}
static ssize_t fake_send(int fd,const void *p,size_t n,int flags)
{
    assert(fd==9&&n<=65536&&flags==(MSG_NOSIGNAL|MSG_DONTWAIT));m.sends++;m.now+=m.advance;
    if(m.send_error){errno=m.send_error;return -1;}
    if(n>m.send_max)n=m.send_max;
    assert(m.bytes_used+n<=sizeof(m.bytes));memcpy(m.bytes+m.bytes_used,p,n);m.bytes_used+=n;return (ssize_t)n;
}
static int detach(void *unused)
{
    (void)unused;m.detaches++;assert(atomic_load(&q.cancelled));
    assert(!pthread_mutex_trylock(&q.lock));assert(!pthread_mutex_unlock(&q.lock)); /* outside queue lock */
    return m.detach_fail;
}
static void reset(unsigned kind,size_t capacity)
{
    if(q.initialized)assert(!pthread_mutex_destroy(&q.lock));
    memset(&q,0,sizeof(q));memset(&m,0,sizeof(m));m.now=100;m.send_max=256;
    int fd=9;PwWineChildUiIdentity id={1,2,3};
    assert(!pw_wine_child_ui_channel_init(&q,&fd,id,kind,storage,capacity,1000,50,clock_cb,stop_cb,NULL)&&fd==-1);
}
static void enqueue_frame(void)
{unsigned char pixel[4]={4,3,2,1};assert(!pw_wine_child_ui_channel_present(&q,pixel,1,1,4));}
static void finish_queue(void){while(q.queued)assert(pw_wine_child_ui_channel_pump(&q)>=0);}
static void positive(void)
{
    reset(PW_WCU_FRAME,sizeof(storage));enqueue_frame();m.send_max=3;finish_queue();
    assert(m.sends==23&&m.bytes_used==68&&!memcmp(m.bytes,"PWUI",4)&&m.bytes[64]==4&&q.tx.next==2);
    assert(!pw_wine_child_ui_channel_pump(&q));
    enqueue_frame();unsigned char pixel[4]={0};
    assert(pw_wine_child_ui_channel_present(&q,pixel,1,1,4)<0&&!atomic_load(&q.cancelled));
    assert(q.tx.next==3&&q.queued);finish_queue(); /* busy frame did not consume a sequence */
    assert(!pw_wine_child_ui_channel_retire(&q,detach,NULL)&&q.fd==-1&&m.closes==1);
    assert(!pw_wine_child_ui_channel_retire(&q,detach,NULL)&&m.closes==1&&m.detaches==1);
    assert(pw_wine_child_ui_channel_present(&q,pixel,1,1,4)<0);
}
static void negative(void)
{
    for(unsigned mode=0;mode<7;mode++){
        reset(PW_WCU_FRAME,sizeof(storage));enqueue_frame();
        if(mode==0)m.now=150;                  /* exact deadline */
        if(mode==1)m.now=99;                   /* clock reversal */
        if(mode==2)m.clock_bad=1;
        if(mode==3)m.stopped=1;
        if(mode==4)pw_wine_child_ui_channel_cancel(&q);
        if(mode==5){m.send_error=EINTR;}       /* never uncertain retry */
        if(mode==6)m.advance=50;              /* full write too late */
        assert(pw_wine_child_ui_channel_pump(&q)<0&&atomic_load(&q.cancelled));
        unsigned sent=m.sends;assert(pw_wine_child_ui_channel_pump(&q)<0&&m.sends==sent);
        assert(!pw_wine_child_ui_channel_retire(&q,detach,NULL)&&m.closes==1);
    }
    reset(PW_WCU_FRAME,sizeof(storage));enqueue_frame();m.send_error=EAGAIN;
    assert(!pw_wine_child_ui_channel_pump(&q)&&q.queued);m.now=150;
    assert(pw_wine_child_ui_channel_pump(&q)<0&&m.sends==1);
    reset(PW_WCU_FRAME,84);unsigned char large[24]={0};
    assert(pw_wine_child_ui_channel_present(&q,large,3,2,12)<0&&atomic_load(&q.cancelled)&&!m.sends&&!q.queued);
    reset(PW_WCU_INPUT,sizeof(storage));PwWineInput e={PW_WINE_INPUT_KEY,65,0,0,1};
    assert(!pw_wine_child_ui_channel_input(&q,&e));e.down=0;
    assert(pw_wine_child_ui_channel_input(&q,&e)<0&&atomic_load(&q.cancelled));
    /* Input cannot discard a release. A refused detach retains the descriptor. */
    m.detach_fail=1;assert(pw_wine_child_ui_channel_retire(&q,detach,NULL)<0&&q.fd==9&&!m.closes);
    m.detach_fail=0;assert(!pw_wine_child_ui_channel_retire(&q,detach,NULL)&&m.closes==1);
    reset(PW_WCU_FRAME,sizeof(storage));enqueue_frame();m.close_bad=1;
    assert(pw_wine_child_ui_channel_retire(&q,detach,NULL)<0&&q.fd==-1&&q.close_uncertain&&m.closes==1);
    assert(pw_wine_child_ui_channel_retire(&q,detach,NULL)<0&&m.closes==1);
    reset(PW_WCU_FRAME,sizeof(storage));assert(!pthread_mutex_lock(&q.lock));
    assert(pw_wine_child_ui_channel_present(&q,large,1,1,4)<0&&!atomic_load(&q.cancelled));
    assert(!pthread_mutex_unlock(&q.lock));enqueue_frame();
    reset(PW_WCU_INPUT,sizeof(storage));assert(!pthread_mutex_lock(&q.lock));
    assert(pw_wine_child_ui_channel_input(&q,&e)<0&&atomic_load(&q.cancelled));assert(!pthread_mutex_unlock(&q.lock));
    reset(PW_WCU_INPUT,sizeof(storage));e.type=4; /* local window-cycle is not a wire event */
    assert(pw_wine_child_ui_channel_input(&q,&e)<0&&!m.sends);
}
int main(void)
{positive();negative();assert(!pthread_mutex_destroy(&q.lock));puts("child UI channel: bounded writes, cancellation, overload, detach and close-once passed");return 0;}
