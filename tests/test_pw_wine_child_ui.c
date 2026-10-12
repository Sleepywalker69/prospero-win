/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _POSIX_C_SOURCE 200809L
#include "../native/pw_wine_child_ui.h"
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static const PwWineChildUiIdentity identity={111,222,333};
static const uint32_t pixels[8]={1,2,3,0xdeadbeef,4,5,6,0xdeadbeef};
typedef struct Capture {
    unsigned char bytes[4096];size_t length;
    unsigned calls,fail_at,frames,inputs;
    int reject;
    PwWineInput last;
} Capture;
static int capture(void *context,const void *p,size_t n)
{
    Capture *c=context;
    if(++c->calls==c->fail_at)return -1;
    assert(n<=sizeof(c->bytes)-c->length);
    memcpy(c->bytes+c->length,p,n);c->length+=n;return 0;
}
static int present(void *context,const void *p,uint32_t w,uint32_t h,uint32_t stride)
{
    Capture *c=context;const uint32_t expected[]={1,2,3,4,5,6};
    assert(w==3&&h==2&&stride==12&&!memcmp(p,expected,sizeof(expected)));
    c->frames++;return c->reject;
}
static int input(void *context,const PwWineInput *e)
{
    Capture *c=context;c->last=*e;c->inputs++;return c->reject;
}
static void init_rx(PwWineChildUiRx *r,unsigned kind,unsigned char *storage,Capture *c)
{
    assert(!pw_wine_child_ui_rx_init(r,identity,kind,storage,128,
                                   kind==PW_WCU_FRAME?present:NULL,
                                   kind==PW_WCU_INPUT?input:NULL,c));
}
static Capture frame(void)
{
    Capture c={0};PwWineChildUiTx tx;
    assert(!pw_wine_child_ui_tx_init(&tx,identity,PW_WCU_FRAME,capture,&c));
    assert(!pw_wine_child_ui_present(&tx,pixels,3,2,16));
    assert(tx.next==2&&c.length==88&&c.calls==3);
    return c;
}
static void test_fragmentation(void)
{
    Capture c=frame();unsigned char storage[128];
    for(size_t split=0;split<=c.length;split++){
        Capture got={0};PwWineChildUiRx rx;init_rx(&rx,PW_WCU_FRAME,storage,&got);
        assert(!pw_wine_child_ui_feed(&rx,c.bytes,split));
        assert(got.frames==(split==c.length));
        assert(!pw_wine_child_ui_feed(&rx,c.bytes+split,c.length-split));
        assert(got.frames==1&&rx.next==2&&!pw_wine_child_ui_end(&rx));
        assert(pw_wine_child_ui_feed(&rx,c.bytes,c.length)==-1);
    }
    Capture got={0};PwWineChildUiRx rx;init_rx(&rx,PW_WCU_FRAME,storage,&got);
    for(size_t i=0;i<c.length;i++)assert(!pw_wine_child_ui_feed(&rx,c.bytes+i,1));
    assert(got.frames==1);
    assert(pw_wine_child_ui_feed(&rx,c.bytes,c.length)==-1); /* replay */
    assert(got.frames==1);
    for(size_t n=1;n<c.length;n++){
        memset(&got,0,sizeof(got));init_rx(&rx,PW_WCU_FRAME,storage,&got);
        assert(!pw_wine_child_ui_feed(&rx,c.bytes,n));
        assert(pw_wine_child_ui_end(&rx)==-1&&!got.frames);
    }
    init_rx(&rx,PW_WCU_FRAME,storage,&got);
    assert(!pw_wine_child_ui_feed(&rx,NULL,0));
    assert(pw_wine_child_ui_feed(&rx,NULL,1)==-1);
}
static void test_rejections(void)
{
    Capture c=frame();unsigned char storage[128];
    /* Every header byte is bound, reserved, or has an exact expected layout
     * for this record. Mutations must fail before the complete-frame sink. */
    for(size_t i=0;i<PW_WCU_HEADER;i++){
        Capture bad=c,got={0};PwWineChildUiRx rx;init_rx(&rx,PW_WCU_FRAME,storage,&got);
        bad.bytes[i]^=0x80;
        assert(pw_wine_child_ui_feed(&rx,bad.bytes,bad.length)==-1);
        assert(!got.frames&&rx.failed);
        assert(pw_wine_child_ui_feed(&rx,c.bytes,c.length)==-1);
    }
    Capture got={0};PwWineChildUiRx rx;init_rx(&rx,PW_WCU_FRAME,storage,&got);
    rx.capacity=23;
    assert(pw_wine_child_ui_feed(&rx,c.bytes,c.length)==-1&&!got.frames);
    init_rx(&rx,PW_WCU_INPUT,storage,&got);
    assert(pw_wine_child_ui_feed(&rx,c.bytes,c.length)==-1&&!got.inputs);
    init_rx(&rx,PW_WCU_FRAME,storage,&got);got.reject=1;
    assert(pw_wine_child_ui_feed(&rx,c.bytes,c.length)==-1&&rx.failed&&got.frames==1);
    assert(pw_wine_child_ui_feed(&rx,c.bytes,c.length)==-1&&got.frames==1);
    PwWineChildUiIdentity invalid=identity;invalid.native_pid=0;
    assert(pw_wine_child_ui_rx_init(&rx,invalid,PW_WCU_FRAME,storage,128,present,NULL,&got)==-1);
    assert(pw_wine_child_ui_rx_init(&rx,identity,PW_WCU_FRAME,storage,128,present,input,&got)==-1);
    assert(pw_wine_child_ui_rx_init(&rx,identity,PW_WCU_INPUT,storage,19,NULL,input,&got)==-1);
    assert(pw_wine_child_ui_end(NULL)==-1);
}
static void test_sender_failure(void)
{
    for(unsigned fail=1;fail<=3;fail++){
        Capture c={.fail_at=fail};PwWineChildUiTx tx;
        assert(!pw_wine_child_ui_tx_init(&tx,identity,PW_WCU_FRAME,capture,&c));
        assert(pw_wine_child_ui_present(&tx,pixels,3,2,16)==-1&&tx.failed&&tx.next==1);
        unsigned calls=c.calls;
        assert(pw_wine_child_ui_present(&tx,pixels,3,2,16)==-1&&calls==c.calls);
    }
    Capture c={0};PwWineChildUiTx tx;
    assert(!pw_wine_child_ui_tx_init(&tx,identity,PW_WCU_FRAME,capture,&c));
    assert(pw_wine_child_ui_present(&tx,pixels,UINT32_MAX,2,UINT32_MAX)==-1);
    assert(pw_wine_child_ui_present(&tx,pixels,3,UINT32_MAX,16)==-1);
    assert(pw_wine_child_ui_present(&tx,pixels,3,2,11)==-1);
    assert(pw_wine_child_ui_present(&tx,NULL,3,2,16)==-1&&!c.calls);
    tx.next=UINT64_MAX;
    assert(pw_wine_child_ui_present(&tx,pixels,3,2,16)==-1&&!c.calls);
    assert(!pw_wine_child_ui_tx_init(&tx,identity,PW_WCU_FRAME,capture,&c));
    pw_wine_child_ui_tx_end(&tx);pw_wine_child_ui_tx_end(NULL);
    assert(pw_wine_child_ui_present(&tx,pixels,3,2,16)==-1&&!c.calls);
}
static void test_input_and_batches(void)
{
    Capture c={0},got={0};PwWineChildUiTx tx;PwWineChildUiRx rx;unsigned char storage[128];
    assert(!pw_wine_child_ui_tx_init(&tx,identity,PW_WCU_INPUT,capture,&c));
    PwWineInput events[]={
        {PW_WINE_INPUT_KEY,0x12,0,0,1},{PW_WINE_INPUT_KEY,0x12,0,0,0},
        {PW_WINE_INPUT_MOUSE_MOVE,0,INT32_MIN,INT32_MAX,0},
        {PW_WINE_INPUT_MOUSE_BUTTON,2,0,0,1}};
    for(size_t i=0;i<sizeof(events)/sizeof(events[0]);i++)assert(!pw_wine_child_ui_send_input(&tx,&events[i]));
    init_rx(&rx,PW_WCU_INPUT,storage,&got);
    assert(!pw_wine_child_ui_feed(&rx,c.bytes,c.length));
    assert(got.inputs==4&&!memcmp(&got.last,&events[3],sizeof(got.last)));
    assert(!pw_wine_child_ui_end(&rx));
    init_rx(&rx,PW_WCU_INPUT,storage,&got);rx.next=3;
    assert(!pw_wine_child_ui_feed(&rx,c.bytes+168,84));
    assert(got.last.x==INT32_MIN&&got.last.y==INT32_MAX);
    PwWineInput invalids[]={{0,0,0,0,0},{PW_WINE_INPUT_KEY,0,0,0,1},
        {PW_WINE_INPUT_KEY,256,0,0,1},{PW_WINE_INPUT_MOUSE_BUTTON,3,0,0,1},
        {PW_WINE_INPUT_KEY,1,0,0,2}};
    for(size_t i=0;i<sizeof(invalids)/sizeof(invalids[0]);i++)assert(pw_wine_child_ui_send_input(&tx,&invalids[i])==-1);
    unsigned char bad[84];memcpy(bad,c.bytes,84);bad[64]=0;
    init_rx(&rx,PW_WCU_INPUT,storage,&got);unsigned before=got.inputs;
    assert(pw_wine_child_ui_feed(&rx,bad,84)==-1&&got.inputs==before);
    c=(Capture){.fail_at=1};
    assert(!pw_wine_child_ui_tx_init(&tx,identity,PW_WCU_INPUT,capture,&c));
    assert(pw_wine_child_ui_send_input(&tx,&events[0])==-1&&tx.failed);
}
typedef struct LargeFrame { unsigned calls; uint32_t width,height; } LargeFrame;
static int large_present(void *context,const void *p,uint32_t w,uint32_t h,uint32_t stride)
{
    LargeFrame *f=context;const unsigned char *bytes=p;
    assert(w==f->width&&h==f->height&&stride==w*4);
    assert(bytes[0]==0x42&&bytes[(size_t)w*h*4-1]==0x24);f->calls++;return 0;
}
static int feed_writer(void *context,const void *p,size_t n)
{
    return pw_wine_child_ui_feed(context,p,n);
}
static void test_frame_limits_and_exhaustion(void)
{
    unsigned char *pixels=calloc(1,PW_WCU_MAX_BYTES),*storage=malloc(PW_WCU_MAX_BYTES);
    assert(pixels&&storage);
    const uint32_t shapes[][2]={{1,1},{PW_WCU_MAX_WIDTH,PW_WCU_MAX_HEIGHT}};
    for(unsigned i=0;i<2;i++){
        LargeFrame got={.width=shapes[i][0],.height=shapes[i][1]};
        size_t size=(size_t)got.width*got.height*4;
        memset(pixels,0,size);pixels[0]=0x42;pixels[size-1]=0x24;
        PwWineChildUiRx rx;PwWineChildUiTx tx;
        assert(!pw_wine_child_ui_rx_init(&rx,identity,PW_WCU_FRAME,storage,PW_WCU_MAX_BYTES,large_present,NULL,&got));
        assert(!pw_wine_child_ui_tx_init(&tx,identity,PW_WCU_FRAME,feed_writer,&rx));
        tx.next=rx.next=UINT64_MAX-1;
        assert(!pw_wine_child_ui_present(&tx,pixels,got.width,got.height,got.width*4));
        assert(got.calls==1&&tx.next==UINT64_MAX&&rx.next==UINT64_MAX);
        assert(pw_wine_child_ui_present(&tx,pixels,got.width,got.height,got.width*4)==-1);
        assert(got.calls==1&&!pw_wine_child_ui_end(&rx));
    }
    free(storage);free(pixels);
}
static int socket_write(void *context,const void *p,size_t n)
{
    int fd=*(int *)context;const unsigned char *bytes=p;
    /* Intentionally fragment every byte. SIGPIPE is disabled in this test;
     * production adapters must preserve bounded cancellation and no SIGPIPE. */
    for(size_t i=0;i<n;i++){
        ssize_t k;do{k=write(fd,bytes+i,1);}while(k<0&&errno==EINTR);
        if(k!=1)return -1;
    }
    return 0;
}
static int post(void *context,const PwWineInput *e)
{
    unsigned *received=context;(*received)++;return pw_wine_post_input(e);
}
static void read_record(int fd,PwWineChildUiRx *rx,uint64_t wanted)
{
    while(rx->next<wanted){
        unsigned char data[7];ssize_t n=read(fd,data,sizeof(data));
        if(n<0&&errno==EINTR)continue;
        assert(n>0&&!pw_wine_child_ui_feed(rx,data,(size_t)n));
    }
}
static void test_real_process_roundtrip(void)
{
    int pair[2];assert(!socketpair(AF_UNIX,SOCK_STREAM,0,pair));
    pid_t child=fork();assert(child>=0);
    if(!child){
        alarm(10);close(pair[0]);PwWineChildUiTx tx;PwWineChildUiRx rx;unsigned char storage[128];
        unsigned received=0;PwWineChildUiIdentity admitted=identity;admitted.native_pid=(uint32_t)getpid();
        assert(!pw_wine_child_ui_tx_init(&tx,admitted,PW_WCU_FRAME,socket_write,&pair[1]));
        pw_wine_set_present_sink(pw_wine_child_ui_present,&tx);
        assert(!pw_wine_present(pixels,3,2,16));
        assert(!pw_wine_child_ui_rx_init(&rx,admitted,PW_WCU_INPUT,storage,sizeof(storage),NULL,post,&received));
        read_record(pair[1],&rx,3);
        PwWineInput e;
        assert(received==2&&pw_wine_next_input(&e)&&e.code==0x09&&e.down==1);
        assert(pw_wine_next_input(&e)&&e.code==0x09&&e.down==0&&!pw_wine_next_input(&e));
        assert(!pw_wine_child_ui_end(&rx));
        pw_wine_set_present_sink(NULL,NULL);close(pair[1]);_exit(0);
    }
    close(pair[1]);Capture got={0};PwWineChildUiRx rx;unsigned char storage[128];
    PwWineChildUiIdentity admitted=identity;admitted.native_pid=(uint32_t)child;
    assert(!pw_wine_child_ui_rx_init(&rx,admitted,PW_WCU_FRAME,storage,sizeof(storage),present,NULL,&got));
    read_record(pair[0],&rx,2);assert(got.frames==1);
    PwWineChildUiTx tx;assert(!pw_wine_child_ui_tx_init(&tx,admitted,PW_WCU_INPUT,socket_write,&pair[0]));
    PwWineInput event={PW_WINE_INPUT_KEY,0x09,0,0,1};
    assert(!pw_wine_child_ui_send_input(&tx,&event));event.down=0;
    assert(!pw_wine_child_ui_send_input(&tx,&event));
    unsigned char byte;assert(read(pair[0],&byte,1)==0&&!pw_wine_child_ui_end(&rx));
    close(pair[0]);int status;assert(waitpid(child,&status,0)==child&&WIFEXITED(status)&&!WEXITSTATUS(status));
}
int main(void)
{
    signal(SIGPIPE,SIG_IGN);alarm(10);
    test_fragmentation();test_rejections();test_sender_failure();test_input_and_batches();
    test_frame_limits_and_exhaustion();test_real_process_roundtrip();alarm(0);
    puts("child UI protocol passed: bounded frames/input, fragmentation, identity/replay/capacity refusal, terminal failure, real two-process sink/input roundtrip");
    return 0;
}
