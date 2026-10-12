/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_wine_child_ui.h"
#include <string.h>

static uint32_t get32(const unsigned char *p)
{
    return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}
static uint64_t get64(const unsigned char *p)
{
    return get32(p)|(uint64_t)get32(p+4)<<32;
}
static void put32(unsigned char *p,uint32_t n)
{
    for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(n>>(8*i));
}
static void put64(unsigned char *p,uint64_t n)
{
    put32(p,(uint32_t)n);put32(p+4,(uint32_t)(n>>32));
}
static int identity_ok(PwWineChildUiIdentity id)
{
    return id.session && id.generation && id.native_pid;
}
static int kind_ok(unsigned kind){return kind==PW_WCU_FRAME||kind==PW_WCU_INPUT;}
static int input_ok(const PwWineInput *e)
{
    if(!e)return 0;
    switch(e->type){
    case PW_WINE_INPUT_KEY:return e->code>0&&e->code<256&&e->down<=1;
    case PW_WINE_INPUT_MOUSE_MOVE:return 1;
    case PW_WINE_INPUT_MOUSE_BUTTON:return e->code<=2&&e->down<=1;
    default:return 0;
    }
}
static int frame_ok(uint32_t w,uint32_t h,uint32_t stride)
{
    return w&&w<=PW_WCU_MAX_WIDTH&&h&&h<=PW_WCU_MAX_HEIGHT&&stride>=w*4;
}
int pw_wine_child_ui_tx_init(PwWineChildUiTx *t,PwWineChildUiIdentity id,
                            unsigned kind,PwWineChildUiWrite write,void *context)
{
    if(!t||!identity_ok(id)||!kind_ok(kind)||!write)return -1;
    *t=(PwWineChildUiTx){.identity=id,.next=1,.kind=kind,.write=write,.context=context};
    return 0;
}
void pw_wine_child_ui_tx_end(PwWineChildUiTx *t)
{
    if(t)t->failed=1;
}
static int ready(const PwWineChildUiTx *t,unsigned kind)
{
    return t&&!t->failed&&t->write&&t->kind==kind&&t->next&&t->next<UINT64_MAX;
}
static void header(unsigned char *h,const PwWineChildUiTx *t,uint32_t bytes,
                   uint32_t w,uint32_t height,uint32_t stride)
{
    memset(h,0,PW_WCU_HEADER);memcpy(h,"PWUI",4);h[4]=1;h[6]=(unsigned char)t->kind;
    put64(h+8,t->identity.session);put64(h+16,t->identity.generation);
    put64(h+24,t->next);put32(h+32,t->identity.native_pid);put32(h+36,bytes);
    put32(h+40,w);put32(h+44,height);put32(h+48,stride);
}
static int emit(PwWineChildUiTx *t,const void *p,size_t n)
{
    if(t->write(t->context,p,n)){t->failed=1;return -1;}
    return 0;
}
int pw_wine_child_ui_present(void *context,const void *bgra,uint32_t w,uint32_t h,uint32_t stride)
{
    PwWineChildUiTx *t=context;
    unsigned char head[PW_WCU_HEADER];
    if(!ready(t,PW_WCU_FRAME)||!bgra||!frame_ok(w,h,stride)||
       (size_t)(h-1)>(SIZE_MAX-w*4)/stride)return -1;
    header(head,t,w*h*4,w,h,w*4);
    if(emit(t,head,sizeof(head)))return -1;
    for(uint32_t y=0;y<h;y++)
        if(emit(t,(const unsigned char *)bgra+(size_t)y*stride,w*4))return -1;
    t->next++;return 0;
}
int pw_wine_child_ui_send_input(PwWineChildUiTx *t,const PwWineInput *e)
{
    unsigned char bytes[PW_WCU_HEADER+20];
    if(!ready(t,PW_WCU_INPUT)||!input_ok(e))return -1;
    header(bytes,t,20,0,0,0);
    put32(bytes+64,e->type);put32(bytes+68,e->code);
    put32(bytes+72,(uint32_t)e->x);put32(bytes+76,(uint32_t)e->y);put32(bytes+80,e->down);
    if(emit(t,bytes,sizeof(bytes)))return -1;
    t->next++;return 0;
}
int pw_wine_child_ui_rx_init(PwWineChildUiRx *r,PwWineChildUiIdentity id,unsigned kind,
                            void *storage,size_t capacity,PwWinePresentSink present,
                            PwWineChildUiInput input,void *context)
{
    if(!r||!identity_ok(id)||!kind_ok(kind)||!storage||capacity<20||
       (kind==PW_WCU_FRAME?(!present||input):(!input||present)))return -1;
    *r=(PwWineChildUiRx){.identity=id,.next=1,.kind=kind,.storage=storage,.capacity=capacity,
                        .present=present,.input=input,.context=context};
    return 0;
}
static int check_header(PwWineChildUiRx *r)
{
    const unsigned char *h=r->header;
    if(memcmp(h,"PWUI",4)||h[4]!=1||h[5]||h[6]!=r->kind||h[7]||
       get64(h+8)!=r->identity.session||get64(h+16)!=r->identity.generation||
       get32(h+32)!=r->identity.native_pid||get64(h+24)!=r->next||r->next==UINT64_MAX)return -1;
    for(unsigned i=52;i<PW_WCU_HEADER;i++)if(h[i])return -1;
    uint32_t n=get32(h+36),w=get32(h+40),height=get32(h+44),stride=get32(h+48);
    if(n>r->capacity)return -1;
    if(r->kind==PW_WCU_FRAME){
        if(!frame_ok(w,height,stride)||stride!=w*4||n!=w*height*4)return -1;
    }else if(n!=20||w||height||stride)return -1;
    r->payload_bytes=n;return 0;
}
static int32_t signed32(uint32_t n)
{
    return n<=INT32_MAX?(int32_t)n:(int32_t)((int64_t)n-INT64_C(4294967296));
}
static int deliver(PwWineChildUiRx *r)
{
    if(r->kind==PW_WCU_FRAME)
        return r->present(r->context,r->storage,get32(r->header+40),get32(r->header+44),get32(r->header+48));
    const unsigned char *p=r->storage;
    PwWineInput e={get32(p),get32(p+4),signed32(get32(p+8)),signed32(get32(p+12)),get32(p+16)};
    return input_ok(&e)?r->input(r->context,&e):-1;
}
int pw_wine_child_ui_feed(PwWineChildUiRx *r,const void *bytes,size_t length)
{
    if(!r||r->failed)return -1;
    if((!bytes&&length)||!r->storage||!r->next||!kind_ok(r->kind))goto fail;
    const unsigned char *p=bytes;
    while(length){
        size_t n;
        if(r->header_used<PW_WCU_HEADER){
            n=PW_WCU_HEADER-r->header_used;if(n>length)n=length;
            memcpy(r->header+r->header_used,p,n);r->header_used+=n;p+=n;length-=n;
            if(r->header_used<PW_WCU_HEADER)continue;
            if(check_header(r))goto fail;
        }
        n=r->payload_bytes-r->payload_used;if(n>length)n=length;
        if(n)memcpy(r->storage+r->payload_used,p,n);
        r->payload_used+=n;p+=n;length-=n;
        if(r->payload_used==r->payload_bytes){
            if(deliver(r))goto fail;
            r->next++;r->header_used=r->payload_used=r->payload_bytes=0;
        }
    }
    return 0;
fail:
    r->failed=1;return -1;
}
int pw_wine_child_ui_end(PwWineChildUiRx *r)
{
    if(!r)return -1;
    int bad=r->failed||r->header_used||r->payload_used;
    r->failed=1;return bad?-1:0;
}
