/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_wine_child_ui_preview.h"
#include <errno.h>
#include <string.h>
static int same(PwWineChildUiIdentity a,PwWineChildUiIdentity b)
{return a.session==b.session&&a.generation==b.generation&&a.native_pid==b.native_pid;}
int pw_wine_child_ui_mailbox_init(PwWineChildUiMailbox *m)
{
    if(!m||m->initialized||pthread_mutex_init(&m->lock,NULL))return -1;
    m->initialized=1;return 0;
}
int pw_wine_child_ui_mailbox_put(PwWineChildUiMailbox *m,PwWineChildUiIdentity id,
                               const void *pixels,uint32_t width,uint32_t height,uint32_t stride)
{
    if(!m||!m->initialized||!id.session||!id.generation||!id.native_pid||!pixels||!width||!height||
       width>PW_WCU_MAX_WIDTH||height>PW_WCU_MAX_HEIGHT||stride<width*4||
       (size_t)(height-1)>(SIZE_MAX-width*4)/stride)return -1;
    int rc=pthread_mutex_trylock(&m->lock);if(rc)return rc==EBUSY?0:-1;
    if(m->preview.sequence==UINT64_MAX){pthread_mutex_unlock(&m->lock);return -1;}
    for(unsigned y=0;y<PW_WCU_PREVIEW_HEIGHT;y++)for(unsigned x=0;x<PW_WCU_PREVIEW_WIDTH;x++){
        uint32_t color;memcpy(&color,(const unsigned char *)pixels+
            (size_t)(y*height/PW_WCU_PREVIEW_HEIGHT)*stride+(x*width/PW_WCU_PREVIEW_WIDTH)*4,4);
        m->preview.pixels[y*PW_WCU_PREVIEW_WIDTH+x]=color;
    }
    m->preview.identity=id;m->preview.valid=1;m->preview.sequence++;
    pthread_mutex_unlock(&m->lock);return 0;
}
void pw_wine_child_ui_mailbox_retire(PwWineChildUiMailbox *m,PwWineChildUiIdentity id)
{
    if(!m||!m->initialized)return;
    /* Supervisor owns all put/retire calls. Main's bounded snapshot copy is
     * the only concurrent reader. Retirement cannot drop its invalidation. */
    if(pthread_mutex_lock(&m->lock))return;
    if(m->preview.valid&&same(m->preview.identity,id)){
        m->preview.valid=0;if(m->preview.sequence<UINT64_MAX)m->preview.sequence++;
    }
    pthread_mutex_unlock(&m->lock);
}
int pw_wine_child_ui_mailbox_take(PwWineChildUiMailbox *m,PwWineChildUiPreview *out)
{
    if(!m||!m->initialized||!out)return 0;
    if(pthread_mutex_trylock(&m->lock))return 0;
    int changed=out->sequence!=m->preview.sequence||out->valid!=m->preview.valid||
                !same(out->identity,m->preview.identity);
    if(changed)*out=m->preview;
    pthread_mutex_unlock(&m->lock);return changed;
}
/* Tiny fixed caption, independent of launcher settings/font state. */
static const unsigned char *glyph(char ch)
{
    static const unsigned char rows[][7]={
        {14,17,16,16,16,17,14}, /* C */ {17,17,17,31,17,17,17}, /* H */
        {14,4,4,4,4,4,14}, /* I */ {16,16,16,16,16,16,31}, /* L */
        {30,17,17,17,17,17,30}, /* D */ {17,17,17,17,17,10,4}, /* V */
        {31,16,16,30,16,16,31}, /* E */ {17,17,17,21,21,21,10}, /* W */
        {14,17,17,17,17,17,14}, /* O */ {17,25,25,21,19,19,17}, /* N */
        {17,17,10,4,4,4,4}, /* Y */ {0,0,0,0,0,0,0}};
    const char *letters="CHILDVEWONY";
    const char *p=ch?strchr(letters,ch):NULL;return rows[p?(size_t)(p-letters):11];
}
int pw_wine_child_ui_preview_overlay(const PwWineChildUiPreview *p,const void *root,uint32_t w,uint32_t h,uint32_t stride,
                                    void *out,size_t capacity)
{
    if(!p||!p->valid||!root||!out||root==out||w<48||h<48||w>PW_WCU_MAX_WIDTH||h>PW_WCU_MAX_HEIGHT||stride<w*4||
       (size_t)(h-1)>(SIZE_MAX-w*4)/stride||(size_t)w*h*4>capacity)return -1;
    unsigned char *pixels=out;
    for(uint32_t y=0;y<h;y++)memcpy(pixels+(size_t)y*w*4,(const unsigned char *)root+(size_t)y*stride,w*4);
    uint32_t pw=w/3,ph=h/3;if(pw>320)pw=320;if(ph>196)ph=196;
    uint32_t left=w-pw-4,top=h-ph-4;
    for(uint32_t y=0;y<ph;y++)for(uint32_t x=0;x<pw;x++){
        uint32_t color=0xff286070u;
        if(x>=2&&x+2<pw&&y>=14&&y+2<ph)
            color=p->pixels[((y-14)*PW_WCU_PREVIEW_HEIGHT/(ph-16))*PW_WCU_PREVIEW_WIDTH+
                            ((x-2)*PW_WCU_PREVIEW_WIDTH/(pw-4))];
        memcpy(pixels+((size_t)(top+y)*w+left+x)*4,&color,4);
    }
    const char caption[]="CHILD VIEW ONLY";
    for(unsigned n=0;n<sizeof(caption)-1;n++)for(unsigned y=0;y<7;y++)for(unsigned x=0;x<5;x++){
        uint32_t dx=4+n*6+x,dy=3+y;
        if(dx+2<pw&&(glyph(caption[n])[y]&(1u<<(4-x)))){
            uint32_t color=0xffffffffu;memcpy(pixels+((size_t)(top+dy)*w+left+dx)*4,&color,4);
        }
    }
    return 0;
}
