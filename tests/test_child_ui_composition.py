#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Execute the actual root frame/badge/child-preview branch in both cohorts."""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
def main():
    source=(ROOT/'native/wine64_main.c').read_text()
    helper='static void child_preview_view('+source.split('static void child_preview_view(',1)[1].split('\n#endif',1)[0]
    branch='if (video_status == PW_OK && frame_shown) {'+source.split('if (video_status == PW_OK && frame_shown) {',1)[1].split('} else if (frame_shown && __atomic_load_n(&display_closed',1)[0]+'}'
    prefix=r'''
#include "native/pw_wine_display.h"
#include "native/pw_wine_child_ui_preview.h"
#include "src/pw_launcher_render.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
enum {W=120,H=90,N=W*H};
#define PW_WINE64_MAX_FRAME (N*4)
#define PW_WINE_CHILD_FIXTURE_MODE 1
static uint32_t pixels[N],rendered[N],composite[N];
static uint8_t *frame_shown=(uint8_t*)pixels;
#if PW_WINE_CHILD_UI_ENABLED
static uint8_t *child_composite=(uint8_t*)composite;
static PwWineChildUiPreview child_preview,incoming;
static int preview_pending;
static int pw_wine_child_title_preview(PwWineChildUiPreview *out)
{if(!preview_pending)return 0;*out=incoming;preview_pending=0;return 1;}
#endif
static int video_status=PW_OK,video,loading,game_input,frames,scaling;
static PwPresentView gdi_view;
static uint64_t shown_sequence,shown,now,started;
static struct {unsigned mouse_mode;} input_router;
static unsigned old_mode;
static int frame_pending,admitted=1,presents,badges,spinners;
static int take_frame(void *f,uint64_t *seq,void *bytes,size_t cap,PwPresentView *view)
{assert(f==&frames&&seq==&shown_sequence&&bytes==pixels&&cap==sizeof(pixels));if(!frame_pending)return 0;frame_pending=0;
 for(unsigned i=0;i<N;i++)pixels[i]=0xff102030;
 *view=(PwPresentView){(const uint8_t*)pixels,W,H,W*4,sizeof(pixels)};return 1;}
#define pw_wine_frame_box_take take_frame
static int loading_admits(void *l,const PwPresentView *v){assert(l==&loading&&v->pixels==(const uint8_t*)pixels);return admitted;}
static const char *mode_name(void *r,void *g){assert(r==&input_router&&g==&game_input);return input_router.mouse_mode?"MOUSE":"GAMEPAD";}
#define pw_wine_input_mode_name mode_name
static int draw_badge(const char *mode,const PwPresentTarget *t)
{assert(t->pixels==(uint8_t*)pixels&&t->width==W&&t->height==H&&t->stride==W*4);badges++;
 pixels[0]=strcmp(mode,"MOUSE")?0xff00aa00:0xffaa0000;return PW_OK;}
#define pw_launcher_input_badge draw_badge
static int show_scaled(void *v,const PwPresentView *p,int s)
{assert(v==&video&&s==scaling&&p->width==W&&p->height==H&&p->stride==W*4&&p->bytes==sizeof(rendered));memcpy(rendered,p->pixels,sizeof(rendered));presents++;return PW_OK;}
static const PwPresentFrame *loading_frame(void *l,uint64_t n,uint64_t s,PwPresentFrame *p)
{assert(l==&loading&&n==now&&s==started);return p;}
static int spinner_present(void *v,const PwPresentFrame *p,int scale,int zero)
{assert(v==&video&&p&&scale==PW_PRESENT_SCALE_FIT&&!zero);spinners++;return PW_OK;}
#define pw_videoout_ps5_present_scaled spinner_present
'''
    suffix=r'''
static void check_root(void){for(unsigned i=1;i<N;i++)assert(pixels[i]==0xff102030);}
int main(void)
{
#if PW_WINE_CHILD_UI_ENABLED
    incoming.valid=1;incoming.identity=(PwWineChildUiIdentity){1,2,3};incoming.sequence=1;
    for(unsigned i=0;i<PW_WCU_PREVIEW_WIDTH*PW_WCU_PREVIEW_HEIGHT;i++)incoming.pixels[i]=0xff885522;
    preview_pending=1;tick();assert(!presents&&spinners==1); /* no root, no preview */
#else
    (void)composite;tick();assert(!presents&&spinners==1);
#endif
    frame_pending=1;tick();assert(presents==1&&badges==1&&rendered[0]==0xff00aa00);check_root();
#if PW_WINE_CHILD_UI_ENABLED
    unsigned difference=0;for(unsigned i=1;i<N;i++)difference+=rendered[i]!=pixels[i];assert(difference>100);
#else
    assert(!memcmp(pixels,rendered,sizeof(pixels)));
#endif
    old_mode=0;input_router.mouse_mode=1;tick();assert(presents==2&&badges==2&&rendered[0]==0xffaa0000);check_root();
    old_mode=1;tick();assert(presents==2); /* idle branch does not repaint stale preview */
#if PW_WINE_CHILD_UI_ENABLED
    incoming.valid=0;incoming.sequence++;preview_pending=1;tick();assert(presents==3&&badges==3);
    assert(!memcmp(pixels,rendered,sizeof(pixels))); /* retirement restores root + current badge */
    incoming.valid=1;incoming.sequence++;preview_pending=1;tick();assert(presents==4&&badges==4);check_root();
    child_composite=NULL;incoming.sequence++;preview_pending=1;tick();assert(presents==5);
    assert(!memcmp(pixels,rendered,sizeof(pixels))); /* allocation failure preserves badge/root */
    child_composite=(uint8_t*)composite;
#endif
    int before=presents;frame_pending=1;admitted=0;tick();assert(presents==before&&!gdi_view.pixels);
    old_mode=1;input_router.mouse_mode=0;
#if PW_WINE_CHILD_UI_ENABLED
    incoming.sequence++;preview_pending=1;
#endif
    tick();assert(presents==before); /* rejected new root invalidates old cache */
    admitted=1;frame_pending=1;tick();assert(presents==before+1&&rendered[0]==0xff00aa00);check_root();
    printf("actual root presentation: child UI=%d, badge repaint, retirement, rejection and fallback passed\n",PW_WINE_CHILD_UI_ENABLED);return 0;
}
'''
    code=prefix+'\n#if PW_WINE_CHILD_UI_ENABLED\n'+helper+'\n#endif\nstatic void tick(void){PwPresentView view;int presented=0;\n'+branch+'\nassert(presented);}\n'+suffix
    cc=shlex.split(os.environ.get('CC','cc'));flags=shlex.split(os.environ.get('CFLAGS','-O2 -std=c11 -Wall -Wextra -Werror'))
    with tempfile.TemporaryDirectory(prefix='pw-child-ui-composition-') as tmp:
        path=Path(tmp);unit=path/'composition.c';unit.write_text(code)
        for enabled in (0,1):
            exe=path/f'ui-{enabled}'
            subprocess.run([*cc,*flags,'-pthread','-I'+str(ROOT),f'-DPW_WINE_CHILD_UI_ENABLED={enabled}',str(unit),str(ROOT/'native/pw_wine_child_ui_preview.c'),'-o',str(exe)],check=True)
            subprocess.run([str(exe)],check=True,timeout=10)
    # Preserve the root-only close chord and queued-release gate in this actual loop.
    assert 'pad_fresh && !input_delivery.count, combo_ticks' in source
    assert 'posted += pw_wine_input_flush(&input_delivery, post_input);' in source
    assert 'pw_wine_post_input' not in (ROOT/'native/pw_wine_child_bootstrap.c').read_text()
if __name__=='__main__':main()
