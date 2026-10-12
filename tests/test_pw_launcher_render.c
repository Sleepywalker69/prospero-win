/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../src/pw_launcher_render.h"
#include "../src/pw_controller_settings.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

enum { W=1920,H=1080,STRIDE=W*4+16 };
static uint8_t pixels[STRIDE*H];

static uint32_t hash(void)
{
    uint32_t h=2166136261u;
    for(uint32_t y=0;y<H;y++)for(uint32_t i=0;i<W*4u;i++){h^=pixels[y*STRIDE+i];h*=16777619u;}
    return h;
}
static uint32_t at(uint32_t x,uint32_t y)
{
    const uint8_t *p=pixels+(size_t)y*STRIDE+x*4u;
    assert(p[3]==0xff);
    return (uint32_t)p[2]<<16|(uint32_t)p[1]<<8|p[0];
}
static uint32_t render(const PwLauncherScene *scene)
{
    memset(pixels,0x5a,sizeof(pixels));
    const PwPresentTarget target={pixels,W,H,STRIDE,sizeof(pixels)};
    assert(pw_launcher_render(scene,&target)==PW_OK);
    for(uint32_t y=0;y<H;y++)for(uint32_t i=W*4u;i<STRIDE;i++)assert(pixels[y*STRIDE+i]==0x5a);
    return hash();
}

static void test_navigation(void)
{
    const PwLauncherItem items[8]={{"a",0,1},{"b",0,1},{"c",0,1},{"d",0,1},{"e",0,1},{"f",0,1},{"g",0,1},{"h",0,0}};
    PwLauncherScene scene={items,8,0,NULL};

    /* Keys: the arrows move, Enter and Space choose, others do nothing. */
    assert(pw_launcher_key_action(0x25)==PW_LAUNCHER_ACTION_LEFT);
    assert(pw_launcher_key_action(0x26)==PW_LAUNCHER_ACTION_UP);
    assert(pw_launcher_key_action(0x27)==PW_LAUNCHER_ACTION_RIGHT);
    assert(pw_launcher_key_action(0x28)==PW_LAUNCHER_ACTION_DOWN);
    assert(pw_launcher_key_action(0x0d)==PW_LAUNCHER_ACTION_CHOOSE);
    assert(pw_launcher_key_action(0x20)==PW_LAUNCHER_ACTION_CHOOSE);
    assert(pw_launcher_key_action('A')==PW_LAUNCHER_ACTION_NONE);
    assert(pw_launcher_key_action(0)==PW_LAUNCHER_ACTION_NONE);
    /* The grid is three wide: left and up stop at the first tile, right and
     * down at the last. */
    assert(!pw_launcher_navigate(&scene,PW_LAUNCHER_ACTION_LEFT,7) && scene.selected==0);
    assert(!pw_launcher_navigate(&scene,PW_LAUNCHER_ACTION_UP,7) && scene.selected==0);
    pw_launcher_navigate(&scene,PW_LAUNCHER_ACTION_RIGHT,7);
    assert(scene.selected==1);
    pw_launcher_navigate(&scene,PW_LAUNCHER_ACTION_DOWN,7);
    assert(scene.selected==4);
    pw_launcher_navigate(&scene,PW_LAUNCHER_ACTION_DOWN,7);
    assert(scene.selected==7);
    pw_launcher_navigate(&scene,PW_LAUNCHER_ACTION_DOWN,7);
    assert(scene.selected==7);             /* no tile three further on */
    pw_launcher_navigate(&scene,PW_LAUNCHER_ACTION_RIGHT,7);
    assert(scene.selected==7);
    /* Tile 7 is a refused profile: choosing it does nothing. */
    assert(!pw_launcher_navigate(&scene,PW_LAUNCHER_ACTION_CHOOSE,7));
    pw_launcher_navigate(&scene,PW_LAUNCHER_ACTION_UP,7);
    assert(scene.selected==4);
    assert(pw_launcher_navigate(&scene,PW_LAUNCHER_ACTION_CHOOSE,7)==1 && scene.selected==4);
    assert(!pw_launcher_navigate(&scene,PW_LAUNCHER_ACTION_NONE,7) && scene.selected==4);
    /* No tiles, no selection, or none of it: nothing happens. */
    PwLauncherScene empty={items,0,PW_LAUNCHER_RENDER_NONE,NULL};
    assert(!pw_launcher_navigate(&empty,PW_LAUNCHER_ACTION_CHOOSE,0) && empty.selected==PW_LAUNCHER_RENDER_NONE);
    assert(!pw_launcher_navigate(NULL,PW_LAUNCHER_ACTION_CHOOSE,1));
}

static void test_controls(void)
{
    const PwLauncherItem items[8]={{"a",0,1},{"b",0,0},{"c",0,1},{"d",0,1},{"e",0,1},{"f",0,1},{"g",0,1},{"h",0,1}};
    PwLauncherScene scene={items,8,0,"Saved logs available"};
    int help=0;
    assert(pw_launcher_pad_action(0x4000)==PW_LAUNCHER_ACTION_CHOOSE);
    assert(pw_launcher_pad_action(0x4000|0x8)==PW_LAUNCHER_ACTION_HELP);
    assert(pw_launcher_pad_action(0x4000|0x2000)==PW_LAUNCHER_ACTION_BACK);
    assert(pw_launcher_pad_action(0x100000)==PW_LAUNCHER_ACTION_NONE);
    assert(pw_launcher_key_action(0x70)==PW_LAUNCHER_ACTION_HELP);
    assert(pw_launcher_key_action(0x71)==PW_LAUNCHER_ACTION_SETTINGS);
    assert(pw_launcher_pad_action(0x8000|0x4000)==PW_LAUNCHER_ACTION_SETTINGS);
    assert(pw_launcher_pad_action(0x8000|0x8)==PW_LAUNCHER_ACTION_HELP);
    assert(pw_launcher_pad_action(0x8000|0x2000)==PW_LAUNCHER_ACTION_BACK);
    assert(pw_launcher_key_action(0x1b)==PW_LAUNCHER_ACTION_BACK);
    assert(pw_launcher_key_action(0x21)==PW_LAUNCHER_ACTION_PAGE_PREVIOUS);
    assert(pw_launcher_key_action(0x22)==PW_LAUNCHER_ACTION_PAGE_NEXT);
    assert(!pw_launcher_control(&scene,PW_LAUNCHER_ACTION_HELP,8,&help) && help);
    for(int i=PW_LAUNCHER_ACTION_LEFT;i<=PW_LAUNCHER_ACTION_PAGE_NEXT;i++)
        assert(!pw_launcher_control(&scene,(PwLauncherAction)i,8,&help) && scene.selected==0 && help);
    const PwPresentTarget target={pixels,W,H,STRIDE,sizeof(pixels)};
    uint32_t plain=render(&scene);
    assert(pw_launcher_render_controls(&scene,1,&target)==PW_OK);
    assert(hash()!=plain && at(227,400)==0x79bcff);
    assert(!pw_launcher_control(&scene,PW_LAUNCHER_ACTION_BACK,8,&help) && !help);
    assert(pw_launcher_render_controls(&scene,0,&target)==PW_OK && hash()==plain);
    /* Back is idempotent, a reopened guide preserves focus, no click-through. */
    assert(!pw_launcher_control(&scene,PW_LAUNCHER_ACTION_BACK,8,&help));
    for(int n=0;n<3;n++){
        pw_launcher_control(&scene,PW_LAUNCHER_ACTION_HELP,8,&help);
        assert(!pw_launcher_control(&scene,PW_LAUNCHER_ACTION_CHOOSE,8,&help));
        pw_launcher_control(&scene,PW_LAUNCHER_ACTION_HELP,8,&help);
    }
    assert(pw_launcher_control(&scene,PW_LAUNCHER_ACTION_CHOOSE,8,&help));
    pw_launcher_control(&scene,pw_launcher_pad_action(0x800),8,&help);
    assert(scene.selected==6);
    pw_launcher_control(&scene,PW_LAUNCHER_ACTION_PAGE_NEXT,8,&help);
    assert(scene.selected==7);
    pw_launcher_control(&scene,pw_launcher_pad_action(0x400),8,&help);
    assert(scene.selected==1);
    /* Even an in-range selectable item cannot run while unavailable. */
    assert(!pw_launcher_control(&scene,PW_LAUNCHER_ACTION_CHOOSE,8,&help));
    pw_launcher_control(&scene,PW_LAUNCHER_ACTION_PAGE_PREVIOUS,8,&help);
    assert(scene.selected==0);
    assert(!pw_launcher_control(&scene,PW_LAUNCHER_ACTION_CHOOSE,8,NULL));
    assert(pw_launcher_render_controls(NULL,1,&target)==PW_ERR_PRECONDITION);
    /* Large libraries have decimal page numbers, never ':' or overflow. */
    PwLauncherItem large[66];
    for(unsigned i=0;i<66;i++)large[i]=(PwLauncherItem){"Application",NULL,1};
    scene=(PwLauncherScene){large,66,65,NULL};
    assert(pw_launcher_render_controls(&scene,0,&target)==PW_OK);
}

static void test_input_badge(void)
{
    enum { BW=320,BH=200,BS=BW*4+16 };
    uint8_t small[BS*BH],reference[BS*BH];
    memset(small,0x5a,sizeof(small));
    PwPresentTarget target={small,BW,BH,BS,sizeof(small)};
    assert(pw_launcher_input_badge("GAMEPAD (XInput)",&target)==PW_OK);
    /* Rows outside the badge and every stride-padding byte are untouched. */
    for(unsigned y=0;y<BH;y++)for(unsigned x=0;x<BS;x++)
        if(y<156 || y>=188 || x<12*4 || x>=140*4)assert(small[y*BS+x]==0x5a);
    assert(pw_launcher_input_badge("MOUSE/UI",&target)==PW_OK);
    memcpy(reference,small,sizeof(small));
    memset(small,0x5a,sizeof(small));
    assert(pw_launcher_input_badge("MOUSE/UI",&target)==PW_OK);
    assert(!memcmp(small,reference,sizeof(small))); /* no stale longer label */
    target=(PwPresentTarget){small,160,48,640,640*48};
    assert(pw_launcher_input_badge("PROFILE KEYS",&target)==PW_OK);
    target.width=159;
    assert(pw_launcher_input_badge("MOUSE/UI",&target)==PW_ERR_MALFORMED);
    target.width=160;target.bytes--;
    assert(pw_launcher_input_badge("MOUSE/UI",&target)==PW_ERR_MALFORMED);
    assert(pw_launcher_input_badge(NULL,&target)==PW_ERR_PRECONDITION);
    assert(pw_launcher_input_badge("MOUSE/UI",NULL)==PW_ERR_PRECONDITION);
    /* The 1080p path keeps the launcher's row guards intact too. */
    memset(pixels,0x5a,sizeof(pixels));
    target=(PwPresentTarget){pixels,W,H,STRIDE,sizeof(pixels)};
    assert(pw_launcher_input_badge("GAMEPAD (XInput)",&target)==PW_OK);
    for(unsigned y=0;y<H;y++)for(unsigned x=W*4;x<STRIDE;x++)assert(pixels[y*STRIDE+x]==0x5a);
}

static void test_settings(void)
{
    const PwLauncherItem items[]={{"Long application title with custom controls",NULL,1}};
    const PwLauncherScene scene={items,1,0,"Ready"};
    PwControllerSettings settings={ {PW_GAME_START_MOUSE,20,1200,100},
                                   {PW_GAME_START_MOUSE,12,1800,150},0,1,PW_OK };
    const PwPresentTarget target={pixels,W,H,STRIDE,sizeof(pixels)};
    memset(pixels,0x5a,sizeof(pixels));
    uint32_t previous=0;
    for(unsigned row=0;row<PW_CONTROLLER_ROWS;row++) {
        settings.selected=row;
        assert(pw_launcher_render_settings(&scene,0,&settings,items[0].title,0,&target)==PW_OK);
        assert(at(280,342+row*72)==0x79bcff && hash()!=previous);
        previous=hash();
        for(uint32_t y=0;y<H;y++)for(uint32_t i=W*4u;i<STRIDE;i++)assert(pixels[y*STRIDE+i]==0x5a);
    }
    settings.selected=PW_CONTROLLER_APPLY;
    const int errors[]={PW_OK,PW_ERR_VM,PW_ERR_STATE,PW_ERR_LIMIT,PW_ERR_MALFORMED};
    for(unsigned i=0;i<sizeof(errors)/sizeof(errors[0]);i++) {
        settings.error=errors[i];
        assert(pw_launcher_render_settings(&scene,0,&settings,items[0].title,0,&target)==PW_OK);
        assert(hash()!=previous); previous=hash();
    }
    settings.error=PW_OK;
    assert(pw_launcher_render_settings(&scene,0,&settings,items[0].title,1,&target)==PW_OK);
    uint32_t fallback=hash();
    assert(pw_launcher_render_settings(&scene,0,&settings,items[0].title,0,&target)==PW_OK && hash()!=fallback);
    settings.active=0;
    assert(pw_launcher_render_settings(&scene,0,&settings,NULL,0,&target)==PW_OK);
    uint32_t normal=hash();
    assert(pw_launcher_render_settings(&scene,1,&settings,NULL,0,&target)==PW_OK && hash()!=normal);
    /* Repeated opening and closing does not leave modal text in the library. */
    for(unsigned i=0;i<3;i++) {
        settings.active=1;
        assert(pw_launcher_render_settings(&scene,0,&settings,items[0].title,0,&target)==PW_OK);
        settings.active=0;
        assert(pw_launcher_render_settings(&scene,0,&settings,NULL,0,&target)==PW_OK && hash()==normal);
    }
    settings.active=1;settings.selected=PW_CONTROLLER_ROWS;
    assert(pw_launcher_render_settings(&scene,0,&settings,items[0].title,0,&target)==PW_ERR_PRECONDITION);
    assert(pw_launcher_render_settings(&scene,0,NULL,items[0].title,0,&target)==PW_ERR_PRECONDITION);
}

int main(void)
{
    test_navigation();
    test_controls();
    test_input_badge();
    test_settings();
    const PwLauncherItem items[]={
        {"Space Cadet Pinball","pe32  gdi  prospero-win-direct",1},
        {"Paint","pe32  gdi  wine-wow64",0},
        {"Minesweeper",NULL,1},
    };
    const PwLauncherScene library={items,3,0,"Ready"};
    const PwLauncherScene unavailable={items,3,1,"Pinball closed normally"};
    const PwLauncherScene empty={NULL,0,PW_LAUNCHER_RENDER_NONE,NULL};
    uint32_t hashes[3]={render(&library),render(&unavailable),render(&empty)};
    /* Golden frames: a visual change must update these deliberately, after
     * looking at the new rendering. */
    const uint32_t golden[3]={0x17a74495u,0x062b2cccu,0x575d5b24u};
    if(memcmp(hashes,golden,sizeof(golden)))
        printf("launcher render hashes 0x%08x 0x%08x 0x%08x\n",hashes[0],hashes[1],hashes[2]);
    assert(!memcmp(hashes,golden,sizeof(golden)));

    /* Semantic probes on the library scene. */
    render(&library);
    /* Original dark panels, bright focus ring, and readable muted cards. */
    assert(at(1900,110)!=at(1900,960));
    assert(at(105,400)!=at(115,400));
    uint32_t selected_edge=at(135,300),plain_edge=at(695,300);
    assert(selected_edge==0x79bcff && plain_edge!=selected_edge);
    uint32_t available_body=at(620,420),unavailable_body=at(1200,420);
    assert((available_body&0xff)>(available_body>>16&0xff));
    assert(available_body!=unavailable_body);
    /* Moving the selection moves the highlight. */
    render(&unavailable);
    assert(at(135,300)!=selected_edge && at(695,300)==selected_edge);

    /* A second page is shown for a selection past the first six tiles. */
    PwLauncherItem many[8];
    for(unsigned i=0;i<8;i++)many[i]=(PwLauncherItem){i<6?"First":"Second",NULL,1};
    const PwLauncherScene first={many,8,5,NULL},second={many,8,6,NULL};
    assert(render(&first)!=render(&second));
    render(&second);assert(at(135,300)==selected_edge);

    const PwPresentTarget target={pixels,W,H,STRIDE,sizeof(pixels)};
    PwPresentTarget small=target;small.width=1280;
    assert(pw_launcher_render(&library,&small)==PW_ERR_MALFORMED);
    small=target;small.bytes=(uint64_t)STRIDE*H-1;
    assert(pw_launcher_render(&library,&small)==PW_ERR_MALFORMED);
    const PwLauncherScene bad_selection={items,3,3,NULL};
    assert(pw_launcher_render(&bad_selection,&target)==PW_ERR_PRECONDITION);
    const PwLauncherItem untitled[]={{NULL,NULL,1}};
    const PwLauncherScene bad_item={untitled,1,0,NULL};
    assert(pw_launcher_render(&bad_item,&target)==PW_ERR_PRECONDITION);
    assert(pw_launcher_render(NULL,&target)==PW_ERR_PRECONDITION);
    return 0;
}
