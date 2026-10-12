/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_launcher_render.h"
#include "pw_controller_settings.h"
#include <string.h>

enum { W=PW_LAUNCHER_RENDER_WIDTH,H=PW_LAUNCHER_RENDER_HEIGHT,
       BAR=96,TASKBAR_Y=996,TILE_W=520,TILE_H=240,TILE_GAP=40,
       TILES_X=(W-3*TILE_W-2*TILE_GAP)/2,TILES_Y=190 };

typedef struct Glyph { char c;uint8_t rows[7]; } Glyph;
/* Original 5x7 dot-matrix glyphs; bit 4 is the leftmost column. */
static const Glyph glyphs[]={
    {' ',{0x00,0x00,0x00,0x00,0x00,0x00,0x00}},
    {'!',{0x04,0x04,0x04,0x04,0x04,0x00,0x04}},
    {'\'',{0x04,0x04,0x08,0x00,0x00,0x00,0x00}},
    {'(',{0x02,0x04,0x08,0x08,0x08,0x04,0x02}},
    {')',{0x08,0x04,0x02,0x02,0x02,0x04,0x08}},
    {'+',{0x00,0x04,0x04,0x1f,0x04,0x04,0x00}},
    {',',{0x00,0x00,0x00,0x00,0x0c,0x04,0x08}},
    {'-',{0x00,0x00,0x00,0x1f,0x00,0x00,0x00}},
    {'.',{0x00,0x00,0x00,0x00,0x00,0x0c,0x0c}},
    {'/',{0x00,0x01,0x02,0x04,0x08,0x10,0x00}},
    {'0',{0x0e,0x11,0x13,0x15,0x19,0x11,0x0e}},
    {'1',{0x04,0x0c,0x04,0x04,0x04,0x04,0x0e}},
    {'2',{0x0e,0x11,0x01,0x02,0x04,0x08,0x1f}},
    {'3',{0x1f,0x02,0x04,0x02,0x01,0x11,0x0e}},
    {'4',{0x02,0x06,0x0a,0x12,0x1f,0x02,0x02}},
    {'5',{0x1f,0x10,0x1e,0x01,0x01,0x11,0x0e}},
    {'6',{0x06,0x08,0x10,0x1e,0x11,0x11,0x0e}},
    {'7',{0x1f,0x01,0x02,0x04,0x08,0x08,0x08}},
    {'8',{0x0e,0x11,0x11,0x0e,0x11,0x11,0x0e}},
    {'9',{0x0e,0x11,0x11,0x0f,0x01,0x02,0x0c}},
    {':',{0x00,0x0c,0x0c,0x00,0x0c,0x0c,0x00}},
    {'=',{0x00,0x00,0x1f,0x00,0x1f,0x00,0x00}},
    {'>',{0x08,0x04,0x02,0x01,0x02,0x04,0x08}},
    {'?',{0x0e,0x11,0x01,0x02,0x04,0x00,0x04}},
    {'A',{0x0e,0x11,0x11,0x1f,0x11,0x11,0x11}},
    {'B',{0x1e,0x11,0x11,0x1e,0x11,0x11,0x1e}},
    {'C',{0x0e,0x11,0x10,0x10,0x10,0x11,0x0e}},
    {'D',{0x1e,0x11,0x11,0x11,0x11,0x11,0x1e}},
    {'E',{0x1f,0x10,0x10,0x1e,0x10,0x10,0x1f}},
    {'F',{0x1f,0x10,0x10,0x1e,0x10,0x10,0x10}},
    {'G',{0x0e,0x11,0x10,0x17,0x11,0x11,0x0f}},
    {'H',{0x11,0x11,0x11,0x1f,0x11,0x11,0x11}},
    {'I',{0x0e,0x04,0x04,0x04,0x04,0x04,0x0e}},
    {'J',{0x07,0x02,0x02,0x02,0x02,0x12,0x0c}},
    {'K',{0x11,0x12,0x14,0x18,0x14,0x12,0x11}},
    {'L',{0x10,0x10,0x10,0x10,0x10,0x10,0x1f}},
    {'M',{0x11,0x1b,0x15,0x15,0x11,0x11,0x11}},
    {'N',{0x11,0x11,0x19,0x15,0x13,0x11,0x11}},
    {'O',{0x0e,0x11,0x11,0x11,0x11,0x11,0x0e}},
    {'P',{0x1e,0x11,0x11,0x1e,0x10,0x10,0x10}},
    {'Q',{0x0e,0x11,0x11,0x11,0x15,0x12,0x0d}},
    {'R',{0x1e,0x11,0x11,0x1e,0x14,0x12,0x11}},
    {'S',{0x0f,0x10,0x10,0x0e,0x01,0x01,0x1e}},
    {'T',{0x1f,0x04,0x04,0x04,0x04,0x04,0x04}},
    {'U',{0x11,0x11,0x11,0x11,0x11,0x11,0x0e}},
    {'V',{0x11,0x11,0x11,0x11,0x11,0x0a,0x04}},
    {'W',{0x11,0x11,0x11,0x15,0x15,0x15,0x0a}},
    {'X',{0x11,0x11,0x0a,0x04,0x0a,0x11,0x11}},
    {'Y',{0x11,0x11,0x0a,0x04,0x04,0x04,0x04}},
    {'Z',{0x1f,0x01,0x02,0x04,0x08,0x10,0x1f}},
    {'_',{0x00,0x00,0x00,0x00,0x00,0x00,0x1f}},
};

typedef struct Canvas { uint8_t *pixels;uint32_t stride,width,height; } Canvas;

static uint32_t rgb(uint32_t r,uint32_t g,uint32_t b){return r<<16|g<<8|b;}
static uint32_t mix(uint32_t a,uint32_t b,uint32_t n,uint32_t d)
{
    uint32_t out=0;
    for(unsigned shift=0;shift<24;shift+=8) {
        uint32_t x=(a>>shift)&0xffu,y=(b>>shift)&0xffu;
        out|=((x*(d-n)+y*n)/d)<<shift;
    }
    return out;
}
static void put(const Canvas *c,int32_t x,int32_t y,uint32_t color)
{
    if(x<0 || y<0 || (uint32_t)x>=c->width || (uint32_t)y>=c->height)return;
    uint8_t *p=c->pixels+(size_t)y*c->stride+(size_t)x*4u;
    p[0]=(uint8_t)color;p[1]=(uint8_t)(color>>8);p[2]=(uint8_t)(color>>16);p[3]=0xff;
}
static void fill(const Canvas *c,int32_t x,int32_t y,int32_t w,int32_t h,uint32_t color)
{
    for(int32_t j=0;j<h;j++)for(int32_t i=0;i<w;i++)put(c,x+i,y+j,color);
}
/* Vertical ramp from top to bottom colour. */
static void ramp(const Canvas *c,int32_t x,int32_t y,int32_t w,int32_t h,
                 uint32_t top,uint32_t bottom)
{
    for(int32_t j=0;j<h;j++)
        fill(c,x,y+j,w,1,mix(top,bottom,(uint32_t)j,h>1?(uint32_t)(h-1):1u));
}
/* A pixel lies outside a rounded corner of radius r. */
static int cut(int32_t i,int32_t j,int32_t w,int32_t h,int32_t r)
{
    int32_t dx=i<r?r-1-i:i>=w-r?i-(w-r):-1,dy=j<r?r-1-j:j>=h-r?j-(h-r):-1;
    return dx>=0 && dy>=0 && dx*dx+dy*dy>=r*r;
}
static void rounded(const Canvas *c,int32_t x,int32_t y,int32_t w,int32_t h,int32_t r,
                    uint32_t top,uint32_t bottom)
{
    for(int32_t j=0;j<h;j++) {
        uint32_t color=mix(top,bottom,(uint32_t)j,h>1?(uint32_t)(h-1):1u);
        for(int32_t i=0;i<w;i++)if(!cut(i,j,w,h,r))put(c,x+i,y+j,color);
    }
}
static const Glyph *glyph(char ch)
{
    if(ch>='a' && ch<='z')ch=(char)(ch-'a'+'A');
    const Glyph *unknown=NULL;
    for(size_t i=0;i<sizeof(glyphs)/sizeof(glyphs[0]);i++) {
        if(glyphs[i].c==ch)return &glyphs[i];
        if(glyphs[i].c=='?')unknown=&glyphs[i];
    }
    return unknown;
}
static int32_t text_width(const char *text,int32_t scale)
{
    size_t n=text?strlen(text):0;return n?(int32_t)(n*6u-1u)*scale:0;
}
/* Draws text clipped to max_width pixels; returns the width used. */
static int32_t text(const Canvas *c,int32_t x,int32_t y,const char *s,int32_t scale,
                    uint32_t color,int32_t max_width)
{
    int32_t used=0;
    for(;s && *s;s++) {
        if(used+5*scale>max_width)break;
        const Glyph *g=glyph(*s);
        for(int32_t row=0;row<7;row++)for(int32_t col=0;col<5;col++)
            if(g->rows[row]&(0x10u>>col))
                fill(c,x+used+col*scale,y+row*scale,scale,scale,color);
        used+=6*scale;
    }
    return used;
}
/* The largest scale from preferred down to minimum at which text fits;
 * text that does not fit even at the minimum is clipped by text(). */
static int32_t fit(const char *s,int32_t preferred,int32_t minimum,int32_t max_width)
{
    int32_t scale=preferred;
    while(scale>minimum && text_width(s,scale)>max_width)scale--;
    return scale;
}
static void background(const Canvas *c)
{
    ramp(c,0,0,W,H,rgb(0x0e,0x19,0x30),rgb(0x24,0x39,0x59));
    /* Original layered panels, no external desktop artwork or branding. */
    rounded(c,104,136,1712,688,32,0x304866,0x293d59);
    rounded(c,112,144,1696,672,26,0x18283f,0x1b2b43);
}
static void title_bar(const Canvas *c)
{
    text(c,140,48,"Prospero Win",5,0xf4f7ff,W-280);
    text(c,W-140-text_width("Your library",3),58,"Your library",3,0xaebfd8,W);
}
static void tile(const Canvas *c,int32_t x,int32_t y,const PwLauncherItem *item,int selected)
{
    if(selected)rounded(c,x-8,y-8,TILE_W+16,TILE_H+16,24,0x79bcff,0x79bcff);
    uint32_t edge=item->available?0x506581:0x454e60;
    rounded(c,x,y,TILE_W,TILE_H,18,edge,edge);
    rounded(c,x+2,y+2,TILE_W-4,TILE_H-4,16,
            item->available?0x334966:0x2b3445,item->available?0x293d59:0x252e3d);
    int32_t title_scale=fit(item->title,5,3,TILE_W-48);
    text(c,x+24,y+32,item->title,title_scale,0xf4f7ff,TILE_W-48);
    if(item->detail)text(c,x+24,y+100,item->detail,fit(item->detail,3,2,TILE_W-48),
                         0xc1cfe2,TILE_W-48);
    if(item->available) {
        rounded(c,x+24,y+TILE_H-64,240,40,12,selected?0x79bcff:0x435f7d,selected?0x79bcff:0x435f7d);
        text(c,x+40,y+TILE_H-54,selected?"Cross: open":"Ready",3,selected?0x10233b:0xf4f7ff,216);
    } else text(c,x+24,y+TILE_H-54,"Unavailable",3,0xf5c49b,TILE_W-48);
}
static void taskbar(const Canvas *c,const char *status)
{
    if(status && *status)text(c,140,886,status,fit(status,3,2,W-280),0xc1cfe2,W-280);
    rounded(c,140,TASKBAR_Y-28,W-280,84,22,0x3d536e,0x354b65);
    text(c,180,TASKBAR_Y,"D-pad: move   Cross: open   L1/R1: page   Options: controls",3,0xf4f7ff,W-360);
}

/* Decimal page labels without adding libc formatting to the portable core. */
static char *decimal(char *out,uint32_t value)
{
    char digits[10];unsigned count=0;
    do { digits[count++]=(char)('0'+value%10);value/=10; } while(value);
    while(count)*out++=digits[--count];
    *out=0;
    return out;
}

int pw_launcher_render(const PwLauncherScene *scene,const PwPresentTarget *target)
{
    if(!scene || !target || !target->pixels || (scene->count && !scene->items))
        return PW_ERR_PRECONDITION;
    if(target->width!=W || target->height!=H || target->stride<(uint32_t)W*4u ||
       target->stride%4u || (uint64_t)target->stride*H>target->bytes)return PW_ERR_MALFORMED;
    if(scene->selected!=PW_LAUNCHER_RENDER_NONE && scene->selected>=scene->count)
        return PW_ERR_PRECONDITION;
    for(uint32_t i=0;i<scene->count;i++)if(!scene->items[i].title)return PW_ERR_PRECONDITION;
    const Canvas canvas={target->pixels,target->stride,target->width,target->height};
    background(&canvas);title_bar(&canvas);
    if(!scene->count) {
        const char *empty="No application profiles found";
        text(&canvas,(W-text_width(empty,5))/2,480,empty,5,rgb(0xff,0xff,0xff),W);
    }
    uint32_t first=scene->selected==PW_LAUNCHER_RENDER_NONE?0:
        scene->selected/PW_LAUNCHER_RENDER_PAGE*PW_LAUNCHER_RENDER_PAGE;
    for(uint32_t i=first;i<scene->count && i-first<PW_LAUNCHER_RENDER_PAGE;i++) {
        uint32_t slot=i-first;
        int32_t x=TILES_X+(int32_t)(slot%3u)*(TILE_W+TILE_GAP);
        int32_t y=TILES_Y+(int32_t)(slot/3u)*(TILE_H+TILE_GAP+24);
        tile(&canvas,x,y,&scene->items[i],i==scene->selected);
    }
    if(scene->count>PW_LAUNCHER_RENDER_PAGE) {
        char page[32]="Page ";
        char *next=decimal(page+5,first/PW_LAUNCHER_RENDER_PAGE+1);
        *next++='/';
        decimal(next,scene->count/PW_LAUNCHER_RENDER_PAGE+!!(scene->count%PW_LAUNCHER_RENDER_PAGE));
        text(&canvas,W-48-text_width(page,3),TILES_Y+2*(TILE_H+TILE_GAP+24),page,3,
             rgb(0xff,0xff,0xff),W);
    }
    taskbar(&canvas,scene->status);
    return PW_OK;
}

PwLauncherAction pw_launcher_key_action(uint32_t vk)
{
    switch(vk) {
    case 0x70:return PW_LAUNCHER_ACTION_HELP; /* F1 */
    case 0x71:return PW_LAUNCHER_ACTION_SETTINGS; /* F2 */
    case 0x1b:return PW_LAUNCHER_ACTION_BACK; /* Escape */
    case 0x21:return PW_LAUNCHER_ACTION_PAGE_PREVIOUS;
    case 0x22:return PW_LAUNCHER_ACTION_PAGE_NEXT;
    case 0x25:return PW_LAUNCHER_ACTION_LEFT;     /* VK_LEFT */
    case 0x26:return PW_LAUNCHER_ACTION_UP;       /* VK_UP */
    case 0x27:return PW_LAUNCHER_ACTION_RIGHT;    /* VK_RIGHT */
    case 0x28:return PW_LAUNCHER_ACTION_DOWN;     /* VK_DOWN */
    case 0x0d:case 0x20:return PW_LAUNCHER_ACTION_CHOOSE;  /* VK_RETURN, VK_SPACE */
    default:return PW_LAUNCHER_ACTION_NONE;
    }
}

int pw_launcher_navigate(PwLauncherScene *scene,PwLauncherAction action,uint32_t choosable)
{
    if(!scene || !scene->count || scene->selected>=scene->count)return 0;
    switch(action) {
    case PW_LAUNCHER_ACTION_RIGHT:if(scene->selected+1<scene->count)scene->selected++;break;
    case PW_LAUNCHER_ACTION_LEFT:if(scene->selected)scene->selected--;break;
    case PW_LAUNCHER_ACTION_DOWN:if(scene->count-1-scene->selected>=3)scene->selected+=3;break;
    case PW_LAUNCHER_ACTION_UP:if(scene->selected>=3)scene->selected-=3;break;
    case PW_LAUNCHER_ACTION_PAGE_PREVIOUS:
        scene->selected=scene->selected>=PW_LAUNCHER_RENDER_PAGE?scene->selected-PW_LAUNCHER_RENDER_PAGE:0;break;
    case PW_LAUNCHER_ACTION_PAGE_NEXT:
        if(scene->count-1-scene->selected<PW_LAUNCHER_RENDER_PAGE)scene->selected=scene->count-1;
        else scene->selected+=PW_LAUNCHER_RENDER_PAGE;
        break;
    case PW_LAUNCHER_ACTION_CHOOSE:
        return scene->selected<choosable && scene->items && scene->items[scene->selected].available;
    default:break;
    }
    return 0;
}

PwLauncherAction pw_launcher_pad_action(uint32_t edges)
{
    if(edges&0x2000u)return PW_LAUNCHER_ACTION_BACK; /* Circle */
    if(edges&0x8u)return PW_LAUNCHER_ACTION_HELP; /* Options */
    if(edges&0x8000u)return PW_LAUNCHER_ACTION_SETTINGS; /* Square */
    if(edges&0x400u)return PW_LAUNCHER_ACTION_PAGE_PREVIOUS;
    if(edges&0x800u)return PW_LAUNCHER_ACTION_PAGE_NEXT;
    if(edges&0x80u)return PW_LAUNCHER_ACTION_LEFT;
    if(edges&0x20u)return PW_LAUNCHER_ACTION_RIGHT;
    if(edges&0x10u)return PW_LAUNCHER_ACTION_UP;
    if(edges&0x40u)return PW_LAUNCHER_ACTION_DOWN;
    if(edges&0x4000u)return PW_LAUNCHER_ACTION_CHOOSE;
    return PW_LAUNCHER_ACTION_NONE;
}
int pw_launcher_control(PwLauncherScene *scene,PwLauncherAction action,uint32_t choosable,int *help)
{
    if(!help)return 0;
    if(action==PW_LAUNCHER_ACTION_BACK){*help=0;return 0;}
    if(action==PW_LAUNCHER_ACTION_HELP){*help=!*help;return 0;}
    return *help?0:pw_launcher_navigate(scene,action,choosable);
}
int pw_launcher_render_controls(const PwLauncherScene *scene,int help,const PwPresentTarget *target)
{
    int result=pw_launcher_render(scene,target);
    if(result!=PW_OK || !help)return result;
    const Canvas canvas={target->pixels,target->stride,target->width,target->height};
    const Canvas *c=&canvas;
    rounded(c,226,174,1468,664,30,0x79bcff,0x79bcff);
    rounded(c,230,178,1460,656,26,0x20344f,0x1a2b43);
    text(c,286,224,"Controls",5,0xf4f7ff,1300);
    static const char *lines[]={
        "LIBRARY",
        "D-pad / arrows       Move between applications",
        "Cross / Enter        Open the selected application",
        "L1/R1 or PgUp/PgDn    Previous / next library page",
        "Options / F1         Show or hide this guide",
        "Circle / Escape      Back to library",
        "IN AN APPLICATION (default bindings)",
        "L3 + R3              Switch profile / mouse mode",
        "Touchpad / left stick  Move pointer in mouse mode",
        "Cross / Circle       Left / right click in mouse mode",
        "D-pad                Arrow keys in mouse mode",
        "Square / Triangle    Escape / Enter in mouse mode",
        "R1 / L1 + R1         Tab / Shift+Tab in mouse mode",
        "Options (release)    Next GDI window (mouse, same process)",
        "Options + Create held 1 second asks the app to close.",
        "Gamepad uses Xbox-compatible input, not native Sony HID.",
        "Release held controls after changing input mode."
    };
    for(size_t i=0;i<sizeof(lines)/sizeof(lines[0]);i++)
        text(c,286,304+(int32_t)i*30,lines[i],3,i==0 || i==6?0x79bcff:0xe2ebf8,1320);
    return PW_OK;
}

int pw_launcher_input_badge(const char *mode,const PwPresentTarget *target)
{
    if(!mode || !target || !target->pixels)return PW_ERR_PRECONDITION;
    if(target->width<160 || target->height<48 || target->width>INT32_MAX || target->height>INT32_MAX ||
       (uint64_t)target->width*4>target->stride || target->stride%4 ||
       (uint64_t)target->stride*target->height>target->bytes)return PW_ERR_MALFORMED;
    const Canvas canvas={target->pixels,target->stride,target->width,target->height};
    const Canvas *c=&canvas;
    int32_t scale=target->width>=1000?3:target->width>=640?2:1;
    int32_t width=scale*128,height=scale*20+12;
    int32_t margin=target->height>=96?12:4;
    if(height+2*margin>(int32_t)target->height){scale=1;height=32;width=128;}
    int32_t x=margin,y=(int32_t)target->height-height-margin;
    /* Fixed extent for every mode: replacing text never leaves an old suffix. */
    fill(c,x,y,width,height,0x10233b);
    fill(c,x,y,3,height,0x79bcff);
    text(c,x+10,y+5,mode,scale,0xf4f7ff,width-20);
    text(c,x+10,y+8+8*scale,"L3+R3: switch mode",scale,0x9ac9ff,width-20);
    return PW_OK;
}


int pw_launcher_render_settings(const PwLauncherScene *scene,int help,
                                const PwControllerSettings *settings,const char *profile_title,
                                int preset_refused,const PwPresentTarget *target)
{
    if(!settings || (settings->active && (!profile_title || settings->selected>=PW_CONTROLLER_ROWS)))
        return PW_ERR_PRECONDITION;
    int status=pw_launcher_render_controls(scene,help && !settings->active,target);
    if(status!=PW_OK)return status;
    const Canvas canvas={target->pixels,target->stride,target->width,target->height};
    const Canvas *c=&canvas;
    if(!settings->active) {
        if(help)text(c,286,856,"Square / F2: edit controller settings after closing this guide",3,0xf4f7ff,1320);
        else {
            rounded(c,140,TASKBAR_Y-28,W-280,84,22,0x3d536e,0x354b65);
            text(c,180,TASKBAR_Y-7,"D-pad: move   Cross: open   L1/R1: page",3,0xf4f7ff,W-360);
            text(c,180,TASKBAR_Y+25,"Square / F2: controller settings   Options / F1: controls",3,0xf4f7ff,W-360);
        }
        return PW_OK;
    }
    rounded(c,140,TASKBAR_Y-28,W-280,84,22,0x3d536e,0x354b65);
    text(c,180,TASKBAR_Y,"D-pad: select / adjust   Cross: confirm   Circle: cancel",3,0xf4f7ff,W-360);
    rounded(c,220,146,1480,794,30,0x79bcff,0x79bcff);
    rounded(c,224,150,1472,786,26,0x20344f,0x1a2b43);
    text(c,280,194,"Controller settings",5,0xf4f7ff,1360);
    text(c,280,248,profile_title,fit(profile_title,3,2,1360),0x9ac9ff,1360);
    text(c,280,292,"For this profile. Changes take effect on its next launch.",3,0xc1cfe2,1360);
    static const char *const labels[]={"Startup mode","Stick deadzone","Stick speed",
                                      "Touch sensitivity","Apply","Cancel"};
    const char *const hints[]={"PROFILE or MOUSE/UI","0-120 raw units","1-20000 pixels/second",
                              "25-400 percent","Save changed values","Discard this edit"};
    for(unsigned row=0;row<PW_CONTROLLER_ROWS;row++) {
        int32_t y=342+(int32_t)row*72;
        int selected=row==settings->selected;
        rounded(c,270,y-12,1380,60,12,selected?0x79bcff:0x2c415e,selected?0x79bcff:0x2c415e);
        uint32_t color=selected?0x10233b:0xf4f7ff;
        text(c,296,y,labels[row],3,color,460);
        if(row<PW_CONTROLLER_APPLY) {
            char number[16];const char *value=number;
            if(row==0)value=settings->draft.start_mode==PW_GAME_START_MOUSE?"MOUSE/UI":"PROFILE";
            else decimal(number,row==1?settings->draft.mouse_deadzone:row==2?settings->draft.mouse_speed:settings->draft.touch_speed);
            text(c,792,y,value,3,color,300);
        }
        text(c,1120,y,hints[row],2,selected?0x213e5c:0xc1cfe2,500);
    }
    const char *message=preset_refused?"Preset unavailable or refused. Showing profile fallback values.":
                                      "Left/right: adjust. L1/R1 or PgUp/PgDn: larger steps.";
    uint32_t color=preset_refused?0xf5c49b:0xc1cfe2;
    if(settings->error!=PW_OK) {
        message=settings->error==PW_ERR_STATE?"Profile changed on disk. Cancel and reopen before saving.":
            settings->error==PW_ERR_MALFORMED?"Invalid settings. Changes were not saved; cancel to reload.":
            settings->error==PW_ERR_LIMIT?"Profile is too large. Changes were not saved.":
            "Could not save. No changes saved. Retry Apply or Cancel.";
        color=0xf5c49b;
    }
    text(c,280,802,message,3,color,1360);
    text(c,280,852,"Up/down: select   Cross / Enter: confirm   Circle / Escape: cancel",3,0xf4f7ff,1360);
    int changed=settings->original.start_mode!=settings->draft.start_mode ||
        settings->original.mouse_deadzone!=settings->draft.mouse_deadzone ||
        settings->original.mouse_speed!=settings->draft.mouse_speed ||
        settings->original.touch_speed!=settings->draft.touch_speed;
    text(c,280,894,changed?"UNSAVED CHANGES. Apply saves for the next launch.":
                           "Current saved values. Only edits are written on Apply.",2,0xaebfd8,1360);
    return PW_OK;
}
