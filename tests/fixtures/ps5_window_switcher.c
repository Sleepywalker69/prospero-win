/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Exact driver bodies, real sink queue. USER is an inert boundary, not Wine. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include "windef.h"
#include "winbase.h"
#include "winuser.h"
#include "wingdi.h"
#include "wine/ps5/pw_wine_sink.h"
static unsigned checks;
#define CHECK(c) do { checks++; if (!(c)) {fprintf(stderr,"line %d: %s\n",__LINE__,#c);exit(1);} } while(0)
#define H(n) ((HWND)(uintptr_t)(n))
enum {PS5_MAX_WINDOWS=64,PS5_INPUT_BATCH=64};
struct window_surface {HWND hwnd; RECT rect,bounds; HRGN clip_region;};
struct window_rects {RECT window,client,visible;};
/* ACTUAL_DECLARATIONS */
static pthread_mutex_t screen_lock=PTHREAD_MUTEX_INITIALIZER,input_lock=PTHREAD_MUTEX_INITIALIZER;
static struct ps5_window windows[PS5_MAX_WINDOWS];
static UINT window_count,screen_width=8,screen_height=8;
static UINT64 window_generation;
static HWND input_owner;
static UINT64 input_generation;
static BYTE held_keys[256],held_buttons[3];
static UINT32 pixels[64],*screen=pixels;
static struct {HWND hwnd,root;DWORD style,exstyle,process,thread;BOOL live,service;} user[70];
static HWND foreground,focus_fail,kill_on_focus,click_focus,focus_redirect,walk_foreground;
static UINT restores,restore_mode,z_walks;
static BOOL z_loop;
enum { RESTORE_OK, RESTORE_VETO, RESTORE_DESTROY, RESTORE_REUSE, RESTORE_HIDE,
       RESTORE_DISABLE, RESTORE_FOREIGN_FOCUS, RESTORE_MODAL_FOCUS,
       RESTORE_FALSE_SUCCESS, RESTORE_REENTER, RESTORE_FOREIGN_PROCESS,
       RESTORE_TOOLWINDOW, RESTORE_FOREIGN_ROOT };
static BOOL NtUserShowWindow(HWND h,INT cmd);
static UINT order[70],order_count,presents,redraws,raises,focuses;
static int token,bad_bridge;
static struct {HWND hwnd;UINT type,code;DWORD flags;} sent[1024];
static UINT sends;
static unsigned boundary_space_held,boundary_refuse_up;
static char trace[2048];static UINT trace_n;
static void mark(char c){CHECK(trace_n+1<sizeof(trace));trace[trace_n++]=c;trace[trace_n]=0;}
static void no_screen_lock(void){CHECK(!pthread_mutex_trylock(&screen_lock));pthread_mutex_unlock(&screen_lock);}
static BOOL is_window(HWND h){return (uintptr_t)h<70 && user[(uintptr_t)h].live;}
static HWND get_desktop_window(void){return H(1);}
static uintptr_t bridge_current_token(void){return token;}
static BOOL bridge_service_window(HWND h){return (uintptr_t)h<70 && user[(uintptr_t)h].service;}
static HWND bridge_input_window(HWND h){return bad_bridge?NULL:h;}
static void bridge_window_destroyed(HWND h){(void)h;}
static HWND NtUserGetForegroundWindow(void){no_screen_lock();return foreground;}
static BOOL NtUserSetForegroundWindow(HWND h){no_screen_lock();mark('F');focuses++;if(h==focus_fail)return FALSE;foreground=focus_redirect?focus_redirect:h;if(h==kill_on_focus)user[(uintptr_t)h].live=FALSE;return TRUE;}
#define GetCurrentProcessId fixture_process_id
static DWORD fixture_process_id(void){return 9;}
#define GetCurrentThreadId fixture_thread_id
static DWORD fixture_thread_id(void){return 11;}
static DWORD NtUserGetWindowThread(HWND h,DWORD *pid){*pid=user[(uintptr_t)h].process;return is_window(h)?user[(uintptr_t)h].thread:0;}
static LONG NtUserGetWindowLongW(HWND h,INT idx){return idx==GWL_STYLE?user[(uintptr_t)h].style:user[(uintptr_t)h].exstyle;}
static HWND NtUserGetAncestor(HWND h,UINT kind){if(!is_window(h))return NULL;return kind==GA_PARENT?H(1):user[(uintptr_t)h].root;}
static HWND NtUserGetWindowRelative(HWND h,UINT rel){UINT i=0;z_walks++;if(walk_foreground){foreground=walk_foreground;walk_foreground=NULL;}if(z_loop)return H(69);if(rel==GW_CHILD)return order_count?H(order[0]):NULL;for(;i<order_count;i++)if(H(order[i])==h)break;return i+1<order_count?H(order[i+1]):NULL;}
static BOOL NtUserSetWindowPos(HWND h,HWND after,INT x,INT y,INT w,INT height,UINT flags){no_screen_lock();CHECK(after==HWND_TOP&&!x&&!y&&!w&&!height);CHECK(flags==(SWP_NOMOVE|SWP_NOSIZE|SWP_NOACTIVATE));raises++;mark('Z');return TRUE;}
static BOOL NtUserRedrawWindow(HWND h,const RECT *r,HRGN region,UINT flags){no_screen_lock();redraws++;mark('R');return TRUE;}
static UINT NtUserMapVirtualKeyEx(UINT code,UINT type,HKL layout){return code^0x5a;}
static HKL NtUserGetKeyboardLayout(DWORD thread){return (HKL)(uintptr_t)1;}
static void NtUserSendHardwareInput(HWND h,UINT a,const INPUT *in,UINT b){no_screen_lock();if(in->type==INPUT_KEYBOARD&&in->ki.wVk==VK_SPACE){if(!(in->ki.dwFlags&KEYEVENTF_KEYUP))boundary_space_held=1;else if(!boundary_refuse_up)boundary_space_held=0;}CHECK(sends<1024&&h);sent[sends].hwnd=h;sent[sends].type=in->type;sent[sends].code=in->ki.wVk;sent[sends++].flags=in->type==INPUT_KEYBOARD?in->ki.dwFlags:in->mi.dwFlags;mark(in->type==INPUT_KEYBOARD?(in->ki.dwFlags&KEYEVENTF_KEYUP?'u':'d'):(in->mi.dwFlags&(MOUSEEVENTF_LEFTUP|MOUSEEVENTF_RIGHTUP|MOUSEEVENTF_MIDDLEUP)?'u':'d'));if(click_focus&&in->type==INPUT_MOUSE&&(in->mi.dwFlags&MOUSEEVENTF_LEFTDOWN))foreground=click_focus;}
static void move_cursor(HWND h,INT x,INT y){CHECK(h==foreground);mark('M');}
static BOOL intersect_rect(RECT *out,const RECT *a,const RECT *b){RECT r={a->left>b->left?a->left:b->left,a->top>b->top?a->top:b->top,a->right<b->right?a->right:b->right,a->bottom<b->bottom?a->bottom:b->bottom};if(r.left>=r.right||r.top>=r.bottom){memset(out,0,sizeof(*out));return FALSE;}*out=r;return TRUE;}
static void clear_screen_rect(const RECT *r){(void)r;}
static void present_screen(void){presents++;}
static int real_next(struct ps5_input *e){PwWineInput input;if(!pw_wine_next_input(&input))return 0;memcpy(e,&input,sizeof(input));return 1;}
static int (*next_input)(struct ps5_input*)=real_next;
static int (*input_fd)(void)=NULL;
/* ACTUAL_FUNCTIONS */
static void reset(void){boundary_space_held=boundary_refuse_up=0;PwWineInput e;while(pw_wine_next_input(&e)){}memset(windows,0,sizeof(windows));memset(user,0,sizeof(user));memset(held_keys,0,sizeof(held_keys));memset(held_buttons,0,sizeof(held_buttons));memset(pixels,0,sizeof(pixels));window_count=0;window_generation=0;input_owner=NULL;input_generation=0;foreground=focus_fail=kill_on_focus=click_focus=focus_redirect=walk_foreground=NULL;restores=restore_mode=z_walks=0;z_loop=FALSE;order_count=presents=redraws=raises=focuses=sends=trace_n=0;trace[0]=0;token=bad_bridge=0;}
static void add(UINT n,UINT root,DWORD style,DWORD exstyle){user[n].hwnd=H(n);user[n].root=H(root);user[n].style=style;user[n].exstyle=exstyle;user[n].process=9;user[n].thread=11;user[n].live=TRUE;order[order_count++]=n;struct window_rects r={.visible={0,0,8,8}};ps5_WindowPosChanged(H(n),NULL,NULL,0,&r,NULL);}
static BOOL NtUserShowWindow(HWND h,INT cmd)
{
    no_screen_lock();CHECK(cmd==SW_RESTORE);CHECK(is_window(h));
    CHECK(user[(uintptr_t)h].process==9 && user[(uintptr_t)h].thread==11);
    CHECK((user[(uintptr_t)h].style&(WS_VISIBLE|WS_MINIMIZE|WS_DISABLED))==(WS_VISIBLE|WS_MINIMIZE));
    restores++;mark('S');
    if(restore_mode==RESTORE_VETO)return TRUE; /* visible, but WM_QUERYOPEN veto */
    if(restore_mode==RESTORE_REENTER)CHECK(!ps5_ProcessEvents(0));
    if(restore_mode==RESTORE_DESTROY||restore_mode==RESTORE_REUSE)
    {
        user[(uintptr_t)h].live=FALSE;ps5_DestroyWindow(h);
        if(restore_mode==RESTORE_REUSE)add((UINT)(uintptr_t)h,(UINT)(uintptr_t)h,WS_VISIBLE,0);
        return TRUE;
    }
    user[(uintptr_t)h].style&=~WS_MINIMIZE;
    if(restore_mode==RESTORE_HIDE)user[(uintptr_t)h].style&=~WS_VISIBLE;
    if(restore_mode==RESTORE_DISABLE)user[(uintptr_t)h].style|=WS_DISABLED;
    if(restore_mode==RESTORE_FOREIGN_PROCESS)user[(uintptr_t)h].process=99;
    if(restore_mode==RESTORE_TOOLWINDOW)user[(uintptr_t)h].exstyle|=WS_EX_TOOLWINDOW;
    if(restore_mode==RESTORE_FOREIGN_ROOT)user[(uintptr_t)h].root=H(68);
    if(restore_mode==RESTORE_FOREIGN_FOCUS)foreground=H(68);
    else if(restore_mode==RESTORE_MODAL_FOCUS){add(4,(UINT)(uintptr_t)h,WS_VISIBLE,0);foreground=H(4);user[(uintptr_t)h].style|=WS_DISABLED;}
    else foreground=h;
    return restore_mode!=RESTORE_FALSE_SUCCESS;
}
static void post(UINT type,UINT code,INT x,UINT down){PwWineInput e={type,code,x,0,down};CHECK(!pw_wine_post_input(&e));}
static void basic(void){reset();add(2,2,WS_VISIBLE,0);add(3,3,WS_VISIBLE,0);foreground=H(2);post(1,VK_UP,0,1);post(3,0,0,1);post(4,0,1,1);post(1,VK_RETURN,0,1);CHECK(ps5_ProcessEvents(0));CHECK(foreground==H(3)&&focuses==1&&raises==1);CHECK(sends==5);CHECK(sent[2].hwnd==H(2)&&sent[2].flags==(KEYEVENTF_KEYUP|KEYEVENTF_EXTENDEDKEY));CHECK(sent[3].hwnd==H(2)&&sent[3].flags==MOUSEEVENTF_LEFTUP);CHECK(sent[4].hwnd==H(3));CHECK(strstr(trace,"dduuFZRd"));post(4,0,-1,1);CHECK(ps5_ProcessEvents(0)&&foreground==H(2));}
static void modal(void){reset();add(4,2,WS_VISIBLE,0);add(2,2,WS_VISIBLE|WS_DISABLED,0);add(3,3,WS_VISIBLE,0);foreground=H(3);post(4,0,1,1);CHECK(ps5_ProcessEvents(0));CHECK(foreground==H(4));post(4,0,1,1);CHECK(ps5_ProcessEvents(0)&&foreground==H(3));}
static void filters(void){reset();add(2,2,WS_VISIBLE,0);add(3,3,WS_VISIBLE,WS_EX_NOACTIVATE);add(4,4,WS_VISIBLE,WS_EX_TOOLWINDOW);add(5,5,WS_VISIBLE|WS_MINIMIZE,0);user[5].thread=12;add(6,6,WS_VISIBLE|WS_DISABLED,0);add(7,7,WS_VISIBLE,0);user[7].service=TRUE;add(8,8,WS_VISIBLE,0);user[8].process=99;add(9,9,WS_VISIBLE,0);foreground=H(2);post(4,0,1,1);CHECK(ps5_ProcessEvents(0)&&foreground==H(9));}
static void destruction(void){reset();add(2,2,WS_VISIBLE,0);add(3,3,WS_VISIBLE,0);foreground=H(2);post(1,VK_SHIFT,0,1);CHECK(ps5_ProcessEvents(0));struct ps5_window_choice stale={H(2),H(2),windows[0].generation};user[2].live=FALSE;ps5_DestroyWindow(H(2));add(2,2,WS_VISIBLE,0);CHECK(!window_choice_live(&stale));CHECK(windows[0].hwnd==H(3)&&windows[1].hwnd==H(2));foreground=H(3);post(1,VK_RETURN,0,1);CHECK(ps5_ProcessEvents(0));CHECK(sends==2&&sent[1].hwnd==H(3));}
static void external_focus(void){reset();add(2,2,WS_VISIBLE,0);add(3,3,WS_VISIBLE,0);foreground=H(2);click_focus=H(3);post(3,0,0,1);post(1,VK_RETURN,0,1);CHECK(ps5_ProcessEvents(0));CHECK(sends==3&&sent[1].hwnd==H(2)&&sent[1].flags==MOUSEEVENTF_LEFTUP&&sent[2].hwnd==H(3));}
static void idle_focus(void){reset();add(2,2,WS_VISIBLE,0);add(3,3,WS_VISIBLE,0);foreground=H(2);post(1,VK_UP,0,1);CHECK(ps5_ProcessEvents(0));foreground=H(3);CHECK(ps5_ProcessEvents(0));CHECK(sends==2&&sent[1].hwnd==H(2)&&sent[1].flags==(KEYEVENTF_KEYUP|KEYEVENTF_EXTENDEDKEY));CHECK(!ps5_ProcessEvents(0));}
static void failure(void){reset();add(2,2,WS_VISIBLE,0);add(3,3,WS_VISIBLE,0);foreground=H(2);focus_fail=H(3);post(1,VK_SHIFT,0,1);post(4,0,1,1);CHECK(ps5_ProcessEvents(0));CHECK(foreground==H(2)&&sends==2&&!held_keys[VK_SHIFT]&&!raises);token=1;post(4,0,1,1);CHECK(!ps5_ProcessEvents(0));token=0;CHECK(!pthread_mutex_lock(&input_lock));CHECK(!ps5_ProcessEvents(0));pthread_mutex_unlock(&input_lock);CHECK(ps5_ProcessEvents(0));}
static void sink_validation(void){PwWineInput out,e={4,0,1,0,1};reset();CHECK(!pw_wine_post_input(&e)&&pw_wine_next_input(&out)&&!memcmp(&e,&out,sizeof(e)));e.x=-1;CHECK(!pw_wine_post_input(&e)&&pw_wine_next_input(&out));e.x=0;CHECK(pw_wine_post_input(&e)==-1);e.x=1;e.code=1;CHECK(pw_wine_post_input(&e)==-1);e.code=0;e.y=1;CHECK(pw_wine_post_input(&e)==-1);e.y=0;e.down=0;CHECK(pw_wine_post_input(&e)==-1);CHECK(!pw_wine_next_input(&out));}
static void clipping(void){reset();add(2,2,WS_VISIBLE,0);struct ps5_surface s={.base={.hwnd=H(2),.rect={0,0,8,8}}};RECT clip={0,0,4,8},all={0,0,8,8};BITMAPINFO info={.bmiHeader={.biWidth=8}};UINT32 color[64];for(UINT i=0;i<64;i++)color[i]=0xaabbccdd; s.base.clip_region=(HRGN)(uintptr_t)1;ps5_surface_set_clip(&s.base,&clip,1);CHECK(EqualRect(&s.base.bounds,&all));CHECK(ps5_surface_flush(&s.base,&all,&all,&info,color,FALSE,NULL,NULL));for(UINT i=0;i<64;i++)CHECK(pixels[i]==((i%8)<4?0xaabbccdd:0));memset(pixels,0,sizeof(pixels));ps5_surface_set_clip(&s.base,NULL,0);CHECK(ps5_surface_flush(&s.base,&all,&all,&info,color,FALSE,NULL,NULL));for(UINT i=0;i<64;i++)CHECK(!pixels[i]);s.base.clip_region=0;ps5_surface_set_clip(&s.base,NULL,0);CHECK(ps5_surface_flush(&s.base,&all,&all,&info,color,FALSE,NULL,NULL));for(UINT i=0;i<64;i++)CHECK(pixels[i]==0xaabbccdd);ps5_surface_destroy(&s.base);}
static void offset_clipping(void)
{
    reset();add(2,2,WS_VISIBLE,0);
    struct ps5_surface s={.base={.hwnd=H(2),.rect={2,3,6,7},.clip_region=(HRGN)(uintptr_t)1}};
    RECT dirty={0,0,4,4}, clip={3,4,5,6};BITMAPINFO info={.bmiHeader={.biWidth=4}};
    UINT32 color[16];for(UINT i=0;i<16;i++)color[i]=0x100+i;
    ps5_surface_set_clip(&s.base,&clip,1);CHECK(EqualRect(&s.base.bounds,&dirty));
    CHECK(ps5_surface_flush(&s.base,&s.base.rect,&dirty,&info,color,FALSE,NULL,NULL));
    for(UINT y=0;y<8;y++)for(UINT x=0;x<8;x++)
        CHECK(pixels[y*8+x]==(x>=3&&x<5&&y>=4&&y<6?0x100+(y-3)*4+x-2:0));
    ps5_surface_destroy(&s.base);
}
static void hidden_and_destroyed_activation(void)
{
    reset();add(2,2,WS_VISIBLE,0);add(3,3,WS_VISIBLE,0);add(4,4,WS_VISIBLE,0);
    struct window_rects r={.visible={0,0,8,8}};
    user[3].style=0;ps5_WindowPosChanged(H(3),NULL,NULL,0,&r,NULL);
    foreground=H(2);post(4,0,1,1);CHECK(ps5_ProcessEvents(0));CHECK(foreground==H(4));
    foreground=H(2);kill_on_focus=H(4);raises=0;post(4,0,1,1);
    CHECK(ps5_ProcessEvents(0));CHECK(!raises&&!is_window(H(4)));
}
static void registry_limit(void)
{
    reset();for(UINT i=2;i<68;i++)add(i,i,WS_VISIBLE,0);
    CHECK(window_count==PS5_MAX_WINDOWS);foreground=H(65);post(4,0,1,1);
    CHECK(ps5_ProcessEvents(0));CHECK(foreground==H(2));
}
static void minimized_restore(void)
{
    reset();add(2,2,WS_VISIBLE,0);add(3,3,WS_VISIBLE|WS_MINIMIZE,0);foreground=H(2);
    post(1,VK_UP,0,1);post(3,0,0,1);post(4,0,1,1);post(1,VK_RETURN,0,1);
    CHECK(ps5_ProcessEvents(0));CHECK(restores==1&&foreground==H(3)&&raises==1);
    CHECK(!(user[3].style&WS_MINIMIZE));CHECK(sends==5&&sent[2].hwnd==H(2)&&sent[3].hwnd==H(2)&&sent[4].hwnd==H(3));
    CHECK(strstr(trace,"dduuSFZRd"));
    post(4,0,-1,1);CHECK(ps5_ProcessEvents(0)&&foreground==H(2)&&restores==1);
    post(4,0,1,1);CHECK(ps5_ProcessEvents(0)&&foreground==H(3)&&restores==1);
    reset();add(2,2,WS_VISIBLE|WS_MINIMIZE,0);foreground=H(2);post(4,0,1,1);
    CHECK(ps5_ProcessEvents(0)&&restores==1&&foreground==H(2));
}
static void minimized_filters_and_modal(void)
{
    reset();add(2,2,WS_VISIBLE,0);add(3,3,WS_VISIBLE|WS_MINIMIZE,0);user[3].thread=12;
    add(4,4,WS_VISIBLE|WS_MINIMIZE|WS_DISABLED,0);add(5,2,WS_VISIBLE|WS_MINIMIZE,0);
    add(6,6,WS_VISIBLE|WS_MINIMIZE,WS_EX_NOACTIVATE);add(7,7,WS_VISIBLE|WS_MINIMIZE,WS_EX_TOOLWINDOW);
    add(8,8,WS_VISIBLE|WS_MINIMIZE,0);user[8].process=99;add(9,9,WS_VISIBLE|WS_MINIMIZE,0);user[9].service=TRUE;
    add(10,10,WS_MINIMIZE,0);add(11,11,WS_VISIBLE,0);user[11].thread=12;
    foreground=H(2);post(4,0,1,1);CHECK(ps5_ProcessEvents(0));CHECK(foreground==H(11)&&!restores);
    reset();add(4,3,WS_VISIBLE,0);add(3,3,WS_VISIBLE|WS_MINIMIZE|WS_DISABLED,0);add(2,2,WS_VISIBLE,0);
    foreground=H(2);post(4,0,1,1);CHECK(ps5_ProcessEvents(0));CHECK(foreground==H(4)&&!restores);
}
static void restore_callbacks(void)
{
    for(UINT mode=RESTORE_VETO;mode<=RESTORE_FOREIGN_ROOT;mode++)
    {
        reset();add(2,2,WS_VISIBLE,0);add(3,3,WS_VISIBLE|WS_MINIMIZE,0);add(5,5,WS_VISIBLE,0);
        user[68].live=TRUE;user[68].process=99;user[68].thread=99;user[68].root=H(68);
        foreground=H(2);restore_mode=mode;post(1,VK_SHIFT,0,1);post(4,0,1,1);
        CHECK(ps5_ProcessEvents(0));CHECK(restores==1&&sends==2&&!held_keys[VK_SHIFT]);
        if(mode==RESTORE_FALSE_SUCCESS||mode==RESTORE_REENTER)CHECK(foreground==H(3)&&focuses==1&&raises==1);
        else CHECK(!focuses&&!raises); /* Never try another family after restore callbacks. */
        if(mode==RESTORE_VETO)CHECK((user[3].style&WS_MINIMIZE)&&foreground==H(2));
        if(mode==RESTORE_FOREIGN_FOCUS)CHECK(foreground==H(68));
        if(mode==RESTORE_MODAL_FOCUS)CHECK(foreground==H(4));
    }
}
static void unrelated_foreground_and_bounded_walk(void)
{
    reset();add(2,2,WS_VISIBLE,0);add(3,3,WS_VISIBLE|WS_MINIMIZE,0);
    user[68].live=TRUE;user[68].process=99;user[68].thread=99;user[68].root=H(68);
    foreground=H(68);post(4,0,1,1);CHECK(ps5_ProcessEvents(0));CHECK(!focuses&&!restores&&foreground==H(68));
    foreground=H(2);walk_foreground=H(68);post(4,0,1,1);CHECK(ps5_ProcessEvents(0));CHECK(!focuses&&!restores&&foreground==H(68));
    foreground=H(2);z_loop=TRUE;z_walks=0;post(4,0,1,1);CHECK(ps5_ProcessEvents(0));
    CHECK(z_walks<=2*(PS5_MAX_WINDOWS*4+1)&&!focuses&&!restores);
    z_loop=FALSE;focus_redirect=H(68);user[3].style&=~WS_MINIMIZE;post(4,0,1,1);
    CHECK(ps5_ProcessEvents(0));CHECK(foreground==H(68)&&!raises&&!restores);
}

/* Characterize actual legacy bodies, not the proposed tagged contract.
 * USER mock can refuse an UP. A send attempt is intentionally not a receipt. */
static void input_receipt_gaps(void)
{
    reset();add(2,2,WS_VISIBLE,0);add(3,3,WS_VISIBLE,0);foreground=H(2);
    post(1,VK_SPACE,0,1);
    CHECK(!boundary_space_held&&!held_keys[VK_SPACE]); /* only admitted */
    CHECK(ps5_ProcessEvents(0)&&boundary_space_held&&held_keys[VK_SPACE]);
    boundary_refuse_up=1;foreground=H(3);
    CHECK(ps5_ProcessEvents(0));
    CHECK(boundary_space_held&&!held_keys[VK_SPACE]&&!input_owner);
    /* Current release bookkeeping has no truthful completion receipt. */
    CHECK(sends==2&&sent[1].hwnd==H(2));
    boundary_refuse_up=0;CHECK(!ps5_ProcessEvents(0)&&boundary_space_held);

    reset();add(2,2,WS_VISIBLE,0);foreground=H(2);
    /* Two conceptual producers share one untagged key. The legacy sink
     * cannot express provenance: A-UP clears B's still-held contribution. */
    post(1,VK_SPACE,0,1);post(1,VK_SPACE,0,1);post(1,VK_SPACE,0,0);
    CHECK(ps5_ProcessEvents(0)&&sends==3&&!boundary_space_held);
    CHECK(!held_keys[VK_SPACE]);
    puts("actual driver receipt/provenance gaps characterized; USER boundary mocked");
}

int main(void){input_receipt_gaps();minimized_restore();minimized_filters_and_modal();restore_callbacks();unrelated_foreground_and_bounded_walk();basic();modal();filters();destruction();external_focus();idle_focus();failure();sink_validation();clipping();offset_clipping();hidden_and_destroyed_activation();registry_limit();printf("PS5 window switcher: %u source-body / real-sink checks passed (inert USER boundaries)\n",checks);return 0;}
