/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Exact extracted USER bodies; server, window state and callbacks are mocked. */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <setjmp.h>
#include "windef.h"
#include "winbase.h"
#include "winuser.h"
#include "winternl.h"
#ifndef OMIT_PS5_DRIVER
#define WINE_PS5_USER_DRIVER 1
#endif
#define WND_OTHER_PROCESS ((WND *)(uintptr_t)1)
#define WND_DESKTOP ((WND *)(uintptr_t)2)
#define NTUSER_OBJ_WINDOW 1
#define COORDS_PARENT 0
#define SET_USER_OBJECT_GET_FULL_NAME 1
/* HAS_CACHE */
static unsigned checks;
#define CHECK(x) do{++checks;if(!(x)){fprintf(stderr,"check %u line %d failed: %s\n",checks,__LINE__,#x);exit(1);}}while(0)
#define HW(n) ((HWND)(uintptr_t)(n))
#define DESKTOP HW(0x10024)
#define MESSAGE HW(0x10026)
#define WINDOW HW(0x1003e)
typedef uint32_t user_handle_t;
typedef struct {HWND parent;} WND;
struct ratio {int num,den;};
struct window_rects {RECT window,client,visible;};
struct user_thread_info {HWND top_window,msg_window;BOOL desktop_cache_only;};
struct obj_locator {int id,offset;};
struct session_thread_data {void*shared_desktop;int shared_foreground[4];};
static struct user_thread_info info[2];static int thread;
static struct session_thread_data session;
static WND window={DESKTOP};
static struct {int server_calls,cache_queries,full_queries,server_fail,empty_reply,partial_reply,full_fail,full_partial,held,object_lookups,driver_calls,builtin_calls,service_calls;int init_calls,query_calls,close_calls,switch_fail,virtual_samples,update_calls;int rect_fail,rect_calls,map_calls,present_calls,client_calls,point_calls,dpi_calls;int present_ok,client_ok,missing_window;DWORD last_error;} m;
static jmp_buf fallback_boundary;static int expect_fallback,fallback_entries;
static struct user_thread_info*get_user_thread_info(void){return &info[thread];}
static struct session_thread_data*get_session_thread_data(void){return &session;}
static HWND get_desktop_window(void);
static HWND WINAPI NtUserGetAncestor(HWND,UINT);
static void desktop_callback(HWND hwnd){CHECK(hwnd==DESKTOP&&!info[thread].desktop_cache_only);m.driver_calls++;CHECK(get_desktop_window()==DESKTOP);}
static void register_builtin_classes(void){CHECK(!info[thread].desktop_cache_only);m.builtin_calls++;CHECK(get_desktop_window()==DESKTOP);}
static struct {void(*pSetDesktopWindow)(HWND);} driver={desktop_callback},*user_driver=&driver;
#define TRACE(...) ((void)0)
#define TRACE_(channel) fake_log
#define ERR_(channel) fake_log
static void fake_log(const char*fmt,...){(void)fmt;}
struct response {user_handle_t top_window,msg_window,parent;int count;struct obj_locator locator;};
struct request {const char*kind;int force;uintptr_t handle;unsigned flags;struct response*response;};
#define SERVER_START_REQ(request_kind) do {struct response response_storage={0},*reply=&response_storage;struct request request_storage={.kind=#request_kind,.response=reply},*req=&request_storage;
#define SERVER_END_REQ }while(0)
static int wine_server_call(struct request*r){
 CHECK(!m.held);m.server_calls++;
 if(!strcmp(r->kind,"get_desktop_window")){
  if(!r->force)m.cache_queries++;else m.full_queries++;
  if(m.server_fail||(r->force&&m.full_fail))return 1;
  if(!m.empty_reply){r->response->top_window=(user_handle_t)(uintptr_t)DESKTOP;r->response->msg_window=((!r->force&&m.partial_reply)||(r->force&&m.full_partial))?0:(user_handle_t)(uintptr_t)MESSAGE;}
  return 0;
 }
 if(!strcmp(r->kind,"set_thread_desktop")){r->response->locator=(struct obj_locator){2,3};return m.switch_fail;}
 CHECK(0);return 1;
}
#define wine_server_call_err wine_server_call
#define wine_server_ptr_handle(x) ((HWND)(uintptr_t)(x))
#define wine_server_user_handle(x) ((uintptr_t)(x))
#define wine_server_obj_handle(x) ((uintptr_t)(x))
#define wine_server_set_reply(a,b,c) ((void)(a),(void)(b),(void)(c))
static size_t wine_server_reply_size(struct response*r){(void)r;return 0;}
static WND*get_user_handle_ptr(HWND h,int type){CHECK(type==NTUSER_OBJ_WINDOW);m.object_lookups++;if(h==WINDOW&&!m.missing_window){CHECK(!m.held);m.held++;return &window;}return NULL;}
static void release_win_ptr(WND*w){CHECK(w==&window&&m.held==1);m.held--;}
static HWND get_full_window_handle(HWND h){return h;}
static HWND get_parent(HWND h){return h==WINDOW?DESKTOP:0;}
static void fake_last_error(DWORD e){m.last_error=e;}
#define RtlSetLastWin32Error fake_last_error
static BOOL is_service_process(void){m.service_calls++;return FALSE;}
static TEB64*NtCurrentTeb64(void){return NULL;}
static RTL_USER_PROCESS_PARAMETERS parameters;static PEB peb={.ProcessParameters=&parameters};
static PEB*fake_peb(void){return &peb;}
#define RtlGetCurrentPeb fake_peb
static void fake_string(UNICODE_STRING*s,const WCHAR*w){(void)s;(void)w;CHECK(0);}
#define RtlInitUnicodeString fake_string
static HDESK fake_desktop(DWORD tid){CHECK(tid==1);if(expect_fallback){fallback_entries++;longjmp(fallback_boundary,1);}CHECK(0);return NULL;}
#define NtUserGetThreadDesktop fake_desktop
#define GetCurrentThreadId() 1
static NTSTATUS fake_system(SYSTEM_INFORMATION_CLASS c,void*i,ULONG il,void*o,ULONG ol,ULONG*r){(void)c;(void)i;(void)il;(void)o;(void)ol;(void)r;m.query_calls++;CHECK(0);return -1;}
#define NtQuerySystemInformationEx fake_system
static NTSTATUS fake_create(HANDLE*a,HANDLE*b,ACCESS_MASK c,ACCESS_MASK d,OBJECT_ATTRIBUTES*e,OBJECT_ATTRIBUTES*f,ULONG g,ULONG h,RTL_USER_PROCESS_PARAMETERS*i,PS_CREATE_INFO*j,PS_ATTRIBUTE_LIST*k){(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;(void)j;(void)k;m.init_calls++;CHECK(0);return -1;}
#define NtCreateUserProcess fake_create
static NTSTATUS fake_resume(HANDLE t,ULONG*c){(void)t;(void)c;CHECK(0);return 0;}
#define NtResumeThread fake_resume
static DWORD NtUserWaitForInputIdle(HANDLE p,DWORD ms,BOOL b){(void)p;(void)ms;(void)b;CHECK(0);return 0;}
static NTSTATUS fake_close(HANDLE h){(void)h;m.close_calls++;CHECK(0);return 0;}
#define NtClose fake_close
static BOOL is_virtual_desktop(void){return m.virtual_samples++!=0;}
static void*find_shared_session_object(int id,int off){CHECK(id==2&&off==3);return (void*)(uintptr_t)55;}
static void update_display_cache(BOOL b){CHECK(b);m.update_calls++;}
static struct ratio get_dpi_for_window(HWND h){(void)h;return (struct ratio){1,1};}
static BOOL get_window_rects(HWND h,int rel,struct window_rects*r,struct ratio dpi){(void)dpi;CHECK(rel==COORDS_PARENT);m.rect_calls++;if(!h||m.rect_fail){*r=(struct window_rects){.client={99,98,199,198},.visible={20,30,220,230}};return FALSE;}r->window=(RECT){0,0,660,510};r->client=(RECT){10,20,650,500};r->visible=(RECT){0,0,660,510};return TRUE;}
static struct window_rects map_window_rects_virt_to_raw(struct window_rects r,struct ratio d){(void)d;m.map_calls++;return r;}
static BOOL get_present_rect(HWND h,RECT*r,struct ratio dpi){(void)h;(void)dpi;m.present_calls++;if(!m.present_ok)return FALSE;*r=(RECT){30,40,130,140};return TRUE;}
static BOOL get_client_rect(HWND h,RECT*r,struct ratio dpi){(void)h;(void)dpi;m.client_calls++;if(!m.client_ok)return FALSE;*r=(RECT){0,0,100,100};return TRUE;}
static void map_window_points(HWND a,HWND b,POINT*p,int n,struct ratio d){(void)a;(void)b;(void)d;CHECK(n==2);m.point_calls++;for(int i=0;i<n;i++){p[i].x+=5;p[i].y+=6;}}
static void get_win_monitor_dpi(HWND h,struct ratio*d){(void)h;m.dpi_calls++;*d=(struct ratio){1,1};}
static RECT map_dpi_rect(RECT r,struct ratio a,struct ratio b){(void)a;(void)b;return r;}
static void fake_offset(RECT*r,int x,int y){r->left+=x;r->right+=x;r->top+=y;r->bottom+=y;}
#define OffsetRect fake_offset
static void fake_empty(RECT*r){memset(r,0,sizeof(*r));}
#define SetRectEmpty fake_empty
/* ACTUAL_FUNCTIONS */
static void reset(void){memset(&m,0,sizeof(m));memset(info,0,sizeof(info));memset(&session,0,sizeof(session));thread=0;expect_fallback=0;fallback_entries=0;m.present_ok=1;m.client_ok=1;window.parent=DESKTOP;}
static int empty(RECT r){return !r.left&&!r.top&&!r.right&&!r.bottom;}
int main(int argc,char**argv){const char*which=argc>1?argv[1]:"all";
 if(!strcmp(which,"desktop-nonps5")){
  reset();CHECK(!NtUserGetAncestor(WINDOW,GA_ROOT));CHECK(!m.cache_queries&&!m.full_queries&&!m.held&&!m.driver_calls&&!m.builtin_calls);puts("non-PS5 ancestor route unchanged");return 0;
 }
 if(!strcmp(which,"all")||!strcmp(which,"desktop-root")){
  reset();CHECK(NtUserGetAncestor(WINDOW,GA_ROOT)==WINDOW);CHECK(m.cache_queries==1&&!m.full_queries&&!m.held&&!m.driver_calls&&!m.builtin_calls);
  CHECK(info[0].desktop_cache_only&&info[0].top_window==DESKTOP&&info[0].msg_window==MESSAGE);
  CHECK(NtUserGetAncestor(WINDOW,GA_ROOT)==WINDOW&&m.cache_queries==1);
  CHECK(get_desktop_window()==DESKTOP);CHECK(m.driver_calls==1&&m.builtin_calls==1&&!info[0].desktop_cache_only&&!m.full_queries);
  CHECK(get_desktop_window()==DESKTOP&&m.driver_calls==1&&m.builtin_calls==1);
  thread=1;CHECK(NtUserGetAncestor(WINDOW,GA_ROOT)==WINDOW&&m.cache_queries==2);CHECK(info[1].desktop_cache_only&&!info[0].desktop_cache_only);
 }
 if(!strcmp(which,"all")||!strcmp(which,"desktop-cache")){
#if HAS_CACHE
  reset();m.server_fail=1;cache_thread_desktop_windows();CHECK(!info[0].top_window&&!info[0].desktop_cache_only&&m.cache_queries==1);m.server_fail=0;cache_thread_desktop_windows();CHECK(info[0].desktop_cache_only&&m.cache_queries==2);
  reset();m.empty_reply=1;cache_thread_desktop_windows();CHECK(!info[0].top_window&&!info[0].desktop_cache_only);m.empty_reply=0;cache_thread_desktop_windows();CHECK(info[0].top_window==DESKTOP&&m.cache_queries==2);
#endif
  reset();CHECK(get_desktop_window()==DESKTOP);CHECK(m.full_queries==1&&m.service_calls==1&&m.driver_calls==1&&m.builtin_calls==1&&!m.init_calls&&!m.query_calls&&!m.close_calls);
  CHECK(get_desktop_window()==DESKTOP&&m.full_queries==1);
  /* Fresh failure still enters the original fallback. Stop at its first mocked boundary. */
  reset();m.full_fail=1;expect_fallback=1;if(!setjmp(fallback_boundary)){get_desktop_window();CHECK(0);}
  CHECK(fallback_entries==1&&m.full_queries==1&&!info[0].top_window&&!info[0].msg_window&&!m.driver_calls&&!m.builtin_calls&&!m.init_calls);
 }
 if(!strcmp(which,"all")||!strcmp(which,"desktop-partial")){
#if HAS_CACHE
  reset();m.partial_reply=1;cache_thread_desktop_windows();CHECK(info[0].top_window==DESKTOP&&!info[0].msg_window&&info[0].desktop_cache_only);CHECK(!m.driver_calls&&!m.builtin_calls);
  CHECK(get_desktop_window()==DESKTOP);CHECK(m.full_queries==1&&info[0].msg_window==MESSAGE);CHECK(m.driver_calls==1&&m.builtin_calls==1&&!info[0].desktop_cache_only);
  reset();m.partial_reply=1;cache_thread_desktop_windows();m.full_fail=1;CHECK(get_desktop_window()==DESKTOP);CHECK(m.full_queries==1&&!info[0].msg_window&&!info[0].desktop_cache_only);CHECK(m.driver_calls==1&&m.builtin_calls==1);CHECK(get_desktop_window()==DESKTOP&&m.full_queries==1);
  reset();m.partial_reply=1;cache_thread_desktop_windows();m.full_partial=1;CHECK(get_desktop_window()==DESKTOP);CHECK(m.full_queries==1&&info[0].top_window==DESKTOP&&!info[0].msg_window&&!info[0].desktop_cache_only);CHECK(m.driver_calls==1&&m.builtin_calls==1&&!fallback_entries);CHECK(get_desktop_window()==DESKTOP&&m.full_queries==1&&m.driver_calls==1&&m.builtin_calls==1);
#endif
 }
 if(!strcmp(which,"all")||!strcmp(which,"desktop-switch")){
  reset();info[0]=(struct user_thread_info){DESKTOP,MESSAGE,TRUE};session.shared_foreground[0]=8;m.switch_fail=1;
  CHECK(!NtUserSetThreadDesktop((HDESK)(uintptr_t)8));CHECK(info[0].top_window==DESKTOP&&info[0].desktop_cache_only&&session.shared_foreground[0]==8&&!m.update_calls);
  m.switch_fail=0;m.virtual_samples=0;CHECK(NtUserSetThreadDesktop((HDESK)(uintptr_t)8));CHECK(!info[0].top_window&&!info[0].msg_window&&!info[0].desktop_cache_only);CHECK(!session.shared_foreground[0]&&session.shared_desktop==(void*)(uintptr_t)55&&m.update_calls==1);
 }
 if(!strcmp(which,"all")||!strcmp(which,"desktop-geometry")){
  RECT r,monitor;reset();m.rect_fail=1;memset(&monitor,0xa5,sizeof(monitor));r=get_client_surface_rects(WINDOW,WINDOW,&monitor);CHECK(empty(r)&&empty(monitor));CHECK(m.rect_calls==1&&!m.map_calls&&!m.present_calls&&!m.client_calls&&!m.dpi_calls);
  reset();m.server_fail=1;m.missing_window=1;memset(&monitor,0xa5,sizeof(monitor));r=get_client_surface_rects(0,WINDOW,&monitor);CHECK(empty(r)&&empty(monitor));CHECK(!m.rect_calls&&!m.map_calls&&!m.present_calls&&!m.dpi_calls&&!m.held);
  reset();r=get_client_surface_rects(WINDOW,WINDOW,&monitor);CHECK(r.left==30&&r.top==40&&r.right==130&&r.bottom==140);CHECK(!memcmp(&r,&monitor,sizeof(r))&&m.map_calls==1&&m.present_calls==1&&!m.client_calls&&m.dpi_calls==1);
  reset();m.present_ok=0;r=get_client_surface_rects(WINDOW,WINDOW,&monitor);CHECK(r.left==15&&r.top==26&&r.right==115&&r.bottom==126);CHECK(m.client_calls==1&&m.point_calls==1&&!memcmp(&r,&monitor,sizeof(r)));
 }
 if(!strcmp(which,"all")||!strcmp(which,"desktop-other")){
  reset();CHECK(NtUserGetAncestor(WINDOW,GA_PARENT)==DESKTOP);CHECK(!m.cache_queries&&!m.full_queries&&!m.held);
  reset();CHECK(NtUserGetAncestor(WINDOW,GA_ROOTOWNER)==DESKTOP);CHECK(!m.cache_queries&&!m.full_queries&&!m.held);
 }
 CHECK(checks>0);
 printf("desktop exact-body controls: %u checks\n",checks);return 0;
}
