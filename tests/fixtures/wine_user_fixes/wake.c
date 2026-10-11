/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* All input, threading and server boundaries below are inert mocks. */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include "windef.h"
#include "winbase.h"
#include "winuser.h"
/* Inert private queue bits; their branch selection is modeled. */
#define QS_DRIVER 0x80000000u
#define QS_HARDWARE 1
static unsigned checks;
#define CHECK(x) do { ++checks; if(!(x)){fprintf(stderr,"check %u line %d failed: %s\n",checks,__LINE__,#x);exit(1);} }while(0)
/* INPUT_DECLARATIONS */
struct peek_message_filter {int internal;};
static struct {uintptr_t current_token,global_token;int service,selected,fd;int read_count,read_positive,read_terminal,fd_calls,next_calls,events;unsigned event_type,event_code;int event_down;int sent,mouse,moved,focus,locks;unsigned bits;int queue_calls,poll,wake,changed,peek,signals;int masks;} m;
static int screen_lock;
static uintptr_t bridge_token;
static int pthread_mutex_lock(int*x){(void)x;CHECK(!m.locks);m.locks++;return 0;}
static int pthread_mutex_unlock(int*x){(void)x;CHECK(m.locks==1);m.locks--;return 0;}
static uintptr_t bridge_current_token(void){return m.current_token;}
static int bridge_service_window(HWND h){(void)h;return m.service;}
static HWND bridge_input_window(HWND h){(void)h;return (HWND)(uintptr_t)m.selected;}
static HWND NtUserGetForegroundWindow(void){return (HWND)(uintptr_t)12;}
static void NtUserSetForegroundWindow(HWND h){CHECK(h!=0);m.focus++;}
static HWND last_shown_window(void){return 0;}
static int fake_fd(void){m.fd_calls++;return m.fd;}
static ssize_t fake_read(int fd,void*buf,size_t size){CHECK(fd==m.fd&&size==64&&buf!=NULL);m.read_count++;if(m.read_positive){m.read_positive--;return 1;}errno=EAGAIN;return m.read_terminal;}
#define read fake_read
static int fake_next(struct ps5_input*event){m.next_calls++;if(!m.events)return 0;m.events--;*event=(struct ps5_input){.type=m.event_type,.code=m.event_code,.down=m.event_down,.x=3,.y=4};return 1;}
static int (*input_fd)(void)=fake_fd;
static int (*next_input)(struct ps5_input*)=fake_next;
static unsigned NtUserMapVirtualKeyEx(unsigned c,unsigned t,HKL layout){CHECK(t==MAPVK_VK_TO_VSC&&layout==(HKL)(uintptr_t)22);return c+1;}
static HKL NtUserGetKeyboardLayout(int t){CHECK(t==0);return (HKL)(uintptr_t)22;}
static void NtUserSendHardwareInput(HWND h,int a,INPUT*i,int b){CHECK(!m.locks&&h==(HWND)(uintptr_t)12&&a==0&&b==0);CHECK(i->ki.wVk==m.event_code&&i->ki.wScan==m.event_code+1);CHECK(i->ki.dwFlags==(m.event_down?0:KEYEVENTF_KEYUP));m.sent++;}
static void move_cursor(HWND h,int x,int y){CHECK(!m.locks&&h==(HWND)(uintptr_t)12&&x==3&&y==4);m.moved++;}
static void send_mouse(HWND h,DWORD flags,int x,int y){CHECK(!m.locks&&h==(HWND)(uintptr_t)12&&flags&&x==0&&y==0);m.mouse++;}
static BOOL ps5_ProcessEvents(DWORD mask);
static struct {BOOL(*pProcessEvents)(DWORD);} driver={ps5_ProcessEvents},*user_driver=&driver;
static BOOL check_internal_bits(UINT bit){return (m.bits&bit)!=0;}
static BOOL check_queue_masks(UINT wake,UINT changed){CHECK(wake==7&&changed==9);return m.masks;}
static BOOL is_queue_signaled(void){m.signals++;return 0;}
static void peek_message(MSG*x,struct peek_message_filter*f){CHECK(x&&f->internal);m.peek++;}
struct request {int poll_events;UINT wake_mask,changed_mask;};
#define SERVER_START_REQ(kind) do {struct request r={0},*req=&r;
#define SERVER_END_REQ }while(0)
static int wine_server_call(struct request*r){CHECK(!m.locks);m.queue_calls++;m.poll=r->poll_events;m.wake=r->wake_mask;m.changed=r->changed_mask;return 0;}
/* ACTUAL_FUNCTIONS */
static void reset(void){memset(&m,0,sizeof(m));bridge_token=0;m.fd=7;m.read_terminal=-1;m.selected=12;m.bits=QS_DRIVER;m.masks=1;input_fd=fake_fd;next_input=fake_next;}
int main(int argc,char**argv){
 const char*which=argc>1?argv[1]:"all";
 if(!strcmp(which,"all")||!strcmp(which,"wake-empty")){
  for(int terminal=-1;terminal<=0;terminal++)for(int bytes=0;bytes<=3;bytes++){
   reset();m.read_terminal=terminal;m.read_positive=bytes;CHECK(!process_driver_events(33,7,9));
   CHECK(m.queue_calls==1&&m.poll==TRUE&&m.wake==7&&m.changed==9);CHECK(m.read_count==bytes+1&&m.next_calls==1&&m.sent==0);
  }
 }
 if(!strcmp(which,"all")||!strcmp(which,"wake-guards")){
  reset();m.current_token=8;CHECK(!ps5_ProcessEvents(0));CHECK(!m.fd_calls&&!m.read_count&&!m.next_calls&&!m.locks);
  reset();next_input=NULL;CHECK(!ps5_ProcessEvents(0));CHECK(!m.fd_calls&&!m.read_count&&!m.next_calls);
  reset();input_fd=NULL;CHECK(!ps5_ProcessEvents(0));CHECK(!m.fd_calls&&!m.read_count&&m.next_calls==1);
  reset();m.fd=-1;CHECK(!ps5_ProcessEvents(0));CHECK(m.fd_calls==1&&!m.read_count&&m.next_calls==1);
  for(int service=0;service<=1;service++){reset();m.selected=0;m.service=service;bridge_token=!service;m.events=PS5_INPUT_BATCH+2;m.event_type=1;m.event_code=65;
   CHECK(ps5_ProcessEvents(0));CHECK(!m.sent&&!m.mouse&&!m.moved&&m.events==2&&m.next_calls==PS5_INPUT_BATCH);}
 }
 if(!strcmp(which,"all")||!strcmp(which,"wake-normal")){
  for(unsigned type=1;type<=3;type++){reset();m.events=1;m.event_type=type;m.event_code=1;m.event_down=1;CHECK(ps5_ProcessEvents(0));CHECK(m.sent+m.mouse+m.moved==1);}
  reset();m.events=PS5_INPUT_BATCH+4;m.event_type=1;m.event_code=65;CHECK(ps5_ProcessEvents(0));CHECK(m.sent==PS5_INPUT_BATCH&&m.events==4&&m.next_calls==PS5_INPUT_BATCH);
  reset();m.bits=0;CHECK(!process_driver_events(33,7,9));CHECK(!m.read_count&&!m.next_calls&&!m.queue_calls);
  reset();m.bits=QS_HARDWARE;m.masks=0;CHECK(!process_driver_events(33,7,9));CHECK(m.queue_calls==1&&!m.poll&&m.peek==1);
 }
 CHECK(checks>0);
 printf("wake exact-body controls: %u checks\n",checks);return 0;
}
