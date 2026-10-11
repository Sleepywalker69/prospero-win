/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Inert boundary mocks for exact ps5drv function bodies. No Wine/PS5 runtime. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include "windef.h"
#include "winbase.h"
#include "winuser.h"
static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr,"check %u line %d failed: %s\n",checks,__LINE__,#x); exit(1); } } while (0)
#define H(n) ((HWND)(uintptr_t)(n))
/* ACTUAL_INPUT_DECLARATIONS */
static struct {
 UINT type,code,down,count,next_calls,fd_calls,reads,sends,moves,buttons,focus,maps,layouts;
 int fd,read_bytes,locks,service; uintptr_t current_token;
 HWND selected,foreground,last,delivered;
 INPUT sent[PS5_INPUT_BATCH];
} m;
static int screen_lock;
static uintptr_t bridge_token;
static int fake_lock(int *p) { CHECK(p==&screen_lock&&!m.locks); m.locks++; return 0; }
static int fake_unlock(int *p) { CHECK(p==&screen_lock&&m.locks==1); m.locks--; return 0; }
#define pthread_mutex_lock fake_lock
#define pthread_mutex_unlock fake_unlock
static uintptr_t bridge_current_token(void) { return m.current_token; }
static BOOL bridge_service_window(HWND h) { CHECK(h==m.foreground); return m.service; }
static HWND bridge_input_window(HWND h) { CHECK(h==m.foreground&&m.locks==1); return m.selected; }
static HWND NtUserGetForegroundWindow(void) { return m.foreground; }
static void NtUserSetForegroundWindow(HWND h) { CHECK(!m.locks&&h); m.foreground=h; m.focus++; }
static HWND last_shown_window(void) { return m.last; }
static int fake_fd(void) { m.fd_calls++; return m.fd; }
static ssize_t fake_read(int fd,void *buffer,size_t size) { CHECK(fd==m.fd&&buffer&&size==64);m.reads++;if(m.read_bytes){m.read_bytes--;return 1;}errno=EAGAIN;return -1; }
#define read fake_read
static BOOL fake_next(struct ps5_input *e) { m.next_calls++;if(!m.count)return FALSE;m.count--;*e=(struct ps5_input){m.type,m.code,3,-4,m.down};return TRUE; }
static BOOL (*next_input)(struct ps5_input *)=fake_next;
static int (*input_fd)(void)=fake_fd;
static HKL NtUserGetKeyboardLayout(DWORD thread) { CHECK(thread==0);m.layouts++;return (HKL)(uintptr_t)22; }
static UINT mock_scan(UINT code) { return code==VK_UP||code==VK_NUMPAD8?0x48:code^0x5a; }
static UINT NtUserMapVirtualKeyEx(UINT code,UINT type,HKL layout) { CHECK(code==m.code&&type==MAPVK_VK_TO_VSC&&layout==(HKL)(uintptr_t)22);m.maps++;return mock_scan(code); }
static void NtUserSendHardwareInput(HWND h,UINT a,INPUT *input,UINT b) { CHECK(!m.locks&&!a&&!b&&m.sends<PS5_INPUT_BATCH);m.delivered=h;m.sent[m.sends++]=*input; }
static void move_cursor(HWND h,INT x,INT y) { CHECK(!m.locks&&h==m.selected&&x==3&&y==-4);m.moves++; }
static void send_mouse(HWND h,DWORD flags,INT x,INT y) { static const DWORD expected[3][2]={{MOUSEEVENTF_LEFTUP,MOUSEEVENTF_LEFTDOWN},{MOUSEEVENTF_RIGHTUP,MOUSEEVENTF_RIGHTDOWN},{MOUSEEVENTF_MIDDLEUP,MOUSEEVENTF_MIDDLEDOWN}};CHECK(!m.locks&&h==m.selected&&!x&&!y&&m.code<3&&flags==expected[m.code][m.down!=0]);m.buttons++; }
/* ACTUAL_FUNCTIONS */
static void reset(void) { memset(&m,0,sizeof(m));bridge_token=0;m.selected=H(12);m.foreground=H(12);m.fd=-1;m.type=1;next_input=fake_next;input_fd=fake_fd; }
/* Independent numeric oracle for the sixteen upstream VKs, not parsed from its switch. */
static BOOL expected_extended(UINT code) { static const UINT codes[]={0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x2d,0x2e,0x5b,0x5c,0x5d,0x6f,0xa3,0xa5};for(size_t i=0;i<sizeof(codes)/sizeof(*codes);i++)if(code==codes[i])return TRUE;return FALSE; }
static void check_key(UINT code,UINT down) {
 reset();m.count=1;m.code=code;m.down=down;CHECK(ps5_ProcessEvents(0));
 CHECK(m.sends==1&&m.maps==1&&m.layouts==1&&m.next_calls==2&&m.count==0&&!m.locks&&!m.moves&&!m.buttons);
 CHECK(m.delivered==H(12)&&m.sent[0].type==INPUT_KEYBOARD&&m.sent[0].ki.wVk==code&&m.sent[0].ki.wScan==mock_scan(code));
 DWORD expected=(down?0:KEYEVENTF_KEYUP)|(expected_extended(code)?KEYEVENTF_EXTENDEDKEY:0);
 if(m.sent[0].ki.dwFlags!=expected)fprintf(stderr,"VK=%#x down=%u actual flags=%#lx expected=%#lx\n",code,down,(unsigned long)m.sent[0].ki.dwFlags,(unsigned long)expected);
 CHECK(m.sent[0].ki.dwFlags==expected);CHECK(!m.sent[0].ki.time&&!m.sent[0].ki.dwExtraInfo);
}
static void matrix(void) {
 /* The old actual body fails immediately on Up; keypad8 keeps the same scan with no extended flag. */
 check_key(VK_UP,1);check_key(VK_UP,0);check_key(VK_NUMPAD8,1);check_key(VK_NUMPAD8,0);
 for(UINT code=0;code<=255;code++)for(UINT down=0;down<3;down++)check_key(code,down==2?7:down);
}
static void guards(void) {
 reset();m.count=1;m.current_token=7;CHECK(!ps5_ProcessEvents(0));CHECK(!m.next_calls&&!m.fd_calls&&!m.sends&&!m.locks&&m.count==1);
 reset();m.count=1;next_input=NULL;CHECK(!ps5_ProcessEvents(0));CHECK(!m.fd_calls&&!m.sends&&!m.locks&&m.count==1);
 for(int service=0;service<=1;service++){reset();m.selected=NULL;m.service=service;bridge_token=!service;m.count=70;m.code=VK_UP;m.down=1;CHECK(ps5_ProcessEvents(0));CHECK(m.next_calls==PS5_INPUT_BATCH&&m.count==6&&!m.sends&&!m.maps&&!m.layouts&&!m.moves&&!m.buttons);}
 reset();m.count=1;m.code=VK_UP;m.down=1;m.selected=H(19);CHECK(ps5_ProcessEvents(0));CHECK(m.sends==1&&m.delivered==H(19)&&m.focus==1);
 reset();m.count=1;m.code=VK_UP;m.down=1;m.selected=NULL;m.last=H(23);CHECK(ps5_ProcessEvents(0));CHECK(m.sends==1&&m.delivered==H(23)&&m.focus==1);
 reset();m.count=1;m.code=VK_UP;m.down=1;m.selected=NULL;CHECK(ps5_ProcessEvents(0));CHECK(m.sends==1&&m.delivered==NULL&&!m.focus);
 reset();m.count=70;m.code=VK_UP;m.down=1;CHECK(ps5_ProcessEvents(0));CHECK(m.sends==PS5_INPUT_BATCH&&m.next_calls==PS5_INPUT_BATCH&&m.count==6);
 reset();m.fd=9;m.read_bytes=3;m.count=1;m.code=VK_UP;m.down=1;CHECK(ps5_ProcessEvents(0));CHECK(m.reads==4&&m.fd_calls==1&&m.sends==1);
 reset();input_fd=NULL;m.count=1;m.code=VK_UP;m.down=1;CHECK(ps5_ProcessEvents(0));CHECK(!m.fd_calls&&!m.reads&&m.sends==1);
 for(UINT down=0;down<2;down++)for(UINT button=0;button<4;button++){reset();m.type=3;m.count=1;m.code=button;m.down=down;CHECK(ps5_ProcessEvents(0));CHECK(m.buttons==(button<3)&&!m.maps&&!m.layouts&&!m.sends&&!m.moves);}
 reset();m.type=2;m.count=1;CHECK(ps5_ProcessEvents(0));CHECK(m.moves==1&&!m.buttons&&!m.maps&&!m.layouts&&!m.sends);
 reset();m.type=99;m.count=1;CHECK(ps5_ProcessEvents(0));CHECK(!m.moves&&!m.buttons&&!m.maps&&!m.layouts&&!m.sends);
 /* Empty no-FD behavior is common to key-only and wake+key compositions. */
 reset();CHECK(!ps5_ProcessEvents(0));CHECK(m.next_calls==1&&!m.sends);
}
int main(int argc,char **argv) { const char *which=argc>1?argv[1]:"all";if(!strcmp(which,"all")||!strcmp(which,"matrix"))matrix();if(!strcmp(which,"all")||!strcmp(which,"guards"))guards();printf("extended-key exact-function %s: %u checks passed\n",which,checks);return 0; }
