/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Actual fixture C with all Windows calls mocked. No child is executed. */
#include "windows_fixture_mock/windows.h"
#include <assert.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static struct {
    unsigned pipe_fail, closes, foreign_closes, launches, tick, next, phase;
    unsigned set_handle_fail, event_fail, create_fail, successful_launches;
    unsigned short_ready, bad_ready, different_address, changed_parent, wait_fail;
    unsigned terminate_fail, truncate_phase, exit_get_fail, no_child_image;
    DWORD error, missing_error, process_pid, process_nonce, process_exit, self_pid, event_wait;
    unsigned write_short;
    HANDLE read_pipe, write_pipe, event, process;
    unsigned process_alive, process_early;
    unsigned live[256];
    char lines[128][512];
    unsigned line_count, max_line;
} m;
static int fixture_printf(const char *format, ...)
{
    /* Windows DWORD is 32-bit unsigned long; normalize its printf spelling
     * for this LP64-host model without modifying the original source. */
    char normalized[512]; size_t n = 0;
    for (size_t i = 0; format[i]; ++i) {
        if (format[i] == '%' && format[i+1] == 'l' && format[i+2] == 'u') {
            normalized[n++] = '%'; normalized[n++] = 'u'; i += 2;
        } else normalized[n++] = format[i];
        assert(n + 1 < sizeof(normalized));
    }
    normalized[n] = 0; assert(m.line_count < 128);
    va_list args; va_start(args, format);
    int len = vsnprintf(m.lines[m.line_count++], 512, normalized, args);
    va_end(args); assert(len >= 0 && len < 512);
    if ((unsigned)len > m.max_line) m.max_line = (unsigned)len;
    return len;
}
static int fixture_fflush(FILE *stream) { assert(stream == stdout); return 0; }
static int fixture_swprintf(wchar_t *out, size_t cap, const wchar_t *format, ...)
{
    wchar_t normalized[1024]; size_t n = 0;
    for (size_t i = 0; format[i]; ++i) {
        if (format[i] == L'%' && format[i+1] == L'l' && format[i+2] == L'u') {
            normalized[n++] = L'%'; normalized[n++] = L'u'; i += 2;
        } else normalized[n++] = format[i];
        assert(n + 1 < 1024);
    }
    normalized[n] = 0;
    va_list args; va_start(args, format); int rc = vswprintf(out,cap,normalized,args); va_end(args); return rc;
}
#define printf fixture_printf
#define fflush fixture_fflush
#define swprintf fixture_swprintf
#define wmain fixture_wmain
#include "fixtures/windows_child_process.c"
#undef printf
#undef fflush
#undef swprintf
#undef wmain

static HANDLE handle(unsigned id) { return (HANDLE)(uintptr_t)id; }
static unsigned id(HANDLE h) { return (unsigned)(uintptr_t)h; }
static HANDLE acquire(void) { assert(m.next < 250); m.live[m.next] = 1; return handle(m.next++); }
BOOL CloseHandle(HANDLE h)
{
    ++m.closes; if (id(h) == 250 || id(h) == 251) { ++m.foreign_closes; return TRUE; }
    assert(id(h) < 250 && m.live[id(h)]); m.live[id(h)] = 0; return TRUE;
}
DWORD GetLastError(void) { return m.error; }
DWORD GetCurrentProcessId(void) { return m.self_pid; }
DWORD GetProcessId(HANDLE h) { assert(h == m.process); return m.process_pid; }
DWORD GetTickCount(void) { return ++m.tick; }
BOOL CreatePipe(HANDLE *r,HANDLE *w,SECURITY_ATTRIBUTES *a,DWORD size)
{
    assert(a->bInheritHandle && !size);
    if (m.pipe_fail) { *r=handle(250); *w=handle(251); m.error=5; return FALSE; }
    *r=acquire();*w=acquire();m.read_pipe=*r;m.write_pipe=*w;return TRUE;
}
BOOL SetHandleInformation(HANDLE h,DWORD mask,DWORD flags)
{ (void)h; assert(mask==HANDLE_FLAG_INHERIT && !flags); if(m.set_handle_fail) { m.error=5;return FALSE; } return TRUE; }
HANDLE CreateEventW(SECURITY_ATTRIBUTES *a,BOOL manual,BOOL initial,const wchar_t *name)
{ assert(a->bInheritHandle && manual && !initial && !name);if(m.event_fail) { m.error=5;return NULL; } m.event=acquire();return m.event; }
BOOL CreateProcessW(const wchar_t *path,wchar_t *cmd,void *a,void *b,BOOL inherit,DWORD flags,void *env,void *cwd,STARTUPINFOW *si,PROCESS_INFORMATION *pi)
{
    assert(!a && !b && !flags && !env && !cwd && si->cb==sizeof(*si));
    ++m.launches;
    if(wcsstr(path,L"pw-fixture-missing-")) { assert(!cmd && !inherit);m.error=m.missing_error;return FALSE; }
    if(m.create_fail) {
        pi->hProcess=handle(250);pi->hThread=handle(251);pi->dwProcessId=900;
        m.error=m.create_fail;return FALSE;
    }
    assert(inherit && cmd);
    const wchar_t *args=wcsstr(cmd,L"--child "); assert(args);
    wchar_t mode[16]; unsigned parent,nonce;unsigned long long pipe_value,event_value;
    assert(swscanf(args,L"--child %15ls %u %u %llu %llu",mode,&parent,&nonce,&pipe_value,&event_value)==5);
    assert(parent==m.self_pid && pipe_value==id(m.write_pipe) && event_value==id(m.event));
    ++m.successful_launches;m.phase=m.successful_launches;
    m.process_pid=200+m.phase;m.process_nonce=nonce;m.process_early=!wcscmp(mode,L"early");
    m.process_alive=!m.process_early;m.process_exit=m.process_early?EARLY_EXIT:STILL_ACTIVE;
    pi->hProcess=m.process=acquire();pi->hThread=acquire();pi->dwProcessId=m.process_pid;pi->dwThreadId=300+m.phase;
    return TRUE;
}
BOOL WriteFile(HANDLE h,const void *b,DWORD size,DWORD *got,void *over)
{ (void)h;(void)b;(void)over;*got=m.write_short?size-1:size;return TRUE; }
BOOL ReadFile(HANDLE h,void *b,DWORD size,DWORD *got,void *over)
{
    assert(h==m.read_pipe && size==sizeof(struct hello) && !over);
    struct hello message={MAGIC,sizeof(message),1,m.process_pid,m.self_pid,m.process_nonce,INITIAL_MARKER,m.process_nonce^0x53594e54u,(uint64_t)(uintptr_t)&private_marker};
    if(m.bad_ready) message.nonce^=1;
    if(m.different_address) message.address+=16;
    if(m.changed_parent) private_marker^=1;
    memcpy(b,&message,sizeof(message));*got=m.short_ready?size-1:size;return TRUE;
}
DWORD WaitForSingleObject(HANDLE h,DWORD ms)
{ (void)ms;if(h==m.event)return m.event_wait;assert(h==m.process);if(m.wait_fail)return WAIT_FAILED;return m.process_alive?WAIT_TIMEOUT:WAIT_OBJECT_0; }
DWORD GetModuleFileNameW(HANDLE h,wchar_t *out,DWORD cap)
{ const wchar_t *path=L"C:\\fixture\\parent.exe";(void)h;assert(wcslen(path)<cap);wcscpy(out,path);return (DWORD)wcslen(path); }
BOOL PeekNamedPipe(HANDLE h,void *buf,DWORD sz,DWORD *got,DWORD *avail,DWORD *left)
{ assert(h==m.read_pipe && !buf && !sz && !got && !left);*avail=m.process_early?0:sizeof(struct hello);return TRUE; }
BOOL GetExitCodeProcess(HANDLE h,DWORD *code)
{ assert(h==m.process);if(m.exit_get_fail)return FALSE;*code=m.process_exit;if(m.truncate_phase==m.phase)*code&=255;return TRUE; }
BOOL TerminateProcess(HANDLE h,unsigned code)
{ assert(h==m.process);if(m.terminate_fail)return FALSE;m.process_alive=0;m.process_exit=code;return TRUE; }
BOOL SetEvent(HANDLE h) { assert(h==m.event);m.process_alive=0;m.process_exit=NORMAL_EXIT;return TRUE; }
DWORD GetFileAttributesW(const wchar_t *path)
{ return (m.no_child_image || wcsstr(path,L"pw-fixture-missing-"))?INVALID_FILE_ATTRIBUTES:0; }
void Sleep(DWORD ms) { m.tick+=ms; }
static void reset(void) { memset(&m,0,sizeof(m));m.next=10;m.self_pid=100;m.missing_error=ERROR_FILE_NOT_FOUND;owned_handles=0;last_launch_error=0;private_marker=INITIAL_MARKER; }
static unsigned checks;
#define CHECK(v) do { ++checks; if(!(v)) { fprintf(stderr,"check line%d failed: %s\n",__LINE__,#v);exit(1); } } while(0)
static int run_parent(void) { wchar_t *args[]={L"parent.exe",NULL};return fixture_wmain(1,args); }
static int has_log(const char *part) { for(unsigned i=0;i<m.line_count;i++)if(strstr(m.lines[i],part))return 1;return 0; }
static void failed_pipe(void)
{
    reset();m.pipe_fail=1;
    struct child child;
    int rc=start_child(L"C:\\fixture\\child.exe",L"normal",123,&child);
    printf("failed CreatePipe: result=%d foreign_closes=%u owned_handles=%u launches=%u\n",rc,m.foreign_closes,owned_handles,m.launches);
    CHECK(rc == -1 && !m.launches);
    CHECK(!m.foreign_closes && !owned_handles);
}
int main(int argc,char **argv)
{
    failed_pipe();if(argc>1 && !strcmp(argv[1],"pipe-red"))return 0;
    reset();CHECK(run_parent()==0);CHECK(m.successful_launches==3 && m.launches==4 && !owned_handles);
    CHECK(has_log("automated_pass") && has_log("exit=5308458 expected=5308458"));
    printf("full mocked fixture pass: attempts=%u successful=%u longest_line=%u\n",m.launches,m.successful_launches,m.max_line);
    for(unsigned stage=1;stage<=3;stage++) {
        reset();m.truncate_phase=stage;CHECK(run_parent()==1);CHECK(!has_log("automated_pass"));CHECK(!owned_handles);
    }
    reset();m.different_address=1;CHECK(run_parent()==77);CHECK(has_log("private_state result=not_established"));CHECK(!has_log("automated_pass"));CHECK(m.successful_launches==3 && !owned_handles);
    const unsigned errors[]={ERROR_NOT_SUPPORTED,ERROR_CALL_NOT_IMPLEMENTED,5,ERROR_FILE_NOT_FOUND};
    for(unsigned i=0;i<sizeof(errors)/sizeof(errors[0]);i++) {
        reset();m.create_fail=errors[i];CHECK(run_parent()==(i<2?77:1));CHECK(!m.foreign_closes && !owned_handles);CHECK(!has_log("automated_pass"));
    }
    const unsigned missing_errors[]={ERROR_FILE_NOT_FOUND,ERROR_PATH_NOT_FOUND,ERROR_NOT_SUPPORTED,5};
    for(unsigned i=0;i<sizeof(missing_errors)/sizeof(missing_errors[0]);i++) {
        reset();m.missing_error=missing_errors[i];CHECK(run_parent()==(i<2?0:1));CHECK(!owned_handles);
    }
    reset();m.set_handle_fail=1;CHECK(run_parent()==1);CHECK(m.closes==2 && !m.launches && !owned_handles);
    reset();m.event_fail=1;CHECK(run_parent()==1);CHECK(m.closes==2 && !m.launches && !owned_handles);
    reset();m.no_child_image=1;CHECK(run_parent()==2);CHECK(!m.launches && !m.closes);
    reset();m.short_ready=1;CHECK(run_parent()==1);CHECK(!has_log("automated_pass") && !owned_handles);
    reset();m.bad_ready=1;CHECK(run_parent()==1);CHECK(!has_log("automated_pass") && !owned_handles);
    reset();m.changed_parent=1;CHECK(run_parent()==1);CHECK(!has_log("automated_pass") && !owned_handles);
    reset();m.wait_fail=1;CHECK(run_parent()==1);CHECK(!has_log("automated_pass"));
    reset();m.exit_get_fail=1;CHECK(run_parent()==1);CHECK(!has_log("automated_pass"));
    reset();m.terminate_fail=1;CHECK(run_parent()==1);CHECK(!has_log("automated_pass") && m.process_alive);
    reset();m.self_pid=UINT32_MAX;m.tick=UINT32_MAX;CHECK(run_parent()==0);CHECK(!owned_handles);
    for(unsigned mode=0;mode<4;mode++) {
        reset();m.self_pid=UINT32_MAX;m.write_pipe=acquire();m.event=acquire();
        wchar_t *args[]={L"child.exe",L"--child",mode==1?L"early":L"normal",L"4294967294",L"4294967295",L"10",L"11",NULL};
        m.write_short=mode==2;m.event_wait=mode==3?WAIT_TIMEOUT:WAIT_OBJECT_0;
        int rc=fixture_wmain(7,args);
        CHECK((DWORD)rc==(mode==0?NORMAL_EXIT:mode==1?EARLY_EXIT:CHILD_ERROR));
        CHECK(!m.live[10] && !m.live[11]);
        if(mode!=1)CHECK(has_log("pid=4294967295 parent_claim=4294967294 nonce=4294967295"));
    }
    printf("fixture decision controls: %u checks passed; no Windows or native process execution\n",checks);
    return 0;
}
