/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Original separate USER control. No vendor assets, inherited handles, input
 * injection, presentation bridge or native ownership claims. */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <wchar.h>

#ifndef PW_USER_CHILD
#define PW_USER_CHILD 0
#endif
enum { PARENT_MS=90000, CHILD_MS=45000, WORKER_MS=20000,
       WATCHDOG_MARGIN_MS=5000, CHILD_EXIT=37, LOG_LIMIT=65536 };
static const char *role=PW_USER_CHILD?"child":"parent";
static HANDLE log_file=INVALID_HANDLE_VALUE, watchdog_stop, watchdog_thread;
static CRITICAL_SECTION log_lock;
static unsigned log_bytes;
static volatile LONG log_failed;
static ULONGLONG started,last_tick;
static DWORD main_limit;

static void record(const char *stage,const char *format,...)
{
    char detail[480],line[720]; va_list args; DWORD wrote=0; int n;
    va_start(args,format);n=vsnprintf(detail,sizeof(detail),format,args);va_end(args);
    if(n<0||(size_t)n>=sizeof(detail)){InterlockedExchange(&log_failed,1);return;}
    n=snprintf(line,sizeof(line),"PW_CHILD_USER role=%s stage=%s pid=%lu tid=%lu %s\r\n",
               role,stage,(unsigned long)GetCurrentProcessId(),
               (unsigned long)GetCurrentThreadId(),detail);
    if(n<0||(size_t)n>=sizeof(line)){InterlockedExchange(&log_failed,1);return;}
    EnterCriticalSection(&log_lock);
    if(log_file==INVALID_HANDLE_VALUE||(unsigned)n>LOG_LIMIT-log_bytes||
       !WriteFile(log_file,line,(DWORD)n,&wrote,NULL)||wrote!=(DWORD)n)
        InterlockedExchange(&log_failed,1);
    else log_bytes+=(unsigned)n;
    LeaveCriticalSection(&log_lock);
    OutputDebugStringA(line);
    /* Secondary only: a service child may have no usable standard stream. */
    (void)fputs(line,stdout);(void)fflush(stdout);
}

static void self_exit(DWORD code)
{
    OutputDebugStringA("PW_CHILD_USER stage=self_exit result=attempt native_settlement=unverified\r\n");
    (void)TerminateProcess(GetCurrentProcess(),code);
    ExitProcess(code+1);
    /* If both unexpected returns occur, preserve process-lifetime storage.
     * Do not return while another thread can still access it. */
    for(;;)Sleep(1000);
}

static DWORD remaining_at(ULONGLONG now)
{
    if(now<last_tick||now<started||now-started>=main_limit)return 0;
    last_tick=now;return main_limit-(DWORD)(now-started);
}
static DWORD remaining(void) { return remaining_at(GetTickCount64()); }

static DWORD WINAPI watchdog(void *unused)
{
    ULONGLONG now=GetTickCount64(); DWORD wait_ms,wait;
    (void)unused;
    if(now<started||now-started>=main_limit+WATCHDOG_MARGIN_MS)self_exit(120);
    wait_ms=main_limit+WATCHDOG_MARGIN_MS-(DWORD)(now-started);
    wait=WaitForSingleObject(watchdog_stop,wait_ms);
    if(wait==WAIT_OBJECT_0)return 0;
    self_exit(122);return 122;
}

static int begin(void)
{
    char path[128];int n;
    started=last_tick=GetTickCount64();main_limit=PW_USER_CHILD?CHILD_MS:PARENT_MS;
    InitializeCriticalSection(&log_lock);
    n=snprintf(path,sizeof(path),"user-%s-%lu-%llu.log",role,
               (unsigned long)GetCurrentProcessId(),(unsigned long long)started);
    if(n<0||(size_t)n>=sizeof(path))return 0;
    log_file=CreateFileA(path,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    if(log_file==INVALID_HANDLE_VALUE)return 0;
    watchdog_stop=CreateEventW(NULL,TRUE,FALSE,NULL);
    if(!watchdog_stop)return 0;
    watchdog_thread=CreateThread(NULL,0,watchdog,NULL,0,NULL);
    if(!watchdog_thread)return 0;
    record("start","mode=original_user_control child_presentation=unverified child_input=unverified");
    return !InterlockedCompareExchange(&log_failed,0,0);
}

static int finish(int status)
{
    DWORD code=0;int cleanup_failed=0;
    /* Caller has joined every diagnostic worker before entering this path. */
    if(!remaining()&&!status)status=90;
    record("finish","planned_exit=%d prior_status=%d diagnostic_cleanup=%s final_log_close=pending native_settlement=unverified",
           status?status:(PW_USER_CHILD?CHILD_EXIT:0),status,status?"not_established":"completed");
    if(watchdog_thread){
        if(!SetEvent(watchdog_stop)||WaitForSingleObject(watchdog_thread,1000)!=WAIT_OBJECT_0||
           !GetExitCodeThread(watchdog_thread,&code)||code)self_exit(124);
        if(!CloseHandle(watchdog_thread))cleanup_failed=1;
        watchdog_thread=NULL;
    }
    if(watchdog_stop){if(!CloseHandle(watchdog_stop))cleanup_failed=1;watchdog_stop=NULL;}
    if(log_file!=INVALID_HANDLE_VALUE){HANDLE owned=log_file;log_file=INVALID_HANDLE_VALUE;
        if(!CloseHandle(owned))cleanup_failed=1;}
    if(!remaining()&&!status)status=90;
    if((cleanup_failed||InterlockedCompareExchange(&log_failed,0,0))&&!status)status=91;
    DeleteCriticalSection(&log_lock);
    if(!remaining()&&!status)status=90;
    return status;
}

#if PW_USER_CHILD
typedef struct WorkerContext {
    HWND top;
    RECT window_rect,client_rect;
    DWORD main_tid,worker_tid;
    volatile LONG finished;
    DWORD status;
} WorkerContext;
static WorkerContext context;
static const wchar_t main_class[]=L"PWOriginalUserMain1";
static const wchar_t worker_class[]=L"PWOriginalUserWorker1";

static LRESULT CALLBACK window_proc(HWND hwnd,UINT msg,WPARAM wparam,LPARAM lparam)
{ return DefWindowProcW(hwnd,msg,wparam,lparam); }

static int same_rect(const RECT *a,const RECT *b)
{ return a->left==b->left&&a->top==b->top&&a->right==b->right&&a->bottom==b->bottom; }

static DWORD WINAPI worker(void *opaque)
{
    WorkerContext *c=opaque;
    ULONGLONG start=GetTickCount64(),last=start;
    DWORD status=0;RECT wr={0},cr={0};HWND root,control=NULL,custom=NULL;
    HDC dc=NULL;HBITMAP bitmap=NULL;HGDIOBJ previous=NULL;void *bits=NULL;
    BITMAPINFO info;BITMAP actual;WNDCLASSW cls;ATOM atom=0;HINSTANCE instance=GetModuleHandleW(NULL);
    c->worker_tid=GetCurrentThreadId();
    record("worker_first_user","next=GetAncestor_GA_ROOT top=%llu main_tid=%lu",
           (unsigned long long)(uintptr_t)c->top,(unsigned long)c->main_tid);
    /* Keep this the worker's first explicit USER/GDI API. The HWND belongs to
     * this process's main thread and stays alive until this thread is joined. */
    root=GetAncestor(c->top,GA_ROOT);
    record("ancestor","returned=%llu expected=%llu matches=%u",
           (unsigned long long)(uintptr_t)root,(unsigned long long)(uintptr_t)c->top,(unsigned)(root==c->top));
    if(root!=c->top){status=10;goto cleanup;}
    if(!GetWindowRect(c->top,&wr)){DWORD e=GetLastError();record("GetWindowRect","result=failed error=%lu",(unsigned long)e);status=11;goto cleanup;}
    if(!GetClientRect(c->top,&cr)){DWORD e=GetLastError();record("GetClientRect","result=failed error=%lu",(unsigned long)e);status=11;goto cleanup;}
    if(!same_rect(&wr,&c->window_rect)||!same_rect(&cr,&c->client_rect)||
       wr.right<=wr.left||wr.bottom<=wr.top||cr.right<=cr.left||cr.bottom<=cr.top){status=11;goto cleanup;}
    record("geometry","window_match=1 client_match=1 width=%ld height=%ld",
           (long)(cr.right-cr.left),(long)(cr.bottom-cr.top));
    control=CreateWindowExW(0,L"STATIC",L"Original hidden static",WS_POPUP,
                             12,12,64,32,NULL,NULL,instance,NULL);
    if(!control){DWORD e=GetLastError();record("static","result=failed error=%lu",(unsigned long)e);status=12;goto cleanup;}
    record("static","created=1 visible=0 hwnd=%llu",(unsigned long long)(uintptr_t)control);
    memset(&cls,0,sizeof(cls));cls.lpfnWndProc=window_proc;cls.hInstance=instance;cls.lpszClassName=worker_class;
    atom=RegisterClassW(&cls);if(!atom){DWORD e=GetLastError();record("RegisterClassW","result=failed error=%lu",(unsigned long)e);status=13;goto cleanup;}
    custom=CreateWindowExW(0,worker_class,L"Original hidden worker",WS_POPUP,
                            24,24,64,32,NULL,NULL,instance,NULL);
    if(!custom){DWORD e=GetLastError();record("custom_class","result=failed error=%lu",(unsigned long)e);status=14;goto cleanup;}
    record("custom_class","registered=1 created=1 visible=0");
    memset(&info,0,sizeof(info));info.bmiHeader.biSize=(DWORD)sizeof(info.bmiHeader);
    info.bmiHeader.biWidth=32;info.bmiHeader.biHeight=-16;info.bmiHeader.biPlanes=1;
    info.bmiHeader.biBitCount=32;info.bmiHeader.biCompression=BI_RGB;
    dc=CreateCompatibleDC(NULL);if(!dc){status=15;goto cleanup;}
    bitmap=CreateDIBSection(dc,&info,DIB_RGB_COLORS,&bits,NULL,0);if(!bitmap||!bits){status=16;goto cleanup;}
    memset(&actual,0,sizeof(actual));
    if(GetObjectW(bitmap,(int)sizeof(actual),&actual)!=(int)sizeof(actual)||actual.bmWidth!=32||
       actual.bmHeight!=16||actual.bmWidthBytes!=128||actual.bmPlanes!=1||actual.bmBitsPixel!=32||actual.bmBits!=bits){status=17;goto cleanup;}
    previous=SelectObject(dc,bitmap);if(!previous||previous==HGDI_ERROR){previous=NULL;status=18;goto cleanup;}
    memset(bits,0,32u*16u*4u);((uint32_t *)bits)[0]=0x00123456u;((uint32_t *)bits)[511]=0x00789abcu;
    if(GetPixel(dc,0,0)!=RGB(0x12,0x34,0x56)||GetPixel(dc,31,15)!=RGB(0x78,0x9a,0xbc)){status=19;goto cleanup;}
    record("dib","width=32 height=16 stride=128 local_readback=matched presentation=unverified");
cleanup:
    if(previous){HGDIOBJ result=SelectObject(dc,previous);if(!result||result==HGDI_ERROR){if(!status)status=20;}}
    if(bitmap&&!DeleteObject(bitmap)&&!status)status=21;
    if(dc&&!DeleteDC(dc)&&!status)status=22;
    if(custom&&!DestroyWindow(custom)&&!status)status=23;
    if(atom&&!UnregisterClassW(worker_class,instance)&&!status)status=24;
    if(control&&!DestroyWindow(control)&&!status)status=25;
    {ULONGLONG now=GetTickCount64();if((now<last||now<start||now-start>=WORKER_MS)&&!status)status=26;last=now;}
    (void)last;
    record("worker_cleanup","status=%lu local_operations_only=1",(unsigned long)status);
    if(InterlockedCompareExchange(&log_failed,0,0)&&!status)status=27;
    c->status=status;
    InterlockedExchange(&c->finished,1); /* publication follows all worker cleanup and logging */
    return status;
}

static int run_role(void)
{
    WNDCLASSW cls;HINSTANCE instance=GetModuleHandleW(NULL);ATOM atom;HANDLE thread;DWORD tid,exit_code=0;
    HWND top;int status=0;BOOL exit_query;ULONGLONG worker_started;
    memset(&cls,0,sizeof(cls));cls.lpfnWndProc=window_proc;cls.hInstance=instance;cls.lpszClassName=main_class;
    atom=RegisterClassW(&cls);if(!atom)return 30;
    top=CreateWindowExW(0,main_class,L"Original hidden owner",WS_POPUP,
                         10,10,320,240,NULL,NULL,instance,NULL);
    if(!top){(void)UnregisterClassW(main_class,instance);return 31;}
    context.top=top;context.main_tid=GetCurrentThreadId();
    if(!GetWindowRect(top,&context.window_rect)||!GetClientRect(top,&context.client_rect)){status=32;goto cleanup;}
    record("top_window","hwnd=%llu width=%ld height=%ld visible=0",
           (unsigned long long)(uintptr_t)top,(long)(context.client_rect.right-context.client_rect.left),
           (long)(context.client_rect.bottom-context.client_rect.top));
    worker_started=GetTickCount64();thread=CreateThread(NULL,0,worker,&context,0,&tid);
    if(!thread){status=33;goto cleanup;}
    for(;;){
        ULONGLONG now=GetTickCount64();DWORD wait;MSG msg;
        if(!remaining_at(now)||now<worker_started||now-worker_started>=WORKER_MS+2000u)self_exit(126);
        wait=MsgWaitForMultipleObjects(1,&thread,FALSE,50,QS_ALLINPUT);
        if(wait==WAIT_OBJECT_0)break;
        if(wait!=WAIT_TIMEOUT&&wait!=WAIT_OBJECT_0+1)self_exit(128);
        for(unsigned i=0;i<64&&PeekMessageW(&msg,NULL,0,0,PM_REMOVE);i++){
            if(msg.message==WM_QUIT)self_exit(130);
            TranslateMessage(&msg);DispatchMessageW(&msg);
        }
    }
    exit_query=GetExitCodeThread(thread,&exit_code);
    if(!exit_query||!InterlockedCompareExchange(&context.finished,0,0)||
       exit_code!=context.status||tid!=context.worker_tid||tid==context.main_tid)status=34;
    else if(exit_code)status=(int)exit_code;
    record("worker_exit","query_ok=%u observed_code=%lu recorded_code=%lu finished=%ld distinct_tid=%u",
           (unsigned)exit_query,(unsigned long)exit_code,(unsigned long)context.status,(long)context.finished,(unsigned)(tid!=context.main_tid));
    if(!CloseHandle(thread)&&!status)status=35;
cleanup:
    if(!DestroyWindow(top)&&!status)status=36;
    if(!UnregisterClassW(main_class,instance)&&!status)status=38;
    return status;
}
#else
static int run_role(void)
{
    wchar_t path[MAX_PATH],command[MAX_PATH+3];wchar_t *slash;
    STARTUPINFOW startup;PROCESS_INFORMATION child;DWORD length,wait,code=0,budget;int status=0;BOOL exit_query;
    length=GetModuleFileNameW(NULL,path,MAX_PATH);
    if(!length||length>=MAX_PATH||!(slash=wcsrchr(path,L'\\')))return 40;
    size_t prefix=(size_t)(slash+1-path);
    if(prefix+wcslen(L"user-child.exe")>=MAX_PATH)return 41;
    wcscpy(path+prefix,L"user-child.exe");
    int n=swprintf(command,sizeof(command)/sizeof(command[0]),L"\"%ls\"",path);
    if(n<=0||(size_t)n>=sizeof(command)/sizeof(command[0]))return 42;
    memset(&startup,0,sizeof(startup));startup.cb=(DWORD)sizeof(startup);memset(&child,0,sizeof(child));
    record("create_process","result=attempt child=user-child.exe inherited_handles=0 arguments=none");
    if(!CreateProcessW(path,command,NULL,NULL,FALSE,0,NULL,NULL,&startup,&child)){
        DWORD error=GetLastError();record("create_process","result=failed error=%lu",(unsigned long)error);return 43;}
    record("create_process","result=returned_success child_pid=%lu child_tid=%lu initialized=unverified",
           (unsigned long)child.dwProcessId,(unsigned long)child.dwThreadId);
    if(!CloseHandle(child.hThread))status=44;
    budget=remaining();if(!budget)self_exit(132);
    wait=WaitForSingleObject(child.hProcess,budget);
    if(wait!=WAIT_OBJECT_0){record("child_wait","result=%lu error_observation=%lu settlement=unverified",(unsigned long)wait,(unsigned long)GetLastError());self_exit(134);}
    exit_query=GetExitCodeProcess(child.hProcess,&code);
    if(!exit_query){DWORD e=GetLastError();record("GetExitCodeProcess","result=failed error=%lu",(unsigned long)e);if(!status)status=45;}
    else if(code!=CHILD_EXIT&&!status)status=46;
    record("child_exit","query_ok=%u observed_code=%lu expected=%u matches=%u native_settlement=unverified",
           (unsigned)exit_query,(unsigned long)code,(unsigned)CHILD_EXIT,(unsigned)(exit_query&&code==CHILD_EXIT));
    if(!CloseHandle(child.hProcess)&&!status)status=47;
    return status;
}
#endif

int main(void)
{
    int status;
    if(!begin())return finish(92);
    status=run_role();status=finish(status);
    /* The child's exact observed process result includes final log closure.
     * No file line claims to prove its own successful close. */
    return status?status:(PW_USER_CHILD?CHILD_EXIT:0);
}
