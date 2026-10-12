/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Compile the actual fixture; only its decision paths use these fake APIs.
 * Unused Windows entrypoints are dropped at link time. No Windows execution. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "chromium_ipc_mock/windows.h"
static int quiet_fputs(const char *text,FILE *stream){(void)text;(void)stream;return 0;}
static int quiet_fflush(FILE *stream){(void)stream;return 0;}
#define fputs quiet_fputs
#define fflush quiet_fflush
#define main fixture_main
#include "fixtures/windows_chromium_ipc.c"
#undef main
#undef fputs
#undef fflush
static struct {
    DWORD error,io_error,cancel_error,completion_error,completion_bytes;
    ULONG_PTR key;OVERLAPPED *completed;
    BOOL io_ok,cancel_ok,completion_ok,log_ok;
    unsigned cancels,completions,reads,releases;
    unsigned char memory[16384];
    DWORD protections[4],states[4],extra_protection;
    unsigned closes,foreign_captures,identity_waits;
    int missing_compare,same_control_bad,different_control_bad,candidate_same;
    int candidate_invalid,candidate_error,child_exited,child_exits_after_capture;
    int compare_unknown_error,duplicate_same_failed,included_invalid,included_control_bad;
} m;
DWORD GetLastError(void){return m.error;}
DWORD GetCurrentProcessId(void){return 100;}
ULONGLONG GetTickCount64(void){return 100;}
BOOL WriteFile(HANDLE h,const void *buffer,DWORD size,DWORD *bytes,void *overlapped)
{
    (void)h;(void)buffer;
    if(!overlapped){*bytes=m.log_ok?size:0;return m.log_ok;}
    *bytes=m.io_ok?size:0;m.error=m.io_error;return m.io_ok;
}
BOOL ReadFile(HANDLE h,void *buffer,DWORD size,DWORD *bytes,void *overlapped)
{ ++m.reads;memset(buffer,0,size);return WriteFile(h,buffer,size,bytes,overlapped); }
BOOL CancelIoEx(HANDLE h,OVERLAPPED *overlapped)
{(void)h;assert(overlapped);++m.cancels;m.error=m.cancel_error;return m.cancel_ok;}
BOOL GetQueuedCompletionStatus(HANDLE h,DWORD *bytes,ULONG_PTR *key,OVERLAPPED **overlapped,DWORD wait)
{
    (void)h;assert(wait==PW_IPC_WAIT_MS);++m.completions;
    *bytes=m.completion_bytes;*key=m.key;*overlapped=m.completed;m.error=m.completion_error;return m.completion_ok;
}
HANDLE GetCurrentProcess(void){return (HANDLE)(intptr_t)-1;}
HMODULE GetModuleHandleW(const wchar_t *name){(void)name;return (HMODULE)(uintptr_t)3;}
static BOOL WINAPI compare_mock(HANDLE first,HANDLE second)
{
    if(first==(HANDLE)(uintptr_t)11){
        assert(second==(HANDLE)(uintptr_t)43);m.error=m.included_control_bad?ERROR_NOT_SAME_OBJECT:0;
        return !m.included_control_bad;
    }
    assert(first==(HANDLE)(uintptr_t)10);
    if(second==(HANDLE)(uintptr_t)40){m.error=m.same_control_bad?ERROR_NOT_SAME_OBJECT:0;return !m.same_control_bad;}
    if(second==(HANDLE)(uintptr_t)41){m.error=m.different_control_bad?0:ERROR_NOT_SAME_OBJECT;return m.different_control_bad;}
    assert(second==(HANDLE)(uintptr_t)42);
    m.error=m.candidate_same?0:m.compare_unknown_error?ERROR_ACCESS_DENIED:ERROR_NOT_SAME_OBJECT;
    return m.candidate_same;
}
FARPROC GetProcAddress(HMODULE module,const char *name)
{
    FARPROC symbol=NULL;compare_objects_fn callback=compare_mock;(void)module;
    assert(!strcmp(name,"CompareObjectHandles"));
    if(m.missing_compare){m.error=127;return NULL;}
    memcpy(&symbol,&callback,sizeof(symbol));return symbol;
}
BOOL DuplicateHandle(HANDLE source,HANDLE original,HANDLE target,HANDLE *copy,DWORD rights,BOOL inherit,DWORD options)
{
    assert((original==(HANDLE)(uintptr_t)10||original==(HANDLE)(uintptr_t)11)&&target==GetCurrentProcess());
    assert(!rights&&!inherit&&options==DUPLICATE_SAME_ACCESS);
    if(source==GetCurrentProcess()){
        if(m.duplicate_same_failed){*copy=(HANDLE)(uintptr_t)99;m.error=ERROR_ACCESS_DENIED;return FALSE;}
        *copy=(HANDLE)(uintptr_t)40;return TRUE;
    }
    assert(source==(HANDLE)(uintptr_t)20);
    if(original==(HANDLE)(uintptr_t)11){
        if(m.included_invalid){*copy=(HANDLE)(uintptr_t)99;m.error=ERROR_INVALID_HANDLE;return FALSE;}
        *copy=(HANDLE)(uintptr_t)43;return TRUE;
    }
    ++m.foreign_captures;
    if(m.candidate_invalid||m.candidate_error){
        *copy=(HANDLE)(uintptr_t)99;m.error=m.candidate_error?ERROR_ACCESS_DENIED:ERROR_INVALID_HANDLE;return FALSE;
    }
    *copy=(HANDLE)(uintptr_t)42;return TRUE;
}
HANDLE CreateEventW(SECURITY_ATTRIBUTES *sa,BOOL manual,BOOL initial,const wchar_t *name)
{ assert(!sa&&manual&&!initial&&!name);return (HANDLE)(uintptr_t)41; }
BOOL CloseHandle(HANDLE h)
{
    /* Only successfully acquired parent-local copies may be closed. */
    assert(h==(HANDLE)(uintptr_t)40||h==(HANDLE)(uintptr_t)41||h==(HANDLE)(uintptr_t)42||h==(HANDLE)(uintptr_t)43);
    ++m.closes;return TRUE;
}
DWORD WaitForSingleObject(HANDLE h,DWORD wait)
{
    assert(h==(HANDLE)(uintptr_t)20&&!wait);++m.identity_waits;
    return m.child_exited||(m.child_exits_after_capture&&m.foreign_captures)?WAIT_OBJECT_0:WAIT_TIMEOUT;
}
/* PAGE_* deliberately have signed int type, matching the Windows SDK.
 * The returned Protect field remains an exact unsigned 32-bit DWORD. */
_Static_assert(_Generic(PAGE_READONLY,int:1,default:0),"SDK protection constant type");
_Static_assert(_Generic(PAGE_READWRITE,int:1,default:0),"SDK protection constant type");
_Static_assert(sizeof(DWORD)==4 && (DWORD)-1>0,"Protect is unsigned 32-bit");
void *VirtualAlloc(void *address,SIZE_T size,DWORD type,DWORD protection)
{
    assert(protection==PAGE_READWRITE);
    if(!address){
        assert(size==sizeof(m.memory)&&type==(MEM_RESERVE|MEM_COMMIT));
        for(unsigned i=0;i<4;++i){m.protections[i]=PAGE_READWRITE;m.states[i]=MEM_COMMIT;}
        return m.memory;
    }
    assert(address==m.memory+8192&&size==4096&&type==MEM_COMMIT);
    memset(address,0,size);m.protections[2]=protection;m.states[2]=MEM_COMMIT;return address;
}
BOOL VirtualProtect(void *address,SIZE_T size,DWORD protection,DWORD *old)
{
    assert(address==m.memory+4096&&size==4096&&protection==PAGE_READONLY);
    *old=m.protections[1];m.protections[1]=protection;return TRUE;
}
SIZE_T VirtualQuery(const void *address,MEMORY_BASIC_INFORMATION *info,SIZE_T size)
{
    size_t offset=(const unsigned char *)address-m.memory;unsigned page=(unsigned)(offset/4096);
    assert(offset<sizeof(m.memory)&&offset%4096==0&&size==sizeof(*info));
    memset(info,0,size);info->State=m.states[page];info->Protect=m.protections[page];
    if(page==0)info->Protect|=m.extra_protection;
    return sizeof(*info);
}
BOOL VirtualFree(void *address,SIZE_T size,DWORD type)
{
    if(type==MEM_RELEASE){assert(address==m.memory&&!size);++m.releases;return TRUE;}
    assert(address==m.memory+8192&&size==4096&&type==MEM_DECOMMIT);
    m.states[2]=MEM_RESERVE;m.protections[2]=0;return TRUE;
}
static void reset(void)
{
    memset(&m,0,sizeof(m));memset(slots,0,sizeof(slots));m.log_ok=1;
    log_file=(HANDLE)(uintptr_t)1;selected=PW_IPC_PIPE;nonce=1;parent_pid=100;epoch=100;
    worker=log_failed=close_failed=unsettled=stage_failed=0;log_bytes=handles=0;
    m.completed=&slots[0].ov;m.key=IO_KEY;
}
int main(void)
{
    HANDLE pipe=(HANDLE)(uintptr_t)2,port=(HANDLE)(uintptr_t)3;unsigned checks=0;
#define CHECK(x) do { ++checks;assert(x); } while(0)
    reset();m.io_ok=1;m.completion_ok=1;m.completion_bytes=sizeof(struct pw_ipc_packet);
    CHECK(submit_io(pipe,&slots[0],0,0));CHECK(slots[0].pending);
    CHECK(complete_io(port,&slots[0],sizeof(struct pw_ipc_packet),0));CHECK(!slots[0].pending&&!stage_failed);
    reset();m.io_error=ERROR_IO_PENDING;
    CHECK(submit_io(pipe,&slots[0],0,1));m.cancel_ok=1;m.completion_error=ERROR_OPERATION_ABORTED;
    CHECK(cancel_and_drain(pipe,port,&slots[0],1));CHECK(!slots[0].pending&&!stage_failed&&m.cancels==1);
    reset();slots[0].pending=1;m.cancel_error=ERROR_ACCESS_DENIED;m.completion_error=ERROR_OPERATION_ABORTED;
    CHECK(cancel_and_drain(pipe,port,&slots[0],1));CHECK(stage_failed);
    CHECK(!pw_ipc_final_ok(!stage_failed,0,0,0,1,unsettled));
    reset();slots[0].pending=1;m.key=IO_KEY+1;m.completion_ok=1;m.completion_bytes=64;
    CHECK(!complete_io(port,&slots[0],64,0));CHECK(slots[0].pending&&unsettled&&stage_failed);
    reset();slots[0].pending=1;m.completed=NULL;m.completion_error=WAIT_TIMEOUT;
    CHECK(!complete_io(port,&slots[0],64,0));CHECK(slots[0].pending&&stage_failed);
    m.cancel_error=ERROR_NOT_FOUND;m.completed=&slots[0].ov;m.completion_error=ERROR_OPERATION_ABORTED;
    CHECK(cancel_and_drain(pipe,port,&slots[0],0));CHECK(!slots[0].pending&&stage_failed);
    reset();slots[0].pending=1;m.cancel_error=ERROR_NOT_FOUND;m.completion_error=ERROR_OPERATION_ABORTED;
    CHECK(cancel_and_drain(pipe,port,&slots[0],1));CHECK(!slots[0].pending&&!stage_failed);
    reset();slots[0].pending=1;m.cancel_ok=1;m.completed=NULL;m.completion_error=WAIT_TIMEOUT;
    CHECK(!settle_slots(pipe,port));CHECK(slots[0].pending&&unsettled&&stage_failed);
    reset();m.io_error=ERROR_BROKEN_PIPE;
    CHECK(!submit_io(pipe,&slots[0],0,0));CHECK(!slots[0].pending&&stage_failed);
    reset();m.io_ok=1;CHECK(!submit_io(pipe,&slots[0],0,1));CHECK(slots[0].pending);
    reset();m.log_ok=0;trace("final","pass",0,0,0,0,0);CHECK(log_failed);
    reset();log_bytes=PW_IPC_LOG_LIMIT;trace("final","pass",0,0,0,0,0);CHECK(log_failed);
    reset();selected=PW_IPC_PAGES;CHECK(pages());CHECK(!stage_failed&&m.releases==1);
    reset();selected=PW_IPC_PAGES;m.extra_protection=UINT32_C(0x80000000);
    CHECK(!pages());CHECK(stage_failed&&m.releases==1);
    reset();selected=PW_IPC_PAGES;m.extra_protection=PAGE_READONLY;
    CHECK(!pages());CHECK(stage_failed&&m.releases==1);
    {
        struct child child;memset(&child,0,sizeof(child));
        child.decoy=(HANDLE)(uintptr_t)10;child.release=(HANDLE)(uintptr_t)11;child.pi.hProcess=(HANDLE)(uintptr_t)20;
        reset();CHECK(excluded_object(&child));CHECK(!stage_failed&&!handles&&m.closes==4&&m.foreign_captures==1);
        /* Original false positive: a valid recycled numeric handle denotes
         * a different object. It is now correctly accepted, never signaled. */
        reset();m.candidate_invalid=1;CHECK(excluded_object(&child));CHECK(!stage_failed&&!handles&&m.closes==3);
        reset();m.candidate_same=1;CHECK(!excluded_object(&child));CHECK(stage_failed&&!handles&&m.closes==4);
        reset();m.same_control_bad=1;CHECK(!excluded_object(&child));CHECK(stage_failed&&!handles&&!m.foreign_captures);
        reset();m.different_control_bad=1;CHECK(!excluded_object(&child));CHECK(stage_failed&&!handles&&!m.foreign_captures);
        reset();m.candidate_error=1;CHECK(!excluded_object(&child));CHECK(stage_failed&&!handles&&m.closes==3);
        reset();m.compare_unknown_error=1;CHECK(!excluded_object(&child));CHECK(stage_failed&&!handles&&m.closes==4);
        reset();m.child_exited=1;CHECK(!excluded_object(&child));CHECK(stage_failed&&!handles&&!m.foreign_captures);
        reset();m.child_exits_after_capture=1;m.candidate_invalid=1;
        CHECK(!excluded_object(&child));CHECK(stage_failed&&!handles&&m.closes==3);
        reset();m.included_invalid=1;m.candidate_invalid=1;
        CHECK(!excluded_object(&child));CHECK(stage_failed&&!handles&&!m.foreign_captures&&m.closes==2);
        reset();m.included_control_bad=1;
        CHECK(!excluded_object(&child));CHECK(stage_failed&&!handles&&!m.foreign_captures&&m.closes==3);
        reset();m.missing_compare=1;CHECK(!excluded_object(&child));CHECK(stage_failed&&!handles&&!m.closes);
        reset();m.duplicate_same_failed=1;CHECK(!excluded_object(&child));CHECK(stage_failed&&!handles&&!m.closes);
    }
    printf("windows_chromium_ipc_fixture: %u mocked decision-path checks passed\n",checks);
    return 0;
}
