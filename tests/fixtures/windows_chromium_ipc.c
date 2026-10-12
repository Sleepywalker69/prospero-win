/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Original Windows-only API probes. No vendor code, networking, privilege or
 * sandbox changes, process termination, native-loader calls or admission. */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "windows_chromium_ipc_contract.h"
#ifndef SECTION_QUERY
#define SECTION_QUERY 0x0001
#endif
#define OWN_RIGHTS (PROCESS_VM_READ|PROCESS_VM_WRITE|PROCESS_VM_OPERATION|PROCESS_QUERY_INFORMATION)
#define IO_KEY ((ULONG_PTR)0x50494331)
static const char *case_names[]={"invalid","self-memory","live-memory","suspended-memory",
    "section-readonly","section-duplicate","section-close-source","mojo-pipe","page-regression"};
static DWORD nonce, parent_pid;
static unsigned selected, handles, log_bytes;
static int worker, log_failed, close_failed, unsettled, stage_failed;
static HANDLE log_file=INVALID_HANDLE_VALUE;
static volatile DWORD private_value=PW_IPC_A;
static ULONGLONG epoch;
struct child { PROCESS_INFORMATION pi; HANDLE rx,tx,release,decoy,reference; int created,resumed; };
struct io_slot { OVERLAPPED ov; struct pw_ipc_packet data; int pending; };
/* Process-lifetime storage: on a missing cancellation completion, nothing in
 * the I/O's reachable storage is freed or reused before process teardown. */
static struct io_slot slots[4];
static OVERLAPPED connection;
typedef LONG (NTAPI *nt_read_fn)(HANDLE,const void *,void *,SIZE_T,SIZE_T *);
typedef LONG (NTAPI *nt_write_fn)(HANDLE,void *,const void *,SIZE_T,SIZE_T *);
typedef LONG (NTAPI *nt_section_fn)(HANDLE,ULONG,void *,ULONG,ULONG *);
typedef BOOL (WINAPI *compare_objects_fn)(HANDLE,HANDLE);
typedef LONG (NTAPI *query_object_fn)(HANDLE,ULONG,void *,ULONG,ULONG *);
struct section_basic { void *base; ULONG attributes; LARGE_INTEGER size; };

static void trace(const char *stage,const char *result,DWORD error,LONG status,
                  SIZE_T bytes,uint64_t a,uint64_t b)
{
    char line[720]; DWORD wrote=0; int len;
    unsigned budget=!strcmp(stage,"wait_child_exit")?PW_IPC_CHILD_MS+PW_IPC_WAIT_MS:
        !strcmp(stage,"WaitForSingleObject_release")?PW_IPC_CHILD_MS:
        !strcmp(stage,"suspended_no_application_record")?100u:PW_IPC_WAIT_MS;
    if(!strcmp(result,"fail")||!strcmp(result,"timeout")||!strcmp(result,"unsupported")||
       !strcmp(result,"not_run"))stage_failed=1;
    len=snprintf(line,sizeof(line),"PW_CHROMIUM_IPC schema=1 role=%s case=%s stage=%s result=%s "
        "nonce=%lu pid=%lu parent=%lu bits=%u elapsed_ms=%llu deadline_ms=%u "
        "error=%lu ntstatus=%lu bytes=%llu a=%llu b=%llu\n",
        worker?"child":"parent",case_names[selected],stage,result,(unsigned long)nonce,
        (unsigned long)GetCurrentProcessId(),(unsigned long)parent_pid,(unsigned)(8*sizeof(void *)),
        (unsigned long long)(GetTickCount64()-epoch),budget,(unsigned long)error,
        (unsigned long)(uint32_t)status,(unsigned long long)bytes,
        (unsigned long long)a,(unsigned long long)b);
    if(len<0 || (size_t)len>=sizeof(line) || (unsigned)len>PW_IPC_LOG_LIMIT-log_bytes){log_failed=1;return;}
    log_bytes+=(unsigned)len;
    if(log_file==INVALID_HANDLE_VALUE || !WriteFile(log_file,line,(DWORD)len,&wrote,NULL) || wrote!=(DWORD)len)log_failed=1;
    (void)fputs(line,stdout);(void)fflush(stdout);
}
static void attempt(const char *stage) { trace(stage,"attempt",0,0,0,0,0); }
static int observation(const char *stage,int ok,DWORD error,LONG status,SIZE_T bytes,uint64_t a,uint64_t b)
{ trace(stage,ok?"pass":"fail",error,status,bytes,a,b);return ok; }
static HANDLE own(HANDLE h) { if(h && h!=INVALID_HANDLE_VALUE)++handles;return h; }
static int close_handle(HANDLE *h)
{
    BOOL ok; DWORD error;
    if(!*h || *h==INVALID_HANDLE_VALUE){*h=NULL;return 1;}
    attempt("CloseHandle");ok=CloseHandle(*h);error=ok?0:GetLastError();
    observation("CloseHandle",ok,error,0,0,(uint64_t)(uintptr_t)*h,0);
    if(ok){*h=NULL;--handles;}else close_failed=1;
    return !!ok;
}
static void start_log(void)
{
    wchar_t path[120];
    (void)swprintf(path,sizeof(path)/sizeof(path[0]),L"ipc-%lu-%lu.log",
                   (unsigned long)nonce,(unsigned long)GetCurrentProcessId());
    log_file=CreateFileW(path,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    if(log_file==INVALID_HANDLE_VALUE)log_failed=1;
}
static struct pw_ipc_packet packet(unsigned kind,unsigned seq)
{
    struct pw_ipc_packet p;
    memset(&p,0,sizeof(p));p.magic=PW_IPC_MAGIC;p.version=PW_IPC_VERSION;p.bytes=sizeof(p);
    p.kind=kind;p.sequence=seq;p.nonce=nonce;p.sender=GetCurrentProcessId();p.parent=parent_pid;
    p.bits=8*sizeof(void *);return p;
}
static int send_packet(HANDLE pipe,const struct pw_ipc_packet *p)
{
    DWORD wrote=0,error;BOOL ok;
    attempt("control_WriteFile");ok=WriteFile(pipe,p,sizeof(*p),&wrote,NULL);error=ok?0:GetLastError();
    return observation("control_WriteFile",ok&&wrote==sizeof(*p),error,0,wrote,p->kind,p->sequence);
}
static int receive_packet(HANDLE pipe,struct pw_ipc_packet *p,DWORD sender,unsigned seq,unsigned kind)
{
    ULONGLONG start=GetTickCount64(),last=start,now; DWORD available=0,got=0,error=0;BOOL ok=FALSE;
    attempt("control_read");
    for(;;){
        now=GetTickCount64();if(!pw_ipc_remaining(start,last,now,PW_IPC_WAIT_MS)){error=WAIT_TIMEOUT;break;}last=now;
        if(!PeekNamedPipe(pipe,NULL,0,NULL,&available,NULL)){error=GetLastError();break;}
        if(available>=sizeof(*p)){
            ok=ReadFile(pipe,p,sizeof(*p),&got,NULL);error=ok?0:GetLastError();
            ok=ok&&pw_ipc_packet_valid(p,got,nonce,sender,parent_pid,seq,kind,8*sizeof(void *));break;
        }
        Sleep(5);
    }
    trace("control_read",ok?"pass":error==WAIT_TIMEOUT?"timeout":"fail",error,0,got,kind,seq);
    return !!ok;
}
static int pipe_pair(HANDLE *rx,HANDLE *tx,SECURITY_ATTRIBUTES *sa)
{
    HANDLE r=NULL,w=NULL;BOOL ok;DWORD error;
    attempt("CreatePipe");ok=CreatePipe(&r,&w,sa,4096);error=ok?0:GetLastError();
    if(!observation("CreatePipe",ok,error,0,0,0,0))return 0;
    *rx=own(r);*tx=own(w);return 1;
}
static int inherit_off(HANDLE h)
{
    BOOL ok;DWORD error;attempt("SetHandleInformation");ok=SetHandleInformation(h,HANDLE_FLAG_INHERIT,0);
    error=ok?0:GetLastError();return observation("SetHandleInformation",ok,error,0,0,(uint64_t)(uintptr_t)h,0);
}
static unsigned explicit_handle_list(HANDLE list[5],HANDLE rx,HANDLE tx,HANDLE release,
                                     HANDLE reference,HANDLE extra,HANDLE excluded)
{
    unsigned i,j,count=extra?5u:4u;
    list[0]=rx;list[1]=tx;list[2]=release;list[3]=reference;list[4]=extra;
    if(!excluded||excluded==INVALID_HANDLE_VALUE)return 0;
    for(i=0;i<count;++i){
        if(!list[i]||list[i]==INVALID_HANDLE_VALUE||list[i]==excluded)return 0;
        for(j=0;j<i;++j)if(list[i]==list[j])return 0;
    }
    return count;
}
static int launch(struct child *c,HANDLE extra,int suspended)
{
    SECURITY_ATTRIBUTES sa={sizeof(sa),NULL,TRUE};STARTUPINFOEXW si;
    HANDLE child_rx=NULL,child_tx=NULL,list[5]; SIZE_T bytes=0;BOOL ok;DWORD error;
    wchar_t path[MAX_PATH],command[1024];DWORD path_size;unsigned list_count;int length,initialized=0,result=0;
    memset(c,0,sizeof(*c));memset(&si,0,sizeof(si));si.StartupInfo.cb=sizeof(si);
    if(!pipe_pair(&c->rx,&child_tx,&sa)||!pipe_pair(&child_rx,&c->tx,&sa)||
       !inherit_off(c->rx)||!inherit_off(c->tx))goto done;
    attempt("CreateEvent_release");c->release=own(CreateEventW(&sa,TRUE,FALSE,NULL));
    if(!observation("CreateEvent_release",!!c->release,c->release?0:GetLastError(),0,0,0,0))goto done;
    attempt("CreateEvent_excluded_decoy");c->decoy=own(CreateEventW(&sa,TRUE,FALSE,NULL));
    if(!observation("CreateEvent_excluded_decoy",!!c->decoy,c->decoy?0:GetLastError(),0,0,0,0))goto done;
    attempt("DuplicateHandle_inherited_reference");
    ok=DuplicateHandle(GetCurrentProcess(),c->decoy,GetCurrentProcess(),&c->reference,0,TRUE,DUPLICATE_SAME_ACCESS);
    error=ok?0:GetLastError();if(ok)own(c->reference);else c->reference=NULL;
    if(!observation("DuplicateHandle_inherited_reference",ok,error,0,0,0,0))goto done;
    list_count=explicit_handle_list(list,child_rx,child_tx,c->release,c->reference,extra,c->decoy);
    if(!observation("identity_reference_values",list_count!=0,0,0,0,
        (uint64_t)(uintptr_t)c->decoy,(uint64_t)(uintptr_t)c->reference))goto done;
    attempt("InitializeProcThreadAttributeList_size");
    ok=InitializeProcThreadAttributeList(NULL,1,0,&bytes);error=ok?0:GetLastError();
    if(!observation("InitializeProcThreadAttributeList_size",!ok&&error==ERROR_INSUFFICIENT_BUFFER&&bytes,
                    error,0,bytes,0,0))goto done;
    attempt("attribute_heap");si.lpAttributeList=(LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(),0,bytes);
    if(!observation("attribute_heap",!!si.lpAttributeList,0,0,bytes,0,0))goto done;
    attempt("InitializeProcThreadAttributeList");ok=InitializeProcThreadAttributeList(si.lpAttributeList,1,0,&bytes);
    if(!observation("InitializeProcThreadAttributeList",ok,ok?0:GetLastError(),0,bytes,0,0))goto done;
    initialized=1;attempt("UpdateProcThreadAttribute_HANDLE_LIST");
    ok=UpdateProcThreadAttribute(si.lpAttributeList,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,list,
        list_count*sizeof(HANDLE),NULL,NULL);
    if(!observation("UpdateProcThreadAttribute_HANDLE_LIST",ok,ok?0:GetLastError(),0,0,list_count,0))goto done;
    attempt("GetModuleFileNameW");path_size=GetModuleFileNameW(NULL,path,MAX_PATH);
    if(!observation("GetModuleFileNameW",path_size&&path_size<MAX_PATH,
        path_size&&path_size<MAX_PATH?0:GetLastError(),0,path_size,0,0))goto done;
    length=swprintf(command,sizeof(command)/sizeof(command[0]),L"\"%ls\" --worker %u %lu %lu %llu %llu %llu %llu %llu %llu",
        path,selected,(unsigned long)nonce,(unsigned long)parent_pid,
        (unsigned long long)(uintptr_t)child_rx,(unsigned long long)(uintptr_t)child_tx,
        (unsigned long long)(uintptr_t)c->release,(unsigned long long)(uintptr_t)extra,
        (unsigned long long)(uintptr_t)c->decoy,(unsigned long long)(uintptr_t)c->reference);
    if(length<0||(size_t)length>=sizeof(command)/sizeof(command[0]))goto done;
    attempt("CreateProcessW_handle_list");
    ok=CreateProcessW(path,command,NULL,NULL,TRUE,EXTENDED_STARTUPINFO_PRESENT|(suspended?CREATE_SUSPENDED:0),
                      NULL,NULL,&si.StartupInfo,&c->pi);error=ok?0:GetLastError();
    if(!ok)memset(&c->pi,0,sizeof(c->pi));
    else{own(c->pi.hProcess);own(c->pi.hThread);c->created=1;c->resumed=!suspended;}
    result=observation("CreateProcessW_handle_list",ok,error,0,0,c->pi.dwProcessId,suspended);
 done:
    close_handle(&child_rx);close_handle(&child_tx);
    if(initialized)DeleteProcThreadAttributeList(si.lpAttributeList);
    if(si.lpAttributeList)HeapFree(GetProcessHeap(),0,si.lpAttributeList);
    return result;
}
static int release_child(struct child *c)
{
    BOOL ok; if(!c->release)return 1;
    attempt("SetEvent_release");ok=SetEvent(c->release);
    return observation("SetEvent_release",ok,ok?0:GetLastError(),0,0,0,0);
}
static int cleanup_child(struct child *c,DWORD *exit_code)
{
    int waited=1;DWORD result;*exit_code=0;
    if(c->created){
        /* A failed suspended experiment is only resumed cooperatively so its
         * own finite worker path can exit. No kill or synthetic death record. */
        if(!c->resumed){
            attempt("cleanup_ResumeThread");result=ResumeThread(c->pi.hThread);
            observation("cleanup_ResumeThread",result!=(DWORD)-1,result==(DWORD)-1?GetLastError():0,0,0,result,0);
            c->resumed=result!=(DWORD)-1;
        }
        (void)release_child(c);
        attempt("wait_child_exit");result=WaitForSingleObject(c->pi.hProcess,PW_IPC_CHILD_MS+PW_IPC_WAIT_MS);
        waited=result==WAIT_OBJECT_0;
        trace("wait_child_exit",waited?"pass":result==WAIT_TIMEOUT?"timeout":"fail",
              result==WAIT_FAILED?GetLastError():0,0,0,result,c->pi.dwProcessId);
        if(waited){
            BOOL ok=GetExitCodeProcess(c->pi.hProcess,exit_code);
            waited=observation("GetExitCodeProcess",ok,ok?0:GetLastError(),0,0,*exit_code,PW_IPC_EXIT);
        }
        if(!waited)unsettled=1;
    }
    close_handle(&c->pi.hThread);close_handle(&c->pi.hProcess);
    close_handle(&c->rx);close_handle(&c->tx);close_handle(&c->release);close_handle(&c->reference);close_handle(&c->decoy);
    return waited;
}
static int memory_api(HANDLE process,void *address,const char *prefix,int native,int write,DWORD expected)
{
    DWORD value=write?expected:0,error=0;SIZE_T moved=0;BOOL ok;LONG status=0;char name[96];
    HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");
    (void)snprintf(name,sizeof(name),"%s_%s",prefix,native?(write?"NtWriteVirtualMemory":"NtReadVirtualMemory"):
                                                  (write?"WriteProcessMemory":"ReadProcessMemory"));
    attempt(name);
    if(native){
        FARPROC symbol=GetProcAddress(ntdll,write?"NtWriteVirtualMemory":"NtReadVirtualMemory");
        nt_read_fn read_fn=NULL;nt_write_fn write_fn=NULL;
        if(!symbol){trace(name,"unsupported",GetLastError(),0,0,0,0);return 0;}
        /* Copy a same-width Windows procedure pointer without a C function
         * pointer cast warning in the strict MSVC build. */
        _Static_assert(sizeof(symbol)==sizeof(read_fn),"Windows procedure pointer width");
        if(write){memcpy(&write_fn,&symbol,sizeof(write_fn));status=write_fn(process,address,&value,sizeof(value),&moved);}
        else{memcpy(&read_fn,&symbol,sizeof(read_fn));status=read_fn(process,address,&value,sizeof(value),&moved);}
        ok=status>=0;
    }else{
        ok=write?WriteProcessMemory(process,address,&value,sizeof(value),&moved):
                 ReadProcessMemory(process,address,&value,sizeof(value),&moved);error=ok?0:GetLastError();
    }
    return observation(name,pw_ipc_transfer_ok(ok,moved,sizeof(value),write?expected:value,expected),
                       error,status,moved,(uint64_t)(uintptr_t)address,value);
}
static int denied_memory(HANDLE process,void *address,int native,int write)
{
    DWORD value=write?PW_IPC_B:0xdeadbeefu,error=0;SIZE_T moved=0;BOOL ok;LONG status=0;
    const char *stage=native?(write?"reduced_NtWriteVirtualMemory":"reduced_NtReadVirtualMemory"):
        (write?"reduced_WriteProcessMemory":"reduced_ReadProcessMemory");
    attempt(stage);
    if(native){
        FARPROC symbol=GetProcAddress(GetModuleHandleW(L"ntdll.dll"),write?"NtWriteVirtualMemory":"NtReadVirtualMemory");
        nt_read_fn read_fn=NULL;nt_write_fn write_fn=NULL;
        if(!symbol){trace(stage,"unsupported",GetLastError(),0,0,0,0);return 0;}
        if(write){memcpy(&write_fn,&symbol,sizeof(write_fn));status=write_fn(process,address,&value,sizeof(value),&moved);}
        else{memcpy(&read_fn,&symbol,sizeof(read_fn));status=read_fn(process,address,&value,sizeof(value),&moved);}
        ok=(uint32_t)status==UINT32_C(0xc0000022);
    }else{
        BOOL success=write?WriteProcessMemory(process,address,&value,sizeof(value),&moved):
                           ReadProcessMemory(process,address,&value,sizeof(value),&moved);
        error=success?0:GetLastError();ok=!success&&error==ERROR_ACCESS_DENIED;
    }
    return observation(stage,ok&&moved==0&&(write||value==0xdeadbeefu),error,status,moved,value,0);
}
static int self_memory(void)
{
    HANDLE real=NULL,reduced=NULL,query_only=NULL;int ok=1;unsigned mode,native;
    attempt("OpenProcess_self");real=own(OpenProcess(OWN_RIGHTS,FALSE,GetCurrentProcessId()));
    if(!observation("OpenProcess_self",!!real,real?0:GetLastError(),0,0,0,0))return 0;
    for(mode=0;mode<2;++mode)for(native=0;native<2;++native){
        HANDLE h=mode?real:GetCurrentProcess();const char *prefix=mode?"real_self":"pseudo_self";
        private_value=PW_IPC_A;ok&=memory_api(h,(void *)&private_value,prefix,native,0,PW_IPC_A);
        private_value=PW_IPC_A;ok&=memory_api(h,(void *)&private_value,prefix,native,1,PW_IPC_B);
        ok&=observation("self_actual_value",private_value==PW_IPC_B,0,0,sizeof(DWORD),private_value,PW_IPC_B);
        private_value=PW_IPC_A;
    }
    reduced=own(OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION,FALSE,GetCurrentProcessId()));
    if(!reduced)ok=0;else{ok&=denied_memory(reduced,(void *)&private_value,0,1);
        ok&=denied_memory(reduced,(void *)&private_value,1,1);
        ok&=observation("self_reduced_unchanged",private_value==PW_IPC_A,0,0,0,private_value,PW_IPC_A);}
    query_only=own(OpenProcess(PROCESS_QUERY_INFORMATION,FALSE,GetCurrentProcessId()));
    if(!query_only)ok=0;else{ok&=denied_memory(query_only,(void *)&private_value,0,0);
        ok&=denied_memory(query_only,(void *)&private_value,1,0);}
    close_handle(&query_only);close_handle(&reduced);close_handle(&real);return ok;
}
static int section_values(void *view,int changed)
{
    unsigned i;int ok=1;
    for(i=0;i<5;++i){
        DWORD actual=*(volatile DWORD *)((unsigned char *)view+pw_ipc_offsets[i]);
        DWORD wanted=nonce^pw_ipc_offsets[i]^(changed?PW_IPC_B:PW_IPC_A);
        ok&=observation("section_byte_visibility",actual==wanted,0,0,sizeof(DWORD),pw_ipc_offsets[i],actual);
    }
    return ok;
}
static void write_section(void *view,int changed)
{
    unsigned i;
    for(i=0;i<5;++i)InterlockedExchange((volatile LONG *)((unsigned char *)view+pw_ipc_offsets[i]),
                                      (LONG)(nonce^pw_ipc_offsets[i]^(changed?PW_IPC_B:PW_IPC_A)));
}
static int section_child(HANDLE section,int readonly)
{
    void *view=NULL,*unexpected=NULL;HANDLE upgrade=NULL;int ok=1;BOOL duplicate;DWORD error;
    nt_section_fn query=NULL;FARPROC symbol;LONG status;struct section_basic info;ULONG returned=0;
    symbol=GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQuerySection");
    if(!symbol){trace("NtQuerySection","unsupported",GetLastError(),0,0,0,0);return 0;}
    memcpy(&query,&symbol,sizeof(query));memset(&info,0,sizeof(info));
    attempt("NtQuerySection");status=query(section,0,&info,sizeof(info),&returned);
    ok&=observation("NtQuerySection",status>=0&&returned==sizeof(info)&&!(info.attributes&SEC_IMAGE)&&
        info.size.QuadPart==PW_IPC_SECTION_SIZE,0,status,returned,info.attributes,(uint64_t)info.size.QuadPart);
    attempt("MapViewOfFile_section");view=MapViewOfFile(section,readonly?FILE_MAP_READ:FILE_MAP_READ|FILE_MAP_WRITE,0,0,PW_IPC_SECTION_SIZE);
    if(!observation("MapViewOfFile_section",!!view,view?0:GetLastError(),0,PW_IPC_SECTION_SIZE,(uint64_t)(uintptr_t)view,readonly))return 0;
    ok&=section_values(view,0);
    if(readonly){
        attempt("MapViewOfFile_write_denied");unexpected=MapViewOfFile(section,FILE_MAP_WRITE,0,0,PW_IPC_SECTION_SIZE);
        error=unexpected?0:GetLastError();ok&=observation("MapViewOfFile_write_denied",!unexpected&&error==ERROR_ACCESS_DENIED,error,0,0,0,0);
        if(unexpected&&!UnmapViewOfFile(unexpected))close_failed=1;
        attempt("DuplicateHandle_write_upgrade_denied");
        duplicate=DuplicateHandle(GetCurrentProcess(),section,GetCurrentProcess(),&upgrade,FILE_MAP_WRITE,FALSE,0);
        error=duplicate?0:GetLastError();if(duplicate)own(upgrade);else upgrade=NULL;
        ok&=observation("DuplicateHandle_write_upgrade_denied",!duplicate&&error==ERROR_ACCESS_DENIED,error,0,0,0,0);
        close_handle(&upgrade);
    }else{write_section(view,1);ok&=section_values(view,1);}
    attempt("UnmapViewOfFile_section");
    duplicate=UnmapViewOfFile(view);error=duplicate?0:GetLastError();
    if(!observation("UnmapViewOfFile_section",duplicate,error,0,0,(uint64_t)(uintptr_t)view,0)){ok=0;close_failed=1;}
    return ok;
}
static HANDLE completion_port(HANDLE pipe)
{
    HANDLE port;attempt("CreateIoCompletionPort");port=own(CreateIoCompletionPort(pipe,NULL,IO_KEY,1));
    observation("CreateIoCompletionPort",!!port,port?0:GetLastError(),0,0,(uint64_t)(uintptr_t)pipe,IO_KEY);
    return port;
}
static int submit_io(HANDLE pipe,struct io_slot *slot,int write,int require_pending)
{
    BOOL ok;DWORD bytes=0,error;
    attempt(write?"overlapped_WriteFile":"overlapped_ReadFile");
    ok=write?WriteFile(pipe,&slot->data,sizeof(slot->data),&bytes,&slot->ov):
             ReadFile(pipe,&slot->data,sizeof(slot->data),&bytes,&slot->ov);
    error=ok?0:GetLastError();
    /* Even immediate success queues an IOCP packet: no skip-on-success mode. */
    slot->pending=ok||error==ERROR_IO_PENDING;
    trace(write?"overlapped_WriteFile":"overlapped_ReadFile",ok?"immediate":error==ERROR_IO_PENDING?"pending":"fail",
          error,0,bytes,require_pending,0);
    return slot->pending&&(!require_pending||(!ok&&error==ERROR_IO_PENDING));
}
static int complete_io(HANDLE port,struct io_slot *slot,DWORD expected_bytes,DWORD expected_error)
{
    DWORD bytes=0,error;ULONG_PTR key=0;OVERLAPPED *overlapped=NULL;BOOL ok;
    attempt("GetQueuedCompletionStatus");
    ok=GetQueuedCompletionStatus(port,&bytes,&key,&overlapped,PW_IPC_WAIT_MS);error=ok?0:GetLastError();
    if(overlapped==&slot->ov && key==IO_KEY)slot->pending=0;
    else if(overlapped)unsettled=1;
    trace("GetQueuedCompletionStatus",pw_ipc_completion_ok(ok,error,bytes,expected_bytes,key,IO_KEY,
          overlapped,&slot->ov,expected_error)?"pass":!overlapped&&error==WAIT_TIMEOUT?"timeout":"fail",
          error,0,bytes,key,(uint64_t)(uintptr_t)overlapped);
    return pw_ipc_completion_ok(ok,error,bytes,expected_bytes,key,IO_KEY,overlapped,&slot->ov,expected_error);
}
static int cancel_and_drain(HANDLE pipe,HANDLE port,struct io_slot *slot,int require_aborted)
{
    BOOL ok;DWORD error;
    if(!slot->pending)return !require_aborted;
    attempt("CancelIoEx");ok=CancelIoEx(pipe,&slot->ov);error=ok?0:GetLastError();
    observation("CancelIoEx",ok||error==ERROR_NOT_FOUND,error,0,0,require_aborted,0);
    /* ERROR_NOT_FOUND is a cancellation race, never a completion receipt. */
    if(require_aborted)return complete_io(port,slot,0,ERROR_OPERATION_ABORTED);
    {
        DWORD bytes=0;ULONG_PTR key=0;OVERLAPPED *overlapped=NULL;BOOL completed;
        attempt("cleanup_GetQueuedCompletionStatus");
        completed=GetQueuedCompletionStatus(port,&bytes,&key,&overlapped,PW_IPC_WAIT_MS);
        error=completed?0:GetLastError();
        if(overlapped==&slot->ov && key==IO_KEY)slot->pending=0;
        observation("cleanup_GetQueuedCompletionStatus",!slot->pending,error,0,bytes,key,(uint64_t)(uintptr_t)overlapped);
        return !slot->pending;
    }
}
static int settle_slots(HANDLE pipe,HANDLE port)
{
    unsigned i;int ok=1;
    for(i=0;i<4;++i)if(slots[i].pending){
        if(!port||!cancel_and_drain(pipe,port,&slots[i],0)){unsettled=1;ok=0;}
    }
    return ok;
}
static int pipe_child(HANDLE pipe,HANDLE rx,HANDLE tx)
{
    HANDLE port=completion_port(pipe);struct pw_ipc_packet control;int ok=0;
    if(!port)goto done;
    if(!receive_packet(rx,&control,parent_pid,1,PW_IPC_COMMAND))goto done;
    slots[0].data=packet(PW_IPC_DATA,1);slots[0].data.value=nonce^PW_IPC_A;
    if(!submit_io(pipe,&slots[0],1,0)||!complete_io(port,&slots[0],sizeof(slots[0].data),0))goto done;
    if(!submit_io(pipe,&slots[1],0,0)||!complete_io(port,&slots[1],sizeof(slots[1].data),0))goto done;
    if(!observation("iocp_peer_record",pw_ipc_packet_valid(&slots[1].data,sizeof(slots[1].data),nonce,parent_pid,
        parent_pid,2,PW_IPC_DATA,8*sizeof(void *))&&slots[1].data.value==(nonce^PW_IPC_B),0,0,
        sizeof(slots[1].data),slots[1].data.value,nonce^PW_IPC_B))goto done;
    control=packet(PW_IPC_RESULT,2);control.value=1;if(!send_packet(tx,&control))goto done;
    if(!receive_packet(rx,&control,parent_pid,3,PW_IPC_COMMAND))goto done;
    ok=1;
 done:
    if(port)ok&=settle_slots(pipe,port);
    close_handle(&port);return ok;
}
/* ObjectTypeInformation prefix documented for NtQueryObject. Type names
 * are categories, not object-instance names; no ObjectNameInformation call. */
struct object_type_prefix { uint16_t length,maximum; const uint16_t *text; };
struct object_category { const char *name,*label; };
static const struct object_category object_categories[]={
    {"","Unclassified"},{"Event","Event"},{"File","File"},{"ALPC Port","ALPC_Port"},
    {"Port","Port"},{"IoCompletion","IoCompletion"},{"TpWorkerFactory","TpWorkerFactory"},
    {"WaitCompletionPacket","WaitCompletionPacket"},{"Process","Process"},{"Thread","Thread"},
    {"Token","Token"},{"Section","Section"},{"Key","Key"},{"Directory","Directory"},
    {"SymbolicLink","SymbolicLink"},{"Mutant","Mutant"},{"Semaphore","Semaphore"},
    {"Timer","Timer"},{"Job","Job"},{"EtwRegistration","EtwRegistration"},
    {"EtwConsumer","EtwConsumer"},{"DebugObject","DebugObject"},{"Desktop","Desktop"},
    {"WindowStation","WindowStation"},{"Session","Session"}
};
static unsigned object_category(const unsigned char *buffer,SIZE_T capacity,ULONG returned)
{
    const struct object_type_prefix *info=(const struct object_type_prefix *)buffer;
    uintptr_t start=(uintptr_t)buffer,text_address;SIZE_T offset,minimum=sizeof(*info)+22*sizeof(ULONG);
    unsigned category,i;int equal;
    if(returned>capacity||returned<minimum)return 0;
    text_address=(uintptr_t)info->text;
    if(text_address<start||text_address%sizeof(uint16_t))return 0;
    offset=(SIZE_T)(text_address-start);
    if(offset<minimum||offset>returned||!info->length||info->length%sizeof(uint16_t)||
       info->maximum%sizeof(uint16_t)||info->length>info->maximum||info->maximum>returned-offset||
       info->length>128)return 0;
    for(category=1;category<sizeof(object_categories)/sizeof(object_categories[0]);++category){
        const char *name=object_categories[category].name;
        if(strlen(name)*sizeof(uint16_t)!=info->length)continue;
        equal=1;
        for(i=0;i<info->length/sizeof(uint16_t);++i){
            uint16_t letter;memcpy(&letter,buffer+offset+i*sizeof(letter),sizeof(letter));
            if(letter!=(unsigned char)name[i]){equal=0;break;}
        }
        if(equal)return category;
    }
    return 0;
}
static unsigned observe_object_type(query_object_fn query,HANDLE handle,const char *stage)
{
    union { void *align_pointer;uint64_t align_integer;unsigned char bytes[4096]; } storage;
    ULONG returned=0;LONG status;unsigned category=0;char label[128];
    memset(&storage,0,sizeof(storage));attempt(stage);
    status=query(handle,2,storage.bytes,sizeof(storage.bytes),&returned); /* ObjectTypeInformation only. */
    if(status>=0)category=object_category(storage.bytes,sizeof(storage.bytes),returned);
    (void)snprintf(label,sizeof(label),"%s_%s",stage,object_categories[category].label);
    trace(label,"observation_only",0,status,returned,category,0);
    return category;
}
static void inspect_candidate_object(HANDLE candidate,HANDLE event,HANDLE pipe)
{
    query_object_fn query=NULL;compare_objects_fn compare=NULL;FARPROC symbol;HANDLE pinned=NULL,control=NULL;
    BOOL api;DWORD error,flags=0;unsigned category;
    attempt("identity_diagnostic_GetHandleInformation");api=GetHandleInformation(candidate,&flags);error=api?0:GetLastError();
    trace("identity_diagnostic_GetHandleInformation","observation_only",error,0,0,api?1:0,flags);
    /* Pin before allocating any other diagnostic handles. Never act on or
     * close the unknown original; a failed API's output is not owned. */
    attempt("identity_diagnostic_local_pin");
    api=DuplicateHandle(GetCurrentProcess(),candidate,GetCurrentProcess(),&pinned,0,FALSE,DUPLICATE_SAME_ACCESS);
    error=api?0:GetLastError();if(api)own(pinned);else pinned=NULL;
    trace("identity_diagnostic_local_pin","observation_only",error,0,0,api?1:0,(uint64_t)(uintptr_t)pinned);
    symbol=GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryObject");
    if(!symbol){trace("identity_diagnostic_query_unavailable","observation_only",GetLastError(),0,0,0,0);goto done;}
    _Static_assert(sizeof(query)==sizeof(symbol),"Windows query pointer width");memcpy(&query,&symbol,sizeof(query));
    if(pinned&&pinned!=INVALID_HANDLE_VALUE)observe_object_type(query,pinned,"identity_candidate_pinned");
    else observe_object_type(query,candidate,"identity_candidate_unpinned_racy");
    category=observe_object_type(query,event,"identity_diagnostic_known_event");
    trace("identity_diagnostic_event_control","observation_only",0,0,0,category==1,category);
    category=observe_object_type(query,pipe,"identity_diagnostic_known_pipe");
    trace("identity_diagnostic_pipe_control","observation_only",0,0,0,category==2,category);
    attempt("identity_diagnostic_local_event_duplicate");
    api=DuplicateHandle(GetCurrentProcess(),event,GetCurrentProcess(),&control,0,FALSE,DUPLICATE_SAME_ACCESS);
    error=api?0:GetLastError();if(api)own(control);else control=NULL;
    trace("identity_diagnostic_local_event_duplicate","observation_only",error,0,0,api?1:0,(uint64_t)(uintptr_t)control);
    symbol=GetProcAddress(GetModuleHandleW(L"kernelbase.dll"),"CompareObjectHandles");
    if(!symbol){trace("identity_diagnostic_compare_unavailable","observation_only",GetLastError(),0,0,0,0);goto done;}
    memcpy(&compare,&symbol,sizeof(compare));
    if(control&&control!=INVALID_HANDLE_VALUE){
        attempt("identity_diagnostic_local_event_same");api=compare(event,control);error=api?0:GetLastError();
        trace("identity_diagnostic_local_event_same","observation_only",error,0,0,api?1:0,0);
    }
    if(pinned&&pinned!=INVALID_HANDLE_VALUE){
        attempt("identity_diagnostic_local_candidate_same");api=compare(candidate,pinned);error=api?0:GetLastError();
        trace("identity_diagnostic_local_candidate_same","observation_only",error,0,0,api?1:0,0);
    }
 done:
    close_handle(&control);close_handle(&pinned);
}
/* Snapshot before opening the log or making diagnostic/control duplicates.
 * The inherited reference remains owned and open through the parent's ACK. */
struct slot_snapshot { compare_objects_fn compare; BOOL same; DWORD error; };
static struct slot_snapshot snapshot_slot(HANDLE candidate,HANDLE reference)
{
    struct slot_snapshot saved={NULL,FALSE,0};FARPROC symbol;
    symbol=GetProcAddress(GetModuleHandleW(L"kernelbase.dll"),"CompareObjectHandles");
    if(!symbol){saved.error=GetLastError();return saved;}
    _Static_assert(sizeof(saved.compare)==sizeof(symbol),"Windows comparison pointer width");
    memcpy(&saved.compare,&symbol,sizeof(saved.compare));
    SetLastError(0);saved.same=saved.compare(candidate,reference);
    saved.error=saved.same?0:GetLastError();return saved;
}
static DWORD validate_slot(struct slot_snapshot saved,HANDLE candidate,HANDLE reference,HANDLE release)
{
    HANDLE same=NULL;BOOL api;DWORD error,verdict=0;
    if(!saved.compare){trace("identity_child_compare_resolve","unsupported",saved.error,0,0,0,0);return 0;}
    trace("identity_candidate_snapshot","observation_only",saved.error,0,0,
          (uint64_t)(uintptr_t)candidate,(uint64_t)(uintptr_t)reference);
    if(!observation("identity_child_reference_values",reference&&reference!=INVALID_HANDLE_VALUE&&
        candidate&&candidate!=INVALID_HANDLE_VALUE&&candidate!=reference&&reference!=release,
        0,0,0,(uint64_t)(uintptr_t)candidate,(uint64_t)(uintptr_t)reference))return 0;
    /* A control duplicate may reuse a previously free candidate slot. Never
     * re-read that slot: all verdicts use the saved pre-allocation result. */
    attempt("identity_child_duplicate_same");
    api=DuplicateHandle(GetCurrentProcess(),reference,GetCurrentProcess(),&same,0,FALSE,DUPLICATE_SAME_ACCESS);
    error=api?0:GetLastError();if(api)own(same);else same=NULL;
    if(!observation("identity_child_duplicate_same",api&&same&&same!=INVALID_HANDLE_VALUE&&same!=reference,
        error,0,0,0,0))goto done;
    attempt("identity_child_same_control");SetLastError(0);api=saved.compare(reference,same);error=api?0:GetLastError();
    if(!observation("identity_child_same_control",api,error,0,0,0,0))goto done;
    attempt("identity_child_different_control");SetLastError(0);api=saved.compare(reference,release);error=api?0:GetLastError();
    if(!observation("identity_child_different_control",!api&&error==ERROR_NOT_SAME_OBJECT,error,0,0,0,0))goto done;
    attempt("identity_child_cross_type_control");SetLastError(0);api=saved.compare(reference,GetCurrentProcess());error=api?0:GetLastError();
    if(!observation("identity_child_cross_type_control",!api&&error==ERROR_NOT_SAME_OBJECT,error,0,0,0,0))goto done;
    attempt("identity_child_invalid_control");SetLastError(0);api=saved.compare(NULL,reference);error=api?0:GetLastError();
    if(!observation("identity_child_invalid_control",!api&&error==ERROR_INVALID_HANDLE,error,0,0,0,0))goto done;
    if(!saved.same&&saved.error==ERROR_NOT_SAME_OBJECT)verdict=1;
    else if(!saved.same&&saved.error==ERROR_INVALID_HANDLE)verdict=2;
    observation("identity_child_slot_verdict",verdict!=0,saved.error,0,0,verdict,(uint64_t)(uintptr_t)reference);
 done:
    close_handle(&same);return !close_failed?verdict:0;
}
static int worker_main(int argc,char **argv)
{
    uint64_t numbers[9];unsigned i;HANDLE rx,tx,release,extra,reference;DWORD wait,verdict;
    struct slot_snapshot saved;
    struct pw_ipc_packet p;int ok=0;
    if(argc!=11)return 2;
    for(i=0;i<9;++i)if(!pw_ipc_number(argv[i+2],i<3?UINT32_MAX:UINTPTR_MAX,&numbers[i]))return 2;
    selected=(unsigned)numbers[0];nonce=(DWORD)numbers[1];parent_pid=(DWORD)numbers[2];
    if(selected<PW_IPC_LIVE||selected>PW_IPC_PIPE||!nonce||!parent_pid||parent_pid==GetCurrentProcessId())return 2;
    worker=1;epoch=GetTickCount64();
    rx=own((HANDLE)(uintptr_t)numbers[3]);tx=own((HANDLE)(uintptr_t)numbers[4]);
    release=own((HANDLE)(uintptr_t)numbers[5]);extra=own((HANDLE)(uintptr_t)numbers[6]);
    reference=own((HANDLE)(uintptr_t)numbers[8]);
    saved=snapshot_slot((HANDLE)(uintptr_t)numbers[7],reference);
    start_log();
    verdict=validate_slot(saved,(HANDLE)(uintptr_t)numbers[7],reference,release);
    if(!verdict)goto done;
    inspect_candidate_object((HANDLE)(uintptr_t)numbers[7],release,rx);
    p=packet(PW_IPC_HELLO,0);p.address=(uint64_t)(uintptr_t)&private_value;p.value=private_value;
    p.flags=verdict;p.argument=numbers[7];
    if(!send_packet(tx,&p))goto done;
    /* Parent captures the continuously held known reference, never the
     * unknown slot, and verifies it denotes the exact decoy before ACK. */
    if(!receive_packet(rx,&p,parent_pid,0,PW_IPC_COMMAND))goto done;
    if(!observation("handle_list_acknowledged",p.value==1,0,0,sizeof(p),p.value,0))goto done;
    if(selected==PW_IPC_LIVE||selected==PW_IPC_SUSPENDED){
        attempt("WaitForSingleObject_release");wait=WaitForSingleObject(release,PW_IPC_CHILD_MS);
        ok=observation("WaitForSingleObject_release",wait==WAIT_OBJECT_0,wait==WAIT_FAILED?GetLastError():0,0,0,wait,0);
        ok&=observation("child_actual_private_value",private_value==PW_IPC_B,0,0,sizeof(DWORD),private_value,PW_IPC_B);
    }else if(selected==PW_IPC_PIPE)ok=pipe_child(extra,rx,tx);
    else{
        if(selected!=PW_IPC_READONLY){
            if(!receive_packet(rx,&p,parent_pid,1,PW_IPC_COMMAND)||!p.argument)goto done;
            extra=own((HANDLE)(uintptr_t)p.argument);
        }
        ok=section_child(extra,selected==PW_IPC_READONLY);
    }
    if(selected!=PW_IPC_PIPE){p=packet(PW_IPC_RESULT,2);p.value=ok?1u:0u;p.address=(uint64_t)(uintptr_t)&private_value;
        p.argument=private_value;ok&=send_packet(tx,&p);}
 done:
    close_handle(&extra);close_handle(&reference);close_handle(&release);close_handle(&rx);close_handle(&tx);
    trace("guest_cleanup",!handles&&!close_failed&&!unsettled?"pass":"uncertain",0,0,0,handles,unsettled);
    ok=ok&&!handles&&!close_failed&&!unsettled&&!log_failed&&!stage_failed;
    trace("final",ok?"pass":"fail",0,0,0,ok?PW_IPC_EXIT:PW_IPC_CHILD_ERROR,0);
    ok=ok&&!log_failed&&!stage_failed;
    if(log_file!=INVALID_HANDLE_VALUE && !CloseHandle(log_file))ok=0;
    return ok?(int)PW_IPC_EXIT:(int)PW_IPC_CHILD_ERROR;
}
static int excluded_object(struct child *c,DWORD verdict)
{
    HANDLE same=NULL,different=NULL,included=NULL,reference=NULL;compare_objects_fn compare=NULL;
    FARPROC symbol;BOOL api;DWORD error,wait;int ok=0;
    attempt("CompareObjectHandles_resolve");
    symbol=GetProcAddress(GetModuleHandleW(L"kernelbase.dll"),"CompareObjectHandles");
    if(!symbol){trace("CompareObjectHandles_resolve","unsupported",GetLastError(),0,0,0,0);return 0;}
    _Static_assert(sizeof(compare)==sizeof(symbol),"Windows comparison pointer width");
    memcpy(&compare,&symbol,sizeof(compare));
    attempt("identity_duplicate_same");
    api=DuplicateHandle(GetCurrentProcess(),c->decoy,GetCurrentProcess(),&same,0,FALSE,DUPLICATE_SAME_ACCESS);
    error=api?0:GetLastError();if(api)own(same);else same=NULL;
    if(!observation("identity_duplicate_same",api,error,0,0,0,0))goto done;
    attempt("identity_create_different");different=own(CreateEventW(NULL,TRUE,FALSE,NULL));
    if(!observation("identity_create_different",!!different,different?0:GetLastError(),0,0,0,0))goto done;
    attempt("identity_same_control");api=compare(c->decoy,same);error=api?0:GetLastError();
    if(!observation("identity_same_control",api,error,0,0,0,0))goto done;
    attempt("identity_different_control");api=compare(c->decoy,different);error=api?0:GetLastError();
    if(!observation("identity_different_control",!api&&error==ERROR_NOT_SAME_OBJECT,error,0,0,0,0))goto done;
    attempt("identity_child_live");wait=WaitForSingleObject(c->pi.hProcess,0);
    if(!observation("identity_child_live",wait==WAIT_TIMEOUT,wait==WAIT_FAILED?GetLastError():0,0,0,wait,0))goto done;
    attempt("identity_capture_included");
    api=DuplicateHandle(c->pi.hProcess,c->release,GetCurrentProcess(),&included,0,FALSE,DUPLICATE_SAME_ACCESS);
    error=api?0:GetLastError();if(api)own(included);else included=NULL;
    if(!observation("identity_capture_included",api&&included&&included!=INVALID_HANDLE_VALUE,error,0,0,0,0))goto done;
    attempt("identity_included_control");api=compare(c->release,included);error=api?0:GetLastError();
    if(!observation("identity_included_control",api,error,0,0,0,0))goto done;
    attempt("identity_capture_reference");
    api=DuplicateHandle(c->pi.hProcess,c->reference,GetCurrentProcess(),&reference,0,FALSE,DUPLICATE_SAME_ACCESS);
    error=api?0:GetLastError();if(api)own(reference);else reference=NULL;
    if(!observation("identity_capture_reference",api&&reference&&reference!=INVALID_HANDLE_VALUE,error,0,0,
        (uint64_t)(uintptr_t)c->reference,0))goto done;
    attempt("identity_reference_control");api=compare(c->decoy,reference);error=api?0:GetLastError();
    if(!observation("identity_reference_control",api,error,0,0,0,0))goto done;
    wait=WaitForSingleObject(c->pi.hProcess,0);
    if(!observation("identity_child_still_live",wait==WAIT_TIMEOUT,wait==WAIT_FAILED?GetLastError():0,0,0,wait,0))goto done;
    ok=observation("handle_list_excluded",verdict==1||verdict==2,
        verdict==1?ERROR_NOT_SAME_OBJECT:verdict==2?ERROR_INVALID_HANDLE:0,
        0,0,verdict,(uint64_t)(uintptr_t)c->reference);
 done:
    close_handle(&reference);close_handle(&included);close_handle(&different);close_handle(&same);
    return ok&&!close_failed;
}
static int hello(struct child *c,struct pw_ipc_packet *p)
{
    struct pw_ipc_packet acknowledgement;
    DWORD pid,error;int ok;attempt("Windows_child_identity");pid=GetProcessId(c->pi.hProcess);error=pid?0:GetLastError();
    ok=observation("Windows_child_identity",pid==c->pi.dwProcessId&&pid&&pid!=parent_pid,error,0,0,pid,c->pi.dwProcessId);
    if(!ok||!receive_packet(c->rx,p,c->pi.dwProcessId,0,PW_IPC_HELLO))return 0;
    if(!observation("child_hello",p->value==PW_IPC_A&&p->address&&(p->flags==1u||p->flags==2u)&&
        p->argument==(uint64_t)(uintptr_t)c->decoy&&WaitForSingleObject(c->decoy,0)==WAIT_TIMEOUT,
        0,0,sizeof(*p),p->address,p->flags)||!excluded_object(c,p->flags))return 0;
    acknowledgement=packet(PW_IPC_COMMAND,0);acknowledgement.value=1;
    return send_packet(c->tx,&acknowledgement);
}
static int live_memory(struct child *c)
{
    struct pw_ipc_packet p;HANDLE readonly=NULL;int ok=0;DWORD available=0,result;BOOL api;
    private_value=nonce^PW_IPC_B;
    if(!launch(c,NULL,selected==PW_IPC_SUSPENDED))return 0;
    if(selected==PW_IPC_SUSPENDED){
        Sleep(100);attempt("suspended_no_application_record");
        api=PeekNamedPipe(c->rx,NULL,0,NULL,&available,NULL);
        if(!observation("suspended_no_application_record",api&&!available&&WaitForSingleObject(c->pi.hProcess,0)==WAIT_TIMEOUT,
             api?0:GetLastError(),0,available,100,0))return 0;
        attempt("ResumeThread");result=ResumeThread(c->pi.hThread);c->resumed=result!=(DWORD)-1;
        if(!observation("ResumeThread",result==1,result==(DWORD)-1?GetLastError():0,0,0,result,1))return 0;
    }
    if(!hello(c,&p)){trace("foreign_memory","not_run",0,0,0,0,0);return 0;}
    ok=memory_api(c->pi.hProcess,(void *)(uintptr_t)p.address,"foreign",0,0,PW_IPC_A);
    ok&=memory_api(c->pi.hProcess,(void *)(uintptr_t)p.address,"foreign",0,1,PW_IPC_B);
    ok&=memory_api(c->pi.hProcess,(void *)(uintptr_t)p.address,"foreign",1,0,PW_IPC_B);
    ok&=memory_api(c->pi.hProcess,(void *)(uintptr_t)p.address,"foreign_restore",1,1,PW_IPC_A);
    ok&=memory_api(c->pi.hProcess,(void *)(uintptr_t)p.address,"foreign_restored",1,0,PW_IPC_A);
    ok&=memory_api(c->pi.hProcess,(void *)(uintptr_t)p.address,"foreign_final",1,1,PW_IPC_B);
    readonly=own(OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION,FALSE,c->pi.dwProcessId));
    if(!readonly)ok=0;else ok&=denied_memory(readonly,(void *)(uintptr_t)p.address,0,1);
    ok&=observation("parent_private_unchanged",private_value==(nonce^PW_IPC_B),0,0,sizeof(DWORD),private_value,nonce^PW_IPC_B);
    close_handle(&readonly);ok&=release_child(c);
    if(!receive_packet(c->rx,&p,c->pi.dwProcessId,2,PW_IPC_RESULT))return 0;
    ok&=observation("peer_confirmed_write",p.value==1&&p.argument==PW_IPC_B,0,0,sizeof(p),p.argument,PW_IPC_B);
    return ok;
}
static int sections(struct child *c)
{
    SECURITY_DESCRIPTOR sd;ACL acl;SECURITY_ATTRIBUTES sa={sizeof(sa),&sd,FALSE};
    HANDLE section=NULL,readonly=NULL,target=NULL,retired=NULL;void *view=NULL;struct pw_ipc_packet p;
    int ok=0;BOOL api;DWORD error,flags=0;
    attempt("section_empty_DACL");
    api=InitializeSecurityDescriptor(&sd,SECURITY_DESCRIPTOR_REVISION)&&
        InitializeAcl(&acl,sizeof(acl),ACL_REVISION)&&SetSecurityDescriptorDacl(&sd,TRUE,&acl,FALSE);
    error=api?0:GetLastError();
    if(!observation("section_empty_DACL",api,error,0,0,0,0))goto done;
    attempt("CreateFileMappingW");section=own(CreateFileMappingW(INVALID_HANDLE_VALUE,&sa,PAGE_READWRITE,0,PW_IPC_SECTION_SIZE,NULL));
    if(!observation("CreateFileMappingW",!!section,section?0:GetLastError(),0,PW_IPC_SECTION_SIZE,0,0))goto done;
    attempt("MapViewOfFile_parent");view=MapViewOfFile(section,FILE_MAP_READ|FILE_MAP_WRITE,0,0,PW_IPC_SECTION_SIZE);
    if(!observation("MapViewOfFile_parent",!!view,view?0:GetLastError(),0,PW_IPC_SECTION_SIZE,(uint64_t)(uintptr_t)view,0))goto done;
    write_section(view,0);
    if(selected==PW_IPC_READONLY){
        attempt("DuplicateHandle_readonly");api=DuplicateHandle(GetCurrentProcess(),section,GetCurrentProcess(),
            &readonly,SECTION_QUERY|FILE_MAP_READ,TRUE,0);error=api?0:GetLastError();
        if(api)own(readonly);else readonly=NULL;
        if(!observation("DuplicateHandle_readonly",api,error,0,0,0,0))goto done;
    }
    if(!launch(c,readonly,0))goto done;
    close_handle(&readonly);
    if(!hello(c,&p)){trace("section_transfer","not_run",0,0,0,0,0);goto done;}
    if(selected!=PW_IPC_READONLY){
        attempt(selected==PW_IPC_CLOSE_SOURCE?"DuplicateHandle_CLOSE_SOURCE":"DuplicateHandle_target");
        retired=section;
        api=DuplicateHandle(GetCurrentProcess(),section,c->pi.hProcess,&target,
            SECTION_QUERY|FILE_MAP_READ|FILE_MAP_WRITE,FALSE,selected==PW_IPC_CLOSE_SOURCE?DUPLICATE_CLOSE_SOURCE:0);
        error=api?0:GetLastError();
        /* Windows closes the source even when DUPLICATE_CLOSE_SOURCE fails.
         * Never retry or close its possibly recycled numeric value. */
        if(selected==PW_IPC_CLOSE_SOURCE){section=NULL;--handles;}
        if(!observation(selected==PW_IPC_CLOSE_SOURCE?"DuplicateHandle_CLOSE_SOURCE":"DuplicateHandle_target",api,error,0,0,
            api?(uint64_t)(uintptr_t)target:0,0))goto done;
        if(selected==PW_IPC_CLOSE_SOURCE){
            api=GetHandleInformation(retired,&flags);error=api?0:GetLastError();
            if(!observation("source_handle_retired",!api&&error==ERROR_INVALID_HANDLE,error,0,0,(uint64_t)(uintptr_t)retired,0))goto done;
        }
        /* target belongs to the child table. Never CloseHandle it here. */
        p=packet(PW_IPC_COMMAND,1);p.argument=(uint64_t)(uintptr_t)target;
        if(!send_packet(c->tx,&p))goto done;
    }
    if(!receive_packet(c->rx,&p,c->pi.dwProcessId,2,PW_IPC_RESULT)||p.value!=1)goto done;
    ok=section_values(view,selected!=PW_IPC_READONLY);
 done:
    if(view){attempt("UnmapViewOfFile_parent");api=UnmapViewOfFile(view);error=api?0:GetLastError();
        if(!observation("UnmapViewOfFile_parent",api,error,0,0,(uint64_t)(uintptr_t)view,0)){ok=0;close_failed=1;}}
    close_handle(&readonly);close_handle(&section);return ok;
}
static int mojo_pipe(struct child *c)
{
    SECURITY_ATTRIBUTES sa={sizeof(sa),NULL,TRUE};HANDLE server=NULL,client=NULL,port=NULL;
    wchar_t name[128];struct pw_ipc_packet p;BOOL api;DWORD error;int ok=0;
    (void)swprintf(name,sizeof(name)/sizeof(name[0]),L"\\\\.\\pipe\\pw-chromium-ipc-%lu-%lu",
                   (unsigned long)parent_pid,(unsigned long)nonce);
    attempt("CreateNamedPipeW");
    server=CreateNamedPipeW(name,PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED|FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,4096,4096,0,NULL);
    if(server==INVALID_HANDLE_VALUE)server=NULL;else own(server);
    if(!observation("CreateNamedPipeW",!!server,server?0:GetLastError(),0,0,0,0))goto done;
    attempt("CreateFileW_pipe_client");
    client=CreateFileW(name,GENERIC_READ|GENERIC_WRITE,0,&sa,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,NULL);
    if(client==INVALID_HANDLE_VALUE)client=NULL;else own(client);
    if(!observation("CreateFileW_pipe_client",!!client,client?0:GetLastError(),0,0,0,0))goto done;
    attempt("ConnectNamedPipe_preconnected");api=ConnectNamedPipe(server,&connection);error=api?0:GetLastError();
    if(!observation("ConnectNamedPipe_preconnected",!api&&error==ERROR_PIPE_CONNECTED,error,0,0,0,0)){
        if(!api&&error==ERROR_IO_PENDING){
            /* Unexpected pending connect has process-lifetime OVERLAPPED
             * storage. We decline to infer settlement from close/cancel. */
            (void)CancelIoEx(server,&connection);unsettled=1;
        }
        goto done;
    }
    port=completion_port(server);if(!port||!launch(c,client,0))goto done;
    close_handle(&client);
    if(!hello(c,&p)){trace("mojo_exchange","not_run",0,0,0,0,0);goto done;}
    if(!submit_io(server,&slots[0],0,1))goto done;
    p=packet(PW_IPC_COMMAND,1);if(!send_packet(c->tx,&p))goto done;
    if(!complete_io(port,&slots[0],sizeof(slots[0].data),0))goto done;
    if(!observation("iocp_peer_record",pw_ipc_packet_valid(&slots[0].data,sizeof(slots[0].data),nonce,
       c->pi.dwProcessId,parent_pid,1,PW_IPC_DATA,8*sizeof(void *))&&slots[0].data.value==(nonce^PW_IPC_A),
       0,0,sizeof(slots[0].data),slots[0].data.value,nonce^PW_IPC_A))goto done;
    slots[1].data=packet(PW_IPC_DATA,2);slots[1].data.value=nonce^PW_IPC_B;
    if(!submit_io(server,&slots[1],1,0)||!complete_io(port,&slots[1],sizeof(slots[1].data),0))goto done;
    if(!receive_packet(c->rx,&p,c->pi.dwProcessId,2,PW_IPC_RESULT)||p.value!=1)goto done;
    if(!submit_io(server,&slots[2],0,1)||!cancel_and_drain(server,port,&slots[2],1))goto done;
    if(!submit_io(server,&slots[3],0,1))goto done;
    p=packet(PW_IPC_COMMAND,3);if(!send_packet(c->tx,&p))goto done;
    ok=complete_io(port,&slots[3],0,ERROR_BROKEN_PIPE);
 done:
    if(server)ok&=settle_slots(server,port);
    close_handle(&port);close_handle(&client);close_handle(&server);return ok;
}
static int pages(void)
{
    unsigned char *base=NULL;void *recommitted;MEMORY_BASIC_INFORMATION info;DWORD old=0,error;BOOL api;int ok=1;unsigned i,j;SIZE_T size;
    attempt("VirtualAlloc_16KiB");base=VirtualAlloc(NULL,16384,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if(!observation("VirtualAlloc_16KiB",!!base,base?0:GetLastError(),0,16384,(uint64_t)(uintptr_t)base,0))return 0;
    for(i=0;i<4;++i)memset(base+4096*i,(int)(0x30+i),4096);
    attempt("VirtualProtect_one_4KiB");api=VirtualProtect(base+4096,4096,PAGE_READONLY,&old);error=api?0:GetLastError();
    ok&=observation("VirtualProtect_one_4KiB",api&&old==PAGE_READWRITE,error,0,4096,old,PAGE_READWRITE);
    for(i=0;i<4;++i){
        const DWORD expected_protect=i==1?PAGE_READONLY:PAGE_READWRITE;
        memset(&info,0,sizeof(info));attempt("VirtualQuery_4KiB");size=VirtualQuery(base+4096*i,&info,sizeof(info));
        ok&=observation("VirtualQuery_4KiB",size==sizeof(info)&&info.State==MEM_COMMIT&&
            info.Protect==expected_protect,size?0:GetLastError(),0,size,i,info.Protect);
    }
    attempt("VirtualFree_decommit_4KiB");api=VirtualFree(base+8192,4096,MEM_DECOMMIT);error=api?0:GetLastError();
    if(!observation("VirtualFree_decommit_4KiB",api,error,0,4096,8192,0)){ok=0;goto done;}
    memset(&info,0,sizeof(info));size=VirtualQuery(base+8192,&info,sizeof(info));
    ok&=observation("VirtualQuery_decommitted",size==sizeof(info)&&info.State==MEM_RESERVE,size?0:GetLastError(),0,size,info.State,0);
    attempt("VirtualAlloc_recommit_4KiB");
    recommitted=VirtualAlloc(base+8192,4096,MEM_COMMIT,PAGE_READWRITE);error=recommitted?0:GetLastError();
    if(!observation("VirtualAlloc_recommit_4KiB",recommitted==base+8192,
       error,0,4096,(uint64_t)(uintptr_t)recommitted,(uint64_t)(uintptr_t)(base+8192))){ok=0;goto done;}
    for(i=0;i<4;++i){
        int same=1;for(j=0;j<4096;++j)if(base[i*4096+j]!=(unsigned char)(i==2?0:0x30+i)){same=0;break;}
        ok&=observation(i==2?"recommit_zeroed":"neighbor_unchanged",same,0,0,4096,i,j);
    }
 done:
    attempt("VirtualFree_release");api=VirtualFree(base,0,MEM_RELEASE);error=api?0:GetLastError();
    if(!observation("VirtualFree_release",api,error,0,0,0,0)){ok=0;close_failed=1;}
    return ok;
}
int main(int argc,char **argv)
{
    struct child c;DWORD exit_code=0;int stages=0,waited=1,ok;unsigned i;
    if(argc>1&&!strcmp(argv[1],"--worker"))return worker_main(argc,argv);
    if(argc!=2)return 2;
    for(i=1;i<=PW_IPC_PAGES;++i)if(!strcmp(argv[1],case_names[i]))selected=i;
    if(!selected)return 2;
    memset(&c,0,sizeof(c));epoch=GetTickCount64();parent_pid=GetCurrentProcessId();
    nonce=(DWORD)epoch^parent_pid^0x51cc8123u;if(!nonce)nonce=1;
    start_log();trace("begin","observation_only",0,0,0,0,0);
    if(selected==PW_IPC_SELF)stages=self_memory();
    else if(selected==PW_IPC_LIVE||selected==PW_IPC_SUSPENDED)stages=live_memory(&c);
    else if(selected>=PW_IPC_READONLY&&selected<=PW_IPC_CLOSE_SOURCE)stages=sections(&c);
    else if(selected==PW_IPC_PIPE)stages=mojo_pipe(&c);
    else stages=pages();
    if(c.created||c.rx||c.tx||c.release||c.decoy)waited=cleanup_child(&c,&exit_code);
    ok=pw_ipc_final_ok(stages&&!stage_failed,c.created,waited,exit_code,!close_failed&&!handles&&!log_failed,unsettled);
    trace("guest_cleanup",!close_failed&&!handles&&waited&&!unsettled?"pass":"uncertain",0,0,0,handles,unsettled);
    trace("native_settlement","unverified",0,0,0,0,0);
    trace("final",ok?"pass":unsettled?"cleanup_uncertain":"fail",0,0,0,exit_code,PW_IPC_EXIT);
    ok=ok&&!log_failed&&!stage_failed;
    if(log_file!=INVALID_HANDLE_VALUE&&!CloseHandle(log_file))ok=0;
    return ok?0:unsettled?78:1;
}
