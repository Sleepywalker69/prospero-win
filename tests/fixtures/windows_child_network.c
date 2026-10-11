/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Original separate Winsock/DNS observation control. No vendor assets, inherited handles, input
 * injection, presentation bridge or native ownership claims. */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windns.h>
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <wchar.h>

#ifndef PW_NET_CHILD
#define PW_NET_CHILD 0
#endif
enum { PARENT_MS=90000, CHILD_MS=45000, WATCHDOG_MARGIN_MS=5000, CHILD_EXIT=37, LOG_LIMIT=65536 };
static const char *role=PW_NET_CHILD?"child":"parent";
static HANDLE log_file=INVALID_HANDLE_VALUE, watchdog_stop, watchdog_thread;
static CRITICAL_SECTION log_lock;
static unsigned log_bytes;
static volatile LONG log_failed;
static ULONGLONG started,last_tick;
static DWORD main_limit;
static int budget_failed;

static void record(const char *stage,const char *format,...)
{
    char detail[480],line[720]; va_list args; DWORD wrote=0; int n;
    va_start(args,format);n=vsnprintf(detail,sizeof(detail),format,args);va_end(args);
    if(n<0||(size_t)n>=sizeof(detail)){InterlockedExchange(&log_failed,1);return;}
    n=snprintf(line,sizeof(line),"PW_CHILD_NET role=%s stage=%s pid=%lu tid=%lu %s\r\n",
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

static _Noreturn void self_exit(DWORD code)
{
    OutputDebugStringA("PW_CHILD_NET stage=self_exit result=attempt native_settlement=unverified\r\n");
    (void)TerminateProcess(GetCurrentProcess(),code);
    /* ExitProcess is nonreturning; no process-lifetime storage is released. */
    ExitProcess(code+1);
}

static DWORD remaining_at(ULONGLONG now)
{
    if(budget_failed)return 0;
    if(now<last_tick||now<started||now-started>=main_limit){budget_failed=1;return 0;}
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
    self_exit(122);
}

static int begin(void)
{
    char path[128];int n;
    started=last_tick=GetTickCount64();main_limit=PW_NET_CHILD?CHILD_MS:PARENT_MS;
    InitializeCriticalSection(&log_lock);
    n=snprintf(path,sizeof(path),"net-%s-%lu-%llu.log",role,
               (unsigned long)GetCurrentProcessId(),(unsigned long long)started);
    if(n<0||(size_t)n>=sizeof(path))return 0;
    log_file=CreateFileA(path,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    if(log_file==INVALID_HANDLE_VALUE)return 0;
    watchdog_stop=CreateEventW(NULL,TRUE,FALSE,NULL);
    if(!watchdog_stop)return 0;
    watchdog_thread=CreateThread(NULL,0,watchdog,NULL,0,NULL);
    if(!watchdog_thread)return 0;
    record("start","mode=original_network_control network_success=unverified child_presentation=unverified child_input=unverified");
    return !InterlockedCompareExchange(&log_failed,0,0);
}

static int finish(int status)
{
    DWORD code=0;int cleanup_failed=0;
    /* Caller has joined every diagnostic worker before entering this path. */
    if(!remaining()&&!status)status=90;
    record("finish","planned_exit=%d prior_status=%d diagnostic_cleanup=%s final_log_close=pending native_settlement=unverified",
           status?status:(PW_NET_CHILD?CHILD_EXIT:0),status,status?"not_established":"completed");
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

#if PW_NET_CHILD
#include "windows_child_network_contract.h"
_Static_assert(sizeof(struct sockaddr_in)==16 && AF_INET==2 && SOCK_STREAM==1 && IPPROTO_TCP==6, "Windows IPv4 shape");
/* Only fixed system-directory providers are loaded, after the original log
 * and watchdog exist. Missing Unix-side initialization remains observable. */
typedef struct NetApi {
    int (WINAPI *startup)(WORD,LPWSADATA);
    int (WINAPI *cleanup)(void);
    int (WINAPI *resolve)(PCSTR,PCSTR,const ADDRINFOA *,PADDRINFOA *);
    void (WINAPI *free_addresses)(PADDRINFOA);
    SOCKET (WINAPI *make_socket)(int,int,int,LPWSAPROTOCOL_INFOW,GROUP,DWORD);
    int (WINAPI *close_socket)(SOCKET);
    int (WINAPI *last_error)(void);
} NetApi;
typedef struct DnsApi {
    DNS_STATUS (WINAPI *query)(PCWSTR,WORD,DWORD,PVOID,PDNS_RECORDW *,PVOID *);
    DNS_STATUS (WINAPI *config)(DNS_CONFIG_TYPE,DWORD,PCWSTR,PVOID,PVOID,PDWORD);
    void (WINAPI *free_records)(PDNS_RECORD,DNS_FREE_TYPE);
} DnsApi;
static HMODULE load_system(const WCHAR *leaf,const char *label,int *status)
{
    WCHAR path[MAX_PATH];UINT length;size_t tail=wcslen(leaf);HMODULE module;DWORD error;
    if(!remaining()){*status=90;return NULL;}
    SetLastError(0);length=GetSystemDirectoryW(path,MAX_PATH);
    error=length?0:GetLastError();
    if(!remaining()){*status=90;return NULL;}
    if(!length||length>=MAX_PATH||length+1+tail>=MAX_PATH){
        record(label,"result=unavailable operation=system_directory returned_length=%u capacity=%u error=%lu",
               length,(unsigned)MAX_PATH,(unsigned long)error);return NULL;}
    path[length++]=L'\\';memcpy(path+length,leaf,(tail+1)*sizeof(WCHAR));
    if(!remaining()){*status=90;return NULL;}
    SetLastError(0);module=LoadLibraryW(path);error=module?0:GetLastError();
    record(label,"result=%s error=%lu",module?"loaded":"unavailable",(unsigned long)error);
    /* Preserve an acquired module for exactly one caller-owned release even
     * when this provider operation consumed the remaining budget. */
    if(!remaining())*status=90;
    return module;
}
static int unload_system(HMODULE module,const char *label,int status,int failure_status)
{
    BOOL result=FreeLibrary(module);DWORD error=result?0:GetLastError();
    record(label,"result=%u error=%lu prior_status=%d",(unsigned)result,(unsigned long)error,status);
    if(!result&&!status)status=failure_status;
    if(!remaining()&&!status)status=90;
    return status;
}
static int get_symbol(HMODULE module,const char *name,void *target,size_t size)
{
    FARPROC symbol=GetProcAddress(module,name);
    if(!symbol||size!=sizeof(symbol)){
        record("export","result=unavailable name=%s error=%lu",name,(unsigned long)GetLastError());return 0;}
    memcpy(target,&symbol,size);return 1;
}
#define LOAD_FN(module,table,field,name) get_symbol(module,name,&table.field,sizeof(table.field))
static int resolve_case(NetApi *api,const char *name,int flags,int loopback,int refusal,int optional)
{
    ADDRINFOA hints,*head=NULL,*item;const ADDRINFOA *seen[64];unsigned count=0;
    int code,valid=1;ULONGLONG begun=GetTickCount64(),ended;
    memset(&hints,0,sizeof(hints));hints.ai_family=AF_INET;hints.ai_socktype=SOCK_STREAM;
    hints.ai_protocol=IPPROTO_TCP;hints.ai_flags=flags;
    if(!remaining_at(begun))return 90;
    record("resolve_attempt","case=%s optional=%u family=AF_INET service=80 flags=%u",
           name,(unsigned)optional,(unsigned)flags);
    code=api->resolve(name,"80",&hints,&head);ended=GetTickCount64();
    if(!remaining_at(ended))valid=0;
    if(!code){
        for(item=head;item;item=item->ai_next){
            const struct sockaddr_in *address;
            if(count==64){valid=0;break;}
            for(unsigned i=0;i<count;i++)if(seen[i]==item)valid=0;
            if(!valid)break;
            seen[count++]=item;
            if(!item->ai_addr||item->ai_addrlen!=sizeof(*address)){valid=0;break;}
            address=(const struct sockaddr_in *)item->ai_addr;
            if(!pw_net_ipv4_shape((unsigned)item->ai_family,item->ai_addrlen,
                    (unsigned)item->ai_socktype,(unsigned)item->ai_protocol,
                    (const unsigned char *)&address->sin_port,
                    (const unsigned char *)&address->sin_addr,loopback)||address->sin_family!=AF_INET){valid=0;break;}
        }
        if(!count||refusal)valid=0;
    }else if(head||(!refusal&&!optional)||
              (refusal&&code!=WSAHOST_NOT_FOUND&&code!=WSANO_DATA))valid=0;
    record("resolve_result","case=%s domain=winsock code=%d count=%u shape_valid=%u optional=%u success=%u elapsed_ms=%llu",
           name,code,count,(unsigned)valid,(unsigned)optional,(unsigned)(!code&&valid),
           (unsigned long long)(ended>=begun?ended-begun:0));
    /* API ownership is released once. There is no second query or fallback. */
    if(head)api->free_addresses(head);
    if(!remaining())return 90;
    return valid?0:21;
}
static int dns_observations(void)
{
    int status=0;HMODULE module=load_system(L"dnsapi.dll","dnsapi_module",&status);DnsApi api={0};
    if(!module)return status;
    if(status)goto done;
    if(!LOAD_FN(module,api,query,"DnsQuery_W")||!LOAD_FN(module,api,config,"DnsQueryConfig")||
       !LOAD_FN(module,api,free_records,"DnsRecordListFree"))goto done;
    if(!remaining()){status=90;goto done;}
    {
        PDNS_RECORDW records=NULL;DNS_STATUS code=api.query(L"127.0.0.1",DNS_TYPE_A,DNS_QUERY_NO_NETBT,NULL,&records,NULL);
        int valid=code?records==NULL:1;
        if(!code){
            const unsigned char *address;
            if(!records||records->pNext||records->wType!=DNS_TYPE_A||records->wDataLength!=sizeof(DNS_A_DATA))valid=0;
            else {address=(const unsigned char *)&records->Data.A.IpAddress;
                valid=address[0]==127&&address[1]==0&&address[2]==0&&address[3]==1;}
        }
        record("dnsapi_numeric","domain=dns_status code=%lu record_present=%u shape_valid=%u optional=1",
               (unsigned long)code,(unsigned)(records!=NULL),(unsigned)valid);
        if(records)api.free_records((PDNS_RECORD)records,DnsFreeRecordList);
        if(!valid)status=22;
        if(!remaining()&&!status)status=90;
    }
    if(status)goto done;
    {
        struct {DWORD count;DWORD addresses[64];} buffer,initial;
        DWORD length=(DWORD)sizeof(buffer),capacity=length;DNS_STATUS code;int valid,unchanged;
        memset(&buffer,0xa5,sizeof(buffer));initial=buffer;
        code=api.config(DnsConfigDnsServerList,0,NULL,NULL,&buffer,&length);
        unchanged=length==capacity&&!memcmp(&buffer,&initial,sizeof(buffer));
        valid=code!=0||pw_net_dns_config_shape(capacity,length,buffer.count);
        record("dnsapi_config","domain=dns_status code=%lu capacity=%lu returned_bytes=%lu count=%lu shape_valid=%u untouched=%u optional=1 server_config_available=%u",
               (unsigned long)code,(unsigned long)capacity,(unsigned long)length,
               (unsigned long)(!code&&valid?buffer.count:0),(unsigned)valid,(unsigned)unchanged,(unsigned)(!code&&valid));
        if(!valid)status=23;
        if(!remaining()&&!status)status=90;
    }
done:
    return unload_system(module,"dnsapi_unload",status,24);
}
static int run_role(void)
{
    int status=0,started_wsa=0,code;
    HMODULE module=load_system(L"ws2_32.dll","winsock_module",&status);NetApi api={0};WSADATA data;
    SOCKET socket=INVALID_SOCKET;
    if(!module)return status?status:10;
    if(status)goto cleanup;
    if(!LOAD_FN(module,api,startup,"WSAStartup")||!LOAD_FN(module,api,cleanup,"WSACleanup")||
       !LOAD_FN(module,api,resolve,"getaddrinfo")||!LOAD_FN(module,api,free_addresses,"freeaddrinfo")||
       !LOAD_FN(module,api,make_socket,"WSASocketW")||!LOAD_FN(module,api,close_socket,"closesocket")||
       !LOAD_FN(module,api,last_error,"WSAGetLastError")){status=11;goto cleanup;}
    if(!remaining()){status=90;goto cleanup;}
    memset(&data,0,sizeof(data));code=api.startup(MAKEWORD(2,2),&data);
    record("wsa_startup","domain=winsock code=%d version=%u high_version=%u",code,(unsigned)data.wVersion,(unsigned)data.wHighVersion);
    if(code){status=12;goto cleanup;}started_wsa=1;
    if(data.wVersion!=MAKEWORD(2,2)){status=13;goto cleanup;}
    if((status=resolve_case(&api,"127.0.0.1",AI_NUMERICHOST,1,0,0)))goto cleanup;
    if((status=resolve_case(&api,"not-numeric.invalid",AI_NUMERICHOST,0,1,0)))goto cleanup;
    if(!remaining()){status=90;goto cleanup;}
    socket=api.make_socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP,NULL,0,WSA_FLAG_NO_HANDLE_INHERIT);
    code=socket==INVALID_SOCKET?api.last_error():0;
    record("socket_create","domain=winsock created=%u code=%d remote_traffic=0",(unsigned)(socket!=INVALID_SOCKET),code);
    if(socket==INVALID_SOCKET){status=14;goto cleanup;}
    code=api.close_socket(socket);
    record("socket_close","domain=winsock result=%d code=%d",code,code==SOCKET_ERROR?api.last_error():0);
    /* A failed close remains an ownership/cleanup failure; it is not retried. */
    socket=INVALID_SOCKET;if(code){status=15;goto cleanup;}
    if((status=dns_observations()))goto cleanup;
    if((status=resolve_case(&api,"example.com.",0,0,0,1)))goto cleanup;
cleanup:
    if(socket!=INVALID_SOCKET){code=api.close_socket(socket);if(code&&!status)status=16;socket=INVALID_SOCKET;}
    if(started_wsa){code=api.cleanup();record("wsa_cleanup","domain=winsock result=%d code=%d",code,code==SOCKET_ERROR?api.last_error():0);if(code&&!status)status=17;}
    status=unload_system(module,"winsock_unload",status,18);
    record("network_cleanup","status=%d local_contract_complete=%u fqdn_success_is_separate=1 native_settlement=unverified",status,(unsigned)(!status));
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
    if(prefix+wcslen(L"net-child.exe")>=MAX_PATH)return 41;
    wcscpy(path+prefix,L"net-child.exe");
    int n=swprintf(command,sizeof(command)/sizeof(command[0]),L"\"%ls\"",path);
    if(n<=0||(size_t)n>=sizeof(command)/sizeof(command[0]))return 42;
    memset(&startup,0,sizeof(startup));startup.cb=(DWORD)sizeof(startup);memset(&child,0,sizeof(child));
    record("create_process","result=attempt child=net-child.exe inherited_handles=0 arguments=none");
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
    return status?status:(PW_NET_CHILD?CHILD_EXIT:0);
}
