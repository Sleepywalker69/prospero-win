/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Actual DNSAPI main/query TUs, real Wine headers; platform/backend boundaries mocked. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "winerror.h"
#include "winnls.h"
#include "windns.h"
#include "nb30.h"
#include "ws2def.h"
#include "inaddr.h"
#include "in6addr.h"
#include "ip2string.h"
#include "wine/debug.h"
#include "dnsapi.h"

extern BOOL WINAPI DllMain(HINSTANCE,DWORD,LPVOID);
/* These existing PE-only exports have no declaration in this pinned windns.h. */
extern BOOL WINAPI DnsFlushResolverCacheEntry_A(PCSTR);
extern BOOL WINAPI DnsFlushResolverCacheEntry_UTF8(PCSTR);
extern BOOL WINAPI DnsFlushResolverCacheEntry_W(PCWSTR);
static unsigned checks, init_calls, disables, dispatches, fallback_calls, extracts, conversions;
static unsigned slot_calls[4], hostname_calls, live_allocations;
static NTSTATUS init_status;
static unixlib_handle_t init_handle;
unixlib_handle_t __wine_unixlib_handle;
static int query_during_init, mode, host_fail;
static DNS_STATUS backend_status[4];
static unsigned expected_slot, response_code, query_options;
static void *expected_params, *expected_servers;
static WORD query_type;
static USHORT expected_family;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr,"check %u line %d failed: %s (dispatches=%u init=%u)\n",checks,__LINE__,#x,dispatches,init_calls); abort(); } } while(0)

/* Only DNSAPI's heap boundaries are renamed at compile time. */
void *dns_test_malloc(size_t n) { void *p=malloc(n); if(p) ++live_allocations; return p; }
void *dns_test_calloc(size_t n,size_t s) { void *p=calloc(n,s); if(p) ++live_allocations; return p; }
void dns_test_free(void *p) { if(p) { CHECK(live_allocations>0); --live_allocations; } free(p); }
char *dns_test_strdup(const char *s) { size_t n=strlen(s)+1; char *p=dns_test_malloc(n); if(p) memcpy(p,s,n); return p; }
static unsigned wide_length(const WCHAR *s) { unsigned n=0; while(s[n]) ++n; return n; }
static void wide_from_ascii(WCHAR *out,const char *s) { while((*out++=(unsigned char)*s++)); }
static int wide_equals(const WCHAR *w,const char *s) { while(*s && *w==(unsigned char)*s) { ++w; ++s; } return !*s&&! *w; }

BOOL WINAPI DisableThreadLibraryCalls(HMODULE h) { CHECK(h==(HMODULE)(uintptr_t)0x111); ++disables; return TRUE; }
NTSTATUS WINAPI __wine_init_unix_call(void)
{
    ++init_calls;
    __wine_unixlib_handle=init_handle;
    if(query_during_init) {
        unsigned char bytes[32]; memset(bytes,0xa5,sizeof(bytes));
        unsigned before=dispatches;
        CHECK(RESOLV_CALL(set_serverlist,bytes)==ERROR_NOT_SUPPORTED);
        CHECK(dispatches==before && bytes[0]==0xa5);
    }
    return init_status;
}
BOOL WINAPI IsBadStringPtrA(LPCSTR s,UINT_PTR n) { (void)s;(void)n;return FALSE; }
BOOL WINAPI IsBadStringPtrW(LPCWSTR s,UINT_PTR n) { (void)s;(void)n;return FALSE; }
unsigned char __cdecl __wine_dbg_get_channel_flags(struct __wine_debug_channel *c) { (void)c; return 0; }
const char *__cdecl __wine_dbg_strdup(const char *s) { (void)s; return "mock-log"; }
int __cdecl __wine_dbg_output(const char *s) { (void)s; return 0; }
int __cdecl __wine_dbg_header(enum __wine_debug_class c,struct __wine_debug_channel *ch,const char *f)
{ (void)c;(void)ch;(void)f;return 0; }
const char *debugstr_type(unsigned short t) { (void)t;return "type"; }

INT WINAPI MultiByteToWideChar(UINT cp,DWORD flags,LPCSTR s,INT count,LPWSTR out,INT capacity)
{
    CHECK((cp==CP_ACP||cp==CP_UTF8)&&flags==0&&count==-1); ++conversions;
    int n=(int)strlen(s)+1; if(out) { CHECK(capacity>=n);wide_from_ascii(out,s); } return n;
}
INT WINAPI WideCharToMultiByte(UINT cp,DWORD flags,LPCWSTR s,INT count,LPSTR out,INT capacity,LPCSTR def,LPBOOL used)
{
    CHECK((cp==CP_ACP||cp==CP_UTF8)&&flags==0&&count==-1&&!def&&!used); ++conversions;
    int n=(int)wide_length(s)+1; if(out) { CHECK(capacity>=n);for(int i=0;i<n;i++)out[i]=(char)s[i]; } return n;
}
NTSTATUS WINAPI RtlIpv4StringToAddressA(const char *s,BOOLEAN strict,const char **end,IN_ADDR *addr)
{
    CHECK(strict==TRUE); *end=s;
    if(strcmp(s,"127.0.0.7")) return (NTSTATUS)0xc000000d;
    *end=s+strlen(s); addr->s_addr=0x0700007f; return 0;
}
NTSTATUS WINAPI RtlIpv6StringToAddressA(const char *s,const char **end,IN6_ADDR *addr)
{
    *end=s; if(strcmp(s,"2001:db8::7"))return (NTSTATUS)0xc000000d;
    *end=s+strlen(s);memset(addr,0,sizeof(*addr));((unsigned char *)addr)[0]=0x20;((unsigned char *)addr)[1]=1;
    ((unsigned char *)addr)[15]=7;return 0;
}
UCHAR WINAPI Netbios(PNCB n) { CHECK(n->ncb_command==NCBFINDNAME);++fallback_calls;return NRC_NAMERR; }
static const char *host_name(COMPUTER_NAME_FORMAT f)
{
    switch(f) {case ComputerNameDnsHostname:return "fixture";case ComputerNameDnsFullyQualified:return "fixture.test";
    case ComputerNameDnsDomain:return "test";default:CHECK(0);return "";}
}
BOOL WINAPI GetComputerNameExA(COMPUTER_NAME_FORMAT f,LPSTR out,LPDWORD n)
{ ++hostname_calls;if(host_fail)return FALSE; const char *s=host_name(f);CHECK(*n>strlen(s));strcpy(out,s);*n=(DWORD)strlen(s);return TRUE; }
BOOL WINAPI GetComputerNameExW(COMPUTER_NAME_FORMAT f,LPWSTR out,LPDWORD n)
{ ++hostname_calls;if(host_fail)return FALSE; const char *s=host_name(f);CHECK(*n>strlen(s));wide_from_ascii(out,s);*n=(DWORD)strlen(s);return TRUE; }
VOID WINAPI DnsRecordListFree(PDNS_RECORD r,DNS_FREE_TYPE kind)
{ CHECK(kind==DnsFreeRecordList);while(r) { PDNS_RECORD next=r->pNext;dns_test_free(r->pName);dns_test_free(r);r=next;} }
PDNS_RECORD WINAPI DnsRecordSetCopyEx(PDNS_RECORD source,DNS_CHARSET from,DNS_CHARSET to)
{
    CHECK(source && (from==DnsCharSetUtf8||from==DnsCharSetUnicode));
    CHECK(to==DnsCharSetUnicode||to==DnsCharSetAnsi);
    DNS_RECORDA *out=dns_test_calloc(1,sizeof(*out));CHECK(out!=NULL);memcpy(out,source,sizeof(*out));out->pNext=NULL;
    char ascii[128];const char *s;
    if(from==DnsCharSetUnicode) { WCHAR *w=(WCHAR *)source->pName;unsigned n=wide_length(w);CHECK(n<sizeof(ascii));for(unsigned i=0;i<=n;i++)ascii[i]=(char)w[i];s=ascii; }
    else s=(const char *)source->pName;
    if(to==DnsCharSetUnicode) { WCHAR *w=dns_test_malloc((strlen(s)+1)*sizeof(*w));CHECK(w!=NULL);wide_from_ascii(w,s);out->pName=(char *)w; }
    else out->pName=dns_test_strdup(s);
    out->Flags.S.CharSet=to;return (PDNS_RECORD)out;
}
DNS_STATUS WINAPI DnsExtractRecordsFromMessage_UTF8(PDNS_MESSAGE_BUFFER msg,WORD n,PDNS_RECORDA *out)
{
    CHECK(n>=sizeof(msg->MessageHead)&&msg->MessageHead.ResponseCode==DNS_RCODE_NOERROR);++extracts;
    DNS_RECORDA *r=dns_test_calloc(1,sizeof(*r));CHECK(r!=NULL);r->pName=dns_test_strdup("healthy.test");r->wType=query_type;
    r->Data.A.IpAddress=0x44332211;*out=r;return ERROR_SUCCESS;
}

static NTSTATUS WINAPI dispatch(unixlib_handle_t handle,unsigned op,void *args)
{
    ++dispatches;CHECK(op<unix_funcs_count);++slot_calls[op];
    if(mode==0) return 777; /* The historical missing-table path is observed, never dereferenced. */
    CHECK(handle==init_handle && handle!=0);
    if(mode==1) { CHECK(op==expected_slot && args==expected_params);return backend_status[op]; }
    if(op==unix_set_serverlist) { CHECK(args==expected_servers);return backend_status[op]; }
    if(op==unix_query) {
        struct query_params *p=args;CHECK(!strcmp(p->name,"healthy.test")||!strcmp(p->name,"short"));
        CHECK(p->type==query_type && p->options==query_options && *p->len==4096);
        if(backend_status[op])return backend_status[op];
        DNS_MESSAGE_BUFFER *m=p->buf;memset(m,0,sizeof(m->MessageHead));m->MessageHead.ResponseCode=response_code;
        *p->len=sizeof(m->MessageHead);return ERROR_SUCCESS;
    }
    if(op==unix_get_searchlist) {
        struct get_searchlist_params *p=args;CHECK(p->list==expected_params);
        if(backend_status[op])return backend_status[op];
        CHECK(*p->len>=8);memset(p->list,0x3c,8);*p->len=8;return 0;
    }
    if(op==unix_get_serverlist) {
        struct get_serverlist_params *p=args;CHECK(p->family==expected_family);
        if(mode!=3)CHECK(p->addrs==expected_params);
        if(backend_status[op])return backend_status[op];
        DWORD n=FIELD_OFFSET(DNS_ADDR_ARRAY,AddrArray[1]);CHECK(*p->len>=n);memset(p->addrs,0,n);
        p->addrs->AddrCount=1;((SOCKADDR_IN *)p->addrs->AddrArray[0].MaxSa)->sin_addr.s_addr=0x12345678;*p->len=n;return 0;
    }
    CHECK(0);return 777;
}
NTSTATUS (WINAPI *__wine_unix_call_dispatcher)(unixlib_handle_t,unsigned int,void *)=dispatch;
static DNS_STATUS direct_slot(unsigned slot,void *p)
{
    char *argument=p;DNS_STATUS result;
    switch(slot) {case unix_get_searchlist:result=RESOLV_CALL(get_searchlist,argument++);break;
    case unix_get_serverlist:result=RESOLV_CALL(get_serverlist,argument++);break;
    case unix_set_serverlist:result=RESOLV_CALL(set_serverlist,argument++);break;
    case unix_query:result=RESOLV_CALL(query,argument++);break;default:CHECK(0);return 0;}
    CHECK(argument==(char *)p+1);return result;
}
static void attach(NTSTATUS status,unixlib_handle_t handle)
{
    init_status=status;init_handle=handle;unsigned old=init_calls;
    CHECK(DllMain((HINSTANCE)(uintptr_t)0x111,DLL_PROCESS_ATTACH,NULL));CHECK(init_calls==old+1&&disables==init_calls);
}
static void reset_observations(void)
{ dispatches=fallback_calls=extracts=hostname_calls=0;memset(slot_calls,0,sizeof(slot_calls));memset(backend_status,0,sizeof(backend_status)); }
static void unavailable(void)
{
    unsigned initializations=init_calls;
    unsigned char buf[256],saved[256];DWORD len;DNS_RECORDA *sentinel=(void *)(uintptr_t)0x1234,*record;
    WCHAR name[32];wide_from_ascii(name,"healthy.test");mode=0;reset_observations();
    for(unsigned slot=0;slot<4;slot++) { memset(buf,0xa5,sizeof(buf));memcpy(saved,buf,sizeof(buf));
        CHECK(direct_slot(slot,buf)==ERROR_NOT_SUPPORTED);CHECK(!memcmp(buf,saved,sizeof(buf))&&dispatches==0); }
    record=sentinel;CHECK(DnsQuery_UTF8("healthy.test",DNS_TYPE_A,0,NULL,&record,NULL)==ERROR_NOT_SUPPORTED);CHECK(record==sentinel);
    record=sentinel;CHECK(DnsQuery_A("healthy.test",DNS_TYPE_AAAA,0,NULL,&record,NULL)==ERROR_NOT_SUPPORTED);CHECK(record==sentinel);
    DNS_RECORDW *wide=(void *)sentinel;CHECK(DnsQuery_W(name,DNS_TYPE_A,0,NULL,&wide,NULL)==ERROR_NOT_SUPPORTED);CHECK(wide==(void *)sentinel);
    const DNS_CONFIG_TYPE configs[]={DnsConfigDnsServerList,DnsConfigDnsServersUnspec,DnsConfigDnsServersIpv4,DnsConfigDnsServersIpv6,DnsConfigSearchList};
    for(unsigned i=0;i<ARRAY_SIZE(configs);i++) { memset(buf,0xa5,sizeof(buf));memcpy(saved,buf,sizeof(buf));len=sizeof(buf);
        CHECK(DnsQueryConfig(configs[i],0,NULL,NULL,buf,&len)==ERROR_NOT_SUPPORTED);
        CHECK(len==sizeof(buf)&&!memcmp(buf,saved,sizeof(buf))); }
    CHECK(dispatches==0&&fallback_calls==0&&extracts==0&&live_allocations==0&&init_calls==initializations);
}
static void pe_only(void)
{
    unsigned before=dispatches,initializations=init_calls;const char *names[]={"127.0.0.7","2001:db8::7"};const WORD types[]={DNS_TYPE_A,DNS_TYPE_AAAA};
    for(unsigned i=0;i<2;i++)for(unsigned flavor=0;flavor<3;flavor++) {
        DNS_RECORDA *r=NULL;DNS_STATUS status;WCHAR wide[40];wide_from_ascii(wide,names[i]);
        if(flavor==0)status=DnsQuery_UTF8(names[i],types[i],0,NULL,&r,NULL);
        else if(flavor==1)status=DnsQuery_A(names[i],types[i],0,NULL,&r,NULL);
        else status=DnsQuery_W(wide,types[i],0,NULL,(DNS_RECORDW **)&r,NULL);
        CHECK(status==0&&r&&r->wType==types[i]&&r->dwTtl==604800);
        CHECK(r->wDataLength==(i?sizeof(r->Data.AAAA):sizeof(r->Data.A)));
        CHECK(flavor==2?wide_equals((WCHAR *)r->pName,names[i]):!strcmp(r->pName,names[i]));
        CHECK(i?((unsigned char *)&r->Data.AAAA.Ip6Address)[15]==7:r->Data.A.IpAddress==0x0700007f);
        DnsRecordListFree((PDNS_RECORD)r,DnsFreeRecordList);
    }
    const DNS_CONFIG_TYPE configs[]={DnsConfigHostName_A,DnsConfigHostName_UTF8,DnsConfigHostName_W,
        DnsConfigFullHostName_A,DnsConfigFullHostName_UTF8,DnsConfigFullHostName_W,
        DnsConfigPrimaryDomainName_A,DnsConfigPrimaryDomainName_UTF8,DnsConfigPrimaryDomainName_W};
    for(unsigned i=0;i<ARRAY_SIZE(configs);i++) {
        unsigned char out[128];DWORD len=128;memset(out,0xa5,sizeof(out));
        CHECK(DnsQueryConfig(configs[i],0,NULL,NULL,out,&len)==0);
        const char *name=i<3?"fixture":i<6?"fixture.test":"test";
        CHECK(i%3==2?wide_equals((WCHAR *)out,name):!strcmp((char *)out,name));
        len=1;memset(out,0xa5,sizeof(out));CHECK(DnsQueryConfig(configs[i],0,NULL,NULL,out,&len)==ERROR_INSUFFICIENT_BUFFER);
        CHECK(len==strlen(name)+1&&out[0]==0xa5);
    }
    CHECK(DnsFlushResolverCacheEntry_A("x")&&DnsFlushResolverCacheEntry_UTF8("x"));
    WCHAR x[]={ 'x',0 };CHECK(DnsFlushResolverCacheEntry_W(x));CHECK(!DnsFlushResolverCacheEntry_A(NULL));
    host_fail=1;unsigned char refused[128];memset(refused,0xa5,sizeof(refused));DWORD len=128;
    CHECK(DnsQueryConfig(DnsConfigHostName_A,0,NULL,NULL,refused,&len)==DNS_ERROR_NAME_DOES_NOT_EXIST);
    CHECK(len==128&&refused[0]==0xa5);
    CHECK(DnsQueryConfig(DnsConfigHostName_W,0,NULL,NULL,refused,&len)==DNS_ERROR_NAME_DOES_NOT_EXIST);
    CHECK(len==128&&refused[0]==0xa5);host_fail=0;
    CHECK(dispatches==before&&live_allocations==0&&init_calls==initializations);
}
static void invalid_arguments(void)
{
    DNS_RECORDA *r=(void *)(uintptr_t)0x1234;DWORD len=91;unsigned before=dispatches;
    CHECK(DnsQuery_UTF8(NULL,DNS_TYPE_A,0,NULL,&r,NULL)==ERROR_INVALID_PARAMETER);
    CHECK(DnsQuery_UTF8("healthy.test",DNS_TYPE_A,0,NULL,NULL,NULL)==ERROR_INVALID_PARAMETER);
    CHECK(DnsQuery_A(NULL,DNS_TYPE_A,0,NULL,&r,NULL)==ERROR_INVALID_PARAMETER);
    CHECK(DnsQuery_W(NULL,DNS_TYPE_A,0,NULL,(DNS_RECORDW **)&r,NULL)==ERROR_INVALID_PARAMETER);
    CHECK(DnsQueryConfig(DnsConfigSearchList,0,NULL,NULL,NULL,NULL)==ERROR_INVALID_PARAMETER);
    CHECK(DnsQueryConfig((DNS_CONFIG_TYPE)999,0,NULL,NULL,NULL,&len)==ERROR_INVALID_PARAMETER&&len==91);
    CHECK(dispatches==before&&r==(void *)(uintptr_t)0x1234&&live_allocations==0);
}
static void healthy(void)
{
    unsigned initializations=init_calls;
    reset_observations();mode=1;unsigned char arg[64];expected_params=arg;
    const DNS_STATUS statuses[]={0,ERROR_MORE_DATA,ERROR_NOT_SUPPORTED,DNS_ERROR_RCODE_NAME_ERROR,12345};
    for(unsigned slot=0;slot<4;slot++)for(unsigned j=0;j<ARRAY_SIZE(statuses);j++) {
        expected_slot=slot;backend_status[slot]=statuses[j];unsigned n=dispatches;void *p=arg;
        CHECK(direct_slot(slot,p++)==statuses[j]);CHECK(p==arg+1&&dispatches==n+1);
    }
    mode=2;memset(backend_status,0,sizeof(backend_status));expected_servers=arg;query_type=DNS_TYPE_A;query_options=DNS_QUERY_NO_NETBT;
    response_code=DNS_RCODE_NOERROR;DNS_RECORDA *record=NULL;unsigned calls=dispatches;
    CHECK(DnsQuery_UTF8("healthy.test",query_type,query_options,arg,&record,NULL)==0);
    CHECK(record&&record->Data.A.IpAddress==0x44332211&&dispatches==calls+2&&extracts==1);DnsRecordListFree((PDNS_RECORD)record,DnsFreeRecordList);
    for(unsigned flavor=0;flavor<2;flavor++) {
        WCHAR name[32];wide_from_ascii(name,"healthy.test");record=NULL;calls=dispatches;
        DNS_STATUS rc=flavor?DnsQuery_W(name,query_type,query_options,arg,(DNS_RECORDW **)&record,NULL):
                             DnsQuery_A("healthy.test",query_type,query_options,arg,&record,NULL);
        CHECK(rc==0&&record&&record->Data.A.IpAddress==0x44332211&&dispatches==calls+2);
        CHECK(flavor?wide_equals((WCHAR *)record->pName,"healthy.test"):!strcmp(record->pName,"healthy.test"));
        DnsRecordListFree((PDNS_RECORD)record,DnsFreeRecordList);
    }
    backend_status[unix_set_serverlist]=ERROR_MORE_DATA;calls=dispatches;record=(void *)(uintptr_t)0x1234;
    CHECK(DnsQuery_UTF8("healthy.test",query_type,query_options,arg,&record,NULL)==ERROR_MORE_DATA);
    CHECK(record==(void *)(uintptr_t)0x1234&&dispatches==calls+1);
    backend_status[unix_set_serverlist]=0;backend_status[unix_query]=ERROR_NOT_SUPPORTED;calls=dispatches;
    CHECK(DnsQuery_UTF8("healthy.test",query_type,query_options,arg,&record,NULL)==ERROR_NOT_SUPPORTED&&dispatches==calls+2);
    CHECK(!fallback_calls&&record==(void *)(uintptr_t)0x1234);
    backend_status[unix_query]=0;response_code=DNS_RCODE_NXDOMAIN;query_options=0;
    CHECK(DnsQuery_UTF8("short",query_type,query_options,arg,&record,NULL)==ERROR_INVALID_NAME&&fallback_calls==1);
    query_options=DNS_QUERY_NO_NETBT;CHECK(DnsQuery_UTF8("short",query_type,query_options,arg,&record,NULL)==DNS_ERROR_RCODE_NAME_ERROR);
    CHECK(fallback_calls==1);
    unsigned char out[512];expected_params=out;DWORD len=sizeof(out);expected_family=AF_INET6;
    CHECK(DnsQueryConfig(DnsConfigDnsServersIpv6,0,NULL,NULL,out,&len)==0);
    CHECK(len==FIELD_OFFSET(DNS_ADDR_ARRAY,AddrArray[1])&&((DNS_ADDR_ARRAY *)out)->AddrCount==1);
    len=sizeof(out);CHECK(DnsQueryConfig(DnsConfigSearchList,0,NULL,NULL,out,&len)==0&&len==8&&out[0]==0x3c);
    mode=3;expected_family=AF_INET;len=sizeof(out);CHECK(DnsQueryConfig(DnsConfigDnsServerList,0,NULL,NULL,out,&len)==0);
    CHECK(((IP4_ARRAY *)out)->AddrCount==1&&((IP4_ARRAY *)out)->AddrArray[0]==0x12345678);
    CHECK(live_allocations==0&&init_calls==initializations);
}
int main(void)
{
    _Static_assert(sizeof(WCHAR)==2,"host harness models Wine UTF-16");
    /* First case is baseline-compatible and traps the original unsafe dispatch. */
    attach((NTSTATUS)0xc0000135,0);unavailable();pe_only();invalid_arguments();
    attach(0,0);unavailable();pe_only();invalid_arguments();
    attach((NTSTATUS)0xc0000135,0x12345678);unavailable();
    query_during_init=1;attach(0,0x12345678);query_during_init=0;healthy();pe_only();invalid_arguments();
    unsigned before=init_calls;CHECK(DllMain((HINSTANCE)(uintptr_t)0x111,DLL_THREAD_ATTACH,NULL));
    CHECK(DllMain((HINSTANCE)(uintptr_t)0x111,DLL_THREAD_DETACH,NULL));CHECK(init_calls==before);
    CHECK(DllMain((HINSTANCE)(uintptr_t)0x111,DLL_PROCESS_DETACH,NULL));CHECK(init_calls==before);
    attach((NTSTATUS)0xc0000001,0);unavailable();CHECK(live_allocations==0);
    printf("DNSAPI actual-entrypoint controls: %u checks; zero live fixture allocations\n",checks);
    return 0;
}
