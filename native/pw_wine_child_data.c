/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _POSIX_C_SOURCE 200809L
#include "pw_wine_child_data.h"
#include "pw_wine_child_bootstrap.h"
#include "lapy_elevation_protocol.h"
#include "pw_lapy_client.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Direct Net calls remain ordinary imports. One fixed-path child-local load
 * observes whether the platform binds them under the unchanged service preload.
 * A successful load is not binding proof: every import cell is checked again.
 * No lookup, GOT writes, NetInit, search path or privilege change is used. */
int32_t sceKernelLoadStartModule(const char *,size_t,const void *,uint32_t,const void *,int *);
int sceNetSocket(const char *,int,int,int);
int sceNetConnect(int,const struct sockaddr *,socklen_t);
int sceNetSend(int,const void *,size_t,int);
int sceNetRecv(int,void *,size_t,int);
int sceNetSetsockopt(int,int,int,const void *,socklen_t);
int sceNetSocketClose(int);
int *sceNetErrnoLoc(void);
/* Slot order is part of the diagnostic manifest. Volatile GOT loads are
 * independently bound to actual instruction bytes by the native builder. */
static __attribute__((noinline)) void observe_net_import_slots(uint64_t slots[8])
{
#ifdef __PROSPERO__
#define READ_SLOT(index,symbol) do { uint64_t value; \
    __asm__ volatile("movq " #symbol "@GOTPCREL(%%rip), %0" : "=r"(value) : : "memory"); \
    slots[index]=value; } while(0)
    READ_SLOT(0,sceNetSocket); READ_SLOT(1,sceNetConnect);
    READ_SLOT(2,sceNetSend); READ_SLOT(3,sceNetRecv);
    READ_SLOT(4,sceNetSetsockopt); READ_SLOT(5,sceNetSocketClose);
    READ_SLOT(6,sceNetErrnoLoc); READ_SLOT(7,sceKernelLoadStartModule);
#undef READ_SLOT
#elif defined(PW_CHILD_NET_IMPORTS_TEST)
    extern void pw_child_net_imports_test(uint64_t [8]);
    pw_child_net_imports_test(slots);
#else
    /* Hosted native-boundary controls only; these are never runtime receipts. */
    for(unsigned i=0;i<8;i++)slots[i]=1;
#endif
}
static unsigned net_missing_mask(void)
{
    uint64_t slots[8];unsigned missing=0;
    observe_net_import_slots(slots);
    for(unsigned i=0;i<8;i++)if(!slots[i])missing|=1u<<i;
    return missing;
}
#define HELPER_LIMIT (4u*1024u*1024u)
#define SETTLE_MS 1000u
#define VISIBLE_MS 5000u
_Static_assert(sizeof(struct lapy_elevation_message)==32,"fixed helper protocol");
_Static_assert(__BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__,"helper wire is little endian");

typedef struct DataContext {
    PwWineChildData *result;
    PwNativeChildIo *original,io;
    const PwWineChildDataConfig *config;
    uint64_t recovery_end;
    int recovering,helper_socket;
    unsigned upload_complete,exchange_started;
    const PwLapyClient *active_client; /* synchronous exchange only; never retained by callbacks */
} DataContext;
static int data_fail(DataContext *c,unsigned api,int32_t raw,int error)
{
    if(!c->result->api){c->result->api=api;c->result->raw=raw;
        c->result->errno_valid=error>0;c->result->native_error=error>0?error:0;}
    return -1;
}
static int data_clock(void *context,uint64_t *value)
{
    DataContext *c=context;
    return c->original->clock_ms(c->original->context,value);
}
static int data_cancel(void *context)
{
    DataContext *c=context;
    if(c->original->cancelled&&c->original->cancelled(c->original->context)){
        c->result->cancel_requested=1;
        return data_fail(c,PW_WCD_CONTROL,1,0)!=0;
    }
    if(c->config->cancel_probe){
        int rc=c->config->cancel_probe(c->config->cancel_context);
        if(rc){
            if(rc>0)c->result->cancel_requested=1;
            else c->result->control_refused=1;
            return data_fail(c,PW_WCD_CONTROL,rc,0)!=0;
        }
        return 0;
    }
    /* Ordinary inherited control FD, never a SceNet socket ID. No second
     * reader: any pre-ACK input or closure is a refusal, not a new command. */
    struct pollfd p={.fd=3,.events=POLLIN};errno=0;
    int rc=poll(&p,1,0),error=rc<0?errno:0;
    if(rc||p.revents){
        c->result->control_refused=1;
        if(!c->result->api)c->result->control_revents=(uint16_t)p.revents;
        return data_fail(c,PW_WCD_CONTROL,rc,error)!=0;
    }
    return 0;
}
static int data_budget(DataContext *c,unsigned *remaining)
{
    unsigned left;
    PwNativeChildIo checked=c->io;
    if(c->recovering){checked.cancelled=NULL;checked.stage_end=c->recovery_end;}
    int rc=pw_native_child_remaining(&checked,&left);
    c->io.last_clock=checked.last_clock;
    c->original->last_clock=c->io.last_clock;
    if(rc)return data_fail(c,PW_WCD_BUDGET,rc,0);
    if(remaining)*remaining=left;
    return 0;
}
static int progress(DataContext *c,unsigned stage)
{
    if(!c->result->progress)return 0;
    if(data_budget(c,NULL))return -1;
    if(c->result->progress){
        int rc=c->result->progress(c->result->progress_context,stage);
        /* The callback may sample the original clock; do not discard it. */
        if(c->original->last_clock>c->io.last_clock)c->io.last_clock=c->original->last_clock;
        if(rc)return data_fail(c,PW_WCD_PROGRESS,rc,0);
    }
    return data_budget(c,NULL);
}
static int net_error(int rc)
{
    if(rc>=0)return 0;
    int *value=sceNetErrnoLoc();return value&&*value>0?*value:0;
}
static unsigned char *helper_bytes(DataContext *c,const char *expected,size_t *size)
{
    unsigned char *bytes=NULL;int fd=-1;struct stat before,after;
    if(data_budget(c,NULL))return NULL;
    errno=0;fd=open("/app0/lapy.elf",O_RDONLY|O_NOFOLLOW|O_NONBLOCK);int error=fd<0?errno:0;
    if(fd<0){data_fail(c,PW_WCD_HELPER_OPEN,fd,error);return NULL;}
    if(data_budget(c,NULL))goto done;
    errno=0;int rc=fstat(fd,&before);error=rc<0?errno:0;
    if(rc){data_fail(c,PW_WCD_HELPER_STAT,rc,error);goto done;}
    if(!S_ISREG(before.st_mode)){data_fail(c,PW_WCD_HELPER_TYPE,0,0);goto done;}
    if(before.st_size<4||(uint64_t)before.st_size>HELPER_LIMIT){data_fail(c,PW_WCD_HELPER_SIZE,0,0);goto done;}
    if(data_budget(c,NULL))goto done;
    *size=(size_t)before.st_size;errno=0;bytes=malloc(*size);error=bytes?0:errno;
    if(!bytes){data_fail(c,PW_WCD_ALLOC,0,error);goto done;}
    size_t used=0;
    while(used<*size){
        if(data_budget(c,NULL))goto done;
        size_t wanted=*size-used;if(wanted>4096)wanted=4096;
        errno=0;ssize_t got=read(fd,bytes+used,wanted);error=got<0?errno:0;
        if(got<=0||(size_t)got>wanted){data_fail(c,PW_WCD_HELPER_READ,(int32_t)got,error);goto done;}
        used+=(size_t)got;if(data_budget(c,NULL))goto done;
    }
    unsigned char extra;errno=0;ssize_t got=read(fd,&extra,1);error=got<0?errno:0;
    if(got){data_fail(c,PW_WCD_HELPER_READ,(int32_t)got,error);goto done;}
    if(data_budget(c,NULL))goto done;
    errno=0;rc=fstat(fd,&after);error=rc<0?errno:0;
    if(rc){data_fail(c,PW_WCD_HELPER_STAT,rc,error);goto done;}
    if(before.st_dev!=after.st_dev||before.st_ino!=after.st_ino||before.st_size!=after.st_size){
        data_fail(c,PW_WCD_HELPER_CHANGED,0,0);goto done;}
    if(data_budget(c,NULL))goto done;
    PwWineChildHash hash;char actual[65];pw_wine_child_hash_init(&hash);
    if(memcmp(bytes,"\177ELF",4)||pw_wine_child_hash_update(&hash,bytes,*size)){
        data_fail(c,PW_WCD_HELPER_HASH,-1,0);goto done;}
    pw_wine_child_hash_final(&hash,actual);
    if(strcmp(actual,expected)){data_fail(c,PW_WCD_HELPER_HASH,-1,0);goto done;}
    (void)data_budget(c,NULL);
 done:
    /* No file is reread after hashing; the exact bounded buffer is uploaded. */
    errno=0;int closed=close(fd);error=closed<0?errno:0;
    if(closed)data_fail(c,PW_WCD_HELPER_CLOSE,closed,error);
    if(c->result->api){free(bytes);bytes=NULL;}
    return bytes;
}
static int timeouts(DataContext *c,int socket)
{
    static const int options[]={0x1105,0x1106,0x1109};
    for(unsigned i=0;i<3;i++){
        unsigned left;if(data_budget(c,&left))return -1;
        uint32_t timeout=(left>5000?5000:left)*1000u;
        int rc=sceNetSetsockopt(socket,0xffff,options[i],&timeout,sizeof(timeout)),error=net_error(rc);
        if(rc)return data_fail(c,PW_WCD_OPTION,rc,error);
        if(data_budget(c,NULL))return -1;
    }
    return 0;
}
/* 0 complete+timely; 1 complete but late/cancelled; -1 incomplete. A complete
 * terminal response may settle ownership even when it cannot admit Wine. */
static int transfer(DataContext *c,int socket,void *bytes,size_t size,int sending,unsigned api)
{
    size_t used=0;
    while(used<size){
        if(timeouts(c,socket)||data_budget(c,NULL))return -1;
        if(sending&&api==PW_WCD_UPLOAD)c->result->no_dispatch=0;
        int got=sending?sceNetSend(socket,(unsigned char *)bytes+used,size-used,0):
                        sceNetRecv(socket,(unsigned char *)bytes+used,size-used,0);
        int error=net_error(got);
        if(got<=0||(size_t)got>size-used)return data_fail(c,api,got,error);
        used+=(size_t)got;
        if(sending&&api==PW_WCD_UPLOAD&&used==size)c->upload_complete=1;
        if(data_budget(c,NULL))return used==size?1:-1;
    }
    return 0;
}
static unsigned client_api(unsigned phase)
{
    switch(phase){case PW_LC_REQUEST:return PW_WCD_REQUEST;case PW_LC_PREPARE:return PW_WCD_PREPARE;
    case PW_LC_PREPARED:return PW_WCD_PREPARED;case PW_LC_CANCEL:return PW_WCD_CANCEL;default:return PW_WCD_RESULT;}
}
static int client_remaining(void *context,int recovery,unsigned *left)
{
    DataContext *c=context;c->recovering=recovery;
    if(!data_budget(c,left))return 0;
    return errno>0?errno:EIO;
}
static long client_transfer(DataContext *c,void *p,size_t size,unsigned phase,int recovery,int *error,int sending)
{
    c->recovering=recovery;
    if(timeouts(c,c->helper_socket)||data_budget(c,NULL)){*error=errno>0?errno:EIO;return -1;}
    int n=sending?sceNetSend(c->helper_socket,p,size,0):sceNetRecv(c->helper_socket,p,size,0);
    *error=net_error(n);
    if(n<=0||(size_t)n>size)data_fail(c,client_api(phase),n,*error);
    return n;
}
static long client_send(void *context,const void *p,size_t size,unsigned left,unsigned phase,int recovery,int *error)
{(void)left;return client_transfer(context,(void*)p,size,phase,recovery,error,1);}
static long client_receive(void *context,void *p,size_t size,unsigned left,unsigned phase,int recovery,int *error)
{(void)left;return client_transfer(context,p,size,phase,recovery,error,0);}
static int client_prepare(void *context,int *error)
{
    DataContext *c=context;errno=0;int rc=seteuid(geteuid());*error=rc<0?errno:0;
    if(rc)data_fail(c,PW_WCD_LOCAL_PREPARE,rc,*error);
    return rc;
}
static void client_result(DataContext *c,const PwLapyClient *client)
{
    c->result->possible_apply=client->possible_apply;c->result->no_request=client->no_request;
    c->result->terminal=client->terminal;c->result->settled_failure=client->settled_failure;
    c->result->helper_status=client->helper_status;c->result->cancel_attempted=client->cancel_attempted;
}
static int client_progress(void *context,unsigned phase)
{
    static const unsigned stages[]={0,PW_WCP_REQUEST_BEGIN,PW_WCP_PREPARE_RECEIVED,
        PW_WCP_LOCAL_PREPARE_BEGIN,PW_WCP_LOCAL_PREPARE_RETURNED,PW_WCP_PREPARED_SENT,PW_WCP_RESULT_RECEIVED};
    DataContext *c=context;
    if(c->active_client)client_result(c,c->active_client);
    if(phase>=sizeof(stages)/sizeof(stages[0])||progress(c,stages[phase]))return EIO;
    return 0;
}
static int exchange(DataContext *c,int socket,int cancel_only)
{
    pid_t pid=getpid();if(pid<=1)return data_fail(c,PW_WCD_ARGUMENT,(int32_t)pid,0);
    c->helper_socket=socket;c->exchange_started=1;
    PwLapyClient client;const PwLapyClientOps ops={c,client_remaining,client_send,client_receive,client_prepare,client_progress,c->upload_complete,(unsigned)cancel_only};
    c->active_client=&client;
    int rc=pw_lapy_client_exchange(&client,&ops,(uint32_t)pid,c->config->transaction_id);
    c->active_client=NULL;
    client_result(c,&client);
    c->recovering=0;
    if(rc)return data_fail(c,PW_WCD_RESULT,(int32_t)client.helper_status,client.error);
    return 0;
}
static int sleep_slice(DataContext *c,unsigned milliseconds)
{
    unsigned left;if(data_budget(c,&left))return -1;
    if(milliseconds>left)milliseconds=left;
    struct timespec pause={(time_t)(milliseconds/1000),(long)(milliseconds%1000)*1000000};
    errno=0;int rc=nanosleep(&pause,NULL),error=rc<0?errno:0;
    if(rc&&error!=EINTR)return data_fail(c,PW_WCD_SETTLE,rc,error);
    return data_budget(c,NULL); /* elapsed clock, never requested sleep, is authority */
}
/* 0 both directory observations; 1 an allowed absent/denied pair permits the one helper attempt
 * (or bounded post-helper visibility polling); -1 an explicit refusal. A
 * successful lstat is an observation, never a substitute for actual paths. */
static int observe_data_access(DataContext *c,int after)
{
    PwWineChildData *r=c->result;struct stat visible,observed;
    if(data_budget(c,NULL))return -1;
    errno=0;int sr=stat("/data",&visible),se=sr<0?errno:0;
    if(after){r->after_observations|=1;r->stat_after_raw=sr;r->stat_after_error=se;
        r->data_after=!sr&&S_ISDIR(visible.st_mode);}
    else {r->before_observations|=1;r->stat_before_raw=sr;r->stat_before_error=se;
        r->data_before=!sr&&S_ISDIR(visible.st_mode);}
    if(data_budget(c,NULL))return -1;
    errno=0;int lr=lstat("/data",&observed),le=lr<0?errno:0;
    if(after){r->after_observations|=2;r->lstat_after_raw=lr;r->lstat_after_error=le;
        r->lstat_after=!lr&&S_ISDIR(observed.st_mode);}
    else {r->before_observations|=2;r->lstat_before_raw=lr;r->lstat_before_error=le;
        r->lstat_before=!lr&&S_ISDIR(observed.st_mode);}
    /* Preserve an actual refusal before later clock/cancellation observers. */
    int refused=0;
    int stat_missing=sr==-1&&se==ENOENT;
    int needs_helper=(lr==-1&&le==EPERM)||
                     (stat_missing&&lr==-1&&le==ENOENT);
    /* Allow only directory/directory, directory/EPERM, ENOENT/ENOENT and
     * ENOENT/EPERM. Other failures do not infer a missing grant. */
    if((sr&&!stat_missing)||(!sr&&!S_ISDIR(visible.st_mode)))
        refused=data_fail(c,PW_WCD_DATA_STAT,sr,se);
    else if(lr&&!needs_helper)refused=data_fail(c,PW_WCD_DATA_LSTAT,lr,le);
    else if(!lr&&!S_ISDIR(observed.st_mode))refused=data_fail(c,PW_WCD_DATA_LSTAT_TYPE,lr,0);
    else if(!lr&&stat_missing)refused=data_fail(c,PW_WCD_DATA_STAT,sr,se);
    int stopped=data_budget(c,NULL);
    if(refused||stopped)return -1;
    return needs_helper?1:0;
}
static int wait_data(DataContext *c)
{
    if(data_budget(c,NULL))return -1;
    uint64_t begun=c->io.last_clock;
    for(;;){
        int rc=observe_data_access(c,1);
        if(rc<0)return -1;
        if(!rc)break;
        if(c->io.last_clock-begun>=VISIBLE_MS)
            return data_fail(c,PW_WCD_DATA_LSTAT,c->result->lstat_after_raw,c->result->lstat_after_error);
        if(sleep_slice(c,100))return -1;
    }
    if(progress(c,PW_WCP_DATA_VISIBLE))return -1;
    begun=c->io.last_clock;
    while(c->io.last_clock-begun<SETTLE_MS){
        uint64_t elapsed=c->io.last_clock-begun;unsigned left=SETTLE_MS-(unsigned)elapsed;
        if(sleep_slice(c,left>100?100:left))return -1;
    }
    c->result->settled_ms=(unsigned)(c->io.last_clock-begun);
    return progress(c,PW_WCP_DATA_SETTLED)||data_budget(c,NULL)?-1:0;
}
int pw_wine_child_data_prepare(PwWineChildData *result,PwNativeChildIo *io,const char *expected,const PwWineChildDataConfig *config)
{
    if(!result||!io||!io->ready||!io->clock_ms||!expected||!config||!config->transaction_id)return -1;
    DataContext c={.result=result,.original=io,.io=*io,.config=config};
    c.recovery_end=io->stage_end>UINT64_MAX-PW_WINE_CHILD_CLEANUP_MS?UINT64_MAX:io->stage_end+PW_WINE_CHILD_CLEANUP_MS;
    if(c.recovery_end>io->total_end)c.recovery_end=io->total_end;
    if(result->attempted)return data_fail(&c,PW_WCD_ARGUMENT,-1,0);
    result->attempted=1;result->no_dispatch=1;result->no_request=1;result->transaction_id=config->transaction_id;c.io.context=&c;c.io.clock_ms=data_clock;c.io.cancelled=data_cancel;
    if(strlen(expected)!=64)return data_fail(&c,PW_WCD_ARGUMENT,-1,0);
    for(unsigned i=0;i<64;i++)if(!((expected[i]>='0'&&expected[i]<='9')||(expected[i]>='a'&&expected[i]<='f')))
        return data_fail(&c,PW_WCD_ARGUMENT,-1,0);
    int rc=observe_data_access(&c,0);
    if(rc<0)return -1;
    if(progress(&c,PW_WCP_DATA_OBSERVED))return -1;
    if(!rc){result->data_after=result->ready=1;return 0;}
    if(progress(&c,PW_WCP_HELPER_READ_BEGIN))return -1;
    size_t size=0;unsigned char *bytes=helper_bytes(&c,expected,&size);
    if(!bytes)return -1;
    int socket=-1,success=0;
    if(data_budget(&c,NULL)||progress(&c,PW_WCP_HELPER_VERIFIED))goto done;
    if(data_budget(&c,NULL))goto done;
    result->net_missing_mask=net_missing_mask();
    if(result->net_missing_mask&(1u<<7)){
        data_fail(&c,PW_WCD_NET_LOADER_SLOT,-1,0);goto done;
    }
    result->net_load_attempted=1;result->net_start_result=INT32_MIN;
    result->net_load_result=sceKernelLoadStartModule("/system/common/lib/libSceNet.sprx",
                                                   0,NULL,0,NULL,&result->net_start_result);
    /* Preserve the immediate signed results before any callback or error read. */
    result->net_missing_mask=net_missing_mask();
    if(progress(&c,PW_WCP_NET_SOCKET_BEGIN))goto done;
    if(result->net_load_result<=0){data_fail(&c,PW_WCD_NET_LOAD,result->net_load_result,0);goto done;}
    if(result->net_start_result){data_fail(&c,PW_WCD_MODULE_START,result->net_start_result,0);goto done;}
    if(data_budget(&c,NULL))goto done;
    /* Callbacks after stage5 remain independent failure sites. Re-read after
     * them; never infer readiness solely from the already-emitted observation. */
    result->net_missing_mask=net_missing_mask();
    if(result->net_missing_mask&0x7fu){data_fail(&c,PW_WCD_NET_IMPORT_SLOT,-1,0);goto done;}
    socket=sceNetSocket("pw-wine-child-data",AF_INET,SOCK_STREAM,6);
    int error=net_error(socket);
    if(socket<0){data_fail(&c,PW_WCD_SOCKET,socket,error);goto done;}
    if(progress(&c,PW_WCP_NET_SOCKET_READY)||data_budget(&c,NULL)||timeouts(&c,socket))goto done;
    /* SceNet uses the target BSD sockaddr layout even in host controls. */
    struct { uint8_t length,family;uint16_t port;uint32_t address;uint8_t zero[8]; } address={0};
    _Static_assert(sizeof(address)==16,"fixed SceNet IPv4 address");
    address.length=sizeof(address);address.family=AF_INET;
    address.port=(uint16_t)((9021u<<8)|(9021u>>8));address.address=UINT32_C(0x0100007f);
    if(progress(&c,PW_WCP_NET_CONNECT_BEGIN)||data_budget(&c,NULL))goto done;
    rc=sceNetConnect(socket,(const struct sockaddr *)&address,sizeof(address));error=net_error(rc);
    if(rc){data_fail(&c,PW_WCD_CONNECT,rc,error);goto done;}
    if(progress(&c,PW_WCP_NET_CONNECTED)||data_budget(&c,NULL)||transfer(&c,socket,bytes,size,1,PW_WCD_UPLOAD))goto done;
    free(bytes);bytes=NULL;
    if(progress(&c,PW_WCP_HELPER_UPLOADED))goto done;
    if(exchange(&c,socket,0)||wait_data(&c))goto done;
    success=1;
 done:
    free(bytes);
    if(socket>=0&&c.upload_complete&&!c.exchange_started)(void)exchange(&c,socket,1);
    if(socket>=0){
        rc=sceNetSocketClose(socket);error=net_error(rc);
        if(rc){data_fail(&c,PW_WCD_NET_CLOSE,rc,error);success=0;}
    }
    if(data_budget(&c,NULL))success=0;
    if(success&&!result->api&&progress(&c,PW_WCP_NET_CLOSED))success=0;
    if(success&&!result->api){result->ready=1;return 0;}
    return -1;
}
