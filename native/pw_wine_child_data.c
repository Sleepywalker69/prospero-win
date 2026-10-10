/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _POSIX_C_SOURCE 200809L
#include "pw_wine_child_data.h"
#include "pw_wine_child_bootstrap.h"
#include "lapy_elevation_protocol.h"
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

int32_t sceKernelLoadStartModule(const char *,size_t,const void *,uint32_t,const void *,int *);
int sceKernelDlsym(int32_t,const char *,void **);
#define NET_ID UINT32_C(0x8000001c)
#define HELPER_LIMIT (4u*1024u*1024u)
#define SETTLE_MS 1000u
#define VISIBLE_MS 5000u
_Static_assert(sizeof(struct lapy_elevation_message)==24,"fixed helper protocol");
_Static_assert(__BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__,"helper wire is little endian");

typedef struct ChildNet {
    int (*init)(void);
    int (*socket)(const char *,int,int,int);
    int (*connect)(int,const struct sockaddr *,socklen_t);
    int (*send)(int,const void *,size_t,int);
    int (*receive)(int,void *,size_t,int);
    int (*option)(int,int,int,const void *,socklen_t);
    int (*close)(int);
    int *(*error)(void);
} ChildNet;
typedef struct DataContext {
    PwWineChildData *result;
    PwNativeChildIo *original,io;
    ChildNet net;
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
        c->result->control_refused=1;
        return data_fail(c,PW_WCD_CONTROL,1,0)!=0;
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
    int rc=pw_native_child_remaining(&c->io,&left);
    c->original->last_clock=c->io.last_clock;
    if(rc)return data_fail(c,PW_WCD_BUDGET,rc,0);
    if(remaining)*remaining=left;
    return 0;
}
static int net_error(DataContext *c,int rc)
{
    if(rc>=0)return 0;
    int *value=c->net.error();return value&&*value>0?*value:0;
}
static int resolve(DataContext *c,int32_t module,const char *name,void *slot,unsigned index)
{
    if(data_budget(c,NULL))return -1;
    void *address=NULL;int rc=sceKernelDlsym(module,name,&address);
    if(rc||!address){
        if(!c->result->api)c->result->resolution_index=index;
        return data_fail(c,PW_WCD_RESOLVE,rc,0);
    }
    /* Function/object pointers have the same representation in this target ABI. */
    _Static_assert(sizeof(void *)==sizeof(c->net.init),"native function pointer ABI");
    memcpy(slot,&address,sizeof(address));
    return data_budget(c,NULL);
}
static int net_start(DataContext *c)
{
    if(data_budget(c,NULL))return -1;
    int started=0;
    int32_t module=sceKernelLoadStartModule("/system/common/lib/libSceSysmodule.sprx",0,NULL,0,NULL,&started);
    if(module<=0)return data_fail(c,PW_WCD_MODULE_LOAD,module,0);
    if(started)return data_fail(c,PW_WCD_MODULE_START,started,0);
    if(data_budget(c,NULL))return -1;
    int (*load)(unsigned)=NULL;int (*handle)(uint32_t,int32_t *)=NULL;
    if(resolve(c,module,"sceSysmoduleLoadModuleInternal",&load,PW_WCD_SYSMODULE_LOAD)||
       resolve(c,module,"sceSysmoduleGetModuleHandleInternal",&handle,PW_WCD_SYSMODULE_HANDLE))return -1;
    if(data_budget(c,NULL))return -1;
    int rc=load(NET_ID);if(rc)return data_fail(c,PW_WCD_NET_LOAD,rc,0);
    if(data_budget(c,NULL))return -1;
    int32_t net=-1;rc=handle(NET_ID,&net);
    if(rc||net<0)return data_fail(c,PW_WCD_NET_HANDLE,rc,0);
    if(data_budget(c,NULL))return -1;
    if(resolve(c,net,"sceNetInit",&c->net.init,PW_WCD_NET_INIT_SYMBOL)||resolve(c,net,"sceNetSocket",&c->net.socket,PW_WCD_NET_SOCKET_SYMBOL)||
       resolve(c,net,"sceNetConnect",&c->net.connect,PW_WCD_NET_CONNECT_SYMBOL)||resolve(c,net,"sceNetSend",&c->net.send,PW_WCD_NET_SEND_SYMBOL)||
       resolve(c,net,"sceNetRecv",&c->net.receive,PW_WCD_NET_RECV_SYMBOL)||resolve(c,net,"sceNetSetsockopt",&c->net.option,PW_WCD_NET_OPTION_SYMBOL)||
       resolve(c,net,"sceNetSocketClose",&c->net.close,PW_WCD_NET_CLOSE_SYMBOL)||resolve(c,net,"sceNetErrnoLoc",&c->net.error,PW_WCD_NET_ERRNO_SYMBOL))return -1;
    if(data_budget(c,NULL))return -1;
    rc=c->net.init();int error=net_error(c,rc);
    if(rc)return data_fail(c,PW_WCD_NET_INIT,rc,error);
    /* These modules and Net initialization remain live for subsequent Wine. */
    return data_budget(c,NULL);
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
        int rc=c->net.option(socket,0xffff,options[i],&timeout,sizeof(timeout)),error=net_error(c,rc);
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
        int got=sending?c->net.send(socket,(unsigned char *)bytes+used,size-used,0):
                        c->net.receive(socket,(unsigned char *)bytes+used,size-used,0);
        int error=net_error(c,got);
        if(got<=0||(size_t)got>size-used)return data_fail(c,api,got,error);
        used+=(size_t)got;
        if(data_budget(c,NULL))return used==size?1:-1;
    }
    return 0;
}
static int matches(const struct lapy_elevation_message *m,const struct lapy_elevation_message *request,unsigned kind)
{
    return m->magic==request->magic&&m->version==request->version&&m->size==request->size&&
           m->kind==kind&&m->capability==request->capability&&m->pid==request->pid;
}
static int terminal_status(unsigned status,int prepared)
{
    if(!prepared)return status>=LAPY_ELEVATION_INVALID_REQUEST&&status<=LAPY_ELEVATION_TARGET_MISMATCH;
    return status==LAPY_ELEVATION_OK||status==LAPY_ELEVATION_TARGET_MISMATCH||status==LAPY_ELEVATION_UNAVAILABLE||
           status==LAPY_ELEVATION_PREPARE_FAILED||status==LAPY_ELEVATION_APPLY_FAILED||
           status==LAPY_ELEVATION_TRANSPORT_ERROR||status==LAPY_ELEVATION_PROTOCOL_ERROR;
}
static int exchange(DataContext *c,int socket)
{
    if(data_budget(c,NULL))return -1;
    pid_t pid=getpid();if(pid<=1)return data_fail(c,PW_WCD_ARGUMENT,(int32_t)pid,0);
    struct lapy_elevation_message request={LAPY_ELEVATION_MAGIC,LAPY_ELEVATION_VERSION,
        sizeof(request),LAPY_ELEVATION_REQUEST,LAPY_ELEVATION_FILESYSTEM,(uint32_t)pid,LAPY_ELEVATION_OK};
    struct lapy_elevation_message message={0};
    /* The helper targets no process before REQUEST. Mark before its first
     * potentially delivered byte and never infer recall from a send failure. */
    c->result->possible_apply=1;
    if(transfer(c,socket,&request,sizeof(request),1,PW_WCD_REQUEST))return -1;
    int rc=transfer(c,socket,&message,sizeof(message),0,PW_WCD_PREPARE);
    if(rc<0)return -1;
    if(matches(&message,&request,LAPY_ELEVATION_RESPONSE)&&terminal_status(message.status,0)){
        c->result->helper_status=message.status;c->result->terminal=1;
        return data_fail(c,PW_WCD_RESULT,(int32_t)message.status,0);
    }
    if(!matches(&message,&request,LAPY_ELEVATION_PREPARE)||message.status!=LAPY_ELEVATION_OK)
        return data_fail(c,PW_WCD_PREPARE,(int32_t)message.status,0);
    if(rc||data_budget(c,NULL))return -1;
    errno=0;int prepared=seteuid(geteuid()),error=prepared<0?errno:0;
    if(prepared)data_fail(c,PW_WCD_LOCAL_PREPARE,prepared,error);
    if(data_budget(c,NULL))return -1;
    message=request;message.kind=LAPY_ELEVATION_PREPARED;
    message.status=prepared?LAPY_ELEVATION_PREPARE_FAILED:LAPY_ELEVATION_OK;
    if(transfer(c,socket,&message,sizeof(message),1,PW_WCD_PREPARED))return -1;
    memset(&message,0,sizeof(message));rc=transfer(c,socket,&message,sizeof(message),0,PW_WCD_RESULT);
    if(rc<0)return -1;
    c->result->helper_status=message.status;
    if(!matches(&message,&request,LAPY_ELEVATION_RESPONSE)||!terminal_status(message.status,1)||
       (prepared&&message.status==LAPY_ELEVATION_OK))return data_fail(c,PW_WCD_RESULT,(int32_t)message.status,0);
    c->result->terminal=1;
    if(message.status||prepared)return data_fail(c,PW_WCD_RESULT,(int32_t)message.status,0);
    return rc||data_budget(c,NULL)?-1:0;
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
    begun=c->io.last_clock;
    while(c->io.last_clock-begun<SETTLE_MS){
        uint64_t elapsed=c->io.last_clock-begun;unsigned left=SETTLE_MS-(unsigned)elapsed;
        if(sleep_slice(c,left>100?100:left))return -1;
    }
    c->result->settled_ms=(unsigned)(c->io.last_clock-begun);
    return data_budget(c,NULL);
}
int pw_wine_child_data_prepare(PwWineChildData *result,PwNativeChildIo *io,const char *expected)
{
    if(!result||!io||!io->ready||!io->clock_ms||!expected)return -1;
    DataContext c={.result=result,.original=io,.io=*io};
    if(result->attempted)return data_fail(&c,PW_WCD_ARGUMENT,-1,0);
    result->attempted=1;c.io.context=&c;c.io.clock_ms=data_clock;c.io.cancelled=data_cancel;
    if(strlen(expected)!=64)return data_fail(&c,PW_WCD_ARGUMENT,-1,0);
    for(unsigned i=0;i<64;i++)if(!((expected[i]>='0'&&expected[i]<='9')||(expected[i]>='a'&&expected[i]<='f')))
        return data_fail(&c,PW_WCD_ARGUMENT,-1,0);
    int rc=observe_data_access(&c,0);
    if(rc<0)return -1;
    if(!rc){result->data_after=result->ready=1;return 0;}
    size_t size=0;unsigned char *bytes=helper_bytes(&c,expected,&size);
    if(!bytes)return -1;
    int socket=-1,success=0;
    if(net_start(&c)||data_budget(&c,NULL))goto done;
    socket=c.net.socket("pw-wine-child-data",AF_INET,SOCK_STREAM,6);
    int error=net_error(&c,socket);
    if(socket<0){data_fail(&c,PW_WCD_SOCKET,socket,error);goto done;}
    if(data_budget(&c,NULL)||timeouts(&c,socket))goto done;
    /* SceNet uses the target BSD sockaddr layout even in host controls. */
    struct { uint8_t length,family;uint16_t port;uint32_t address;uint8_t zero[8]; } address={0};
    _Static_assert(sizeof(address)==16,"fixed SceNet IPv4 address");
    address.length=sizeof(address);address.family=AF_INET;
    address.port=(uint16_t)((9021u<<8)|(9021u>>8));address.address=UINT32_C(0x0100007f);
    if(data_budget(&c,NULL))goto done;
    rc=c.net.connect(socket,(const struct sockaddr *)&address,sizeof(address));error=net_error(&c,rc);
    if(rc){data_fail(&c,PW_WCD_CONNECT,rc,error);goto done;}
    if(data_budget(&c,NULL)||transfer(&c,socket,bytes,size,1,PW_WCD_UPLOAD))goto done;
    free(bytes);bytes=NULL;
    if(exchange(&c,socket)||wait_data(&c))goto done;
    success=1;
 done:
    free(bytes);
    if(socket>=0){
        rc=c.net.close(socket);error=net_error(&c,rc);
        if(rc){data_fail(&c,PW_WCD_NET_CLOSE,rc,error);success=0;}
    }
    if(data_budget(&c,NULL))success=0;
    if(success&&!result->api){result->ready=1;return 0;}
    return -1;
}
