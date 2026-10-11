/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _POSIX_C_SOURCE 200809L
#include "pw_lapy_elevation.h"
#include "lapy_elevation_protocol.h"
#include "pw_lapy_client.h"
#include "pw_sha256.h"
#include <stdlib.h>
#include "ps5log/ps5log_ps5_net.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>

#ifndef PW_LAPY_HELPER_PATH
#define PW_LAPY_HELPER_PATH "/app0/lapy.elf"
#endif
#ifndef PW_LAPY_HELPER_SHA256
#error PW_LAPY_HELPER_SHA256 must bind the admitted same-repository v2 helper
#endif
#ifndef PW_LAPY_INITIAL_CANCEL_ONLY
#define PW_LAPY_INITIAL_CANCEL_ONLY 0
#endif
#if PW_LAPY_INITIAL_CANCEL_ONLY != 0 && PW_LAPY_INITIAL_CANCEL_ONLY != 1
#error PW_LAPY_INITIAL_CANCEL_ONLY must be 0 or 1
#endif
#define PW_LAPY_PORT 9021
#define PW_LAPY_TIMEOUT_US 5000000
#define PW_LAPY_MAX_ELF_SIZE (4u * 1024u * 1024u)

struct pw_lapy_sockaddr_in {
    uint8_t length;
    uint8_t family;
    uint16_t port;
    uint32_t address;
    uint16_t virtual_port;
    uint8_t zero[6];
};

extern int sceNetRecv(int socket, void *data, size_t length, int flags);
extern int *sceNetErrnoLoc(void);

static int network_result(int result)
{
    if (result < 0) {
        int *network_errno = sceNetErrnoLoc();
        errno = network_errno ? *network_errno : EIO;
        return -1;
    }
    return result;
}

typedef struct RootClient {
    int socket;
    PwLapyElevationResult *detail;
    uint64_t operation_end,recovery_end,last_clock,transaction_id;
} RootClient;
enum { ROOT_ADMISSION_MS=30000,ROOT_RECOVERY_MS=30000 };
static int root_clock(uint64_t *out)
{
    struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC,&t)||t.tv_sec<0||t.tv_nsec<0||t.tv_nsec>=1000000000||
       (uint64_t)t.tv_sec>UINT64_MAX/1000)return EIO;
    uint64_t value=(uint64_t)t.tv_sec*1000,part=(uint64_t)t.tv_nsec/1000000;
    if(value>UINT64_MAX-part)return EOVERFLOW;
    *out=value+part;return 0;
}
static int root_remaining(void *context,int recovery,unsigned *out)
{
    RootClient *c=context;uint64_t now=0;int error=root_clock(&now);
    if(error)return error;
    if(now<c->last_clock)return EIO;
    c->last_clock=now;
    uint64_t end=recovery?c->recovery_end:c->operation_end;
    if(now>=end)return ETIMEDOUT;
    *out=(unsigned)(end-now);return 0;
}
static int root_options(RootClient *c,unsigned left,int recovery)
{
    const int options[]={0x1105,0x1106,0x1109};
    for(unsigned i=0;i<3;i++){
        int error=root_remaining(c,recovery,&left);if(error){errno=error;return -1;}
        uint32_t timeout=(left>5000?5000:left)*1000u;
        if(ps5log_ps5_setsockopt(c->socket,0xffff,options[i],&timeout,sizeof(timeout))<0)return -1;
    }
    int error=root_remaining(c,recovery,&left);if(error){errno=error;return -1;}
    return 0;
}
static long root_send(void *context,const void *p,size_t n,unsigned left,unsigned phase,int recovery,int *error)
{
    RootClient *c=context;(void)phase;(void)recovery;
#if PW_LAPY_INITIAL_CANCEL_ONLY
    if(phase&&phase!=PW_LC_CANCEL){*error=EPROTO;return -1;}
#endif
    if(root_options(c,left,recovery)){*error=errno>0?errno:EIO;return -1;}
    if(!phase)c->detail->no_dispatch=0;
    long rc=ps5log_ps5_send(c->socket,p,n,0);*error=rc<0?errno:0;return rc;
}
static long root_receive(void *context,void *p,size_t n,unsigned left,unsigned phase,int recovery,int *error)
{
    RootClient *c=context;(void)phase;(void)recovery;
#if PW_LAPY_INITIAL_CANCEL_ONLY
    if(phase!=PW_LC_RESULT){*error=EPROTO;return -1;}
#endif
    if(root_options(c,left,recovery)){*error=errno>0?errno:EIO;return -1;}
    int rc=network_result(sceNetRecv(c->socket,p,n,0));*error=rc<0?errno:0;return rc;
}
#if !PW_LAPY_INITIAL_CANCEL_ONLY
static int root_prepare(void *context,int *error)
{(void)context;int rc=seteuid(geteuid());*error=rc?errno:0;return rc;}
#endif
static int send_all(RootClient *c,const void *data,size_t size)
{
    const uint8_t *bytes=data;
    while(size){
        unsigned left=0;int error=root_remaining(c,0,&left);
        if(error){errno=error;return -1;}
        long count=root_send(c,bytes,size,left,0,0,&error);
        if(count<=0||(size_t)count>size){errno=error?error:count==0?EPIPE:EPROTO;return -1;}
        bytes+=count;size-=(size_t)count;
    }
    return 0;
}

static int status_errno(uint32_t status)
{
    switch (status) {
    case LAPY_ELEVATION_TARGET_MISMATCH: return ESRCH;
    case LAPY_ELEVATION_UNAVAILABLE: return ENOENT;
    case LAPY_ELEVATION_PREPARE_FAILED: return EPERM;
    case LAPY_ELEVATION_TRANSPORT_ERROR: return ETIMEDOUT;
    case LAPY_ELEVATION_OK: return 0;
    case LAPY_ELEVATION_CANCELLED: return ECANCELED;
    default: return EACCES;
    }
}

static int exchange(RootClient *c,int32_t pid,PwLapyElevationResult *detail)
{
    PwLapyClient client;
#if PW_LAPY_INITIAL_CANCEL_ONLY
    const PwLapyClientOps ops={c,root_remaining,root_send,root_receive,NULL,NULL,1,1};
#else
    const PwLapyClientOps ops={c,root_remaining,root_send,root_receive,root_prepare,NULL,1,0};
#endif
    int rc=pw_lapy_client_exchange(&client,&ops,(uint32_t)pid,c->transaction_id);
    detail->possible_apply=client.possible_apply;detail->terminal=client.terminal;
    detail->helper_status=client.helper_status;detail->no_request=client.no_request;
    detail->settled_failure=client.settled_failure;detail->cancel_attempted=client.cancel_attempted;
    if(rc)errno=client.error==EACCES&&client.terminal?status_errno(client.helper_status):client.error?client.error:EIO;
    return rc;
}

#if PW_LAPY_INITIAL_CANCEL_ONLY
int pw_lapy_initial_cancel_result(int32_t pid, PwLapyElevationResult *detail)
#else
int pw_lapy_elevation_request_result(int32_t pid, PwLapyElevationResult *detail)
#endif
{
    PwLapyElevationResult local;
    if (!detail) detail = &local;
    memset(detail, 0, sizeof(*detail));
    struct stat st;
    struct pw_lapy_sockaddr_in address;
    RootClient client={0};
    uint8_t *buffer=NULL;
    int helper = -1, socket = -1, result = -1, saved_errno = EIO;

    detail->no_dispatch=1;detail->no_request=1;client.detail=detail;
    if (pid <= 1) { errno = EINVAL; return -1; }
    int clock_error=root_clock(&client.last_clock);
    if(clock_error||client.last_clock>UINT64_MAX-ROOT_ADMISSION_MS-ROOT_RECOVERY_MS){errno=clock_error?clock_error:EOVERFLOW;return -1;}
    client.operation_end=client.last_clock+ROOT_ADMISSION_MS;
    client.recovery_end=client.operation_end+ROOT_RECOVERY_MS;
    client.transaction_id=((uint64_t)(uint32_t)pid<<32)^client.last_clock;
    if(!client.transaction_id)client.transaction_id=1;
    detail->transaction_id=client.transaction_id;
    helper = open(PW_LAPY_HELPER_PATH, O_RDONLY|O_NOFOLLOW|O_NONBLOCK);
    if (helper < 0) return -1;
    if (fstat(helper, &st)) {
        saved_errno = errno ? errno : EIO;
        goto done;
    }
    if (!S_ISREG(st.st_mode) || st.st_size <= 0) {
        saved_errno = EINVAL;
        goto done;
    }
    if ((uint64_t)st.st_size > PW_LAPY_MAX_ELF_SIZE) {
        saved_errno = EFBIG;
        goto done;
    }
    /* Hash one bounded immutable buffer before any executable byte is sent.
     * This is also the capability proof for a clean-boundary initial CANCEL. */
    buffer=malloc((size_t)st.st_size);
    if(!buffer){saved_errno=ENOMEM;goto done;}
    size_t used=0;
    while(used<(size_t)st.st_size){
        unsigned left;int e=root_remaining(&client,0,&left);
        if(e){saved_errno=e;goto done;}
        size_t wanted=(size_t)st.st_size-used;if(wanted>4096)wanted=4096;
        ssize_t n=read(helper,buffer+used,wanted);
        if(n<=0||(size_t)n>wanted){saved_errno=errno>0?errno:EIO;goto done;}
        used+=(size_t)n;
    }
    unsigned char extra;struct stat after;
    ssize_t extra_bytes=read(helper,&extra,1);
    if(extra_bytes||fstat(helper,&after)||after.st_dev!=st.st_dev||after.st_ino!=st.st_ino||after.st_size!=st.st_size){saved_errno=EIO;goto done;}
    PwSha256 hash;char actual[65];pw_sha256_init(&hash);
    if(used<4||memcmp(buffer,"\177ELF",4)||pw_sha256_update(&hash,buffer,used)){saved_errno=EINVAL;goto done;}
    pw_sha256_final(&hash,actual);
    if(strcmp(actual,PW_LAPY_HELPER_SHA256)){saved_errno=EINVAL;goto done;}
    unsigned left;int e=root_remaining(&client,0,&left);
    if(e){saved_errno=e;goto done;}
    socket = ps5log_ps5_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket < 0) { saved_errno = errno ? errno : EIO; goto done; }
    client.socket=socket;
    if(root_options(&client,left,0)){saved_errno=errno?errno:EIO;goto done;}
    memset(&address, 0, sizeof(address));
    address.length = sizeof(address);
    address.family = AF_INET;
    address.port = (uint16_t)((PW_LAPY_PORT << 8) | (PW_LAPY_PORT >> 8));
    address.address = UINT32_C(0x0100007f);
    if (ps5log_ps5_connect(socket, (const struct sockaddr *)&address,
                           sizeof(address)) < 0) {
        saved_errno = errno ? errno : EIO;
        goto done;
    }

    if(send_all(&client,buffer,used)){saved_errno=errno?errno:EIO;goto done;}
    int exchanged=exchange(&client,pid,detail);
#if PW_LAPY_INITIAL_CANCEL_ONLY
    if(detail->terminal&&detail->helper_status==LAPY_ELEVATION_CANCELLED&&
       detail->no_request&&!detail->possible_apply)result=0;
    else saved_errno=errno?errno:EIO;
    (void)exchanged;
#else
    if(!exchanged)result=0;
    else saved_errno=errno?errno:EIO;
#endif

done:
    free(buffer);
    if (socket >= 0) (void)ps5log_ps5_close(socket);
    if (helper >= 0) (void)close(helper);
    if (result) errno = saved_errno;
    return result;
}

#if !PW_LAPY_INITIAL_CANCEL_ONLY
int pw_lapy_elevation_request(int32_t pid)
{
    return pw_lapy_elevation_request_result(pid, NULL);
}

#endif
