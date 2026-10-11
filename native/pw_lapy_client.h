/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_LAPY_CLIENT_H
#define PW_LAPY_CLIENT_H
/* One original connection and one request. Recovery has a precomputed absolute
 * deadline supplied by the adapter; it never renews admission or authorizes
 * Wine startup. A full matching terminal response is the only settlement. */
#include "lapy_elevation_protocol.h"
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
enum { PW_LC_REQUEST=1, PW_LC_PREPARE, PW_LC_PREPARED, PW_LC_RESULT, PW_LC_CANCEL };
enum { PW_LC_REQUEST_BEGIN=1,PW_LC_PREPARE_RECEIVED,PW_LC_LOCAL_PREPARE_BEGIN,
       PW_LC_LOCAL_PREPARE_RETURNED,PW_LC_PREPARED_SENT,PW_LC_RESULT_RECEIVED };
typedef struct PwLapyClientOps {
    void *context;
    int (*remaining)(void *,int recovery,unsigned *milliseconds);
    long (*send)(void *,const void *,size_t,unsigned milliseconds,unsigned phase,int recovery,int *error);
    long (*receive)(void *,void *,size_t,unsigned milliseconds,unsigned phase,int recovery,int *error);
    int (*prepare)(void *,int *error);
    int (*progress)(void *,unsigned); /* optional; normal work only */
    unsigned initial_cancel_capable; /* exact uploaded v2 bytes admitted by adapter */
    unsigned cancel_only; /* full upload, but admission already failed */
} PwLapyClientOps;
typedef struct PwLapyClient {
    struct lapy_elevation_message request, incoming;
    size_t incoming_bytes;
    unsigned possible_apply,terminal,no_request,settled_failure;
    unsigned negotiated,request_complete,prepared_complete,cancel_attempted,cancel_complete,local_prepare_failed;
    unsigned outgoing_partial,transport_broken,protocol_refused;
    uint32_t helper_status;
    int error;
} PwLapyClient;
static int pw_lapy_client_error(PwLapyClient *c,int error)
{ if(!c->error)c->error=error>0?error:EIO;return -1; }
static int pw_lapy_client_remaining(PwLapyClient *c,const PwLapyClientOps *o,int recovery,unsigned *left)
{int error=o->remaining(o->context,recovery,left);return error||!*left?pw_lapy_client_error(c,error?error:ETIMEDOUT):0;}
static int pw_lapy_client_progress(PwLapyClient *c,const PwLapyClientOps *o,unsigned phase)
{int error=o->progress?o->progress(o->context,phase):0;return error?pw_lapy_client_error(c,error):0;}
static int pw_lapy_client_matches(const PwLapyClient *c,const struct lapy_elevation_message *m)
{
    return m->magic==c->request.magic&&m->version==LAPY_ELEVATION_VERSION&&
        m->size==sizeof(*m)&&m->capability==c->request.capability&&
        m->pid==c->request.pid&&m->transaction_id==c->request.transaction_id;
}
static int pw_lapy_client_terminal_status(uint32_t status,int prepared,int cancel)
{
    if(status==LAPY_ELEVATION_CANCELLED)return cancel;
    if(!prepared)return (status>=LAPY_ELEVATION_INVALID_REQUEST&&status<=LAPY_ELEVATION_UNAVAILABLE)||
        status==LAPY_ELEVATION_APPLY_FAILED||
        status==LAPY_ELEVATION_TRANSPORT_ERROR||status==LAPY_ELEVATION_PROTOCOL_ERROR;
    return status==LAPY_ELEVATION_OK||status==LAPY_ELEVATION_TARGET_MISMATCH||
        status==LAPY_ELEVATION_UNAVAILABLE||status==LAPY_ELEVATION_PREPARE_FAILED||
        status==LAPY_ELEVATION_APPLY_FAILED||status==LAPY_ELEVATION_TRANSPORT_ERROR||
        status==LAPY_ELEVATION_PROTOCOL_ERROR;
}
static int pw_lapy_client_write(PwLapyClient *c,const PwLapyClientOps *o,
                                const struct lapy_elevation_message *m,unsigned phase,int recovery)
{
    size_t used=0;
    while(used<sizeof(*m)){
        unsigned left=0;
        if(pw_lapy_client_remaining(c,o,recovery,&left)){
            if(used)c->outgoing_partial=1;
            return -1;
        }
        if(phase==PW_LC_REQUEST){c->possible_apply=1;c->no_request=0;}
        if(phase==PW_LC_CANCEL)c->cancel_attempted=1;
        int error=0;long n=o->send(o->context,(const unsigned char*)m+used,sizeof(*m)-used,left,phase,recovery,&error);
        if(n<=0||(size_t)n>sizeof(*m)-used){
            c->outgoing_partial=1;
            if(!n||error==EPIPE||error==ECONNRESET)c->transport_broken=1;
            return pw_lapy_client_error(c,error);
        }
        used+=(size_t)n;
    }
    if(phase==PW_LC_REQUEST)c->request_complete=1;
    if(phase==PW_LC_PREPARED)c->prepared_complete=1;
    if(phase==PW_LC_CANCEL)c->cancel_complete=1;
    unsigned left=0;return pw_lapy_client_remaining(c,o,recovery,&left);
}
static int pw_lapy_client_read(PwLapyClient *c,const PwLapyClientOps *o,unsigned phase,int recovery)
{
    while(c->incoming_bytes<sizeof(c->incoming)){
        unsigned left=0;if(pw_lapy_client_remaining(c,o,recovery,&left))return -1;
        int error=0;long n=o->receive(o->context,(unsigned char*)&c->incoming+c->incoming_bytes,
                                      sizeof(c->incoming)-c->incoming_bytes,left,phase,recovery,&error);
        if(n>0&&(size_t)n>sizeof(c->incoming)-c->incoming_bytes){
            /* An impossible read count invalidates this transport result.
             * Never recover by parsing a later frame as its replacement. */
            c->protocol_refused=1;return pw_lapy_client_error(c,EPROTO);
        }
        if(n<=0){
            if(!n||error==EPIPE||error==ECONNRESET)c->transport_broken=1;
            return pw_lapy_client_error(c,error);
        }
        c->incoming_bytes+=(size_t)n;
    }
    /* A complete terminal frame remains available even if the last read used
     * the final deadline slice. Adapters sample the unchanged clock afterward. */
    if(!pw_lapy_client_matches(c,&c->incoming)){
        c->protocol_refused=1;return pw_lapy_client_error(c,EPROTO);
    }
    return 0;
}
static int pw_lapy_client_terminal(PwLapyClient *c,int prepared,int cancel)
{
    if(c->incoming.kind!=LAPY_ELEVATION_RESPONSE||
       !pw_lapy_client_terminal_status(c->incoming.status,prepared,cancel)||
       (c->local_prepare_failed&&c->incoming.status==LAPY_ELEVATION_OK)){
        c->protocol_refused=1;return pw_lapy_client_error(c,EPROTO);
    }
    c->terminal=1;c->helper_status=c->incoming.status;return 0;
}
static void pw_lapy_client_next(PwLapyClient *c)
{memset(&c->incoming,0,sizeof(c->incoming));c->incoming_bytes=0;}
static void pw_lapy_client_recover(PwLapyClient *c,const PwLapyClientOps *o)
{
    unsigned left=0;
    if(c->terminal||c->outgoing_partial||c->transport_broken||
       c->protocol_refused||pw_lapy_client_remaining(c,o,1,&left))return;
    if(!c->request_complete){
        /* No request byte was attempted. A trusted full v2 upload supports a
         * first-frame CANCEL; older or incompletely uploaded helpers do not. */
        if(!c->no_request||!o->initial_cancel_capable)return;
        struct lapy_elevation_message cancel=c->request;cancel.kind=LAPY_ELEVATION_CANCEL;
        (void)pw_lapy_client_write(c,o,&cancel,PW_LC_CANCEL,1);
        if(c->transport_broken||pw_lapy_client_read(c,o,PW_LC_RESULT,1))return;
        if(c->incoming.kind!=LAPY_ELEVATION_RESPONSE||c->incoming.status!=LAPY_ELEVATION_CANCELLED||!c->cancel_complete){
            c->protocol_refused=1;return;
        }
        (void)pw_lapy_client_terminal(c,0,1);return;
    }
    if(!c->negotiated){
        if(pw_lapy_client_read(c,o,PW_LC_PREPARE,1))return;
        if(c->incoming.kind==LAPY_ELEVATION_RESPONSE){(void)pw_lapy_client_terminal(c,0,0);return;}
        if(c->incoming.kind!=LAPY_ELEVATION_PREPARE||c->incoming.status){
            c->protocol_refused=1;return;
        }
        c->negotiated=1;pw_lapy_client_next(c);
    }
    struct lapy_elevation_message cancel=c->request;cancel.kind=LAPY_ELEVATION_CANCEL;
    (void)pw_lapy_client_write(c,o,&cancel,PW_LC_CANCEL,1);
    /* Do not retransmit an ambiguous CANCEL. A concurrently completed, exact
     * RESPONSE can still prove settlement; partial reply bytes are retained. */
    if(c->transport_broken||pw_lapy_client_read(c,o,PW_LC_RESULT,1))return;
    (void)pw_lapy_client_terminal(c,c->prepared_complete,c->cancel_complete);
}
static int pw_lapy_client_exchange(PwLapyClient *c,const PwLapyClientOps *o,uint32_t pid,uint64_t transaction_id)
{
    if(!c)return -1;
    memset(c,0,sizeof(*c));c->no_request=1;
    if(!o||!o->remaining||!o->send||!o->receive||(!o->prepare&&!o->cancel_only)||pid<=1||!transaction_id)
        return pw_lapy_client_error(c,EINVAL);
    c->request=(struct lapy_elevation_message){LAPY_ELEVATION_MAGIC,LAPY_ELEVATION_VERSION,
        sizeof(c->request),LAPY_ELEVATION_REQUEST,LAPY_ELEVATION_FILESYSTEM,pid,LAPY_ELEVATION_OK,transaction_id};
    if(o->cancel_only){pw_lapy_client_error(c,ECANCELED);goto failed;}
    if(pw_lapy_client_progress(c,o,PW_LC_REQUEST_BEGIN)||pw_lapy_client_write(c,o,&c->request,PW_LC_REQUEST,0)||pw_lapy_client_read(c,o,PW_LC_PREPARE,0))goto failed;
    if(c->incoming.kind==LAPY_ELEVATION_RESPONSE){
        if(!pw_lapy_client_terminal(c,0,0))pw_lapy_client_error(c,EACCES);
        goto failed;
    }
    if(c->incoming.kind!=LAPY_ELEVATION_PREPARE||c->incoming.status){
        c->protocol_refused=1;pw_lapy_client_error(c,EPROTO);goto failed;
    }
    c->negotiated=1;pw_lapy_client_next(c);
    unsigned left=0;if(pw_lapy_client_remaining(c,o,0,&left)||
       pw_lapy_client_progress(c,o,PW_LC_PREPARE_RECEIVED)||
       pw_lapy_client_progress(c,o,PW_LC_LOCAL_PREPARE_BEGIN))goto failed;
    int error=0,prepared=o->prepare(o->context,&error);
    if(prepared){c->local_prepare_failed=1;pw_lapy_client_error(c,error);}
    if(pw_lapy_client_progress(c,o,PW_LC_LOCAL_PREPARE_RETURNED))goto failed;
    struct lapy_elevation_message ready=c->request;ready.kind=LAPY_ELEVATION_PREPARED;
    ready.status=prepared?LAPY_ELEVATION_PREPARE_FAILED:LAPY_ELEVATION_OK;
    if(pw_lapy_client_write(c,o,&ready,PW_LC_PREPARED,0)||pw_lapy_client_progress(c,o,PW_LC_PREPARED_SENT)||pw_lapy_client_read(c,o,PW_LC_RESULT,0))goto failed;
    if(pw_lapy_client_terminal(c,1,0))goto failed;
    if(prepared&&c->helper_status==LAPY_ELEVATION_OK){c->terminal=0;c->protocol_refused=1;pw_lapy_client_error(c,EPROTO);goto failed;}
    if(c->helper_status||prepared){pw_lapy_client_error(c,prepared?error:EACCES);goto failed;}
    if(pw_lapy_client_progress(c,o,PW_LC_RESULT_RECEIVED)||pw_lapy_client_remaining(c,o,0,&left))goto failed;
    return 0;
failed:
    pw_lapy_client_recover(c,o);
    c->settled_failure=c->terminal;
    return -1;
}
#endif
