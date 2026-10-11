/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* The production exchange engine; inert socket, clock and preparation seams. */
#include <assert.h>
#include <stdio.h>
#include "../native/pw_lapy_client.h"
static unsigned checks;
#define CHECK(x) do{checks++;assert(x);}while(0)
static struct {
    unsigned normal,recovery,stop_at,normal_limit,recovery_limit,prepares,sends,receives;
    unsigned request_frames,prepared_frames,cancel_frames,frames_read,fragment,rx_used,tx_used;
    unsigned fail_send,fail_receive,eof_receive,bad_nonce,bad_version,bad_kind,prepare_failed;
    unsigned terminal_status,force_cancelled,duplicate_prepare,force_success;
    struct lapy_elevation_message outgoing,incoming;
} m;
static int remaining(void *unused,int recovery,unsigned *left)
{
    (void)unused;
    if(recovery){m.recovery++;if(m.recovery>m.recovery_limit)return ETIMEDOUT;}
    else {m.normal++;if(m.normal>m.normal_limit||(m.stop_at&&m.normal>=m.stop_at))return ECANCELED;}
    *left=100;return 0;
}
static long send_bytes(void *unused,const void *p,size_t size,unsigned left,unsigned phase,int recovery,int *error)
{
    (void)unused;CHECK(left==100&&size>0);m.sends++;
    CHECK(!recovery||phase==PW_LC_CANCEL);
    if(m.fail_send==m.sends){*error=ETIMEDOUT;return -1;}
    size_t n=m.fragment&&size>m.fragment?m.fragment:size;
    CHECK(m.tx_used+n<=sizeof(m.outgoing));memcpy((char*)&m.outgoing+m.tx_used,p,n);m.tx_used+=(unsigned)n;
    if(m.tx_used==sizeof(m.outgoing)){
        CHECK(m.outgoing.version==2&&m.outgoing.transaction_id==UINT64_C(0x123456789));
        if(m.outgoing.kind==LAPY_ELEVATION_REQUEST){m.request_frames++;CHECK(phase==PW_LC_REQUEST&&!recovery);}
        else if(m.outgoing.kind==LAPY_ELEVATION_PREPARED){m.prepared_frames++;CHECK(phase==PW_LC_PREPARED&&!recovery);}
        else {CHECK(m.outgoing.kind==LAPY_ELEVATION_CANCEL&&phase==PW_LC_CANCEL&&recovery);m.cancel_frames++;}
        m.tx_used=0;
    }
    return (long)n;
}
static long receive_bytes(void *unused,void *p,size_t size,unsigned left,unsigned phase,int recovery,int *error)
{
    (void)unused;(void)phase;(void)recovery;CHECK(left==100&&size>0);m.receives++;
    if(m.eof_receive==m.receives)return 0;
    if(m.fail_receive==m.receives){*error=ETIMEDOUT;return -1;}
    if(!m.rx_used){
        m.incoming=(struct lapy_elevation_message){LAPY_ELEVATION_MAGIC,2,sizeof(m.incoming),
            m.frames_read?LAPY_ELEVATION_RESPONSE:LAPY_ELEVATION_PREPARE,
            LAPY_ELEVATION_FILESYSTEM,600,0,UINT64_C(0x123456789)};
        if(m.frames_read)m.incoming.status=m.cancel_frames||m.force_cancelled?LAPY_ELEVATION_CANCELLED:
            m.prepare_failed?LAPY_ELEVATION_PREPARE_FAILED:m.terminal_status;
        if(m.force_success&&m.frames_read)m.incoming.status=LAPY_ELEVATION_OK;
        if(m.bad_nonce==m.frames_read+1)m.incoming.transaction_id++;
        if(m.bad_version==m.frames_read+1)m.incoming.version=1;
        if(m.bad_kind==m.frames_read+1)m.incoming.kind=LAPY_ELEVATION_REQUEST;
        if(m.duplicate_prepare&&m.frames_read)m.incoming.kind=LAPY_ELEVATION_PREPARE;
    }
    size_t n=m.fragment&&size>m.fragment?m.fragment:size;
    CHECK(m.rx_used+n<=sizeof(m.incoming));memcpy(p,(char*)&m.incoming+m.rx_used,n);m.rx_used+=(unsigned)n;
    if(m.rx_used==sizeof(m.incoming)){m.frames_read++;m.rx_used=0;}
    return (long)n;
}
static int prepare(void *unused,int *error)
{(void)unused;m.prepares++;if(m.prepare_failed){*error=EPERM;return -1;}return 0;}
static PwLapyClientOps ops={NULL,remaining,send_bytes,receive_bytes,prepare,NULL,0,0};
static PwLapyClient client;
static void reset(void){memset(&m,0,sizeof(m));m.normal_limit=m.recovery_limit=1000;memset(&client,0,sizeof(client));}
static int run(void){int rc=pw_lapy_client_exchange(&client,&ops,600,UINT64_C(0x123456789));CHECK(m.request_frames<=1&&m.cancel_frames<=1&&m.prepared_frames<=1);return rc;}
int main(void)
{
    reset();CHECK(run()==0&&client.terminal&&!client.no_request&&!client.settled_failure&&m.prepares==1&&!m.cancel_frames);
    unsigned normal=m.normal;
    /* Every normal clock/cancel boundary including after a complete frame. */
    for(unsigned i=1;i<=normal;i++){
        reset();m.stop_at=i;CHECK(run()==-1);
        CHECK(!client.terminal||client.settled_failure);
        CHECK(client.no_request?(!client.possible_apply&&!m.request_frames):client.possible_apply);
        if(client.request_complete)CHECK(client.terminal&&client.settled_failure);
        CHECK(m.normal<=i&&m.recovery<1000);
    }
    reset();m.fragment=3;CHECK(!run()&&client.terminal&&m.receives>2&&m.sends>2);
    unsigned fragmented_normal=m.normal;
    for(unsigned i=1;i<=fragmented_normal;i++){
        reset();m.fragment=3;m.stop_at=i;CHECK(run()==-1);
        if(client.outgoing_partial)CHECK(!m.cancel_frames&&!client.terminal);
        if(client.terminal)CHECK(client.settled_failure);
    }
    reset();m.fail_receive=2;CHECK(run()==-1&&client.terminal&&client.helper_status==LAPY_ELEVATION_CANCELLED&&m.cancel_frames==1);
    reset();m.fragment=8;m.fail_receive=7;CHECK(run()==-1&&client.terminal&&client.helper_status==LAPY_ELEVATION_OK&&client.settled_failure);
    /* Partial outgoing REQUEST/PREPARED can never be followed by CANCEL. */
    for(unsigned i=1;i<=8;i++){
        reset();m.fragment=8;m.fail_send=i;CHECK(run()==-1&&client.outgoing_partial&&!m.cancel_frames&&!client.terminal);
    }
    for(unsigned phase=1;phase<=2;phase++){
        reset();m.bad_nonce=phase;CHECK(run()==-1&&!client.terminal&&!m.cancel_frames&&client.protocol_refused);
        reset();m.bad_version=phase;CHECK(run()==-1&&!client.terminal&&!m.cancel_frames&&client.protocol_refused);
        reset();m.bad_kind=phase;CHECK(run()==-1&&!client.terminal&&!m.cancel_frames&&client.protocol_refused);
    }
    reset();m.eof_receive=2;CHECK(run()==-1&&!client.terminal&&!m.cancel_frames&&client.transport_broken);
    reset();m.prepare_failed=1;CHECK(run()==-1&&client.terminal&&client.helper_status==LAPY_ELEVATION_PREPARE_FAILED&&client.error==EPERM);
    reset();m.prepare_failed=1;m.fail_receive=2;m.force_success=1;
    CHECK(run()==-1&&!client.terminal&&client.protocol_refused&&client.error==EPERM);
    reset();m.prepare_failed=1;m.fragment=8;m.fail_receive=7;m.force_success=1;
    CHECK(run()==-1&&!client.terminal&&client.protocol_refused&&client.error==EPERM);
    reset();m.force_cancelled=1;CHECK(run()==-1&&!client.terminal&&client.protocol_refused); /* unsolicited */
    reset();m.terminal_status=LAPY_ELEVATION_ROLLBACK_FAILED;CHECK(run()==-1&&!client.terminal&&client.protocol_refused);
    reset();m.duplicate_prepare=1;CHECK(run()==-1&&!client.terminal&&client.protocol_refused);
    reset();m.stop_at=4;m.recovery_limit=0;CHECK(run()==-1&&!client.terminal&&!m.cancel_frames);
    /* Every recovery bound, including terminal drain, must remain finite. */
    reset();m.stop_at=4;CHECK(run()==-1&&client.terminal);unsigned recovery=m.recovery;
    for(unsigned i=0;i<recovery;i++){
        reset();m.stop_at=4;m.recovery_limit=i;CHECK(run()==-1);CHECK(m.recovery<=i+2);
        CHECK(!client.terminal||client.settled_failure);
    }
    printf("Lapy v2 client: %u checks passed\n",checks);return 0;
}
