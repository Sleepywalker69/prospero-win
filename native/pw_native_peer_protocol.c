/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_native_peer_protocol.h"
#include <limits.h>
#include <string.h>

static uint32_t get32(const uint8_t *p)
{ return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24; }
static uint64_t get64(const uint8_t *p) { return get32(p) | (uint64_t)get32(p+4)<<32; }
static void put32(uint8_t *p, uint32_t n) { for (unsigned i=0;i<4;i++) p[i]=(uint8_t)(n>>(8*i)); }
static void put64(uint8_t *p, uint64_t n) { put32(p,(uint32_t)n); put32(p+4,(uint32_t)(n>>32)); }
static int32_t signed32(uint32_t n) { return n<=INT32_MAX ? (int32_t)n : -(int32_t)(~n)-1; }
static int64_t signed64(uint64_t n) { return n<=INT64_MAX ? (int64_t)n : -(int64_t)(~n)-1; }
static int pid_valid(uint32_t pid) { return pid>1 && pid<=INT32_MAX; }
static int zero(const uint8_t *p, unsigned n) { for(unsigned i=0;i<n;i++) if(p[i])return 0;return 1; }
static int build_valid(const char p[PW_NC_BUILD_BYTES])
{
    unsigned i=0;
    for(;i<PW_NC_BUILD_BYTES && p[i];i++) if((unsigned char)p[i]<33 || (unsigned char)p[i]>126)return 0;
    return i>0 && i<PW_NC_BUILD_BYTES && zero((const uint8_t *)p+i,PW_NC_BUILD_BYTES-i);
}
static unsigned phase_for(unsigned kind)
{
    switch(kind) {
    case PW_NP_WORKER_READY: case PW_NP_PARENT_READY:return PW_NP_READY;
    case PW_NP_CHALLENGE:return PW_NP_CHALLENGE_PHASE;
    case PW_NP_WORKER_ECHO:return PW_NP_ECHO_PHASE;
    case PW_NP_WORKER_RESULT:return PW_NP_REPORT;
    default:return UINT_MAX;
    }
}
static int success_fields(const PwNativePeerRecord *r)
{
    return r && r->kind==PW_NP_WORKER_RESULT && r->status==PW_NP_OK &&
           r->phase==PW_NP_REPORT && r->observations==7 && !r->raw_result;
}
static int valid(const PwNativePeerRecord *r)
{
    if(!r || !pid_valid(r->parent_pid) || !pid_valid(r->child_pid) ||
       r->parent_pid==r->child_pid || !r->correlation || !build_valid(r->build_id) ||
       r->kind<PW_NP_WORKER_READY || r->kind>PW_NP_WORKER_RESULT)return 0;
    if(r->kind!=PW_NP_CHALLENGE && r->kind!=PW_NP_WORKER_ECHO &&
       !zero(r->challenge,PW_NP_CHALLENGE_BYTES))return 0;
    if(r->kind!=PW_NP_WORKER_RESULT)
        return !r->status && !r->raw_result && !r->observations && r->phase==phase_for(r->kind);
    if(!r->status)return success_fields(r);
    if(r->status>PW_NP_OK || r->status<PW_NP_EXIT || r->phase>PW_NP_REPORT || r->phase==PW_NP_ARM)return 0;
    /* Echo cannot precede the worker's reciprocal credential check. Clean
     * closure remains a separate fact even on a failed exchange. */
    return !(r->observations & ~7u) &&
           (!(r->observations & PW_NP_WORKER_ECHO_SENT) || (r->observations & PW_NP_WORKER_CREDENTIAL));
}
int pw_native_peer_worker_success(const PwNativePeerRecord *r)
{ return valid(r) && success_fields(r); }
void pw_native_peer_record(PwNativePeerRecord *r, const PwNativeChildFrame *s, uint32_t kind)
{
    memset(r,0,sizeof(*r));r->kind=kind;r->phase=phase_for(kind);
    r->parent_pid=s->parent_pid;r->child_pid=s->child_pid;r->correlation=s->correlation;
    memcpy(r->build_id,s->build_id,PW_NC_BUILD_BYTES);
}
int pw_native_peer_encode(uint8_t wire[PW_NP_RECORD_BYTES], const PwNativePeerRecord *r)
{
    if(!wire || !valid(r))return -1;
    memset(wire,0,PW_NP_RECORD_BYTES);memcpy(wire,"PWPE",4);put32(wire+4,1);
    put32(wire+8,r->kind);put32(wire+12,(uint32_t)r->status);
    put32(wire+16,r->parent_pid);put32(wire+20,r->child_pid);put64(wire+24,r->correlation);
    put32(wire+32,r->phase);put32(wire+36,r->observations);memcpy(wire+40,r->build_id,PW_NC_BUILD_BYTES);
    memcpy(wire+88,r->challenge,PW_NP_CHALLENGE_BYTES);put64(wire+120,(uint64_t)r->raw_result);return 0;
}
int pw_native_peer_decode(PwNativePeerRecord *r, const uint8_t wire[PW_NP_RECORD_BYTES], const PwNativeChildFrame *s)
{
    PwNativePeerRecord v={0};
    if(!r || !wire || !s || memcmp(wire,"PWPE",4) || get32(wire+4)!=1)return -1;
    v.kind=get32(wire+8);v.status=signed32(get32(wire+12));v.parent_pid=get32(wire+16);v.child_pid=get32(wire+20);
    v.correlation=get64(wire+24);v.phase=get32(wire+32);v.observations=get32(wire+36);
    memcpy(v.build_id,wire+40,PW_NC_BUILD_BYTES);memcpy(v.challenge,wire+88,PW_NP_CHALLENGE_BYTES);
    v.raw_result=signed64(get64(wire+120));
    if(!valid(&v) || v.parent_pid!=s->parent_pid || v.child_pid!=s->child_pid ||
       v.correlation!=s->correlation || memcmp(v.build_id,s->build_id,PW_NC_BUILD_BYTES))return -1;
    *r=v;return 0;
}
