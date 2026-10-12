/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_WINDOWS_CHROMIUM_IPC_CONTRACT_H
#define PW_WINDOWS_CHROMIUM_IPC_CONTRACT_H
#include <stddef.h>
#include <stdint.h>
#define PW_IPC_MAGIC UINT32_C(0x50494331)
#define PW_IPC_VERSION 1u
#define PW_IPC_EXIT UINT32_C(0x0052002a)
#define PW_IPC_CHILD_ERROR UINT32_C(0x005200ee)
#define PW_IPC_A UINT32_C(0x13579bdf)
#define PW_IPC_B UINT32_C(0x2468ace0)
#define PW_IPC_SECTION_SIZE 65536u
#define PW_IPC_WAIT_MS 5000u
#define PW_IPC_CHILD_MS 15000u
#define PW_IPC_LOG_LIMIT 131072u
enum pw_ipc_kind { PW_IPC_HELLO=1, PW_IPC_COMMAND, PW_IPC_RESULT, PW_IPC_DATA };
enum pw_ipc_case { PW_IPC_SELF=1, PW_IPC_LIVE, PW_IPC_SUSPENDED, PW_IPC_READONLY,
                   PW_IPC_DUPLICATE, PW_IPC_CLOSE_SOURCE, PW_IPC_PIPE, PW_IPC_PAGES };
/* All fields are explicit fixed-width values; same-architecture original
 * images use this 64-byte local wire. Reserved words must remain zero. */
struct pw_ipc_packet {
    uint32_t magic, version, bytes, kind, nonce, sender, parent, sequence;
    uint32_t bits, value, flags, reserved;
    uint64_t address, argument;
};
_Static_assert(sizeof(struct pw_ipc_packet)==64,"IPC packet ABI");
static const uint32_t pw_ipc_offsets[5]={0,4096,8192,12288,65532};
static inline int pw_ipc_packet_valid(const struct pw_ipc_packet *p,size_t size,
    uint32_t nonce,uint32_t sender,uint32_t parent,uint32_t sequence,uint32_t kind,
    uint32_t bits)
{
    return p && size==sizeof(*p) && p->magic==PW_IPC_MAGIC && p->version==PW_IPC_VERSION &&
        p->bytes==sizeof(*p) && p->nonce==nonce && p->sender==sender && sender &&
        p->parent==parent && parent && p->sequence==sequence && p->kind==kind &&
        p->bits==bits && (bits==32 || bits==64) && !p->reserved &&
        (bits!=32 || (p->address<=UINT32_MAX && p->argument<=UINT32_MAX));
}
static inline int pw_ipc_number(const char *s,uint64_t maximum,uint64_t *out)
{
    uint64_t n=0; unsigned digit;
    if(!s || !*s || !out)return 0;
    for(;*s;++s){ if(*s<'0'||*s>'9')return 0;digit=(unsigned)(*s-'0');
        if(digit>maximum || n>(maximum-digit)/10)return 0;
        n=n*10+digit; }
    *out=n;return 1;
}
static inline uint32_t pw_ipc_remaining(uint64_t start,uint64_t last,uint64_t now,uint32_t budget)
{
    return now<last || now<start || now-start>=budget ? 0 : budget-(uint32_t)(now-start);
}
static inline int pw_ipc_transfer_ok(int api_ok,uint64_t transferred,uint64_t expected,
                                    uint32_t observed,uint32_t wanted)
{ return api_ok && transferred==expected && observed==wanted; }
static inline int pw_ipc_completion_ok(int api_ok,uint32_t error,uint32_t bytes,
    uint32_t expected_bytes,uintptr_t key,uintptr_t expected_key,
    const void *overlapped,const void *expected_overlapped,uint32_t expected_error)
{
    return overlapped && overlapped==expected_overlapped && key==expected_key &&
        bytes==expected_bytes && (expected_error ? (!api_ok && error==expected_error) : api_ok);
}
static inline int pw_ipc_final_ok(int stages,int child_created,int waited,uint32_t exit_code,
                                 int closed,int outstanding)
{
    return stages && (!child_created || (waited && exit_code==PW_IPC_EXIT)) && closed && !outstanding;
}
#endif
