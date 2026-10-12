/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "fixtures/windows_chromium_ipc_contract.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(void)
{
    struct pw_ipc_packet p={PW_IPC_MAGIC,PW_IPC_VERSION,sizeof(p),PW_IPC_HELLO,10,20,30,1,64,0,0,0,0,0},q;
    uint64_t n=99; int operation=0,foreign=0; unsigned checks=0;
#define CHECK(x) do { ++checks;assert(x); } while(0)
#define VALID(a) pw_ipc_packet_valid(&(a),sizeof(a),10,20,30,1,PW_IPC_HELLO,64)
    CHECK(VALID(p));
    for(unsigned i=0;i<9;++i){q=p; ((uint32_t *)&q)[i]^=1;CHECK(!VALID(q));}
    q=p;q.reserved=1;CHECK(!VALID(q));CHECK(!pw_ipc_packet_valid(&p,sizeof(p)-1,10,20,30,1,PW_IPC_HELLO,64));
    q=p;q.bits=32;q.address=UINT64_C(0x100000000);CHECK(!pw_ipc_packet_valid(&q,sizeof(q),10,20,30,1,PW_IPC_HELLO,32));
    q.address=UINT32_MAX;q.argument=UINT32_MAX;CHECK(pw_ipc_packet_valid(&q,sizeof(q),10,20,30,1,PW_IPC_HELLO,32));
    q.argument++;CHECK(!pw_ipc_packet_valid(&q,sizeof(q),10,20,30,1,PW_IPC_HELLO,32));
    CHECK(pw_ipc_number("18446744073709551615",UINT64_MAX,&n)&&n==UINT64_MAX);
    CHECK(!pw_ipc_number("18446744073709551616",UINT64_MAX,&n));
    CHECK(!pw_ipc_number("4294967296",UINT32_MAX,&n));
    const char *bad[]={"","-1","+1"," 1","1 ","1x","0x1",NULL};
    for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);++i)CHECK(!pw_ipc_number(bad[i],UINT64_MAX,&n));
    CHECK(pw_ipc_number("0",0,&n)&&n==0);CHECK(!pw_ipc_number("1",0,&n));
    CHECK(pw_ipc_remaining(100,120,121,5000)==4979);
    CHECK(!pw_ipc_remaining(100,120,119,5000));CHECK(!pw_ipc_remaining(100,100,99,5000));
    CHECK(!pw_ipc_remaining(100,5099,5100,5000));
    CHECK(pw_ipc_transfer_ok(1,4,4,1,1));CHECK(!pw_ipc_transfer_ok(0,4,4,1,1));
    CHECK(!pw_ipc_transfer_ok(1,3,4,1,1));CHECK(!pw_ipc_transfer_ok(1,4,4,2,1));
    CHECK(pw_ipc_completion_ok(1,123,64,64,11,11,&operation,&operation,0));
    CHECK(!pw_ipc_completion_ok(1,0,64,64,11,11,&foreign,&operation,0));
    CHECK(!pw_ipc_completion_ok(0,258,0,0,11,11,NULL,&operation,258));
    CHECK(!pw_ipc_completion_ok(1,0,63,64,11,11,&operation,&operation,0));
    CHECK(pw_ipc_completion_ok(0,995,0,0,11,11,&operation,&operation,995));
    CHECK(!pw_ipc_completion_ok(1,995,0,0,11,11,&operation,&operation,995));
    CHECK(pw_ipc_final_ok(1,1,1,PW_IPC_EXIT,1,0));
    CHECK(!pw_ipc_final_ok(1,1,1,PW_IPC_EXIT&255,1,0));
    CHECK(!pw_ipc_final_ok(1,1,0,PW_IPC_EXIT,1,0));
    CHECK(!pw_ipc_final_ok(1,1,1,PW_IPC_EXIT,0,0));
    CHECK(!pw_ipc_final_ok(1,1,1,PW_IPC_EXIT,1,1));
    CHECK(!pw_ipc_final_ok(0,0,0,0,1,0));CHECK(pw_ipc_final_ok(1,0,0,0,1,0));
    for(unsigned i=0;i<5;++i)CHECK(pw_ipc_offsets[i]+sizeof(uint32_t)<=PW_IPC_SECTION_SIZE);
    printf("windows_chromium_ipc_contract: %u checks passed (portable contracts only)\n",checks);
    return 0;
}
