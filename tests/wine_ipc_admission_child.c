/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Actual decoder, bootstrap and Wine child installer; PRX/OS are inert. */
#define PW_IPC_BOOTSTRAP_BRIDGE
#include "test_wine_ipc_bootstrap.c"
#undef PW_IPC_BOOTSTRAP_BRIDGE
int ipc_bootstrap_from_owner(const PwWineChildFrame *sent)
{
 unsigned char packet[PW_WC_WIRE_BYTES];PwWineChildFrame decoded;
 if(pw_wine_child_wire_encode(packet,sent)||pw_wine_child_wire_decode(&decoded,packet))return -1;
 ipc_mode=decoded.profile;ipc_reset();
 ops.child=(PwWineCreationChild){PW_WINE_CREATION_ABI,sizeof(PwWineCreationChild),decoded.generation,decoded.wine_pid,decoded.wine_tid,decoded.profile,decoded.machine};
 if(pw_wine_child_bootstrap_prepare(&b,&io,9,hash,1,decoded.profile,decoded.machine,&ops))return -1;
 const PwWineCreationChild *child=pw_wine_creation_child_get();
 if(!child||memcmp(child,&ops.child,sizeof(*child))||pw_wine_fixture_get()||pw_wine_creation_get())return -1;
 if(pw_wine_child_bootstrap_start(&b,&io,&ops))return -1;
 m.entry(m.arg);return 0;
}
