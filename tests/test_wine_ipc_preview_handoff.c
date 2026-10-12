/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Actual handoff parser with inert OS boundaries: unsupported IPC profiles must
 * close both received rights before publishing any UI ownership. */
#define main legacy_handoff_main
#include "test_pw_wine_child_ui_handoff_faults.c"
#undef main
int main(void)
{
    assert(PW_WINE_CHILD_UI_ENABLED==1);
    for(unsigned profile=PW_WC_PROFILE_IPC_FIRST;profile<=PW_WC_PROFILE_IPC_LAST;profile++){
        reset();m.bytes[128]=(unsigned char)profile;
        assert(receive()==PW_WC_ERROR&&h.state==PW_WCU_HANDOFF_FAILED);
        assert(m.receives==1&&m.closes==2&&m.closed[0]==9&&m.closed[1]==10);
        assert(h.result.rights_closed==2&&!h.result.ownership_uncertain);
        assert(receive()==PW_WC_ERROR&&m.receives==1&&m.closes==2);
        reset();bootstrap.profile=profile;
        assert(pw_wine_child_ui_handoff_send(&h,&budget_io,3,&bootstrap,80,9,10)==PW_WC_ERROR);
        assert(!m.sends&&!m.closes);
    }
    assert(!legacy_handoff_main());
    puts("preview IPC refusal: eight profiles, both rights closed, no transfer, legacy controls passed");
    return 0;
}
