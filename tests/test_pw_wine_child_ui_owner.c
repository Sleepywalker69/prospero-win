/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Actual opt-in owner call graph. Native/service/UI boundaries are mocks;
 * real v3 rights and byte transport have separate fork/runtime tests. */
#define PW_WINE_CHILD_UI_ENABLED 1
#include "../native/pw_wine_child_ui_runtime.h"
static unsigned ui_inits,ui_sends,ui_pumps,ui_retires,ui_notices;
static int ui_pump_error;
static int fake_ui_init(PwWineChildUiOwner *,PwWineChildUiIdentity,PwWinePresentSink,void *);
static int fake_ui_send(PwWineChildUiOwner *,PwNativeChildIo *,int,const PwWineChildFrame *,uint64_t,int);
static int fake_ui_pump(PwWineChildUiOwner *);
static int fake_ui_retire(PwWineChildUiOwner *);
static int ui_callback(void *,PwWineChildUiIdentity,const void *,uint32_t,uint32_t,uint32_t);
static void ui_notice(void *,PwWineChildUiIdentity);
#define pw_wine_child_ui_owner_init fake_ui_init
#define pw_wine_child_ui_owner_send fake_ui_send
#define pw_wine_child_ui_owner_pump fake_ui_pump
#define pw_wine_child_ui_owner_retire fake_ui_retire
#define PW_WFO_UI_TEST_CONFIG ,.ui_frame=ui_callback,.ui_retired=ui_notice
#define main legacy_owner_controls
#include "test_pw_wine_fixture_owner.c"
#undef main
static int ui_callback(void *context,PwWineChildUiIdentity id,const void *pixels,uint32_t w,uint32_t h,uint32_t stride)
{CHECK(context==&m&&id.session==owner.config.session&&id.generation&&id.native_pid&&pixels&&w&&h&&stride);return 0;}
static void ui_notice(void *context,PwWineChildUiIdentity id)
{CHECK(context==&m&&id.session==owner.config.session);ui_notices++;}
static int fake_ui_init(PwWineChildUiOwner *u,PwWineChildUiIdentity id,PwWinePresentSink sink,void *context)
{
    Generation *g=context;CHECK(g&&g->owner==&owner&&g->hello&&g->service_id>0&&atomic_load(&g->identity_ready));
    CHECK(id.session==owner.config.session&&id.generation==g->generation&&id.native_pid==g->session.child_pid);
    CHECK(!u->initialized&&sink==ui_frame);u->initialized=1;u->fd=90;u->passed_fd=91;u->rx.identity=id;ui_inits++;return 0;
}
static int fake_ui_send(PwWineChildUiOwner *u,PwNativeChildIo *io,int control,const PwWineChildFrame *b,uint64_t session_id,int server)
{
    Generation *g=io->context;CHECK(u==&g->ui&&u->passed_fd==91&&u->rx.identity.session==session_id);
    CHECK(u->rx.identity.generation==b->generation&&u->rx.identity.native_pid==b->child_pid&&g->helper_possible);
    ui_sends++;int rc=pw_wine_child_wire_send_step(io,control,b,server,&u->handoff.result);
    if(rc!=PW_WC_IDLE)u->passed_fd=-1;
    if(rc==PW_WC_RECORD){u->handoff.state=PW_WCU_HANDOFF_DONE;u->handoff.bootstrap=*b;u->handoff.session=session_id;}
    return rc;
}
static int fake_ui_pump(PwWineChildUiOwner *u)
{CHECK(u&&u->initialized&&!u->retired&&u->handoff.state==PW_WCU_HANDOFF_DONE);ui_pumps++;return ui_pump_error?-1:0;}
static int fake_ui_retire(PwWineChildUiOwner *u)
{CHECK(u&&u->initialized);if(!u->retired){u->retired=1;u->fd=u->passed_fd=-1;ui_retires++;}return u->close_uncertain?-1:0;}
int main(void)
{
    assert(!legacy_owner_controls(0,NULL));
    CHECK(ui_inits&&ui_sends&&ui_pumps&&ui_retires&&ui_notices);
    /* UI failure cannot turn into helper/process cleanup or Kill. */
    Generation *g=bound(2);m.sleep_action=1;
    CHECK(!provider.spawn(provider.context,g->generation,70,46,47));
    CHECK(atomic_load(&g->state)==G_RUNNING&&g->ui.initialized);
    unsigned kills=m.kills;ui_pump_error=1;(void)pw_wine_fixture_owner_pump(&owner);
    CHECK(g->ui.retired&&!atomic_load(&g->cleanup_requested)&&m.kills==kills&&!atomic_load(&owner.blocked));
    /* A helper hold can retire UI but never settle or kill that helper. */
    ui_pump_error=0;g=bound(2);m.sleep_action=1;CHECK(!provider.spawn(provider.context,g->generation,70,46,47));
    g->helper_possible=1;kills=m.kills;helper_hold(&owner,g);
    CHECK(g->ui.retired&&g->helper_possible&&atomic_load(&g->state)==G_UNCERTAIN&&m.kills==kills);
    puts("child UI owner: opt-in receipt/role binding and independent retirement controls passed");return 0;
}
