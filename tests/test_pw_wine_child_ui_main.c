/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _POSIX_C_SOURCE 200809L
#define PW_WINE_CHILD_UI_ENABLED 1
#define PW_WINE_CHILD_UI_COHORT 1
#include "../native/pw_wine_child_bootstrap.h"
#include "../native/pw_wine_child_ui_handoff.h"
#include <sys/mman.h>
#include <sys/socket.h>
static int fake_ui_receive(PwWineChildUiHandoff *,PwNativeChildIo *,int,const PwWineChildFrame *,int *,int *);
static int fake_ui_identity(const PwWineChildUiHandoff *,const PwWineChildFrame *,PwWineChildUiIdentity *);
static int fake_ui_init(PwWineChildUiChannel *,int *,PwWineChildUiIdentity,unsigned,void *,size_t,uint64_t,unsigned,int(*)(void*,uint64_t*),int(*)(void*),void *);
static int fake_ui_retire(PwWineChildUiChannel *,int(*)(void *),void *);
static int fake_ui_pump(PwWineChildUiChannel *);
static void *fake_ui_mmap(void *,size_t,int,int,int,off_t);
static void fake_ui_bind(PwWineChildBootstrap *,const PwWineChildBootstrapOps *);
#define pw_wine_child_ui_handoff_receive fake_ui_receive
#define pw_wine_child_ui_handoff_identity fake_ui_identity
#define pw_wine_child_ui_channel_init fake_ui_init
#define pw_wine_child_ui_channel_retire fake_ui_retire
#define pw_wine_child_ui_channel_pump fake_ui_pump
#define mmap fake_ui_mmap
#define PW_WCU_MAIN_PREPARE(b,o) fake_ui_bind(b,o)
#define PW_WCU_MAIN_TEST_ENTRY legacy_main_controls
#include "test_pw_wine_child_main.c"
#undef PW_WCU_MAIN_TEST_ENTRY
#undef mmap
static unsigned binds,detaches,pumps,ui_closes;
static int pump_failure;
static unsigned char storage[1]; /* inert mapped storage; queue IO is mocked */
static void *fake_ui_mmap(void *hint,size_t bytes,int prot,int flags,int fd,off_t offset)
{assert(!hint&&bytes==PW_WCU_HEADER+PW_WCU_MAX_BYTES&&prot==(PROT_READ|PROT_WRITE)&&flags==(MAP_PRIVATE|MAP_ANON)&&fd==-1&&!offset);return storage;}
static int fake_ui_receive(PwWineChildUiHandoff *h,PwNativeChildIo *i,int control,const PwWineChildFrame *hello,int *server,int *ui)
{
    assert(h==&ui_handoff&&hello->child_pid==600&&hello->child_ppid==53&&hello->kind==PW_WC_HELLO);
    int rc=fake_receive(i,control,PW_WC_KIND(PW_WC_BOOTSTRAP),&h->bootstrap,server,&wire_result);
    h->result=wire_result; /* preserve the composed diagnostic fixture result */
    if(rc==PW_WC_RECORD){*ui=10;h->state=PW_WCU_HANDOFF_DONE;h->session=80;}
    else {*ui=-1;h->state=PW_WCU_HANDOFF_FAILED;}
    return rc;
}
static int fake_ui_identity(const PwWineChildUiHandoff *h,const PwWineChildFrame *b,PwWineChildUiIdentity *id)
{assert(h==&ui_handoff&&b==&active_session&&b->child_pid==600);*id=(PwWineChildUiIdentity){80,b->generation,b->child_pid};return 0;}
static int fake_ui_init(PwWineChildUiChannel *q,int *fd,PwWineChildUiIdentity id,unsigned kind,void *bytes,size_t capacity,
                       uint64_t end,unsigned write_ms,int(*clock)(void*,uint64_t*),int(*stop)(void*),void *context)
{
    assert(q==&ui_channel&&*fd==10&&id.session==80&&id.generation==active_session.generation&&id.native_pid==600);
    assert(kind==PW_WCU_FRAME&&bytes==storage&&capacity==PW_WCU_HEADER+PW_WCU_MAX_BYTES&&end==child_io.total_end&&write_ms==1000&&clock==clock_ms&&stop==cancelled&&!context);
    q->initialized=1;q->fd=*fd;*fd=-1;q->tx.identity=id;return 0;
}
static void fake_ui_set(PwWinePresentSink sink,void *context)
{assert(!sink&&!context);detaches++;}
static void fake_ui_bind(PwWineChildBootstrap *b,const PwWineChildBootstrapOps *o)
{assert(o->ui==&ui_channel&&o->ui->initialized&&!b->started);b->ui_set_present=fake_ui_set;b->ui_attached=1;binds++;}
static int fake_ui_retire(PwWineChildUiChannel *q,int(*detach)(void *),void *context)
{
    assert(q==&ui_channel&&q->initialized);if(q->retired)return 0;
    assert(!detach(context)&&!bootstrap.ui_attached);q->retired=1;fake_close(q->fd);q->fd=-1;ui_closes++;return 0;
}
static int fake_ui_pump(PwWineChildUiChannel *q){assert(q==&ui_channel&&!q->retired);pumps++;return pump_failure?-1:0;}
int main(void)
{
    assert(!legacy_main_controls());assert(binds&&detaches&&pumps&&ui_closes);
    reset();pump_failure=1;run();assert(m.exit_code==17&&m.kills==1&&ui_channel.retired&&!atomic_load(&runtime_failure));
    assert(closed(10)==1&&!closed(9)&&!closed(3));
    puts("child UI worker: opt-in pre-Wine binding, control coexistence and independent detach controls passed");return 0;
}
