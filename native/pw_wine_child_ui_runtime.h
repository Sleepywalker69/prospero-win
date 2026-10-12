/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_WINE_CHILD_UI_RUNTIME_H
#define PW_WINE_CHILD_UI_RUNTIME_H
#include "pw_wine_child_ui_handoff.h"
#include "pw_wine_child_ui_config.h"
/* Supervisor-owned records; never accessed by Wine callbacks. Each admitted
 * generation owns its separately-created pair and receive storage for life.
 * Incoming identities never choose or replace a generation. */
typedef struct PwWineChildUiOwner {
    int fd,passed_fd;
    unsigned initialized,retired,close_uncertain;
    unsigned char *storage;
    PwWineChildUiRx rx;
    PwWineChildUiHandoff handoff;
} PwWineChildUiOwner;
int pw_wine_child_ui_owner_init(PwWineChildUiOwner *,PwWineChildUiIdentity,
                               PwWinePresentSink,void *);
/* Call from the owning supervisor only, with its original launch receipt's
 * bootstrap and server stream. Uses internally created passed_fd, never a
 * received or caller-selected UI descriptor. No UI bytes use control. */
int pw_wine_child_ui_owner_send(PwWineChildUiOwner *,PwNativeChildIo *,int control,
                               const PwWineChildFrame *,uint64_t session,int server);
/* Read at most eight 64KiB chunks, never wait. Any ancillary data is refused
 * after closing every collected right. Failure retires UI only. */
int pw_wine_child_ui_owner_pump(PwWineChildUiOwner *);
/* Called before generation owner retirement/uncertainty. Independent of
 * helper settlement; never frees process-lifetime storage or kills anything. */
int pw_wine_child_ui_owner_retire(PwWineChildUiOwner *);
#endif
