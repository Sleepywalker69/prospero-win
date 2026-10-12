/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_WINE_CHILD_UI_PREVIEW_H
#define PW_WINE_CHILD_UI_PREVIEW_H
#include "pw_wine_child_ui.h"
#include <pthread.h>
enum { PW_WCU_PREVIEW_WIDTH=320,PW_WCU_PREVIEW_HEIGHT=180 };
typedef struct PwWineChildUiPreview {
    PwWineChildUiIdentity identity;
    uint64_t sequence;
    unsigned valid;
    uint32_t pixels[PW_WCU_PREVIEW_WIDTH*PW_WCU_PREVIEW_HEIGHT];
} PwWineChildUiPreview;
typedef struct PwWineChildUiMailbox {
    pthread_mutex_t lock;
    PwWineChildUiPreview preview;
    unsigned initialized;
} PwWineChildUiMailbox;
int pw_wine_child_ui_mailbox_init(PwWineChildUiMailbox *);
/* Latest complete software frame, scaled to a fixed diagnostic preview.
 * Busy mailbox drops this complete frame. No partial record is published. */
int pw_wine_child_ui_mailbox_put(PwWineChildUiMailbox *,PwWineChildUiIdentity,
                               const void *,uint32_t,uint32_t,uint32_t);
void pw_wine_child_ui_mailbox_retire(PwWineChildUiMailbox *,PwWineChildUiIdentity);
/* 1=new snapshot; 0=none/busy. Caller retains its own sequence and storage. */
int pw_wine_child_ui_mailbox_take(PwWineChildUiMailbox *,PwWineChildUiPreview *);
/* Copy root pixels to separate output and add a bordered, labelled read-only
 * picture-in-picture. Root storage and its input routing stay unchanged.
 * No display-plane ownership, alpha/window composition or child focus. */
int pw_wine_child_ui_preview_overlay(const PwWineChildUiPreview *,const void *,uint32_t,uint32_t,uint32_t,
                                    void *out,size_t capacity);
#endif
