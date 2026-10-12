/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_WINE_CHILD_UI_HANDOFF_H
#define PW_WINE_CHILD_UI_HANDOFF_H
#include "pw_wine_child_wire.h"
#include "pw_wine_child_ui.h"

/* Opt-in BOOTSTRAP v3, never UI payload on control. The first 136 bytes are
 * the v2 bootstrap layout with version=3; session follows at 136, and eight
 * reserved zero bytes at 144. Exactly two rights, ordered server then UI.
 * Legacy v2 entrypoints refuse this record and clean every collected right.
 * This does not alter the production launcher or the service's fd3 mapping. */
enum { PW_WCU_HANDOFF_BYTES=152 };
enum { PW_WCU_HANDOFF_NEW, PW_WCU_HANDOFF_DONE, PW_WCU_HANDOFF_FAILED };
typedef struct PwWineChildUiHandoff {
    unsigned state;
    uint64_t session;
    PwWineChildFrame bootstrap;
    PwWineChildWireResult result;
} PwWineChildUiHandoff;
/* Zero-initialize once per owned control channel. NEW (zero) may poll again;
 * any attempted transfer is terminal. Never reset/reuse on the same channel.
 * Caller serializes these calls with all other control traffic. The send's
 * bootstrap must originate from a verified launch receipt + matched HELLO.
 * Descriptor numbers are borrowed. No descriptor is closed by send. */
int pw_wine_child_ui_handoff_send(PwWineChildUiHandoff *,PwNativeChildIo *,int control,
                                const PwWineChildFrame *,uint64_t session,
                                int server,int ui);
/* At most one nonblocking receive. The locally-created HELLO supplies this
 * worker's actual PID, PPID and exact matched build, never an incoming UI
 * header. Outputs must start at -1. They become owned only on RECORD.
 * The caller must accept the remaining bootstrap through its existing owner
 * admission checks before constructing a UI codec. Every refusal closes all
 * collected unique rights once; close uncertainty stays in result.
 * Socket object identity must be supported (fstat: nonzero inode) to rule out
 * alias descriptors for server/UI. Unsupported identity fails closed. */
int pw_wine_child_ui_handoff_receive(PwWineChildUiHandoff *,PwNativeChildIo *,int control,
                                   const PwWineChildFrame *local_hello,
                                   int *server,int *ui);
/* Bind only after caller accepted this exact bootstrap, with the same local
 * generation/child PID and the root-provided session. This is correlation to
 * an already-owned launch, not authentication or a helper-settlement proof. */
int pw_wine_child_ui_handoff_identity(const PwWineChildUiHandoff *,
                                    const PwWineChildFrame *accepted_bootstrap,
                                    PwWineChildUiIdentity *);
#endif
