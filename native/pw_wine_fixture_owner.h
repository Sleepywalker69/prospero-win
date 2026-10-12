/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_WINE_FIXTURE_OWNER_H
#define PW_WINE_FIXTURE_OWNER_H
#include "pw_wine_child_ui_config.h"
#if PW_WINE_CHILD_UI_ENABLED
#include "pw_wine_child_ui.h"
#endif
#include "pw_wine_ipc_profile.h"
#include "../wine/ps5/pw_wine_fixture_provider.h"
#include "../wine/ps5/pw_wine_creation.h"
#include "../wine/ps5/pw_wine_fixture_socket.h"
#include <stdint.h>

/* The native title creates one owner before ordinary profile launch, then a
 * single supervisor thread runs pump(). Wine callbacks never call the service
 * enumerator or killer under the server lock. Fixed records survive the run. */
enum { PW_WFO_MAX_GENERATIONS=16, PW_WFO_ATTEMPT_MS=180000,
       PW_WFO_VENDOR_MS=600000, PW_WFO_VENDOR_CHILD_MS=300000, PW_WFO_CLEANUP_MS=5000,
       PW_WFO_STARTUP_MS=30000, PW_WFO_CHILD_MS=60000,
       PW_WFO_USER_MS=180000, PW_WFO_USER_CHILD_MS=120000,
       PW_WFO_NET_MS=180000, PW_WFO_NET_CHILD_MS=120000, PW_WFO_LIST_CAP=16 };
enum { PW_WFO_IDLE, PW_WFO_ADMITTED, PW_WFO_BOUND, PW_WFO_LAUNCH_POSSIBLE,
       PW_WFO_BOOTSTRAP, PW_WFO_RUNNING, PW_WFO_RETIRED, PW_WFO_UNCERTAIN };
typedef struct PwWineFixtureOwnerConfig {
    uint64_t session;
    unsigned profile; /* 1 original fixture; 2 Battle.net experiment; 3 original USER control; 4 original network control; 16..23 fixed IPC controls */
    const char *child_unix_path; /* exact original mode1/3/4 or selected IPC image; NULL for vendor */
    const char *child_sha256;    /* exact original mode1/3/4 or selected IPC hash; NULL for vendor */
    const unsigned char *helper_image;
    uint32_t helper_bytes;
    const char *build_id;        /* exact full-CRT helper build identity */
    void *context;
    int (*clock_ms)(void *,uint64_t *);
    int (*cancelled)(void *);
#if PW_WINE_CHILD_UI_ENABLED
    int (*ui_frame)(void *,PwWineChildUiIdentity,const void *,uint32_t,uint32_t,uint32_t);
    void (*ui_retired)(void *,PwWineChildUiIdentity);
#endif
    /* Called from supervisor only, after mutable records are copied. */
    void (*record)(void *,const char *event,uint64_t generation,
                   int64_t first,int64_t second,int64_t third);
} PwWineFixtureOwnerConfig;
typedef struct PwWineFixtureOwner PwWineFixtureOwner;
/* Caller provides process-lifetime storage; an init-size helper avoids exposing
 * pthread/atomic internals to Wine. No allocations occur in server callbacks. */
unsigned pw_wine_fixture_owner_bytes(void);
int pw_wine_fixture_owner_init(void *storage,unsigned bytes,
                               const PwWineFixtureOwnerConfig *,PwWineFixtureProvider *out);
int pw_wine_fixture_owner_pump(PwWineFixtureOwner *);
/* Install once before Wine entry; only Battle profile admission uses this
 * separately versioned, nonblocking server callback table. */
int pw_wine_fixture_owner_creation(PwWineFixtureOwner *, PwWineCreationProvider *);
void pw_wine_fixture_owner_cancel(PwWineFixtureOwner *);
/* Root-only ordinary exit closes root-origin admission; Battle descendants
 * remain eligible until tree settlement. Preserve the full Windows DWORD.
 * Safe release is separate from a successful experiment: settled failed
 * runs may release, while unknown descriptor/service ownership never does.
 * Active callbacks must settle. Server object release is a separate later
 * observation: a retained root handle must not deadlock this barrier. Records
 * remain allocated until native process exit for all later server callbacks. */
int pw_wine_fixture_owner_root_result(PwWineFixtureOwner *,uint64_t session,unsigned windows_result);
int pw_wine_fixture_owner_release_ready(const PwWineFixtureOwner *);
void pw_wine_fixture_owner_socket_failure(void *,const PwWineFixtureSocketResult *);
#endif
