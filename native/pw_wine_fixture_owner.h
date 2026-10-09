/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_WINE_FIXTURE_OWNER_H
#define PW_WINE_FIXTURE_OWNER_H
#include "../wine/ps5/pw_wine_fixture_provider.h"
#include "../wine/ps5/pw_wine_fixture_socket.h"
#include <stdint.h>

/* The native title creates one owner before ordinary profile launch, then a
 * single supervisor thread runs pump(). Wine callbacks never call the service
 * enumerator or killer under the server lock. Fixed records survive the run. */
enum { PW_WFO_MAX_GENERATIONS=16, PW_WFO_ATTEMPT_MS=180000,
       PW_WFO_VENDOR_MS=600000, PW_WFO_VENDOR_CHILD_MS=300000, PW_WFO_CLEANUP_MS=5000,
       PW_WFO_STARTUP_MS=30000, PW_WFO_CHILD_MS=60000, PW_WFO_LIST_CAP=16 };
enum { PW_WFO_IDLE, PW_WFO_ADMITTED, PW_WFO_BOUND, PW_WFO_LAUNCH_POSSIBLE,
       PW_WFO_BOOTSTRAP, PW_WFO_RUNNING, PW_WFO_RETIRED, PW_WFO_UNCERTAIN };
typedef struct PwWineFixtureOwnerConfig {
    uint64_t session;
    unsigned profile; /* 1 original fixture; 2 explicit Battle.net experiment */
    const char *child_unix_path; /* exact original fixture image; NULL for vendor */
    const char *child_sha256;    /* exact fixture hash; NULL for vendor */
    const unsigned char *helper_image;
    uint32_t helper_bytes;
    const char *build_id;        /* exact full-CRT helper build identity */
    void *context;
    int (*clock_ms)(void *,uint64_t *);
    int (*cancelled)(void *);
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
void pw_wine_fixture_owner_cancel(PwWineFixtureOwner *);
/* Root-only ordinary exit closes admission and preserves the full Windows
 * DWORD. Safe release is separate from a successful experiment: settled failed
 * runs may release, while unknown descriptor/service ownership never does.
 * Active callbacks must settle. Server object release is a separate later
 * observation: a retained root handle must not deadlock this barrier. Records
 * remain allocated until native process exit for all later server callbacks. */
int pw_wine_fixture_owner_root_result(PwWineFixtureOwner *,uint64_t session,unsigned windows_result);
int pw_wine_fixture_owner_release_ready(const PwWineFixtureOwner *);
void pw_wine_fixture_owner_socket_failure(void *,const PwWineFixtureSocketResult *);
#endif
