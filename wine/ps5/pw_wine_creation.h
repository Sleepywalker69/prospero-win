/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_WINE_CREATION_H
#define PW_WINE_CREATION_H
#include <stdint.h>
/* Same-address-space owner callbacks. No pointer in this contract is a wire
 * value. Descendant clients use ordinary Wine requests, never this table. */
#define PW_WINE_CREATION_ABI 1u
#define PW_WINE_CREATION_PROTOCOL 962u
#define PW_WINE_CREATION_PATH_BYTES 1024u
#define PW_WINE_CREATION_IMAGE_BYTES 2048u
#define PW_WINE_CREATION_REQUESTS 16u
#define PW_WINE_CREATION_STARTUP_MS 30000u
/* Fixed original IPC diagnostic modes; structural child identity only.
 * Root admission separately binds the opt-in profile, exact path and digest. */
#define PW_WINE_CREATION_IPC_FIRST 16u
#define PW_WINE_CREATION_IPC_LAST 23u

typedef struct PwWineCreationRequest {
    uint64_t origin, lease, key, now, deadline;
    uint32_t caller_pid, caller_tid, machine, image_bytes, path_bytes;
    unsigned char image[PW_WINE_CREATION_IMAGE_BYTES];
    char path[PW_WINE_CREATION_PATH_BYTES];
} PwWineCreationRequest;
enum { PW_WCR_PENDING, PW_WCR_ADMITTED, PW_WCR_BOUND, PW_WCR_SUBMITTED,
       PW_WCR_BOOTSTRAPPED, PW_WCR_FAILED };
typedef struct PwWineCreationStatus {
    uint64_t deadline;
    uint32_t phase, status;
} PwWineCreationStatus;
typedef struct PwWineCreationProvider {
    uint32_t abi, bytes;
    void *context;
    /* Bounded copies/CAS only: all file, service and wait operations belong
     * to the independent native supervisor. Every record is nonrecycled. */
    uint32_t (*prepare)(void *, const PwWineCreationRequest *, uint64_t *generation);
    uint32_t (*query)(void *, uint64_t generation, uint64_t lease, uint64_t now,
                      PwWineCreationStatus *);
    uint32_t (*bind)(void *, uint64_t generation, uint64_t lease, uint64_t now,
                     uint32_t child_pid, uint32_t machine, const void *image, uint32_t bytes);
    /* The handler owns *stream. Only successful acceptance sets it to -1;
     * subsequent failure does not undo the move or authorize resubmission. */
    uint32_t (*submit)(void *, uint64_t generation, uint64_t lease, uint64_t now,
                       uint32_t child_pid, uint32_t child_tid, int *stream);
    uint32_t (*result)(void *, uint64_t generation, uint64_t lease,
                       uint32_t success, uint32_t status);
    void (*abandon)(void *, uint64_t generation, uint64_t lease);
    void (*transport_failure)(void *, uint64_t generation, uint64_t lease,
                               int32_t raw, int32_t native_error);
    void (*origin_dead)(void *, uint64_t generation, uint32_t wine_pid);
    /* Called before init_thread or native identity writes. Expected values
     * are independently compared to the actual server process/thread first. */
    uint32_t (*join)(void *, uint64_t generation, uint32_t wine_pid,
                     uint32_t wine_tid, int32_t native_pid);
} PwWineCreationProvider;
typedef struct PwWineCreationChild {
    uint32_t abi, bytes;
    uint64_t generation;
    uint32_t wine_pid, wine_tid, profile, machine;
} PwWineCreationChild;
int pw_wine_creation_install(const PwWineCreationProvider *);
int pw_wineserver_creation_install(const PwWineCreationProvider *);
const PwWineCreationProvider *pw_wine_creation_get(void);
int pw_wine_creation_child_install(const PwWineCreationChild *);
const PwWineCreationChild *pw_wine_creation_child_get(void);
unsigned __wine_ps5_creation_abi(void);
unsigned __wine_ps5_creation_protocol(void);
#endif
