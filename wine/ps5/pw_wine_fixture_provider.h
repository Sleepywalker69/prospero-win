/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_WINE_FIXTURE_PROVIDER_H
#define PW_WINE_FIXTURE_PROVIDER_H
#include <stdint.h>
/* Experimental profile-bound child-process interface. This table stays within the
 * title's address space; none of its addresses or structures are sent to the
 * service child. It is absent from default builds and has a real profile-admitted
 * caller in NtCreateUserProcess, plus consumers in the in-process server.
 * Registration is once, before Wine entry/server startup. */
#define PW_WINE_FIXTURE_ABI 1u
#define PW_WINE_FIXTURE_AMD64 0x8664u
#define PW_WINE_FIXTURE_I386 0x14cu
#define PW_WINE_FIXTURE_MAX_CHILDREN 16u

enum PwWineFixtureProcessState {
    PW_WF_NOT_OWNED = 0, PW_WF_OWNED_ACTIVE = 1,
    PW_WF_OWNED_RETIRED = 2, PW_WF_OWNED_UNCERTAIN = 3
};
enum PwWineFixtureSignalState {
    PW_WF_SIGNAL_NOT_OWNED = 0,
    PW_WF_SIGNAL_QUEUED = 1,
    PW_WF_SIGNAL_FAILED = -1
};
typedef struct PwWineFixtureProvider {
    uint32_t abi, bytes;
    void *context;
    /* Called only after ordinary Wine image lookup succeeded, before
     * new_process/new_thread reservation. Preserve ordinary missing-file
     * errors. The selected experimental profile, caller identity, image path and
     * explicitly supported machine are required. Prior service retirement gates the next nonzero generation.
     * Returns a real NTSTATUS; it does not create or fabricate Wine handles. */
    uint32_t (*admit)(void *, uint32_t caller_wine_pid, uint32_t caller_wine_tid,
                      uint32_t machine, const char *unix_image, uint64_t *generation);
    /* The server new_process handler binds its newly allocated object once,
     * while the exact admitted caller PID/TID is current. The generation is
     * then stored on that process object, never reconstructed from reused IDs.
     * A failure aborts reservation before any native launch. */
    uint32_t (*bind_process)(void *, uint32_t caller_wine_pid,
                             uint32_t caller_wine_tid, uint32_t child_wine_pid,
                             uint64_t *generation);
    /* Destruction of that server object releases its reference. Records are
     * never recycled during the attempt; all callbacks/timers retain their
     * captured generation until finished. */
    void (*release_process)(void *, uint64_t generation, uint32_t wine_pid);
    /* new_process/new_thread must already have succeeded. server_fd is
     * borrowed until return: no read, close or transfer of that original.
     * The asynchronous owner first takes one checked dup reference so a late
     * service return cannot use a closed/reused borrowed number. A single
     * SCM_RIGHTS handoff produces the child's
     * separate owned reference. Failed/short delivery is uncertain, no retry.
     * Wait only for bootstrap/right-receipt, never guest READY or guest exit.
     * Returned success is not CreateProcess success; Wine still performs its
     * startup_info wait and get_new_process_info authority check. */
    uint32_t (*spawn)(void *, uint64_t generation, int server_fd,
                      uint32_t wine_pid, uint32_t wine_tid);
    /* Positive remaining time in milliseconds within the original absolute
     * startup endpoint, or zero on Stop/expiry/error. No deadline renewal. */
    uint32_t (*startup_remaining_ms)(void *, uint64_t generation);
    /* Called on every post-admission exit, including reservation failure.
     * Actual success and the full NTSTATUS remain Wine-owned observations. */
    void (*startup_result)(void *, uint64_t generation,
                           uint32_t wine_success, uint32_t status);
    /* Server-lock-safe bounded nonblocking submission only. Validate exact
     * owned Wine/native identity and generation; never wait for guest reply.
     * QUEUED means a full typed control packet was accepted, not that the
     * signal was delivered or that a process died. Child-local registry later
     * reports the actual pthread_kill result. Unknown/stale IDs never become
     * ESRCH-as-death and no raw foreign kill(pid) is permitted. */
    int (*signal)(void *, uint64_t generation, uint32_t wine_pid, int32_t native_pid,
                  int64_t native_tid, int32_t signal);
    /* Server-lock-safe snapshot/cleanup request. Own-app service calls run in
     * the native supervisor, outside the Wine server lock. RETIRED means the
     * already bound owned service generation was observed absent on a valid
     * complete list; it never claims native wait/reap or an OS exit code.
     * A cleanup request may not target unowned, ambiguous or retired IDs.
     * native_pid=-1 before first server registration is an observation;
     * generation plus the reserved server object determines ownership.
     * A conflicting positive PID is uncertainty, never a fallback to kill(). */
    uint32_t (*process_state)(void *, uint64_t generation, uint32_t wine_pid, int32_t native_pid,
                              uint32_t request_cleanup);
    /* Root-only ordinary exit barrier. The ntdll caller supplies the full
     * Windows DWORD before Unix exit-code conversion. Initial call freezes
     * admission before the root client is logically detached; later calls
     * wait after its checked endpoint closure. First call freezes admission, including active admit
     * callbacks and reserved/queued generations. Nonzero means safe release,
     * not compatibility success. Unknown ownership never releases on time.
     * Child ntdll has no installed provider and keeps ordinary exit behavior.
     * Native supervisor progress cannot require this exiting Wine thread. */
    uint32_t (*root_exit)(void *, uint32_t windows_status);
    /* Actual result of root-only existing Wine termination requests and
     * owned endpoint closes. This is an observation, never a synthetic
     * Windows process signal. Failure retains uncertain native ownership. */
    void (*root_detached)(void *, uint32_t success, int32_t raw, int32_t native_error);
} PwWineFixtureProvider;
/* Proposed concrete exports, implemented only in the experimental build.
 * ntdll passes the same-address-space table to the newly loaded server before
 * pw_wineserver_connect. Both endpoints reject size/ABI mismatch or rebind. */
int pw_wine_fixture_install(const PwWineFixtureProvider *provider);
int pw_wineserver_fixture_install(const PwWineFixtureProvider *provider);
const PwWineFixtureProvider *pw_wine_fixture_get(void);
#endif
