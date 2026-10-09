/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_NATIVE_FD_PROBE_H
#define PW_NATIVE_FD_PROBE_H
#include <stdint.h>

/* Original synthetic AF_UNIX diagnostic. No Wine/loader/SceNet descriptors. */
enum { PW_NATIVE_FD_PATH_CAP = 100 };
typedef struct {
    void *context;
    int (*clock_ms)(void *, uint64_t *);
    int (*cancelled)(void *); /* optional; nonzero stops */
    uint64_t deadline_ms;    /* absolute, never extended by partial I/O */
} PwNativeFdContext;

typedef enum {
    PW_NATIVE_FD_OK = 0,
    PW_NATIVE_FD_INVALID = -1,
    PW_NATIVE_FD_OS = -2,
    PW_NATIVE_FD_TIMEOUT = -3,
    PW_NATIVE_FD_CANCELLED = -4,
    PW_NATIVE_FD_CLOCK = -5,
    PW_NATIVE_FD_PROTOCOL = -6,
    PW_NATIVE_FD_EOF = -7
} PwNativeFdStatus;

typedef enum {
    PW_NATIVE_FD_VALIDATE = 0,
    PW_NATIVE_FD_LISTEN,
    PW_NATIVE_FD_ACCEPT,
    PW_NATIVE_FD_CONNECT,
    PW_NATIVE_FD_HELLO,
    PW_NATIVE_FD_QUEUE,
    PW_NATIVE_FD_HANDOFF,
    PW_NATIVE_FD_FORWARD,
    PW_NATIVE_FD_REVERSE,
    PW_NATIVE_FD_FINISH,
    PW_NATIVE_FD_CLEANUP,
    PW_NATIVE_FD_COMPLETE
} PwNativeFdStage;

typedef enum {
    PW_NATIVE_FD_API_NONE = 0, PW_NATIVE_FD_API_CLOCK, PW_NATIVE_FD_API_POLL,
    PW_NATIVE_FD_API_FCNTL, PW_NATIVE_FD_API_SETSOCKOPT,
    PW_NATIVE_FD_API_SOCKET, PW_NATIVE_FD_API_SOCKETPAIR,
    PW_NATIVE_FD_API_SHUTDOWN, PW_NATIVE_FD_API_SENDMSG,
    PW_NATIVE_FD_API_RECVMSG, PW_NATIVE_FD_API_GETPID,
    PW_NATIVE_FD_API_BIND, PW_NATIVE_FD_API_LISTEN,
    PW_NATIVE_FD_API_ACCEPT, PW_NATIVE_FD_API_CONNECT,
    PW_NATIVE_FD_API_CLOSE, PW_NATIVE_FD_API_UNLINK
} PwNativeFdApi;

enum {
    PW_NATIVE_FD_CONNECTED = 1u << 0,
    PW_NATIVE_FD_HELLO_OK = 1u << 1,
    PW_NATIVE_FD_QUEUED_RIGHT_OK = 1u << 2,
    PW_NATIVE_FD_FORWARD_OK = 1u << 3,
    PW_NATIVE_FD_FORWARD_EOF = 1u << 4,
    PW_NATIVE_FD_REVERSE_OK = 1u << 5,
    PW_NATIVE_FD_REVERSE_EOF = 1u << 6,
    PW_NATIVE_FD_COMPLETED = 1u << 7
};

typedef struct {
    PwNativeFdStatus status;
    PwNativeFdStage stage;
    PwNativeFdApi api;
    int64_t raw_result; /* first failed ordinary API result; no errno dependency */
    uint32_t observations;
    uint32_t peer_observations; /* acknowledged by original peer, not directly observed */
    uint64_t last_clock_ms;
    uint32_t clock_observed;
    uint32_t local_pid;
    uint32_t reported_peer_pid; /* correlation only, NOT authenticated */
    uint32_t peer_identity_verified; /* always zero in this proposal */
    uint32_t cleanup_failed;
} PwNativeFdResult;

typedef struct {
    int fd;
    int bound;
    uint64_t last_clock_ms;
    char path[PW_NATIVE_FD_PATH_CAP];
} PwNativeFdListener;

/* path must name an absent socket inside a fresh caller-owned directory.
 * No directory creation or removal, stale-path deletion, chmod or credentials.
 * Listener must be fresh; successful open owns fd/path until parent/dispose.
 * Open before telling the worker to connect through the separate control ABI. */
int pw_native_fd_parent_open(PwNativeFdListener *, const char *path,
                            const PwNativeFdContext *, PwNativeFdResult *);
int pw_native_fd_parent(PwNativeFdListener *, uint64_t correlation,
                       const PwNativeFdContext *, PwNativeFdResult *);
int pw_native_fd_worker(const char *path, uint64_t correlation,
                       const PwNativeFdContext *, PwNativeFdResult *);
/* Closes/unlinks only resources owned by a successful parent_open. */
void pw_native_fd_dispose(PwNativeFdListener *, PwNativeFdResult *);
#endif
