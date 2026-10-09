/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_NATIVE_PEER_PROBE_H
#define PW_NATIVE_PEER_PROBE_H
#include "pw_native_peer_protocol.h"
#include <stdint.h>

enum { PW_NP_PATH_CAP = 100 };
enum { PW_NP_API_NONE, PW_NP_API_CLOCK, PW_NP_API_SOCKET, PW_NP_API_FCNTL,
       PW_NP_API_SETSOCKOPT, PW_NP_API_BIND, PW_NP_API_LISTEN, PW_NP_API_ACCEPT,
       PW_NP_API_CONNECT, PW_NP_API_POLL, PW_NP_API_SENDMSG, PW_NP_API_RECVMSG,
       PW_NP_API_CONTROL, PW_NP_API_KQUEUE, PW_NP_API_ARM, PW_NP_API_PENDING,
       PW_NP_API_ENTROPY, PW_NP_API_EVENT, PW_NP_API_CLOSE, PW_NP_API_UNLINK,
       /* Append codes so saved records retain their original meaning. */
       PW_NP_API_FCNTL_GETFD, PW_NP_API_FCNTL_SETFD,
       PW_NP_API_FCNTL_GETFL, PW_NP_API_FCNTL_SETFL,
       PW_NP_API_IOCTL_FIOCLEX, PW_NP_API_IOCTL_FIONBIO };
typedef struct {
    uint32_t pid, uid, euid, gid, groups;
} PwNativePeerCredential;
typedef struct {
    int status;
    int native_error; /* parent-only immediate errno; worker never reads it */
    unsigned phase, api;
    int64_t raw_result;
    PwNativePeerCredential initial_credential, post_arm_credential;
    unsigned credential_ok, reciprocal_ok, receipt_ok, initial_empty;
    unsigned entropy_ok, entropy_bytes, nonce_match, prestop_empty;
    int64_t entropy_return;
    unsigned receipt_flags, receipt_fflags;
    int64_t receipt_data;
    unsigned worker_report_valid;
    PwNativePeerRecord worker_report; /* RESULT is canonical with zero nonce */
    unsigned exit_observed, exit_status_match, exit_flags, exit_fflags;
    uint64_t event_ident;
    int event_filter, event_tag_matches;
    int64_t exit_data;
    unsigned cleanup_failed;
} PwNativePeerResult;
typedef struct {
    int listener, stream, queue;
    unsigned bound, armed;
    uint32_t peer_pid;
    char path[PW_NP_PATH_CAP];
} PwNativePeerProbe;

int pw_native_peer_paths(uint32_t parent_pid, uint64_t correlation,
                          char directory[PW_NP_PATH_CAP], char path[PW_NP_PATH_CAP]);
/* Caller owns fresh-directory creation/removal; no stale-path cleanup or
 * permission change. SceNet's control socket is never an ordinary FD here. */
int pw_native_peer_parent_open(PwNativePeerProbe *, const char *path, PwNativeChildIo *, PwNativePeerResult *);
int pw_native_peer_parent_exchange(PwNativePeerProbe *, PwNativeChildIo *,
                                    const PwNativeChildFrame *, PwNativePeerResult *);
int pw_native_peer_worker_exchange(PwNativeChildIo *, const PwNativeChildFrame *, PwNativePeerResult *);
/* Caller finishes its owned directory cleanup before this final pending check. */
int pw_native_peer_pre_stop(PwNativePeerProbe *, PwNativeChildIo *, PwNativePeerResult *);
/* Observe only the existing registration. A prior failure is never cleared;
 * cooperative requires independently validated STOP_ACK plus control EOF. */
int pw_native_peer_observe(PwNativePeerProbe *, PwNativeChildIo *, int cooperative, PwNativePeerResult *);
void pw_native_peer_parent_cleanup(PwNativePeerProbe *, PwNativePeerResult *);
#endif
