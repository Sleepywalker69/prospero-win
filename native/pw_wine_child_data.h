/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_WINE_CHILD_DATA_H
#define PW_WINE_CHILD_DATA_H
#include "pw_native_child_protocol.h"
#include <stdint.h>

/* Child-only, single-threaded readiness before log creation and Wine entry.
 * The parent has already latched possible helper activity before BOOTSTRAP.
 * No helper path, PID, module name or capability is caller-selectable. */
enum { PW_WCD_ARGUMENT=0x200, PW_WCD_BUDGET, PW_WCD_CONTROL, PW_WCD_DATA_STAT,
       PW_WCD_MODULE_LOAD, PW_WCD_MODULE_START, PW_WCD_RESOLVE, PW_WCD_NET_LOAD,
       PW_WCD_NET_HANDLE, PW_WCD_NET_INIT, PW_WCD_HELPER_OPEN, PW_WCD_HELPER_STAT,
       PW_WCD_HELPER_TYPE, PW_WCD_HELPER_SIZE, PW_WCD_ALLOC, PW_WCD_HELPER_READ,
       PW_WCD_HELPER_HASH, PW_WCD_HELPER_CHANGED, PW_WCD_HELPER_CLOSE,
       PW_WCD_SOCKET, PW_WCD_OPTION, PW_WCD_CONNECT, PW_WCD_UPLOAD,
       PW_WCD_REQUEST, PW_WCD_PREPARE, PW_WCD_LOCAL_PREPARE, PW_WCD_PREPARED,
       PW_WCD_RESULT, PW_WCD_SETTLE, PW_WCD_NET_CLOSE,
       PW_WCD_DATA_LSTAT, PW_WCD_DATA_LSTAT_TYPE };
/* MODULE_LOAD/START and SYSMODULE_LOAD/HANDLE resolution indices remain
 * reserved for historical diagnostics. Sysmodule now uses static imports. */
/* Every bootstrap FAILURE reserves returned_length bits16..21 for the state
 * mask below; low16 bits preserve the operation auxiliary. For data APIs it
 * is zero. returned_value is
 * control_revents for CONTROL, resolution_index for RESOLVE, otherwise the
 * observed helper status. Resolution indices follow this fixed table: */
enum { PW_WCD_RESOLVE_NONE, PW_WCD_SYSMODULE_LOAD, PW_WCD_SYSMODULE_HANDLE,
       PW_WCD_NET_INIT_SYMBOL, PW_WCD_NET_SOCKET_SYMBOL, PW_WCD_NET_CONNECT_SYMBOL,
       PW_WCD_NET_SEND_SYMBOL, PW_WCD_NET_RECV_SYMBOL, PW_WCD_NET_OPTION_SYMBOL,
       PW_WCD_NET_CLOSE_SYMBOL, PW_WCD_NET_ERRNO_SYMBOL };
enum { PW_WCD_POSSIBLE=1u, PW_WCD_TERMINAL=2u, PW_WCD_DATA_BEFORE=4u, PW_WCD_DATA_AFTER=8u,
       PW_WCD_LSTAT_BEFORE=16u, PW_WCD_LSTAT_AFTER=32u };
#define PW_WCD_STATE_SHIFT 16u
typedef struct PwWineChildData {
    unsigned attempted, possible_apply, terminal, ready, control_refused;
    unsigned data_before, data_after, settled_ms, lstat_before, lstat_after;
    unsigned before_observations, after_observations; /* values1 stat;2 lstat */
    int32_t stat_before_raw, stat_before_error, lstat_before_raw, lstat_before_error;
    int32_t stat_after_raw, stat_after_error, lstat_after_raw, lstat_after_error;
    unsigned api, errno_valid;
    int32_t raw, native_error;
    uint32_t helper_status, control_revents, resolution_index;
} PwWineChildData;
/* Retains original absolute deadlines and clock history. A zero result means
 * preexisting data or terminal helper success plus the full measured settle.
 * Actual log/prefix/CWD/runtime checks still follow in the caller. On nonzero,
 * possible_apply&&!terminal requires keeping this native PID alive; timeout,
 * channel loss and socket close are not remote-settlement evidence.
 * The state must begin zero and is used for exactly one attempt. */
int pw_wine_child_data_prepare(PwWineChildData *, PwNativeChildIo *, const char *helper_sha256);
#endif
