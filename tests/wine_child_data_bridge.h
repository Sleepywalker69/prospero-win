/* Original socket-free composition controls. */
#ifndef BOOTSTRAP_DIAGNOSTIC_BRIDGE_H
#define BOOTSTRAP_DIAGNOSTIC_BRIDGE_H
#include "../native/pw_wine_child_bootstrap.h"
#include "data_adapter_fixture.h"
enum { CASE_LOG=1,CASE_PREFIX,CASE_CWD,CASE_RUNTIME_OPEN,CASE_RUNTIME_HASH,CASE_PREFIX_TYPE,CASE_RUNTIME_READ,CASE_RUNTIME_STAT,CASE_RUNTIME_TYPE,CASE_RUNTIME_SIZE,CASE_RUNTIME_EXTRA,CASE_RUNTIME_CHANGED,CASE_RUNTIME_CLOSE,CASE_PATH_BUDGET,CASE_LOG_HEADER,CASE_SUCCESS,CASE_DATA_MARKER };
typedef struct {int which,probe,cleanup_error,expire_probe,cancel_probe,profile,expire_open,log_after_path,transport_guard,data_mode;} DiagnosticCase;
typedef struct {char data_marker[512];unsigned data_marker_count;int parked,exit_code,sends,closes[128],stats,probe_stats,envs,loads,threads; PwWineChildData data;unsigned data_calls,data_clones,data_sends;unsigned stage,api,auxiliary,errno_valid; int raw,error,detail; uint64_t stage_end,total_end; PwWineChildFrame hello,failure; unsigned char bytes[PW_WC_WIRE_BYTES];} DiagnosticResult;
void diagnostic_child_run(const PwWineChildFrame *,const DiagnosticCase *,DiagnosticResult *);
#endif
