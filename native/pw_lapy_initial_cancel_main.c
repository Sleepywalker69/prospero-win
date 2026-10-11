/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Source-only initial-CANCEL fixture. Target execution remains gated until a
 * supported identity-bound, non-reboot helper-exit observation/stop route exists. */
#define _POSIX_C_SOURCE 200809L
#if !defined(PW_LAPY_INITIAL_CANCEL_ONLY) || PW_LAPY_INITIAL_CANCEL_ONLY != 1
#error This entry requires the compile-time initial-CANCEL-only adapter
#endif
#include "pw_lapy_initial_cancel_fixture.h"
#include "ps5log/ps5log.h"
#include <time.h>
#include <unistd.h>
#ifndef PW_BUILD_ID
#error The initial-CANCEL fixture requires an exact source build identity
#endif

int main(void)
{
    /* No /data configuration fallback or root-data preparation is reachable. */
    const char *const paths[]={"/app0/dev.conf"};
    ps5log_config config;ps5log_config_defaults(&config);
    if(ps5log_load_config(paths,1,&config,NULL)||
       ps5log_init(&config,"PPSA99995","prospero-win-initial-cancel",ps5log_monotonic_ns()))return 2;
    if(ps5log_printf(PS5LOG_MARK,"PW_INITIAL_CANCEL build=%s stage=before_upload one_attempt=1",PW_BUILD_ID)){
        ps5log_close("not-dispatched");return 3;
    }
    PwLapyElevationResult result={0};
    int rc=pw_lapy_initial_cancel_result((int32_t)getpid(),&result);
    unsigned outcome=pw_initial_cancel_classify(&result);
    (void)ps5log_printf(PS5LOG_MARK,
        "PW_INITIAL_CANCEL build=%s stage=transaction_result rc=%d outcome=%u transaction=%llu no_dispatch=%u no_request=%u terminal=%u status=%u helper_exit=unobserved",
        PW_BUILD_ID,rc,outcome,(unsigned long long)result.transaction_id,
        result.no_dispatch,result.no_request,result.terminal,result.helper_status);
    if(outcome==PW_INITIAL_CANCEL_NO_DISPATCH){ps5log_close("not-dispatched");return 1;}
    /* Terminal CANCELLED is not process-exit evidence. Never turn EOF, elapsed
     * time, a receipt, or app closure into permission to stop an unknown helper. */
    (void)ps5log_printf(PS5LOG_ERR,"PW_INITIAL_CANCEL stage=held helper_exit=unobserved reboot_fallback=forbidden");
    for(;;){const struct timespec wait={1,0};(void)nanosleep(&wait,NULL);}
}
