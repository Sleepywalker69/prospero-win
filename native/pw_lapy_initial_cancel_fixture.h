/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_LAPY_INITIAL_CANCEL_FIXTURE_H
#define PW_LAPY_INITIAL_CANCEL_FIXTURE_H
#include "pw_lapy_elevation.h"
#include "lapy_elevation_protocol.h"
enum { PW_INITIAL_CANCEL_NO_DISPATCH, PW_INITIAL_CANCEL_RECEIPT_ONLY, PW_INITIAL_CANCEL_HELD };
/* A receipt is transaction evidence only. There is deliberately no EXITED or
 * PASS classification: the current loader exposes no bound lifetime observer. */
static inline unsigned pw_initial_cancel_classify(const PwLapyElevationResult *r)
{
    if(!r)return PW_INITIAL_CANCEL_HELD;
    if(r->no_dispatch==1&&r->no_request==1&&!r->possible_apply&&!r->terminal&&
       !r->settled_failure&&!r->cancel_attempted&&!r->helper_status)return PW_INITIAL_CANCEL_NO_DISPATCH;
    if(!r->no_dispatch&&r->no_request==1&&!r->possible_apply&&r->terminal==1&&
       r->settled_failure==1&&r->cancel_attempted==1&&r->transaction_id&&
       r->helper_status==LAPY_ELEVATION_CANCELLED)return PW_INITIAL_CANCEL_RECEIPT_ONLY;
    return PW_INITIAL_CANCEL_HELD;
}
#endif
