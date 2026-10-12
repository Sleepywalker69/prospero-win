/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Compile the exact final #else implementation from pw_focus_requests.c.
 * These host-shaped request objects make no wire-layout claim.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#define STATUS_NOT_SUPPORTED 0xc00000bbu
static unsigned int error_;
static void set_error(unsigned int error) { error_=error; }
struct thread { unsigned int unused; };
struct process { unsigned int unused; };
struct focus_open_request { unsigned int unused; };
struct focus_open_reply { unsigned int unused; };
struct focus_control_request { unsigned int unused; };
struct focus_control_reply { unsigned int unused; };
struct focus_input_request { unsigned int unused; };
struct focus_input_reply { unsigned int unused; };
#define DECL_HANDLER(name) static void req_##name(const struct name##_request *req, struct name##_reply *reply)
#include "actual_disabled_requests.inc"
int main(void) {
    uint64_t now=123;
    pw_focus_requests_init();
    pw_focus_requests_thread_dead(NULL);
    pw_focus_requests_process_dead(NULL);
    assert(pw_focus_requests_clock(&now)==0 && now==123);
    req_focus_open(NULL,NULL); assert(error_==STATUS_NOT_SUPPORTED);
    error_=0; req_focus_control(NULL,NULL); assert(error_==STATUS_NOT_SUPPORTED);
    error_=0; req_focus_input(NULL,NULL); assert(error_==STATUS_NOT_SUPPORTED);
    puts("disabled: actual request stubs refuse OPEN, CONTROL and INPUT; no clock or initialization");
    return 0;
}
