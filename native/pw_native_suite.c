/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _POSIX_C_SOURCE 200809L
#include "pw_native_suite.h"
#include "pw_native_socket_diagnostic.h"
#include "pw_native_service_child.h"
#include "pw_native_child_probe.h"
#include "pw_diagnostics.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

/* Results live off the UI stack and are published by the single owner before
 * DONE. Cancellation only sets a flag; it never closes an owner's descriptor. */
static struct {
    atomic_uint state, attempts, selected, ticks, locked;
    atomic_int status;
    PwNativeSocketDiagnosticResult socket;
    PwNativeServiceChildResult service;
} suite;
enum { SUITE_IDLE, SUITE_RUNNING, SUITE_DONE, SUITE_STATE_MASK = 3, SUITE_CANCEL = 4 };

static int suite_clock(void *context, uint64_t *value)
{
    struct timespec now;
    (void)context;
    if (clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec < 0 ||
        now.tv_nsec < 0 || now.tv_nsec >= 1000000000 ||
        (uint64_t)now.tv_sec > (UINT64_MAX - 999) / 1000) return -1;
    *value = (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
    return 0;
}
static int suite_cancelled(void *context)
{
    (void)context;
    return (atomic_load_explicit(&suite.state, memory_order_relaxed) & SUITE_CANCEL) != 0;
}
static unsigned suite_ticks(void *context)
{
    (void)context;
    return atomic_load_explicit(&suite.ticks, memory_order_relaxed);
}
static void service_progress(void *context, const PwNativeServiceChildResult *r)
{
    (void)context;
    /* A phase record is not the returned verdict: its callback can consume
     * the final deadline before the service controller returns. */
    pw_diagnostics_log_local("PW_SERVICE_PROGRESS phase=%u status=%u launch_possible=%u app=%d service_id=%d cleanup_uncertain=%u",
        r->phase, r->status, r->launch_possible, r->app_id, r->service_id, r->cleanup_uncertain);
}
static void socket_report(const PwNativeSocketDiagnosticResult *r)
{
    pw_diagnostics_log_local("PW_SOCKET_MATRIX status=%u complete=%u cleanup_uncertain=%u rows=%u calls=%u cases=%u finished=%u failed_calls=%u malformed=%u skipped=%u domain=ordinary collection_only=1 traffic_tested=0",
        r->status,r->collection_complete,r->cleanup_uncertain,r->rows,r->native_calls,
        r->cases_started,r->cases_finished,r->failed_calls,r->malformed_readbacks,r->skipped_setters);
    for (unsigned i=0;i<r->rows && i<PW_SD_MAX_ROWS;i++) {
        const PwNativeSocketDiagnosticRow *v=&r->row[i];
        pw_diagnostics_log_local("PW_SOCKET_ROW row=%u case=%u topology=%u method=%u op=%u disposition=%u fd=%d companion=%d input=%d rc=%lld errno_valid=%u errno=%d buffer=%u inlen=%u outlen=%u value=%d hex=%08x unchanged=%u length_match=%u type_match=%u in=%02x%02x%02x%02x out=%02x%02x%02x%02x",
            i,v->case_id,v->topology,v->method,v->operation,v->disposition,v->descriptor,v->companion,
            v->input_value,(long long)v->raw_return,v->errno_valid,v->native_error,v->has_buffer,
            v->input_length,v->output_length,v->output_value,v->output_hex,v->buffer_unchanged,
            v->length_matches,v->type_control_matches,v->input_bytes[0],v->input_bytes[1],v->input_bytes[2],v->input_bytes[3],
            v->output_bytes[0],v->output_bytes[1],v->output_bytes[2],v->output_bytes[3]);
    }
}
static void service_report(int returned, const PwNativeServiceChildResult *r)
{
    pw_diagnostics_log_local("PW_SERVICE_FINAL returned=%d status=%u phase=%u api=%u raw=%lld native_error=%d attempted=%u launch_possible=%u cleanup_uncertain=%u app=%d service_id=%d launch_return=%d selected_path=%d namespace_verified=0",
        returned,r->status,r->phase,r->api,(long long)r->raw_result,r->native_error,r->attempted,
        r->launch_possible,r->cleanup_uncertain,r->app_id,r->service_id,r->launch_return,r->selected_path);
    pw_diagnostics_log_local("PW_SERVICE_APP rc=%d words=%08x,%08x,%08x,%08x canary_valid=%u baseline_valid=%u baseline_count=%u list_calls=%u list_return=%d list_count=%u listed=%u absent=%u retired=%u kill_called=%u kill_return=%d forced=%u parent_closed=%u passed_closed=%u",
        r->app_status_return,r->app_status_words[0],r->app_status_words[1],r->app_status_words[2],r->app_status_words[3],
        r->app_status_canary_valid,r->baseline_valid,r->baseline_count,r->list_calls,r->last_list_return,
        r->last_list_count,r->listed,r->absent,r->retired,r->kill_attempted,r->kill_return,
        r->forced_cleanup,r->parent_closed,r->passed_closed);
    for(unsigned i=0;i<2;i++) {
        const PwNativeServicePathResult *p=&r->path[i];
        pw_diagnostics_log_local("PW_SERVICE_PATH alias=%u opened=%d error=%d regular=%d size=%lld size_match=%d bytes_match=%d close_rc=%d",
            i,p->opened,p->open_error,p->regular,(long long)p->size,p->size_matches,p->bytes_match,p->close_result);
    }
    const PwNativeServicePacketResult *p=&r->packet;
    pw_diagnostics_log_local("PW_SERVICE_PACKET status=%d api=%d raw=%lld errno_valid=%u errno=%d bytes=%lld control=%llu flags=%u revents=%u rights_closed=%u cleanup_failed=%u ownership_uncertain=%u cleanup_errno_valid=%u cleanup_errno=%d type=%d type_length=%u",
        p->status,p->api,(long long)p->raw_result,p->errno_valid,p->native_error,(long long)p->received_bytes,
        (unsigned long long)p->control_bytes,p->message_flags,p->poll_revents,p->rights_closed,p->cleanup_failed,
        p->ownership_uncertain,p->cleanup_errno_valid,p->cleanup_native_error,p->socket_type,p->socket_type_length);
    pw_diagnostics_log_local("PW_SERVICE_PROTOCOL complete=%u native_pid=%u native_ppid=%u echoes=%u stop_ack=%d channel_zero=%u hangup=%u ui_ticks=%u native_exit_code=unverified native_reap=unverified service_absence_is_exit=0 windows_child=unsupported",
        r->protocol_complete,r->child.child_pid,r->child.child_ppid,r->child.echoes,r->child.stop_ack,
        p->channel_zero_observed,p->hangup_observed,r->ui_ticks);
}
static void *suite_controller(void *unused)
{
    (void)unused;
    unsigned selection=atomic_load_explicit(&suite.selected,memory_order_relaxed), uncertain=0;
    int status=-1;
    if(selection==PW_SUITE_SOCKET) {
        PwNativeSocketDiagnosticContext context={NULL,suite_clock,suite_cancelled};
        status=pw_native_socket_diagnostic_run(&context,&suite.socket);
        uncertain=suite.socket.cleanup_uncertain;
        /* No live socket remains when potentially slow local storage starts. */
        socket_report(&suite.socket);
    } else if(selection==PW_SUITE_SERVICE) {
        PwNativeServiceChildContext context={NULL,suite_clock,suite_cancelled,suite_ticks,service_progress};
        status=pw_native_service_child_run(&context,&suite.service);
        uncertain=suite.service.cleanup_uncertain;
        service_report(status,&suite.service);
    } else {
        status=suite_cancelled(NULL)?-1:pw_native_child_probe_start();
        if(!status) {
            for (;;) {
                if(suite_cancelled(NULL)) pw_native_child_probe_cancel();
                if(pw_native_child_probe_finished(&status,&uncertain)) break;
                struct timespec delay={0,100000000};
                (void)nanosleep(&delay,NULL);
            }
        }
    }
    if(uncertain) atomic_store_explicit(&suite.locked,1,memory_order_release);
    suite.status=status;
    pw_diagnostics_log_local("PW_NATIVE_SUITE selection=%u returned=%d cleanup_uncertain=%u locked=%u attempts=%u",
        selection,status,uncertain,atomic_load(&suite.locked),atomic_load(&suite.attempts));
    atomic_store_explicit(&suite.state,SUITE_DONE,memory_order_release);
    return NULL;
}
const char *pw_native_suite_title(void) { return "NATIVE DIAGNOSTIC SUITE"; }
const char *pw_native_suite_item(unsigned index)
{
    static const char *const names[]={"SOCKET API MATRIX","SERVICE CHILD (HEADLESS)","LEGACY PEER / EXIT"};
    return index<PW_SUITE_COUNT?names[index]:"UNAVAILABLE";
}
int pw_native_suite_available(unsigned selection)
{
    return selection<PW_SUITE_COUNT && !atomic_load_explicit(&suite.locked,memory_order_acquire) &&
        (atomic_load_explicit(&suite.state,memory_order_acquire)&SUITE_STATE_MASK)!=SUITE_RUNNING &&
        !(atomic_load_explicit(&suite.attempts,memory_order_relaxed)&(1u<<selection));
}
int pw_native_suite_start(unsigned selection)
{
    if(!pw_native_suite_available(selection)) return -1;
    unsigned state=atomic_load_explicit(&suite.state,memory_order_acquire);
    if((state&SUITE_STATE_MASK)==SUITE_RUNNING || !atomic_compare_exchange_strong(&suite.state,&state,SUITE_RUNNING)) return -1;
    if(atomic_load_explicit(&suite.locked,memory_order_acquire) ||
       (atomic_fetch_or(&suite.attempts,1u<<selection)&(1u<<selection))) {
        atomic_store_explicit(&suite.state,state,memory_order_release);return -1;
    }
    atomic_store_explicit(&suite.selected,selection,memory_order_relaxed);
    pthread_attr_t attributes;pthread_t thread;
    int rc=pthread_attr_init(&attributes);
    if(!rc) {
        rc=pthread_attr_setdetachstate(&attributes,PTHREAD_CREATE_DETACHED);
        if(!rc) rc=pthread_create(&thread,&attributes,suite_controller,NULL);
        (void)pthread_attr_destroy(&attributes);
    }
    if(rc) {
        suite.status=-1;
        pw_diagnostics_log_local("PW_NATIVE_SUITE selection=%u thread_error=%d attempted=1",selection,rc);
        atomic_store_explicit(&suite.state,SUITE_DONE,memory_order_release);
    }
    return rc?-1:0;
}
void pw_native_suite_cancel(void)
{
    unsigned state=atomic_load_explicit(&suite.state,memory_order_acquire);
    while((state&SUITE_STATE_MASK)==SUITE_RUNNING && !(state&SUITE_CANCEL))
        if(atomic_compare_exchange_weak(&suite.state,&state,state|SUITE_CANCEL)) break;
}
void pw_native_suite_tick(void)
{
    atomic_fetch_add_explicit(&suite.ticks,1,memory_order_relaxed);
    pw_native_child_probe_tick();
}
void pw_native_suite_status(char *text,size_t capacity)
{
    if(atomic_load_explicit(&suite.locked,memory_order_acquire)) {
        snprintf(text,capacity,"CLEANUP UNKNOWN. STOP TESTING. GET SAVED LOG.");return;
    }
    unsigned state=atomic_load_explicit(&suite.state,memory_order_acquire)&SUITE_STATE_MASK;
    if(state==SUITE_RUNNING) snprintf(text,capacity,"TEST ACTIVE. SQUARE/ESC: CANCEL. PLEASE WAIT.");
    else if(state==SUITE_IDLE) snprintf(text,capacity,"SELECT TEST. CROSS/ENTER: RUN ONCE.");
    else snprintf(text,capacity,"%s. GET SAVED LOG. SELECT AN UNUSED TEST.",suite.status?"TEST INCOMPLETE":"OBSERVATIONS RECORDED");
}
