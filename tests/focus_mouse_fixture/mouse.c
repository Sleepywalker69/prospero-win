/* SPDX-License-Identifier: LGPL-2.1-or-later
 * This translation unit intentionally mocks Wine's surrounding services.
 * actual_mouse_functions.inc is generated from exact composed source.
 * pw_focus_core.c is compiled separately, whole and unchanged.
 * This is desktop-state receipt evidence, never application-delivery evidence.
 */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include "pw_focus_core.h"
#include "pw_focus_protocol.h"

#define PW_FOCUS_SERVER_ADAPTER 1
#define PW_FOCUS_SERVER_REQUESTS 1
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define max(a,b) ((a) > (b) ? (a) : (b))
typedef uint32_t user_handle_t;
typedef int64_t lparam_t;
typedef int64_t timeout_t;
typedef size_t data_size_t;
typedef struct { int x, y; } POINT;
struct rectangle { int left, top, right, bottom; };
enum {
    INPUT_MOUSE=0, INPUT_KEYBOARD=1, IMO_HARDWARE=1, IMO_INJECTED=2,
    IMDT_MOUSE=1, MSG_HARDWARE=1, MSG_HOOK_LL=2, MSG_CALLBACK=3,
    MSG_CALLBACK_RESULT=4, SEND_MESSAGE=0, WH_MOUSE_LL=14,
    WM_INPUT=0xff, WM_KEYDOWN=0x100, WM_KEYUP=0x101,
    WM_SYSKEYDOWN=0x104, WM_SYSKEYUP=0x105, WM_MOUSEMOVE=0x200,
    WM_LBUTTONDOWN=0x201, WM_LBUTTONUP=0x202,
    WM_RBUTTONDOWN=0x204, WM_RBUTTONUP=0x205,
    WM_MBUTTONDOWN=0x207, WM_MBUTTONUP=0x208, WM_MOUSEWHEEL=0x20a,
    WM_XBUTTONDOWN=0x20b, WM_XBUTTONUP=0x20c, WM_MOUSEHWHEEL=0x20e,
    MOUSEEVENTF_MOVE=1, MOUSEEVENTF_LEFTDOWN=2, MOUSEEVENTF_LEFTUP=4,
    MOUSEEVENTF_RIGHTDOWN=8, MOUSEEVENTF_RIGHTUP=16,
    MOUSEEVENTF_MIDDLEDOWN=32, MOUSEEVENTF_MIDDLEUP=64,
    MOUSEEVENTF_WHEEL=0x800, MOUSEEVENTF_ABSOLUTE=0x8000,
    KEYEVENTF_EXTENDEDKEY=1, KEYEVENTF_KEYUP=2,
    VK_LBUTTON=1, VK_RBUTTON=2, VK_MBUTTON=4, VK_XBUTTON1=5, VK_XBUTTON2=6,
    VK_SHIFT=16, VK_CONTROL=17, VK_MENU=18,
    VK_LSHIFT=160, VK_RSHIFT=161, VK_LCONTROL=162, VK_RCONTROL=163,
    VK_LMENU=164, VK_RMENU=165, XBUTTON1=1, XBUTTON2=2,
    QS_KEY=1, QS_MOUSEMOVE=2, QS_MOUSEBUTTON=4, QS_SENDMESSAGE=8, QS_SMRESULT=16,
    MK_LBUTTON=1, MK_RBUTTON=2, MK_SHIFT=4, MK_CONTROL=8, MK_MBUTTON=16,
    MK_XBUTTON1=32, MK_XBUTTON2=64, KF_ALTDOWN=0x2000, KF_EXTENDED=0x100,
    RIDEV_NOLEGACY=0x30, LLMHF_INJECTED=1
};
#define STATUS_INVALID_PARAMETER 0xc000000du
#define STATUS_ACCESS_DENIED 0xc0000022u
#define STATUS_NO_MEMORY 0xc0000017u
#define STATUS_TIMEOUT 0x00000102u
#define TIMEOUT_INFINITE INT64_MAX

struct process;
struct thread;
struct desktop;
struct window;
union hw_input {
    struct {
        unsigned int type;
        int x, y;
        unsigned int data, flags, time, raw_count;
        lparam_t info;
    } mouse;
    struct { unsigned int type, vkey, scan, flags; } kbd;
};
#include "pw_focus_adapter.h"

struct object { unsigned int refs; };
struct list { struct list *next, *prev; };
struct timeout_user { void (*callback)(void *); void *arg; };
struct hw_msg_source { unsigned int device, origin; };
struct hardware_msg_data {
    lparam_t info;
    data_size_t size;
    struct hw_msg_source source;
    unsigned int flags;
};
struct callback_msg_data { lparam_t result; };
typedef struct {
    unsigned char keystate[256];
    uint64_t keystate_serial;
    struct { int x, y; unsigned int last_change; } cursor;
} desktop_shm_t;
typedef struct {
    unsigned char keystate[256];
    user_handle_t capture;
} input_shm_t;
struct thread_input {
    input_shm_t *shared;
    struct list msg_list;
    uint64_t user_time;
};
struct msg_queue {
    struct list msg_list[1], send_result, callback_result;
    struct thread_input *input;
};
struct process { struct object obj; };
struct thread { struct object obj; struct process *process; struct msg_queue *queue; };
struct window { struct object obj; };
struct desktop {
    struct object obj;
    desktop_shm_t *shared;
    struct thread_input *foreground_input;
    struct { struct pw_focus_timer_tag focus; } key_repeat;
};
struct message_result;
struct message {
    struct list entry;
    unsigned int type, msg, time, unique_id;
    user_handle_t win;
    lparam_t wparam, lparam;
    int x, y;
    void *data;
    data_size_t data_size;
    struct message_result *result;
    struct pw_focus_tag focus;
};
struct message_result {
    struct list sender_entry;
    struct msg_queue *sender, *receiver;
    struct message *msg, *hardware_msg, *callback_msg;
    struct timeout_user *timeout;
    struct desktop *desktop;
    struct message_result *recv_next;
    void *data;
    data_size_t data_size;
    lparam_t result;
    unsigned int error, replied;
};
struct rawinput { unsigned int unused; };
typedef struct { unsigned int unused; } RAWMOUSE;
struct rawinput_message {
    struct thread *foreground;
    struct hw_msg_source source;
    unsigned int time, message, flags;
    struct rawinput rawinput;
    union { RAWMOUSE mouse; } data;
};

#define SHARED_WRITE_BEGIN(object,type) do { type *shared = (object);
#define SHARED_WRITE_END } while (0)
static void list_init(struct list *list) { list->next=list->prev=list; }
static int list_empty(const struct list *list) { return list->next == list; }
static struct list *list_head(struct list *list) { return list_empty(list) ? NULL : list->next; }
static void list_add_tail(struct list *list, struct list *entry) {
    entry->prev=list->prev; entry->next=list; list->prev->next=entry; list->prev=entry;
}
static void list_add_head(struct list *list, struct list *entry) {
    entry->next=list->next; entry->prev=list; list->next->prev=entry; list->next=entry;
}
static void list_remove(struct list *entry) {
    entry->prev->next=entry->next; entry->next->prev=entry->prev; list_init(entry);
}
static void *grab_object(void *ptr) {
    struct object *object=ptr; assert(object && object->refs); ++object->refs; return ptr;
}
static void release_object(void *ptr) {
    struct object *object=ptr; assert(object && object->refs > 1); --object->refs;
}

PwFocusCore pw_focus_server_core;
static PwFocusTicket focus_submissions[PW_FOCUS_CONTEXTS][PW_FOCUS_OPS];
static uint64_t monotonic_time=100, now_ms=100;
static unsigned int last_input_time, status_, allocations, fail_alloc, timeout_fail;
static unsigned int hook_enabled, hook_hung, repeat_stops, error_writes, keyboard_calls;
static unsigned int raw_calls, clock_ok=1, permit_ok_=1, window_live_=1;
static data_size_t req_bytes;
static struct process process_;
static struct window window_;
static struct desktop desktop_;
static desktop_shm_t shared_;
static struct msg_queue hook_queue_;
static struct thread hook_thread_, consumer_;
static struct thread *current=&consumer_;
static uint32_t slot_;
static uint64_t cookie_, epoch_=1;
static PwFocusIdentity identity_={7,0,42,43,PW_FOCUS_ROOT};
static struct focus_registration { struct thread *consumer; } focus_registrations[PW_FOCUS_CONTEXTS];
enum { FOCUS_STARTED=3 };
static atomic_uint focus_install_state;
static struct timeout_user *focus_watchdog;

static void set_error(unsigned int error) { status_=error; ++error_writes; }
static unsigned int get_error(void) { return status_; }
static data_size_t get_req_data_size(void) { return req_bytes; }
static const void *get_req_data(void) { assert(!"raw samples are out of scope"); return NULL; }
static unsigned int get_tick_count(void) { return (unsigned int)now_ms; }
static void *mem_alloc(size_t bytes) {
    if (++allocations == fail_alloc) { set_error(STATUS_NO_MEMORY); return NULL; }
    return calloc(1,bytes);
}
static void *memdup(const void *source, size_t bytes) {
    void *result=mem_alloc(bytes); if (result) memcpy(result,source,bytes); return result;
}
static struct timeout_user *add_timeout_user(timeout_t timeout, void (*callback)(void *), void *arg) {
    struct timeout_user *result;
    assert(timeout < 0);
    if (timeout_fail) return NULL;
    result=calloc(1,sizeof(*result)); assert(result);
    result->callback=callback; result->arg=arg; return result;
}
static void remove_timeout_user(struct timeout_user *timeout) { assert(timeout); free(timeout); }
static void set_queue_bits(struct msg_queue *queue, unsigned int bits) { (void)queue; (void)bits; }
static void clear_queue_bits(struct msg_queue *queue, unsigned int bits) { (void)queue; (void)bits; }
static void stop_key_repeat(struct desktop *desktop) {
    ++repeat_stops;
    assert(!desktop->key_repeat.focus.active && !"mouse must not own a repeat timer");
}
int pw_focus_requests_clock(uint64_t *out) {
    if (!clock_ok) {
        for (unsigned int n=0;n<PW_FOCUS_CONTEXTS;++n) {
            PwFocusContext *x=&pw_focus_server_core.contexts[n];
            if (x->cookie) pw_focus_queue_abandon(n,x->cookie,x->epoch);
        }
        return 0;
    }
    *out=now_ms; return 1;
}
static struct thread *get_first_global_hook(struct desktop *desktop, int id) {
    assert(desktop==&desktop_ && id==WH_MOUSE_LL);
    return hook_enabled ? &hook_thread_ : NULL;
}
static int is_queue_hung(struct msg_queue *queue) { assert(queue==&hook_queue_); return hook_hung; }
static struct thread *get_window_thread(user_handle_t win) { (void)win; return NULL; }
static struct thread *get_foreground_thread(struct desktop *desktop, user_handle_t win) {
    (void)desktop; (void)win; return NULL;
}
static void set_window_rect_visible(user_handle_t win, struct rectangle rect) {
    (void)win; (void)rect; assert(!"motion should have been refused");
}
static bool rawmouse_init(struct rawinput *input, RAWMOUSE *mouse, int x, int y,
                          unsigned int flags, unsigned int data, lparam_t info) {
    (void)input; (void)mouse; (void)x; (void)y; (void)flags; (void)data; (void)info;
    return true;
}
static void dispatch_rawinput_message(struct desktop *desktop, struct rawinput_message *msg) {
    (void)desktop; (void)msg; ++raw_calls;
}
static user_handle_t get_user_full_handle(user_handle_t win) { return win; }
static unsigned int get_hardware_msg_bit(unsigned int msg) {
    if (msg==WM_MOUSEMOVE) return QS_MOUSEMOVE;
    if (msg>=WM_LBUTTONDOWN && msg<=WM_MOUSEHWHEEL) return QS_MOUSEBUTTON;
    return QS_KEY;
}
static int queue_hotkey_message(struct desktop *desktop, struct message *msg) {
    (void)desktop; (void)msg; assert(!"keyboard routing is not covered by this fixture"); return 0;
}
static void prepend_cursor_history(int x, int y, unsigned int time, lparam_t info) {
    (void)x; (void)y; (void)time; (void)info; assert(!"unexpected motion");
}
static int update_desktop_cursor_pos(struct desktop *desktop, user_handle_t win, int x, int y) {
    (void)win; assert(x==desktop->shared->cursor.x && y==desktop->shared->cursor.y); return 0;
}
static user_handle_t find_hardware_message_window(struct desktop *desktop, struct thread_input *input,
    struct message *msg, unsigned int *code, struct thread **thread) {
    (void)desktop; (void)input; *code=msg->msg; *thread=NULL;
    return 0; /* Deliberate no-target fixture: desktop mutation precedes delivery. */
}
static int get_rawinput_device_flags(struct process *process, struct message *msg) {
    (void)process; (void)msg; return 0;
}
static int merge_message(struct thread_input *input, struct message *msg) {
    (void)input; (void)msg; assert(!"application queueing not covered"); return 0;
}

/* Forward declarations for the real mutually recursive source bodies. */
static void free_message(struct message *);
static void queue_hardware_message(struct desktop *, struct message *, int);
static void store_message_result(struct message_result *, lparam_t, unsigned int);
static void focus_retire(unsigned int);
static void remove_queue_message(struct msg_queue *queue, struct message *msg, int kind) {
    assert(queue==&hook_queue_ && kind==SEND_MESSAGE);
    list_remove(&msg->entry); free_message(msg);
}
static void focus_refuse(unsigned int);
static int focus_header(unsigned int abi) {
    if (abi!=PW_FOCUS_ABI || req_bytes) { focus_refuse(STATUS_INVALID_PARAMETER); return 0; }
    return 1;
}
int pw_focus_queue_keyboard(const PwFocusTicket *ticket, struct desktop *desktop,
                           user_handle_t win, const union hw_input *input) {
    (void)ticket; (void)desktop; (void)win; (void)input; ++keyboard_calls; return PW_FOCUS_REFUSED;
}

/* Request structures are host-shaped mocks: wire size/offsets are not claimed. */
struct focus_input_request {
    unsigned int abi, slot, type;
    uint64_t cookie, epoch, client_sequence;
    unsigned int code, x, y, down;
};
struct focus_input_reply { unsigned int unused; };
struct focus_control_request {
    unsigned int abi, opcode, slot;
    uint64_t cookie, epoch, sequence, client_sequence, reserved;
};
struct focus_control_reply {
    unsigned int abi, phase_disposition;
    uint64_t cookie, epoch, sequence, client_sequence, desktop_serial;
    unsigned int key_edge, hook_error;
};
#define DECL_HANDLER(name) static void req_##name(const struct name##_request *req, struct name##_reply *reply)
#include "actual_mouse_functions.inc"

static int permit(void *opaque, void *object, PwFocusPermit *out) {
    (void)opaque;
    if (!permit_ok_ || object!=&process_) return -1;
    *out=(PwFocusPermit){identity_,epoch_,100000,&process_,0,1}; return 0;
}
static void *pin(void *opaque, void *object) { (void)opaque; return grab_object(object); }
static void unpin(void *opaque, void *object) { (void)opaque; release_object(object); }
static int live(void *opaque, void *process, void *desktop, void *window, uint64_t handle, uint64_t gen) {
    (void)opaque;
    return window_live_ && process==&process_ && desktop==&desktop_ &&
        window==&window_ && handle==99 && gen==4;
}
static PwFocusContext *context(void) { return &pw_focus_server_core.contexts[slot_]; }
static void invariants(void) {
    assert(pw_focus_invariants(&pw_focus_server_core));
    assert(!context()->timer && !desktop_.key_repeat.focus.active && repeat_stops==0);
}
static void reset(void) {
    memset(&pw_focus_server_core,0,sizeof(pw_focus_server_core));
    memset(focus_submissions,0,sizeof(focus_submissions));
    memset(focus_registrations,0,sizeof(focus_registrations));
    memset(&desktop_,0,sizeof(desktop_)); memset(&shared_,0,sizeof(shared_));
    memset(&hook_queue_,0,sizeof(hook_queue_));
    process_.obj.refs=window_.obj.refs=desktop_.obj.refs=consumer_.obj.refs=hook_thread_.obj.refs=1;
    desktop_.shared=&shared_; shared_.cursor.x=123; shared_.cursor.y=456;
    hook_thread_.queue=&hook_queue_; consumer_.process=&process_;
    list_init(&hook_queue_.msg_list[0]); list_init(&hook_queue_.send_result); list_init(&hook_queue_.callback_result);
    status_=allocations=fail_alloc=timeout_fail=hook_enabled=hook_hung=repeat_stops=error_writes=0;
    keyboard_calls=raw_calls=0; clock_ok=permit_ok_=window_live_=1;
    req_bytes=0; epoch_=1; now_ms=monotonic_time=100; focus_watchdog=NULL;
    atomic_store(&focus_install_state,FOCUS_STARTED);
    PwFocusCallbacks callbacks={NULL,permit,pin,unpin,live};
    PwFocusServerFacts facts={&process_,0,42,43,0};
    assert(!pw_focus_init(&pw_focus_server_core,&callbacks));
    assert(!pw_focus_open(&pw_focus_server_core,&identity_,epoch_,&facts,&desktop_,&window_,
                          99,4,now_ms,&slot_,&cookie_));
    focus_registrations[slot_].consumer=grab_object(current);
    invariants();
}
static void cleanup(void) {
    assert(list_empty(&hook_queue_.msg_list[0]));
    pw_focus_queue_abandon(slot_,cookie_,epoch_);
    if (focus_registrations[slot_].consumer) focus_retire(slot_);
    invariants();
    assert(context()->refs==0);
    assert(process_.obj.refs==1 && window_.obj.refs==1 && desktop_.obj.refs==1);
    assert(consumer_.obj.refs==1 && hook_thread_.obj.refs==1);
}
static struct focus_input_request input_request(unsigned int code, unsigned int down, uint64_t seq) {
    return (struct focus_input_request){PW_FOCUS_ABI,slot_,PW_FOCUS_MOUSE_BUTTON,cookie_,epoch_,seq,code,0,0,down};
}
static void request_input(struct focus_input_request request) {
    struct focus_input_reply reply={0}; status_=0; req_focus_input(&request,&reply); invariants();
}
static struct focus_control_reply control(unsigned int opcode, uint64_t sequence, uint64_t client_seq) {
    struct focus_control_request request={PW_FOCUS_ABI,opcode,slot_,cookie_,epoch_,sequence,client_seq,0};
    struct focus_control_reply reply={0};
    status_=0; req_focus_control(&request,&reply); invariants(); return reply;
}
static PwFocusReceipt receipt(void) {
    PwFocusReceipt result; PwFocusPhase phase;
    assert(!pw_focus_queue_poll(slot_,cookie_,epoch_,&result,&phase));
    assert(result.ticket.seq && phase==context()->phase); return result;
}
static void ack(void) {
    PwFocusReceipt result=receipt();
    struct focus_control_reply reply=control(PW_FOCUS_ACK_RESULT,result.ticket.seq,result.client_seq);
    assert(!status_ && reply.abi==PW_FOCUS_ABI && !context()->normal_result);
}
static union hw_input mouse_input(unsigned int code, unsigned int down) {
    const unsigned int flags[3][2]={{4,2},{16,8},{64,32}};
    union hw_input input={0}; assert(code<3 && down<2);
    input.mouse.type=INPUT_MOUSE; input.mouse.flags=flags[code][down]; return input;
}
static PwFocusTicket reserve(unsigned int code, unsigned int down, uint64_t seq) {
    PwFocusTicket ticket;
    assert(!pw_focus_queue_begin(slot_,cookie_,epoch_,seq,256+code,down,&ticket)); return ticket;
}
static void finish_hook(lparam_t result, unsigned int error) {
    struct list *entry=list_head(&hook_queue_.msg_list[0]); assert(entry);
    struct message *message=(struct message *)((char *)entry - offsetof(struct message,entry));
    struct message_result *retained=message->result; assert(retained && retained->hardware_msg);
    /* Model receipt of the hook message; all completion is the actual result
       function below. Free only the consumed hook envelope, not its hardware. */
    list_remove(entry); message->result=NULL; retained->msg=NULL; retained->receiver=NULL;
    free_message(message);
    store_message_result(retained,result,error);
    invariants(); assert(list_empty(&hook_queue_.msg_list[0]));
}
static void check_outcome(unsigned int outcome, unsigned int error, unsigned int held, uint64_t serial) {
    PwFocusReceipt result=receipt();
    assert(result.outcome==outcome && result.hook_error==error);
    assert(result.desktop_serial==serial && context()->held[256]==held);
    assert(shared_.keystate_serial==serial);
    invariants();
}
static void clean_lifecycle(unsigned int button, int hook) {
    reset(); hook_enabled=(unsigned int)hook;
    request_input(input_request(button,1,1)); assert(!status_);
    assert(context()->outstanding==(unsigned int)hook);
    assert(!pw_focus_queue_quiesce(slot_,cookie_,epoch_));
    assert(context()->phase==PW_FOCUS_DRAINING);
    assert(pw_focus_queue_settle(slot_,cookie_,epoch_)==PW_FOCUS_REFUSED);
    if (hook) finish_hook(0,0);
    struct focus_control_reply reply=control(PW_FOCUS_POLL,0,0);
    assert(!status_ && reply.key_edge==(256+button+(1u<<16)) && reply.desktop_serial==1);
    PwFocusTicket old=receipt().ticket, stale=old; ++stale.seq;
    assert(pw_focus_queue_ack(&stale)==PW_FOCUS_BAD_ID);
    ack(); assert(context()->phase==PW_FOCUS_RELEASE_READY);
    assert(pw_focus_queue_ack(&old)==PW_FOCUS_BAD_ID);
    assert(pw_focus_queue_settle(slot_,cookie_,epoch_)==PW_FOCUS_REFUSED); /* still held */
    request_input(input_request(button,0,2)); assert(!status_);
    assert(context()->phase==PW_FOCUS_RELEASING);
    assert(pw_focus_queue_settle(slot_,cookie_,epoch_)==PW_FOCUS_REFUSED);
    if (hook) finish_hook(0,0);
    reply=control(PW_FOCUS_POLL,0,0);
    assert(!status_ && reply.key_edge==256+button && reply.desktop_serial==2);
    assert(context()->held[256+button]==0 && context()->phase==PW_FOCUS_RELEASING);
    ack(); reply=control(PW_FOCUS_SETTLE,0,2);
    assert(!status_ && context()->phase==PW_FOCUS_SETTLED && reply.client_sequence==2 && reply.sequence==2);
    reply=control(PW_FOCUS_CLOSE,0,0); assert(!status_ && context()->phase==PW_FOCUS_CLOSED);
    cleanup();
}
static void rejected_hook(void) {
    reset(); hook_enabled=1; request_input(input_request(0,1,1)); finish_hook(1,0);
    check_outcome(PW_FOCUS_SUPPRESSED,0,0,0);
    assert(context()->phase==PW_FOCUS_POISONED);
    ack(); assert(pw_focus_queue_settle(slot_,cookie_,epoch_)==PW_FOCUS_REFUSED); cleanup();
}
static void error_hooks(void) {
    for (unsigned int result=0;result<2;++result) {
        reset(); hook_enabled=1; request_input(input_request(0,1,1));
        finish_hook(result,STATUS_TIMEOUT);
        check_outcome(PW_FOCUS_APPLIED_EXCEPTION,STATUS_TIMEOUT,1,1);
        assert(context()->phase==PW_FOCUS_POISONED);
        ack(); assert(pw_focus_queue_settle(slot_,cookie_,epoch_)==PW_FOCUS_REFUSED); cleanup();
    }
}
static void actual_hook_timeout(void) {
    reset(); hook_enabled=1; request_input(input_request(0,1,1));
    struct list *entry=list_head(&hook_queue_.msg_list[0]); assert(entry);
    struct message *message=(struct message *)((char *)entry - offsetof(struct message,entry));
    struct message_result *result=message->result; assert(result && result->timeout);
    struct timeout_user *timer=result->timeout;
    void (*callback)(void *)=timer->callback;
    void *arg=timer->arg;
    assert(callback==result_timeout && arg==result);
    /* The scheduler removes its expired timer allocation before invoking the
       unchanged timeout callback; that callback removes the still-queued hook
       envelope and applies the hardware edge through the actual result path. */
    free(timer); callback(arg);
    assert(list_empty(&hook_queue_.msg_list[0]));
    check_outcome(PW_FOCUS_APPLIED_EXCEPTION,STATUS_TIMEOUT,1,1);
    assert(context()->outstanding==0 && context()->phase==PW_FOCUS_POISONED);
    ack(); cleanup();
}
static void untracked_wrapper(void) {
    reset();
    union hw_input input=mouse_input(0,1);
    assert(!queue_mouse_message(&desktop_,99,&input,IMO_HARDWARE,NULL,false));
    assert(shared_.keystate_serial==1 && (shared_.keystate[VK_LBUTTON]&0x80));
    assert(context()->issued==0 && context()->outstanding==0 && !context()->held[256]);
    assert(!context()->normal_result && !context()->timer);
    cleanup();
}
static void allocation_failures(void) {
    for (unsigned int at=1;at<=5;++at) {
        reset(); hook_enabled=1; fail_alloc=at;
        PwFocusTicket ticket=reserve(0,1,1); union hw_input input=mouse_input(0,1);
        assert(!pw_focus_queue_mouse_button(&ticket,&desktop_,99,&input));
        assert(allocations==at && context()->outstanding==0);
        if (at<=2) check_outcome(PW_FOCUS_FAILED,STATUS_NO_MEMORY,0,0);
        else check_outcome(PW_FOCUS_APPLIED_EXCEPTION,STATUS_NO_MEMORY,1,1);
        assert(pw_focus_complete(&pw_focus_server_core,&ticket,PW_FOCUS_FAILED,0,0)==PW_FOCUS_BAD_ID);
        ack(); cleanup();
    }
}
static void missing_timeout(void) {
    reset(); hook_enabled=timeout_fail=1;
    request_input(input_request(0,1,1));
    assert(context()->registry==0 && context()->outstanding==1 && context()->refs==1);
    assert(context()->normal_result==0 && shared_.keystate_serial==0);
    finish_hook(0,0);
    assert(context()->refs==0 && context()->outstanding==0 && context()->normal_result==0);
    assert(shared_.keystate_serial==1 && pw_focus_queue_settle(slot_,cookie_,epoch_)!=0);
    cleanup();
}
static void cancellation(void) {
    reset(); PwFocusTicket ticket=reserve(0,1,1);
    pw_focus_queue_abandon(slot_,cookie_,epoch_);
    assert(context()->refs==0 && !context()->outstanding);
    assert(pw_focus_complete(&pw_focus_server_core,&ticket,PW_FOCUS_FAILED,0,0)==PW_FOCUS_BAD_ID);
    cleanup();
    reset(); hook_enabled=1; request_input(input_request(0,1,1));
    pw_focus_queue_abandon(slot_,cookie_,epoch_);
    assert(context()->registry==0 && context()->outstanding==1 && context()->refs==1);
    pw_focus_queue_abandon(slot_,cookie_,epoch_); /* repeated cancellation keeps the claim */
    finish_hook(1,0); assert(context()->refs==0 && !context()->outstanding); cleanup();
}
static void clock_and_revocation(void) {
    for (unsigned int why=0;why<4;++why) {
        reset(); PwFocusTicket ticket=reserve(0,1,1); union hw_input input=mouse_input(0,1);
        if (why==0) clock_ok=0;
        if (why==1) permit_ok_=0;
        if (why==2) window_live_=0;
        if (why==3) now_ms=6100;
        assert(pw_focus_queue_mouse_button(&ticket,&desktop_,99,&input)==PW_FOCUS_REFUSED);
        assert(!context()->registry && !context()->outstanding && context()->refs==0);
        assert(allocations==0 && shared_.keystate_serial==0);
        assert(pw_focus_complete(&pw_focus_server_core,&ticket,PW_FOCUS_FAILED,0,0)==PW_FOCUS_BAD_ID);
        clock_ok=1; cleanup();
    }
}
static void malformed_requests(void) {
    for (unsigned int test=0;test<8;++test) {
        reset(); struct focus_input_request request=input_request(0,1,1);
        if (test==0) request.code=3;
        if (test==1) request.code=UINT32_MAX;
        if (test==2) request.down=2;
        if (test==3) request.x=1;
        if (test==4) request.y=1;
        if (test==5) request.type=3; /* motion deliberately unsupported */
        if (test==6) request.client_sequence=2;
        if (test==7) request.cookie++;
        request_input(request);
        assert(status_==STATUS_INVALID_PARAMETER && error_writes==1);
        assert(!context()->outstanding && allocations==0 && shared_.keystate_serial==0);
        assert(!keyboard_calls && !repeat_stops); cleanup();
    }
}
static void malformed_adapter_inputs(void) {
    for (unsigned int test=0;test<11;++test) {
        reset(); PwFocusTicket ticket=reserve(0,1,1); union hw_input input=mouse_input(0,1);
        if (test==0) input.mouse.flags|=MOUSEEVENTF_RIGHTDOWN;
        if (test==1) input.mouse.flags=MOUSEEVENTF_MOVE;
        if (test==2) input.mouse.flags=MOUSEEVENTF_WHEEL;
        if (test==3) input.mouse.flags=MOUSEEVENTF_LEFTUP;
        if (test==4) input.mouse.x=1;
        if (test==5) input.mouse.y=1;
        if (test==6) input.mouse.raw_count=1;
        if (test==7) input.mouse.data=1;
        if (test==8) input.mouse.info=1;
        if (test==9) input.mouse.time=1;
        if (test==10) input.mouse.type=INPUT_KEYBOARD;
        assert(!pw_focus_queue_mouse_button(&ticket,&desktop_,99,&input));
        check_outcome(PW_FOCUS_FAILED,STATUS_INVALID_PARAMETER,0,0);
        assert(allocations==0 && raw_calls==0 && shared_.cursor.last_change==0);
        ack(); cleanup();
    }
}
static void stale_and_duplicate_submission(void) {
    reset(); hook_enabled=1;
    PwFocusTicket ticket=reserve(0,1,1), bad=ticket; union hw_input input=mouse_input(0,1);
    ++bad.epoch; assert(pw_focus_queue_mouse_button(&bad,&desktop_,99,&input)==PW_FOCUS_BAD_ID);
    bad=ticket; ++bad.cookie;
    assert(pw_focus_queue_mouse_button(&bad,&desktop_,99,&input)==PW_FOCUS_BAD_ID);
    assert(!pw_focus_queue_mouse_button(&ticket,&desktop_,99,&input));
    unsigned int before=allocations;
    assert(pw_focus_queue_mouse_button(&ticket,&desktop_,99,&input)==PW_FOCUS_BAD_ID);
    assert(allocations==before && context()->outstanding==1);
    finish_hook(0,0); check_outcome(PW_FOCUS_CLEAN,0,1,1); ack(); cleanup();
}
int main(void) {
    _Static_assert(PW_FOCUS_MOUSE_BUTTON==2,"mouse wire type");
    _Static_assert(PW_FOCUS_KEYS==259,"button ownership range");
    for (unsigned int button=0;button<3;++button)
        for (int hook=0;hook<2;++hook) clean_lifecycle(button,hook);
    rejected_hook(); error_hooks(); actual_hook_timeout(); untracked_wrapper();
    allocation_failures(); missing_timeout();
    cancellation(); clock_and_revocation(); malformed_requests();
    malformed_adapter_inputs(); stale_and_duplicate_submission();
    puts("mouse: actual core, INPUT/CONTROL, single-transfer, hook/completion, held/ACK/settle and refusal controls passed");
    return 0;
}
