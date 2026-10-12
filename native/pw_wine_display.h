/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_WINE_DISPLAY_H
#define PW_WINE_DISPLAY_H
/*
 * The title's side of Wine's PS5 user driver (wine/ps5/pw_wine_sink.h).
 *
 * win32u hands each frame to the present sink on one of Wine's threads. The
 * sink only copies it into a PwWineFrameBox; the title's own thread takes the
 * newest frame and shows it, so the display backend never runs on a Wine
 * thread and a slow flip never stalls Wine. The same thread reads the pad and
 * turns it into Wine input with the game profile's bindings: buttons send
 * keys or mouse buttons, and a stick can move the pointer. In xinput mode it
 * also becomes the game's XInput controller (the sink's gamepad slot).
 */
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include "../src/pw_present.h"
#include "../src/pw_game_profile.h"
#include "../src/pw_script_input.h"
#include "../wine/ps5/pw_wine_sink.h"
#include "pw_pad_ps5.h"

typedef struct PwWineFrameBox {
    pthread_mutex_t lock;
    uint8_t *pixels;              /* the caller's storage; rows packed, width * 4 bytes */
    size_t capacity;
    uint32_t width, height;
    uint64_t sequence;            /* frames put */
    uint64_t rejected;            /* too large, or invalid */
} PwWineFrameBox;

/* A box keeping frames of at most bytes (width * height * 4) in storage,
 * which the caller owns: a title's libc heap is too small for frames, so it
 * lends static memory. 0, or -1. */
int pw_wine_frame_box_init(PwWineFrameBox *box, uint8_t *storage, size_t bytes);
void pw_wine_frame_box_destroy(PwWineFrameBox *box);
/* Keep a copy of a BGRA frame, top-down, stride in bytes. 0, or -1 when it
 * is invalid or larger than the box. */
int pw_wine_frame_box_put(PwWineFrameBox *box, const void *bgra, uint32_t width,
                          uint32_t height, uint32_t stride);
/* When a frame newer than *seen was put, copy it into out (at most
 * capacity bytes), describe it in view, update *seen and return 1; 0 when
 * there is nothing new, -1 when out is too small. */
int pw_wine_frame_box_take(PwWineFrameBox *box, uint64_t *seen, uint8_t *out,
                           size_t capacity, PwPresentView *view);

/* Wine input for one pad batch's edges under a profile's bindings: a
 * release for each bound button in released, then a press for each in
 * pressed, as a key or a mouse button. Returns how many were written (at
 * most max). */
size_t pw_wine_game_inputs(const PwGameInput *input, uint32_t pressed, uint32_t released,
                           PwWineInput *out, size_t max);

/* The DualSense as an XInput gamepad: its held buttons (Cross A, Circle B,
 * Square X, Triangle Y, L1/R1 shoulders, L3/R3 thumbs, Options Start,
 * Create Back, the touchpad Guide), the analog triggers, and the sticks
 * scaled to -32768..32767 with y up. 1 and the state in out while the pad
 * is connected; 0 and a neutral state otherwise. The sink numbers the
 * packets. */
int pw_wine_game_pad(const PwPadPs5 *pad, PwWinePad *out);

/* A script build's scripted controller (src/pw_script_input.h) added to
 * the real one in pad, which pw_wine_game_pad filled (connected says
 * whether it is): the scripted buttons join the held ones, and each stick
 * the script holds off centre takes the real stick's place. With scripted
 * set (the macro drives a controller), controller 0 stays connected
 * without a DualSense. Returns whether it is connected; a neutral pad
 * when not. */
int pw_wine_script_pad(PwWinePad *pad, int connected, const PwScriptPad *script, int scripted);

/* A stick's pointer motion not yet sent, in 1/65536 pixels. Wine keeps
 * the pointer's position: the title sends only motion, as a mouse does
 * (patch 0670), so a game can move or clip the pointer itself and motion
 * against an edge still reaches it. */
typedef struct PwWinePointer {
    int64_t x, y;
} PwWinePointer;

enum { PW_WINE_POINTER_DEADZONE = PW_GAME_MOUSE_DEADZONE_DEFAULT };

/* Move by a stick position (0..255 each axis, 0x80 centred) held for
 * elapsed_us, at up to speed pixels per second at full tilt, on a squared
 * curve past the dead zone. 1 and a MOUSE_MOVE of the whole pixels moved
 * in out when there are any (the fraction is kept for the next step),
 * else 0. */
int pw_wine_pointer_step(PwWinePointer *pointer, uint8_t stick_x, uint8_t stick_y,
                         uint32_t speed, uint32_t elapsed_us, PwWineInput *out);
/* Same motion curve, with a validated profile deadzone (0..120 of 128).
 * Out-of-range deadzones use 20; speed is capped at the profile maximum. */
int pw_wine_pointer_step_configured(PwWinePointer *, uint8_t, uint8_t, uint32_t speed,
                                    uint32_t deadzone, uint32_t elapsed_us, PwWineInput *);
/* Exclusive controller routing. The caller passes title focus (ScePad
 * interception also disconnects the pad), and publishes the returned gamepad
 * every tick, including its neutral/disconnected state. Capacity must be at
 * least PW_WINE_ROUTED_EVENTS; otherwise no state is changed.
 * L3+R3 switches between profile/game and mouse/UI. The chord is reserved.
 * Mouse/UI: left stick or one-finger relative touch; Cross left, Circle right.
 * mode_name is a UI/status hook; this does not emulate a Sony HID device. */
enum { PW_WINE_ROUTED_EVENTS = 2 * PW_GAME_BUTTON_COUNT + 2,
       PW_WINE_INPUT_STALE_US = 250000 };
typedef struct PwWineInputRouter {
    PwWinePointer pointer;
    uint64_t serial,discontinuities,touch_epoch;
    uint32_t stale_us,held,blocked;
    unsigned mouse_mode,chord_latched,active,generation_valid;
    unsigned analog_blocked,touch_valid,cycle_armed;
    uint8_t generation,finger;
    uint16_t touch_x,touch_y;
} PwWineInputRouter;
/* Once per launch, before any input is delivered. Reinitializing a live router
 * would discard held releases; runtime toggles continue through route_input. */
void pw_wine_input_router_init(PwWineInputRouter *, const PwGameInput *);
const char *pw_wine_input_mode_name(const PwWineInputRouter *,const PwGameInput *);
size_t pw_wine_route_input(PwWineInputRouter *,const PwGameInput *,const PwPadPs5 *,
                           int focused,uint32_t elapsed_us,PwWineInput *,size_t,
                           PwWinePad *);
/* A single bounded batch with per-event acknowledgement. Flush pending
 * events before routing another batch; a refused release is never forgotten
 * and accepted presses are never retried. */
typedef struct PwWineInputDelivery {
    PwWineInput events[PW_WINE_ROUTED_EVENTS];
    size_t count,next;
} PwWineInputDelivery;
size_t pw_wine_input_flush(PwWineInputDelivery *,int (*post)(const PwWineInput *));
uint64_t pw_wine_close_chord_tick(const PwWineInputRouter *,const PwPadPs5 *,
                                 int fresh,uint64_t ticks);
#endif
