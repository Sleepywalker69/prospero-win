/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_wine_display.h"
#include <string.h>

int pw_wine_frame_box_init(PwWineFrameBox *box, uint8_t *storage, size_t bytes)
{
    if (!box || !storage || !bytes) return -1;
    memset(box, 0, sizeof(*box));
    if (pthread_mutex_init(&box->lock, NULL)) return -1;
    box->pixels = storage;
    box->capacity = bytes;
    return 0;
}

void pw_wine_frame_box_destroy(PwWineFrameBox *box)
{
    if (!box || !box->pixels) return;
    pthread_mutex_destroy(&box->lock);
    box->pixels = NULL;
}

int pw_wine_frame_box_put(PwWineFrameBox *box, const void *bgra, uint32_t width,
                          uint32_t height, uint32_t stride)
{
    size_t row, bytes;

    if (!box || !box->pixels) return -1;
    row = (size_t)width * 4u;
    bytes = row * height;
    pthread_mutex_lock(&box->lock);
    if (!bgra || !width || !height || stride < row || bytes / height != row ||
        bytes > box->capacity) {
        box->rejected++;
        pthread_mutex_unlock(&box->lock);
        return -1;
    }
    for (uint32_t y = 0; y < height; y++)
        memcpy(box->pixels + y * row, (const uint8_t *)bgra + (size_t)y * stride, row);
    box->width = width;
    box->height = height;
    box->sequence++;
    pthread_mutex_unlock(&box->lock);
    return 0;
}

int pw_wine_frame_box_take(PwWineFrameBox *box, uint64_t *seen, uint8_t *out,
                           size_t capacity, PwPresentView *view)
{
    size_t bytes;
    int status = 0;

    if (!box || !box->pixels || !seen || !out || !view) return -1;
    pthread_mutex_lock(&box->lock);
    if (box->sequence != *seen) {
        bytes = (size_t)box->width * 4u * box->height;
        if (bytes > capacity) status = -1;
        else {
            memcpy(out, box->pixels, bytes);
            view->pixels = out;
            view->width = box->width;
            view->height = box->height;
            view->stride = box->width * 4u;
            view->bytes = (uint32_t)bytes;
            *seen = box->sequence;
            status = 1;
        }
    }
    pthread_mutex_unlock(&box->lock);
    return status;
}

static size_t add_edges(const PwGameInput *input, uint32_t edges, uint32_t down,
                        PwWineInput *out, size_t used, size_t max)
{
    for (size_t i = 0; i < PW_GAME_BUTTON_COUNT && used < max; i++) {
        const PwGameBinding *b = &input->bindings[i];
        if (!(edges & b->mask) || (b->kind != PW_GAME_BIND_KEY && b->kind != PW_GAME_BIND_MOUSE))
            continue;
        out[used].type = b->kind == PW_GAME_BIND_KEY ? PW_WINE_INPUT_KEY : PW_WINE_INPUT_MOUSE_BUTTON;
        out[used].code = b->code;
        out[used].x = out[used].y = 0;
        out[used].down = down;
        used++;
    }
    return used;
}

size_t pw_wine_game_inputs(const PwGameInput *input, uint32_t pressed, uint32_t released,
                           PwWineInput *out, size_t max)
{
    size_t used;

    if (!input || !out) return 0;
    used = add_edges(input, released, 0, out, 0, max);
    return add_edges(input, pressed, 1, out, used, max);
}

static const struct { uint32_t dualsense; uint16_t xinput; } pad_buttons[] = {
    { 0x4000u, 0x1000u }, { 0x2000u, 0x2000u }, { 0x8000u, 0x4000u }, { 0x1000u, 0x8000u },
    { 0x400u, 0x0100u }, { 0x800u, 0x0200u }, { 0x2u, 0x0040u }, { 0x4u, 0x0080u },
    { 0x10u, 0x0001u }, { 0x40u, 0x0002u }, { 0x80u, 0x0004u }, { 0x20u, 0x0008u },
    { 0x8u, 0x0010u }, { 0x1u, 0x0020u }, { 0x100000u, 0x0400u },
};

/* One stick axis (0..255, 0x80 centred) as XInput's -32768..32767, centre
 * 0; up is 0 on the DualSense and positive in XInput. */
static int16_t pad_axis(uint8_t raw, int up)
{
    int32_t d = up ? 0x80 - (int32_t)raw : (int32_t)raw - 0x80;   /* -127..128 or -128..127 */
    int32_t reach = d < 0 ? (up ? 127 : 128) : (up ? 128 : 127);
    return (int16_t)(d * (d < 0 ? 32768 : 32767) / reach);
}

int pw_wine_game_pad(const PwPadPs5 *pad, PwWinePad *out)
{
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    if (!pad || !pad->core.connected) return 0;
    out->connected = 1;
    for (size_t i = 0; i < sizeof(pad_buttons) / sizeof(pad_buttons[0]); i++)
        if (pad->core.previous_buttons & pad_buttons[i].dualsense) out->buttons |= pad_buttons[i].xinput;
    out->left_trigger = pad->l2;
    out->right_trigger = pad->r2;
    out->thumb_lx = pad_axis(pad->left_stick.x, 0);
    out->thumb_ly = pad_axis(pad->left_stick.y, 1);
    out->thumb_rx = pad_axis(pad->right_stick.x, 0);
    out->thumb_ry = pad_axis(pad->right_stick.y, 1);
    return 1;
}

int pw_wine_script_pad(PwWinePad *pad, int connected, const PwScriptPad *script, int scripted)
{
    if (!pad) return 0;
    if (!connected) memset(pad, 0, sizeof(*pad));
    if (!script || !scripted) return connected ? 1 : 0;
    pad->connected = 1;
    pad->buttons |= script->buttons;
    if (script->stick[0][0] || script->stick[0][1]) {
        pad->thumb_lx = script->stick[0][0];
        pad->thumb_ly = script->stick[0][1];
    }
    if (script->stick[1][0] || script->stick[1][1]) {
        pad->thumb_rx = script->stick[1][0];
        pad->thumb_ry = script->stick[1][1];
    }
    return 1;
}

/* Signed 1/65536-pixel travel of one axis. */
static int64_t travel(uint8_t stick, uint32_t speed, uint32_t deadzone, uint32_t elapsed_us)
{
    int32_t axis = (int32_t)stick - 0x80, magnitude = axis < 0 ? -axis : axis;
    int64_t t, v;

    if ((uint32_t)magnitude <= deadzone) return 0;
    t = (int64_t)(magnitude - (int32_t)deadzone) * 65536 / (127 - deadzone);
    if (t > 65536) t = 65536;
    v = t * t >> 16;                       /* 0..65536: a squared curve */
    v = v * speed * elapsed_us / 1000000;   /* < 2^63 for speed <= 20000 */
    return axis < 0 ? -v : v;
}

int pw_wine_pointer_step(PwWinePointer *pointer, uint8_t stick_x, uint8_t stick_y,
                         uint32_t speed, uint32_t elapsed_us, PwWineInput *out)
{
    return pw_wine_pointer_step_configured(pointer, stick_x, stick_y, speed,
                                           PW_WINE_POINTER_DEADZONE, elapsed_us, out);
}

int pw_wine_pointer_step_configured(PwWinePointer *pointer, uint8_t stick_x, uint8_t stick_y,
                                    uint32_t speed, uint32_t deadzone, uint32_t elapsed_us,
                                    PwWineInput *out)
{
    int64_t dx, dy;

    if (!pointer || !out) return 0;
    if (speed > PW_GAME_MOUSE_SPEED_MAX) speed = PW_GAME_MOUSE_SPEED_MAX;
    if (deadzone > PW_GAME_MOUSE_DEADZONE_MAX) deadzone = PW_GAME_MOUSE_DEADZONE_DEFAULT;
    pointer->x += travel(stick_x, speed, deadzone, elapsed_us);
    pointer->y += travel(stick_y, speed, deadzone, elapsed_us);
    /* whole pixels, towards zero, so both directions keep their fraction */
    dx = pointer->x / 65536;
    dy = pointer->y / 65536;
    if (!dx && !dy) return 0;
    pointer->x -= dx * 65536;
    pointer->y -= dy * 65536;
    *out = (PwWineInput){ PW_WINE_INPUT_MOUSE_MOVE, 0, (int32_t)dx, (int32_t)dy, 0 };
    return 1;
}

void pw_wine_input_router_init(PwWineInputRouter *router, const PwGameInput *profile)
{
    if (!router) return;
    memset(router, 0, sizeof(*router));
    router->mouse_mode = profile && profile->start_mode == PW_GAME_START_MOUSE;
}

const char *pw_wine_input_mode_name(const PwWineInputRouter *r,const PwGameInput *profile)
{
    if(r && r->mouse_mode)return "MOUSE/UI";
    return profile && profile->mode==PW_GAME_INPUT_XINPUT ? "GAMEPAD (XInput)" : "PROFILE KEYS";
}

static PwGameInput routed_bindings(const PwGameInput *profile,unsigned mouse)
{
    PwGameInput b=*profile;
    if(mouse) {
        if(pw_game_input_ui_bindings(profile,b.bindings)!=PW_OK) {
            /* Malformed programmatic inputs fail back to the known UI map. */
            PwGameInput defaults;
            pw_game_input_init(&defaults);
            (void)pw_game_input_ui_bindings(&defaults,b.bindings);
        }
    } else if(profile->mode==PW_GAME_INPUT_XINPUT) {
        /* A physical control belongs to exactly one input path. */
        memset(b.bindings,0,sizeof(b.bindings));
    }
    return b;
}

size_t pw_wine_route_input(PwWineInputRouter *r,const PwGameInput *profile,
                           const PwPadPs5 *pad,int focused,uint32_t elapsed_us,
                           PwWineInput *out,size_t max,PwWinePad *gamepad)
{
    const uint32_t chord=0x6u;
    uint32_t raw=pad ? pad->core.previous_buttons : 0;
    unsigned fresh;
    size_t n=0;
    if(!r || !profile || !out || !gamepad || max<PW_WINE_ROUTED_EVENTS)return 0;
    fresh=pad && pad->sample_serial!=r->serial;
    memset(gamepad,0,sizeof(*gamepad));
    PwGameInput bindings=routed_bindings(profile,r->mouse_mode);
    if(fresh){r->serial=pad->sample_serial;r->stale_us=0;}
    else if(elapsed_us>=PW_WINE_INPUT_STALE_US-r->stale_us)r->stale_us=PW_WINE_INPUT_STALE_US;
    else r->stale_us+=elapsed_us;
    unsigned active=focused && pad && pad->core.connected && r->stale_us<PW_WINE_INPUT_STALE_US;
    unsigned generation=active && ((r->generation_valid && r->generation!=pad->core.generation) ||
                                  r->discontinuities!=pad->discontinuities);
    if(pad)r->discontinuities=pad->discontinuities;
    unsigned toggle=active && fresh && !r->chord_latched && (raw&chord)==chord;
    if(!(raw&chord))r->chord_latched=0;
    if(toggle)r->chord_latched=1;
    unsigned reset=!active || !r->active || generation || toggle;
    if(reset) {
        n=pw_wine_game_inputs(&bindings,0,r->held,out,max);
        r->held=0;r->blocked=raw;r->analog_blocked=1;
        r->pointer=(PwWinePointer){0,0};r->touch_valid=0;r->cycle_armed=0;
    }
    if(pad && r->touch_epoch!=pad->touch_epoch)r->touch_valid=0;
    if(pad)r->touch_epoch=pad->touch_epoch;
    r->active=active;
    if(!active)return n;
    r->generation=pad->core.generation;r->generation_valid=1;
    if(toggle) {
        r->mouse_mode=!r->mouse_mode;
        return n; /* neutral gamepad and release old path before new mode */
    }
    uint32_t was_blocked=r->blocked;
    r->blocked&=raw;
    uint32_t held=raw&~r->blocked;
    if(r->chord_latched)held&=~chord;
    if(r->analog_blocked &&
       pad->left_stick.x>=108 && pad->left_stick.x<=148 &&
       pad->left_stick.y>=108 && pad->left_stick.y<=148 &&
       pad->right_stick.x>=108 && pad->right_stick.x<=148 &&
       pad->right_stick.y>=108 && pad->right_stick.y<=148 && !pad->l2 && !pad->r2)
        r->analog_blocked=0;
    if(!r->mouse_mode && profile->mode==PW_GAME_INPUT_XINPUT) {
        PwPadPs5 filtered=*pad;
        filtered.core.previous_buttons=held;
        if(r->analog_blocked) {
            filtered.left_stick=filtered.right_stick=(PwPadPs5Stick){128,128};
            filtered.l2=filtered.r2=0;
        }
        pw_wine_game_pad(&filtered,gamepad);
    } else {
        bindings=routed_bindings(profile,r->mouse_mode);
        n+=pw_wine_game_inputs(&bindings,held&~r->held,r->held&~held,out+n,max-n);
        /* Keep a complete quick tap delivered within one native batch.
         * Held transitions above and tap pulses are disjoint. */
        uint32_t taps=fresh && !reset ? pad->core.pressed_edges&pad->core.released_edges&
                             ~held&~r->held&~was_blocked : 0;
        if(r->chord_latched)taps&=~chord;
        n+=pw_wine_game_inputs(&bindings,taps,0,out+n,max-n);
        n+=pw_wine_game_inputs(&bindings,0,taps,out+n,max-n);
        /* Options acts on release, so Options+Create remains the title's
         * close chord even when Options was pressed first. */
        if(r->mouse_mode) {
            if((raw|(fresh ? pad->core.pressed_edges : 0))&0x1u)r->cycle_armed=0;
            else if(((held&~r->held)|taps)&0x8u)r->cycle_armed=1;
            if(r->cycle_armed && !(held&0x8u)) {
                out[n++]=(PwWineInput){PW_WINE_INPUT_WINDOW_CYCLE,0,1,0,1};
                r->cycle_armed=0;
            }
        }
        if(r->mouse_mode && fresh && pad->touch_data.fingers==1) {
            const PwPadPs5Touch *t=&pad->touch_data.touch[0];
            /* Relative raw sensor units, half a pixel each at 100 percent.
             * No invented sensor extent/absolute mapping. Re-anchor new IDs. */
            if(r->touch_valid && r->finger==t->finger) {
                int dx=(int)t->x-r->touch_x,dy=(int)t->y-r->touch_y;
                if(dx>=-512 && dx<=512 && dy>=-512 && dy<=512) {
                    uint32_t speed=profile->touch_speed;
                    if(speed<PW_GAME_TOUCH_SPEED_MIN || speed>PW_GAME_TOUCH_SPEED_MAX)
                        speed=PW_GAME_TOUCH_SPEED_DEFAULT;
                    r->pointer.x+=(int64_t)dx*32768*speed/100;
                    r->pointer.y+=(int64_t)dy*32768*speed/100;
                    n+=(size_t)pw_wine_pointer_step(&r->pointer,128,128,0,0,out+n);
                }
            }
            r->touch_x=t->x;r->touch_y=t->y;r->finger=t->finger;r->touch_valid=1;
        } else if(fresh)r->touch_valid=0;
        PwGameStick stick=r->mouse_mode ? PW_GAME_STICK_LEFT : profile->mouse;
        if(!r->analog_blocked && stick!=PW_GAME_STICK_NONE &&
           !(r->mouse_mode && pad->touch_data.fingers)) {
            const PwPadPs5Stick *s=stick==PW_GAME_STICK_LEFT ? &pad->left_stick : &pad->right_stick;
            uint32_t speed=profile->mouse_speed;
            if(speed>PW_GAME_MOUSE_SPEED_MAX)speed=PW_GAME_MOUSE_SPEED_MAX;
            if(elapsed_us>50000)elapsed_us=50000;
            n+=(size_t)pw_wine_pointer_step_configured(&r->pointer,s->x,s->y,speed,
                                                       profile->mouse_deadzone,elapsed_us,out+n);
        }
    }
    r->held=held;
    return n;
}

size_t pw_wine_input_flush(PwWineInputDelivery *delivery,int (*post)(const PwWineInput *))
{
    size_t accepted=0;
    if(!delivery || !post || delivery->count>PW_WINE_ROUTED_EVENTS ||
       delivery->next>delivery->count)return 0;
    while(delivery->next<delivery->count) {
        if(post(&delivery->events[delivery->next])!=0)break;
        delivery->next++;accepted++;
    }
    if(delivery->next==delivery->count)delivery->next=delivery->count=0;
    return accepted;
}

uint64_t pw_wine_close_chord_tick(const PwWineInputRouter *router,const PwPadPs5 *pad,
                                 int fresh,uint64_t ticks)
{
    return router && router->active && fresh && pad && pad->core.connected &&
           router->stale_us<PW_WINE_INPUT_STALE_US &&
           (pad->core.previous_buttons&0x9u)==0x9u ? ticks+1 : 0;
}
