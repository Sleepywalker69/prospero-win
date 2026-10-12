/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../native/pw_wine_display.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

static void test_frames(void)
{
    PwWineFrameBox box;
    PwPresentView view;
    uint8_t source[3 * 16], out[64], small[8], storage[48];
    uint64_t seen = 0;

    for (size_t i = 0; i < sizeof(source); i++) source[i] = (uint8_t)i;
    assert(pw_wine_frame_box_init(NULL, storage, 48) == -1);
    assert(pw_wine_frame_box_init(&box, NULL, 48) == -1 && pw_wine_frame_box_init(&box, storage, 0) == -1);
    assert(!pw_wine_frame_box_init(&box, storage, sizeof(storage)));
    assert(pw_wine_frame_box_take(&box, &seen, out, sizeof(out), &view) == 0);

    /* Rows are packed: a 3x2 frame with a 16-byte stride keeps 12 bytes a row. */
    assert(!pw_wine_frame_box_put(&box, source, 3, 2, 16));
    assert(pw_wine_frame_box_take(&box, &seen, small, sizeof(small), &view) == -1 && seen == 0);
    assert(pw_wine_frame_box_take(&box, &seen, out, sizeof(out), &view) == 1 && seen == 1);
    assert(view.pixels == out && view.width == 3 && view.height == 2 && view.stride == 12 &&
           view.bytes == 24);
    assert(!memcmp(out, source, 12) && !memcmp(out + 12, source + 16, 12));
    assert(pw_wine_frame_box_take(&box, &seen, out, sizeof(out), &view) == 0);

    /* Only the newest of several frames is taken. */
    assert(!pw_wine_frame_box_put(&box, source, 1, 1, 4));
    assert(!pw_wine_frame_box_put(&box, source + 4, 2, 1, 8));
    assert(pw_wine_frame_box_take(&box, &seen, out, sizeof(out), &view) == 1 && seen == 3);
    assert(view.width == 2 && view.height == 1 && !memcmp(out, source + 4, 8));

    /* Refusals: invalid, stride below a row, larger than the box. */
    assert(pw_wine_frame_box_put(&box, NULL, 1, 1, 4) == -1);
    assert(pw_wine_frame_box_put(&box, source, 0, 1, 4) == -1);
    assert(pw_wine_frame_box_put(&box, source, 1, 0, 4) == -1);
    assert(pw_wine_frame_box_put(&box, source, 2, 1, 4) == -1);
    assert(pw_wine_frame_box_put(&box, source, 4, 4, 16) == -1);
    assert(pw_wine_frame_box_put(&box, source, 0x40000000u, 2, 0xffffffffu) == -1);
    assert(box.rejected == 6 && box.sequence == 3);
    assert(pw_wine_frame_box_put(NULL, source, 1, 1, 4) == -1);
    assert(pw_wine_frame_box_take(&box, NULL, out, sizeof(out), &view) == -1);
    assert(pw_wine_frame_box_take(&box, &seen, NULL, sizeof(out), &view) == -1);
    assert(pw_wine_frame_box_take(&box, &seen, out, sizeof(out), NULL) == -1);
    pw_wine_frame_box_destroy(&box);
    pw_wine_frame_box_destroy(&box);              /* a second destroy is harmless */
    pw_wine_frame_box_destroy(NULL);
    assert(pw_wine_frame_box_put(&box, source, 1, 1, 4) == -1);
    assert(pw_wine_frame_box_take(&box, &seen, out, sizeof(out), &view) == -1);
}

/* Wine's threads put while the title's thread takes. */
static PwWineFrameBox shared;
static uint8_t shared_storage[16];

static void *producer(void *arg)
{
    uint32_t pixels[4];

    (void)arg;
    for (uint32_t i = 1; i <= 2000; i++) {
        for (int p = 0; p < 4; p++) pixels[p] = i;
        assert(!pw_wine_frame_box_put(&shared, pixels, 2, 2, 8));
    }
    return NULL;
}

static void test_threads(void)
{
    pthread_t thread;
    PwPresentView view;
    uint32_t out[4], last = 0;
    uint64_t seen = 0;

    assert(!pw_wine_frame_box_init(&shared, shared_storage, sizeof(shared_storage)));
    assert(!pthread_create(&thread, NULL, producer, NULL));
    while (last < 2000) {
        if (pw_wine_frame_box_take(&shared, &seen, (uint8_t *)out, sizeof(out), &view) != 1)
            continue;
        /* never a torn frame, never older than the last one taken */
        assert(out[0] == out[1] && out[1] == out[2] && out[2] == out[3] && out[0] >= last);
        last = out[0];
    }
    assert(!pthread_join(thread, NULL) && seen == 2000);
    pw_wine_frame_box_destroy(&shared);
}

static const char preset_text[] =
    "[input]\nl1 = z\nr1 = slash\ncross = space\nr2 = mouse_left\nl2 = mouse_right\n"
    "square = none\n";
enum { L1 = 0x400u, R1 = 0x800u, CROSS = 0x4000u, SQUARE = 0x8000u, L2 = 0x100u, R2 = 0x200u,
       CIRCLE = 0x2000u };

static void test_inputs(void)
{
    PwGameInput input;
    PwWineInput events[8];

    pw_game_input_init(&input);
    assert(pw_game_input_parse((const uint8_t *)preset_text, sizeof(preset_text) - 1, &input) == PW_OK);
    assert(pw_wine_game_inputs(&input, L1 | CROSS | CIRCLE | SQUARE, 0, events, 8) == 2);
    assert(events[0].type == PW_WINE_INPUT_KEY && events[0].code == 0x20 && events[0].down == 1);
    assert(events[1].code == 'Z' && events[1].down == 1 && !events[1].x && !events[1].y);

    /* Releases come first; mouse bindings send buttons; unbound and none send nothing. */
    assert(pw_wine_game_inputs(&input, R2 | L2, L1 | CROSS, events, 8) == 4);
    assert(events[0].code == 0x20 && !events[0].down && events[1].code == 'Z' && !events[1].down);
    assert(events[2].type == PW_WINE_INPUT_MOUSE_BUTTON && events[2].code == 1 && events[2].down);
    assert(events[3].type == PW_WINE_INPUT_MOUSE_BUTTON && events[3].code == 0 && events[3].down);
    assert(pw_wine_game_inputs(&input, R1 | L1, 0, events, 1) == 1 && events[0].code == 'Z');
    assert(pw_wine_game_inputs(&input, 0, 0, events, 8) == 0);
    assert(pw_wine_game_inputs(NULL, L1, 0, events, 8) == 0 && pw_wine_game_inputs(&input, L1, 0, NULL, 8) == 0);
}

static void test_pointer(void)
{
    PwWinePointer pointer = { 0, 0 };
    PwWineInput move;

    /* At rest and inside the dead zone nothing moves. */
    assert(!pw_wine_pointer_step(&pointer, 0x80, 0x80, 1200, 16000, &move));
    assert(!pw_wine_pointer_step(&pointer, 0x80 + PW_WINE_POINTER_DEADZONE, 0x80 - PW_WINE_POINTER_DEADZONE,
                                 1200, 1000000, &move));
    assert(!pointer.x && !pointer.y);
    /* Full tilt for a second is the speed's worth of motion, right or up. */
    assert(pw_wine_pointer_step(&pointer, 0xff, 0x80, 300, 1000000, &move) == 1);
    assert(move.type == PW_WINE_INPUT_MOUSE_MOVE && move.x == 300 && move.y == 0 && !move.code && !move.down);
    assert(pw_wine_pointer_step(&pointer, 0x80, 0x00, 1200, 1000000, &move) == 1);
    assert(move.x == 0 && move.y == -1200);
    /* Motion has no edge: held, it keeps coming, which is what scrolls a
     * strategy game's map with the pointer against the screen's edge. */
    for (int i = 0; i < 3; i++) {
        assert(pw_wine_pointer_step(&pointer, 0xff, 0xff, 20000, 1000000, &move) == 1);
        assert(move.x == 20000 && move.y == 20000);
    }
    /* Half tilt is slower than half speed (squared curve). */
    assert(pw_wine_pointer_step(&pointer, 0x80 + 74, 0x80, 1000, 1000000, &move) == 1);
    assert(move.x > 200 && move.x < 300 && move.y == 0);
}

static void test_pointer_fraction(void)
{
    PwWinePointer pointer = { 0, 0 };
    PwWineInput move;
    int32_t right = 0, left = 0;
    int moves = 0;

    /* Steps smaller than a pixel add up: 60 px/s for 100 frames of 16 ms is
     * 62914/65536 of a pixel a step: 95 whole pixels, sent a pixel at a time,
     * with the fraction kept. */
    for (int i = 0; i < 100; i++)
        if (pw_wine_pointer_step(&pointer, 0xff, 0x80, 60, 16000, &move)) {
            assert(move.x == 1 && move.y == 0);
            right += move.x;
            moves++;
        }
    assert(right == 95 && moves == 95 && pointer.x > 0 && pointer.x < 65536);
    /* Left is the mirror image: the fraction rounds towards zero both ways. */
    pointer = (PwWinePointer){ 0, 0 };
    for (int i = 0; i < 100; i++)
        if (pw_wine_pointer_step(&pointer, 0x01, 0x80, 60, 16000, &move)) left += move.x;
    assert(left == -95 && pointer.x < 0 && pointer.x > -65536);
    assert(!pw_wine_pointer_step(NULL, 0xff, 0x80, 1, 1, &move) && !pw_wine_pointer_step(&pointer, 0, 0, 1, 1, NULL));
}

static void test_pad(void)
{
    PwPadPs5 pad;
    PwWinePad xinput;

    memset(&pad, 0, sizeof(pad));
    pad.left_stick = pad.right_stick = (PwPadPs5Stick){ 0x80, 0x80 };
    /* Disconnected: nothing, and a neutral state. */
    memset(&xinput, 0x5a, sizeof(xinput));
    assert(pw_wine_game_pad(&pad, &xinput) == 0);
    assert(!xinput.connected && !xinput.buttons && !xinput.thumb_lx && !xinput.left_trigger);
    assert(pw_wine_game_pad(NULL, &xinput) == 0 && pw_wine_game_pad(&pad, NULL) == 0);

    /* Centred and released. */
    pad.core.connected = 1;
    assert(pw_wine_game_pad(&pad, &xinput) == 1 && xinput.connected == 1 && xinput.packet == 0);
    assert(!xinput.buttons && !xinput.left_trigger && !xinput.right_trigger);
    assert(!xinput.thumb_lx && !xinput.thumb_ly && !xinput.thumb_rx && !xinput.thumb_ry);

    /* Each DualSense button, alone, as its XInput bit. */
    static const struct { uint32_t dualsense; uint16_t xinput; } buttons[] = {
        { 0x4000u, 0x1000u /* cross: A */ }, { 0x2000u, 0x2000u /* circle: B */ },
        { 0x8000u, 0x4000u /* square: X */ }, { 0x1000u, 0x8000u /* triangle: Y */ },
        { 0x400u, 0x0100u /* l1 */ }, { 0x800u, 0x0200u /* r1 */ },
        { 0x2u, 0x0040u /* l3 */ }, { 0x4u, 0x0080u /* r3 */ },
        { 0x10u, 0x0001u /* up */ }, { 0x40u, 0x0002u /* down */ },
        { 0x80u, 0x0004u /* left */ }, { 0x20u, 0x0008u /* right */ },
        { 0x8u, 0x0010u /* options: start */ }, { 0x1u, 0x0020u /* create: back */ },
        { 0x100000u, 0x0400u /* touchpad: guide */ },
    };
    for (size_t i = 0; i < sizeof(buttons) / sizeof(buttons[0]); i++) {
        pad.core.previous_buttons = buttons[i].dualsense;
        assert(pw_wine_game_pad(&pad, &xinput) == 1 && xinput.buttons == buttons[i].xinput);
    }
    /* L2/R2 are analog triggers, not buttons; unknown bits are dropped. */
    pad.core.previous_buttons = 0x100u | 0x200u | 0x80000000u;
    pad.l2 = 1;
    pad.r2 = 255;
    assert(pw_wine_game_pad(&pad, &xinput) == 1 && !xinput.buttons);
    assert(xinput.left_trigger == 1 && xinput.right_trigger == 255);
    pad.core.previous_buttons = 0x4000u | 0x8u | 0x10u;
    assert(pw_wine_game_pad(&pad, &xinput) == 1 && xinput.buttons == (0x1000u | 0x0010u | 0x0001u));

    /* Sticks: full reach both ways, centre 0, y up. */
    pad.left_stick = (PwPadPs5Stick){ 0x00, 0x00 };     /* left, up */
    pad.right_stick = (PwPadPs5Stick){ 0xff, 0xff };    /* right, down */
    assert(pw_wine_game_pad(&pad, &xinput) == 1);
    assert(xinput.thumb_lx == -32768 && xinput.thumb_ly == 32767);
    assert(xinput.thumb_rx == 32767 && xinput.thumb_ry == -32768);
    pad.left_stick = (PwPadPs5Stick){ 0x81, 0x7f };     /* a step right, a step up */
    pad.right_stick = (PwPadPs5Stick){ 0x7f, 0x81 };
    assert(pw_wine_game_pad(&pad, &xinput) == 1);
    assert(xinput.thumb_lx == 32767 / 127 && xinput.thumb_ly == 32767 / 128);
    assert(xinput.thumb_rx == -32768 / 128 && xinput.thumb_ry == -32768 / 127);
    pad.left_stick = (PwPadPs5Stick){ 0xc0, 0x40 };     /* halfway right and up */
    assert(pw_wine_game_pad(&pad, &xinput) == 1);
    assert(xinput.thumb_lx == 64 * 32767 / 127 && xinput.thumb_ly == 64 * 32767 / 128);
}

/* A script build's controller added to the DualSense's. */
static void test_script_pad(void)
{
    PwPadPs5 pad;
    PwWinePad xinput;
    PwScriptPad script = { 0 };

    memset(&pad, 0, sizeof(pad));
    pad.core.connected = 1;
    pad.core.previous_buttons = 0x2000u;                /* circle: B */
    pad.left_stick = (PwPadPs5Stick){ 0xff, 0x80 };     /* full right */
    pad.right_stick = (PwPadPs5Stick){ 0x80, 0x00 };    /* full up */
    pad.r2 = 200;

    /* Nothing scripted: the real controller as it is. */
    assert(pw_wine_game_pad(&pad, &xinput) == 1);
    assert(pw_wine_script_pad(&xinput, 1, &script, 1) == 1);
    assert(xinput.buttons == 0x2000u && xinput.thumb_lx == 32767 && xinput.thumb_ly == 0 &&
           xinput.thumb_ry == 32767 && xinput.right_trigger == 200);

    /* Buttons join; a stick held off centre replaces the real one, and
     * only that stick. */
    script.buttons = 0x1000u | 0x2000u;                 /* A, and B both ways */
    script.stick[0][0] = -16000;
    script.stick[0][1] = 0;
    assert(pw_wine_game_pad(&pad, &xinput) == 1);
    assert(pw_wine_script_pad(&xinput, 1, &script, 1) == 1);
    assert(xinput.connected == 1 && xinput.buttons == 0x3000u);
    assert(xinput.thumb_lx == -16000 && xinput.thumb_ly == 0);
    assert(xinput.thumb_rx == 0 && xinput.thumb_ry == 32767 && xinput.right_trigger == 200);
    script.stick[0][0] = 0;
    script.stick[1][1] = -1;                            /* any off-centre value counts */
    assert(pw_wine_game_pad(&pad, &xinput) == 1);
    assert(pw_wine_script_pad(&xinput, 1, &script, 1) == 1);
    assert(xinput.thumb_lx == 32767 && xinput.thumb_rx == 0 && xinput.thumb_ry == -1);

    /* No DualSense: the script's controller alone, still connected while it
     * holds nothing. */
    pad.core.connected = 0;
    memset(&script, 0, sizeof(script));
    assert(pw_wine_game_pad(&pad, &xinput) == 0);
    assert(pw_wine_script_pad(&xinput, 0, &script, 1) == 1);
    assert(xinput.connected == 1 && !xinput.buttons && !xinput.thumb_lx && !xinput.right_trigger);
    script.buttons = 0x0010u;
    memset(&xinput, 0x5a, sizeof(xinput));              /* stale: cleared when not connected */
    assert(pw_wine_script_pad(&xinput, 0, &script, 1) == 1);
    assert(xinput.buttons == 0x0010u && !xinput.thumb_lx && !xinput.left_trigger && !xinput.packet);

    /* A macro without pad events leaves controller 0 to the DualSense. */
    assert(pw_wine_script_pad(&xinput, 0, &script, 0) == 0 && !xinput.connected && !xinput.buttons);
    pad.core.connected = 1;
    assert(pw_wine_game_pad(&pad, &xinput) == 1);
    assert(pw_wine_script_pad(&xinput, 1, &script, 0) == 1 && xinput.buttons == 0x2000u);
    assert(pw_wine_script_pad(&xinput, 1, NULL, 1) == 1 && xinput.buttons == 0x2000u);
    assert(pw_wine_script_pad(NULL, 1, &script, 1) == 0);

    /* From a parsed macro, through the scripted controller, to XInput. */
    {
        static PwScriptInputEvent storage[4];
        static const char macro[] = "0 pad a 1\n0 stick l 0 32767\n";
        PwScriptInput in;
        size_t bad;
        uint16_t changed = 0;

        memset(&script, 0, sizeof(script));
        assert(pw_script_input_parse(macro, sizeof(macro) - 1, storage, 4, &in, &bad) == PW_OK);
        for (size_t i = 0; i < in.count; i++) assert(pw_script_pad_apply(&script, &in.events[i], &changed) == 1);
        pad.core.connected = 0;
        assert(pw_wine_game_pad(&pad, &xinput) == 0);
        assert(pw_wine_script_pad(&xinput, 0, &script, in.pad_events != 0) == 1);
        assert(xinput.buttons == 0x1000u && xinput.thumb_lx == 0 && xinput.thumb_ly == 32767);
    }
}

static void test_input_router(void)
{
    PwWineInputRouter r={0};
    PwGameInput profile;
    PwPadPs5 pad={0};
    PwWinePad game;
    PwWineInput e[PW_WINE_ROUTED_EVENTS];
    size_t n;
    pw_game_input_init(&profile);profile.mode=PW_GAME_INPUT_XINPUT;
    pad.core.connected=1;pad.left_stick=pad.right_stick=(PwPadPs5Stick){128,128};
#define STEP() (pad.sample_serial++,pw_wine_route_input(&r,&profile,&pad,1,10000,e,PW_WINE_ROUTED_EVENTS,&game))
    assert(STEP()==0 && game.connected);
    pad.core.previous_buttons=0x4000;assert(STEP()==0 && game.buttons==0x1000);
    pad.core.previous_buttons=2;assert(STEP()==0 && game.buttons==0x40); /* L3 remains usable */
    pad.core.previous_buttons=0;assert(STEP()==0);
    pad.core.previous_buttons=0x4000;assert(STEP()==0);
    /* Switch with Cross held: release gamepad, never leak held click. */
    pad.core.previous_buttons|=6;assert(STEP()==0 && !game.connected && r.mouse_mode);
    for(int i=0;i<8;i++)assert(STEP()==0 && r.mouse_mode && !game.connected);
    pad.core.previous_buttons=0x4000;assert(STEP()==0);
    pad.core.previous_buttons=0;assert(STEP()==0);
    pad.core.previous_buttons=0x4000;n=STEP();
    assert(n==1 && e[0].type==PW_WINE_INPUT_MOUSE_BUTTON && e[0].code==0 && e[0].down);
    /* Toggle releases held mouse before exposing gamepad. */
    pad.core.previous_buttons|=6;n=STEP();assert(n==1 && !e[0].down && !r.mouse_mode && !game.connected);
    pad.core.previous_buttons=0;assert(STEP()==0);
    pad.core.previous_buttons=6;assert(STEP()==0 && r.mouse_mode);
    pad.core.previous_buttons=0;assert(STEP()==0);
    /* Touch anchors, uses actual deltas, ignores repeated/stale frames. */
    pad.touch_data.fingers=1;pad.touch_data.touch[0]=(PwPadPs5Touch){100,100,7,{0}};
    assert(STEP()==0);
    pad.touch_data.touch[0].x=110;pad.touch_data.touch[0].y=94;
    n=STEP();assert(n==1 && e[0].x==5 && e[0].y==-3);
    assert(pw_wine_route_input(&r,&profile,&pad,1,10000,e,PW_WINE_ROUTED_EVENTS,&game)==0);
    pad.touch_data.touch[0].finger=8;pad.touch_data.touch[0].x=900;assert(STEP()==0);
    pad.touch_data.fingers=0;assert(STEP()==0);
    pad.left_stick.x=148;assert(STEP()==0); /* dead zone */
    pad.left_stick.x=255;n=STEP();assert(n==1 && e[0].x>0);
    pad.left_stick.x=128;pad.core.previous_buttons=0x2000;n=STEP();assert(n==1 && e[0].code==1 && e[0].down);
    /* Focus loss releases; held input cannot be re-pressed on restoration. */
    n=pw_wine_route_input(&r,&profile,&pad,0,10000,e,PW_WINE_ROUTED_EVENTS,&game);
    assert(n==1 && !e[0].down && !game.connected);
    assert(STEP()==0);pad.core.previous_buttons=0;assert(STEP()==0);
    pad.core.previous_buttons=0x4000;assert(STEP()==1);
    /* Empty reads eventually release without replaying movement. */
    n=pw_wine_route_input(&r,&profile,&pad,1,PW_WINE_INPUT_STALE_US,e,PW_WINE_ROUTED_EVENTS,&game);
    assert(n==1 && !e[0].down && !r.active);
    assert(STEP()==0);pad.core.previous_buttons=0;assert(STEP()==0);
    pad.core.previous_buttons=0x4000;assert(STEP()==1);
    pad.core.connected=0;n=STEP();assert(n==1 && !e[0].down);
    pad.core.connected=1;assert(STEP()==0);
    pad.core.previous_buttons=0;assert(STEP()==0);
    pad.core.previous_buttons=0x4000;assert(STEP()==1);
    pad.discontinuities++;n=STEP();assert(n==1 && !e[0].down);
    pad.core.previous_buttons=0;pad.discontinuities++;
    pad.core.pressed_edges=pad.core.released_edges=0x4000;
    assert(STEP()==0); /* discontinuity must discard batched click pulses */
    pad.core.pressed_edges=pad.core.released_edges=0;
    pad.touch_data.fingers=1;pad.touch_data.touch[0]=(PwPadPs5Touch){100,100,7,{0}};
    assert(STEP()==0);
    pad.touch_epoch++;pad.touch_data.touch[0].x=300;
    assert(STEP()==0); /* lift/re-touch same ID inside native batch reanchors */
    pad.touch_data.fingers=0;assert(STEP()==0);
    pad.core.previous_buttons=0;assert(STEP()==0);
    pad.core.previous_buttons=0xc00;n=STEP();
    assert(n==2 && e[0].code==0x10 && e[0].down && e[1].code==9 && e[1].down);
    pad.core.connected=0;n=STEP();assert(n==2 && !e[0].down && !e[1].down);
    pad.core.connected=1;pad.core.previous_buttons=0;assert(STEP()==0);
    pad.core.previous_buttons=8;assert(STEP()==0);
    assert(STEP()==0);
    pad.core.previous_buttons=0;n=STEP();
    assert(n==1 && e[0].type==PW_WINE_INPUT_WINDOW_CYCLE && e[0].x==1);
    pad.core.previous_buttons=8;assert(STEP()==0);
    pad.core.previous_buttons=9;assert(STEP()==0); /* close chord cancels cycle */
    pad.core.previous_buttons=8;assert(STEP()==0);
    pad.core.previous_buttons=0;assert(STEP()==0);
    pad.core.previous_buttons=1;assert(STEP()==0);
    pad.core.previous_buttons=9;assert(STEP()==0);
    pad.core.previous_buttons=0;assert(STEP()==0);
    /* Tiny output buffers cannot consume state or lose releases. */
    PwWineInputRouter saved=r;
    assert(pw_wine_route_input(&r,&profile,&pad,1,10000,e,0,&game)==0 && !memcmp(&r,&saved,sizeof(r)));
    assert(pw_wine_route_input(NULL,&profile,&pad,1,10000,e,PW_WINE_ROUTED_EVENTS,&game)==0);
    /* Repeat toggles, full-release latch and no duplicate ownership. */
    pad.core.previous_buttons=0;assert(STEP()==0);
    for(int i=0;i<100;i++) {
        unsigned old=r.mouse_mode;
        pad.core.previous_buttons=6;STEP();assert(r.mouse_mode!=old && !game.connected);
        STEP();assert(r.mouse_mode!=old);
        pad.core.previous_buttons=0;STEP();
    }
    pad.core.previous_buttons=9;STEP();
    assert(pw_wine_close_chord_tick(&r,&pad,1,10)==11);
    assert(pw_wine_close_chord_tick(&r,&pad,0,10)==0);
    r.stale_us=PW_WINE_INPUT_STALE_US;r.active=0;
    assert(pw_wine_close_chord_tick(&r,&pad,1,10)==0);
    /* A reset releases the maximum old binding set without admitting
     * batch tap pulses or exceeding the fixed delivery capacity. */
    memset(&r,0,sizeof(r));r.active=1;r.held=0x1ffff;
    profile.mode=PW_GAME_INPUT_KEYBOARD;
    for(unsigned i=0;i<PW_GAME_BUTTON_COUNT;i++)
        profile.bindings[i]=(PwGameBinding){1u<<i,PW_GAME_BIND_KEY,(uint16_t)(0x30+i)};
    pad.core.previous_buttons=0;pad.core.pressed_edges=pad.core.released_edges=0x1ffff;
    pad.discontinuities++;
    n=STEP();assert(n==PW_GAME_BUTTON_COUNT);
    for(size_t i=0;i<n;i++)assert(!e[i].down);
    pad.core.pressed_edges=pad.core.released_edges=0;
    pw_game_input_init(&profile);
    /* Keyboard profiles retain their bindings, without a gamepad. */
    memset(&r,0,sizeof(r));profile.mode=PW_GAME_INPUT_KEYBOARD;
    profile.bindings[0]=(PwGameBinding){0x4000,PW_GAME_BIND_KEY,0x20};
    pad.core.previous_buttons=0;assert(STEP()==0 && !game.connected);
    pad.core.previous_buttons=0x4000;n=STEP();assert(n==1 && e[0].code==0x20 && e[0].down);
    pad.core.generation++;n=STEP();assert(n==1 && !e[0].down && !game.connected);
    assert(STEP()==0);pad.core.previous_buttons=0;assert(STEP()==0);
    pad.core.pressed_edges=pad.core.released_edges=0x4000;
    n=STEP();assert(n==2 && e[0].down && !e[1].down && e[0].code==0x20);
    assert(pw_wine_route_input(&r,&profile,&pad,1,10000,e,PW_WINE_ROUTED_EVENTS,&game)==0);
#undef STEP
}

static void test_delivery_backpressure(void)
{
    PwWineInputDelivery d={0};
    PwWineInput next,move={PW_WINE_INPUT_MOUSE_MOVE,0,1,1,0};
    while(pw_wine_next_input(&next)) {}
    /* Actual sink, one free slot: down accepted, up refused. */
    for(int i=0;i<PW_WINE_INPUT_QUEUE-1;i++)assert(!pw_wine_post_input(&move));
    d.events[0]=(PwWineInput){PW_WINE_INPUT_KEY,0x20,0,0,1};
    d.events[1]=(PwWineInput){PW_WINE_INPUT_KEY,0x20,0,0,0};d.count=2;
    assert(pw_wine_input_flush(&d,pw_wine_post_input)==1 && d.next==1 && d.count==2);
    assert(pw_wine_input_flush(&d,pw_wine_post_input)==0 && d.next==1);
    unsigned downs=0,ups=0;
    while(pw_wine_next_input(&next))if(next.type==PW_WINE_INPUT_KEY){downs+=next.down;ups+=!next.down;}
    assert(downs==1 && ups==0);
    assert(pw_wine_input_flush(&d,pw_wine_post_input)==1 && !d.count && !d.next);
    assert(pw_wine_next_input(&next) && next.code==0x20 && !next.down);
    assert(!pw_wine_next_input(&next));
    assert(pw_wine_input_flush(&d,pw_wine_post_input)==0);
}

static void test_configured_controller(void)
{
    PwGameInput profile;
    PwWineInputRouter router;
    PwPadPs5 pad = { 0 };
    PwWineInput events[PW_WINE_ROUTED_EVENTS], movement, expected;
    PwWinePad gamepad;
    PwWinePointer pointer = { 0 }, reference = { 0 };
    const char *settings = "[input]\nmode = xinput\nstart_mode = mouse\nmouse_deadzone = 40\n"
                           "touch_speed = 200\nui_cross = space\nui_circle = none\n";
    pw_game_input_init(&profile);
    assert(pw_game_input_parse((const uint8_t *)settings, strlen(settings), &profile) == PW_OK);
    pw_wine_input_router_init(&router, &profile);
    assert(router.mouse_mode && !router.active && !router.held);
    assert(!strcmp(pw_wine_input_mode_name(&router, &profile), "MOUSE/UI"));
    pad.core.connected = 1;
    pad.left_stick = pad.right_stick = (PwPadPs5Stick){ 128, 128 };
#define CONFIG_STEP() (++pad.sample_serial, pw_wine_route_input(&router, &profile, &pad, 1, 16000, events, PW_WINE_ROUTED_EVENTS, &gamepad))
    assert(CONFIG_STEP() == 0 && !gamepad.connected);
    pad.core.previous_buttons = 0x4000;
    assert(CONFIG_STEP() == 1 && events[0].type == PW_WINE_INPUT_KEY && events[0].code == 0x20 && events[0].down);
    pad.core.previous_buttons |= 6;
    assert(CONFIG_STEP() == 1 && !events[0].down && events[0].code == 0x20);
    assert(!router.mouse_mode && !gamepad.connected); /* old remapped key released before switch */
    pad.core.previous_buttons = 0;
    assert(CONFIG_STEP() == 0 && gamepad.connected);
    pad.core.previous_buttons = 0x4000;
    assert(CONFIG_STEP() == 0 && gamepad.buttons == 0x1000); /* profile mode still XInput */
    pad.core.previous_buttons = 0;
    CONFIG_STEP();
    pad.core.previous_buttons = 6;
    assert(CONFIG_STEP() == 0 && router.mouse_mode && !gamepad.connected);
    pad.core.previous_buttons = 0;
    assert(CONFIG_STEP() == 0);
    pad.core.previous_buttons = 0x2000;
    assert(CONFIG_STEP() == 0); /* explicit UI none */
    pad.core.previous_buttons = 0;
    assert(CONFIG_STEP() == 0);
    pad.left_stick.x = 158;
    assert(CONFIG_STEP() == 0); /* configured 40-unit deadzone */
    pad.left_stick.x = 255;
    assert(CONFIG_STEP() == 1 && events[0].type == PW_WINE_INPUT_MOUSE_MOVE && events[0].x == 19);
    pad.left_stick.x = 128;
    pad.touch_data.fingers = 1;
    pad.touch_data.touch[0] = (PwPadPs5Touch){ 100, 100, 3, {0} };
    assert(CONFIG_STEP() == 0); /* anchor only */
    pad.touch_data.touch[0].x = 110;
    pad.touch_data.touch[0].y = 95;
    assert(CONFIG_STEP() == 1 && events[0].x == 10 && events[0].y == -5);
    pad.touch_data.touch[0].finger++;
    pad.touch_data.touch[0].x = 300;
    assert(CONFIG_STEP() == 0); /* sensitivity never bypasses re-anchoring */
    pad.touch_data.fingers = 0;
    assert(CONFIG_STEP() == 0);
    /* Defaults and invalid programmatic startup enums select profile mode. */
    pw_wine_input_router_init(&router, NULL);
    assert(!router.mouse_mode && !router.active);
    profile.start_mode = (PwGameStartMode)99;
    pw_wine_input_router_init(&router, &profile);
    assert(!router.mouse_mode);
    pw_wine_input_router_init(NULL, &profile);
#undef CONFIG_STEP

    /* Boundary deadzones remain finite, monotone and retain full travel. */
    for (uint32_t deadzone = 0; deadzone <= PW_GAME_MOUSE_DEADZONE_MAX; deadzone++) {
        pointer = (PwWinePointer){ 0, 0 };
        assert(!pw_wine_pointer_step_configured(&pointer, (uint8_t)(128 + deadzone), 128,
                                               1200, deadzone, 16000, &movement));
        assert(pw_wine_pointer_step_configured(&pointer, 255, 0, 1200, deadzone, 16000, &movement));
        assert(movement.x == 19 && movement.y == -19);
    }
    pointer = reference = (PwWinePointer){ 0, 0 };
    assert(pw_wine_pointer_step_configured(&pointer, 160, 96, 1200, UINT32_MAX, 1000000, &movement));
    assert(pw_wine_pointer_step(&reference, 160, 96, 1200, 1000000, &expected));
    assert(movement.type == expected.type && movement.x == expected.x && movement.y == expected.y);
    assert(!memcmp(&pointer, &reference, sizeof(pointer)));
    pointer = (PwWinePointer){ 0, 0 };
    assert(pw_wine_pointer_step_configured(&pointer, 255, 128, UINT32_MAX, 0, UINT32_MAX, &movement));
    assert(movement.x > 0 && movement.x < INT32_MAX); /* speed capped before multiply */
}


/* Exact native sample -> production tracker -> production router chain.
 * Only ScePad/user-service calls are mocked; no input state is reconstructed.
 * A deflection must not survive system interception or disconnect, nor leak
 * back from empty polls or a still-held control when ownership returns. */
static PwPadPs5Data interruption_sample;
static int interruption_count;
static int interruption_user_init(const void *p) { assert(!p); return 0; }
static int interruption_user(int32_t *user) { *user = 42; return 0; }
static int interruption_user_end(void) { return 0; }
static int interruption_pad_init(void) { return 0; }
static int interruption_open(int32_t user, int32_t type, int32_t index, const void *p)
{ assert(user == 42 && !type && !index && !p); return 7; }
static int interruption_read(int32_t handle, PwPadPs5Data *samples, int32_t capacity)
{
    assert(handle == 7 && capacity == PW_PAD_PS5_BATCH);
    if (interruption_count) samples[0] = interruption_sample;
    return interruption_count;
}
static int interruption_close(int32_t handle) { assert(handle == 7); return 0; }
static const PwPadPs5Ops interruption_ops = {
    interruption_user_init, interruption_user, interruption_user_end,
    interruption_pad_init, interruption_open, interruption_read, interruption_close, NULL
};
static const PwPadKeyMap interruption_map[] = {{CROSS, 0x20, 0, 0, "cross"}};

static void interruption_neutral_gamepad(const PwWinePad *game)
{
    assert(!game->buttons && !game->left_trigger && !game->right_trigger);
    assert(!game->thumb_lx && !game->thumb_ly && !game->thumb_rx && !game->thumb_ry);
}
static size_t interruption_poll(PwPadPs5 *pad, PwWineInputRouter *router,
                               const PwGameInput *profile, PwWineInput *events,
                               PwWinePad *game)
{
    assert(pw_pad_ps5_read(pad) == PW_OK);
    return pw_wine_route_input(router, profile, pad, 1, 16000,
                               events, PW_WINE_ROUTED_EVENTS, game);
}
static void test_native_interception_empty_regain(void)
{
    for (unsigned mouse = 0; mouse != 2; ++mouse) {
        for (unsigned disconnect = 0; disconnect != 2; ++disconnect) {
            PwPadPs5 pad;
            PwWineInputRouter router;
            PwGameInput profile;
            PwWineInput events[PW_WINE_ROUTED_EVENTS];
            PwWinePad game;
            size_t n;
            pw_game_input_init(&profile);
            profile.mode = PW_GAME_INPUT_XINPUT;
            profile.start_mode = mouse ? PW_GAME_START_MOUSE : PW_GAME_START_PROFILE;
            pw_wine_input_router_init(&router, &profile);
            assert(pw_pad_ps5_open(&pad, &interruption_ops, interruption_map, 1) == PW_OK);

            interruption_count = 1;
            interruption_sample = (PwPadPs5Data){
                .left_stick = {128,128}, .right_stick = {128,128},
                .connected = 1, .timestamp = 1, .connected_count = 1
            };
            assert(interruption_poll(&pad, &router, &profile, events, &game) == 0);
            interruption_sample.buttons = CROSS | 8u; /* hold Options too: no late window cycle */
            interruption_sample.left_stick.x = 255;
            interruption_sample.right_stick.y = 0;
            interruption_sample.l2 = 31;
            interruption_sample.r2 = 200;
            interruption_sample.timestamp++;
            n = interruption_poll(&pad, &router, &profile, events, &game);
            if (mouse) {
                assert(n == 2 && events[0].type == PW_WINE_INPUT_MOUSE_BUTTON &&
                       events[0].code == 0 && events[0].down);
                assert(events[1].type == PW_WINE_INPUT_MOUSE_MOVE && events[1].x > 0);
                assert(!game.connected);
            } else {
                assert(n == 0 && game.connected && game.buttons == (0x1000u | 0x10u));
                assert(game.thumb_lx > 0 && game.thumb_ry > 0 &&
                       game.left_trigger == 31 && game.right_trigger == 200);
            }

            /* Loss wins even though the raw sample retains all held/analog data. */
            if (disconnect) interruption_sample.connected = 0;
            else interruption_sample.buttons |= 0x80000000u;
            interruption_sample.timestamp++;
            n = interruption_poll(&pad, &router, &profile, events, &game);
            assert(!pad.core.connected && !router.active && !game.connected);
            assert(pad.left_stick.x == 128 && pad.right_stick.y == 128 && !pad.l2 && !pad.r2);
            assert(!router.pointer.x && !router.pointer.y && !router.cycle_armed);
            interruption_neutral_gamepad(&game);
            assert(n == mouse);
            if (mouse) assert(events[0].type == PW_WINE_INPUT_MOUSE_BUTTON &&
                              events[0].code == 0 && !events[0].down);

            /* 800 ms exceeds our 250 ms stale limit and the reference UI's
             * 350 ms repeat delay. Empty reads cannot resurrect the old axes,
             * re-emit releases, or turn held Options into a window cycle. */
            const uint64_t serial = pad.sample_serial;
            interruption_count = 0;
            for (unsigned i = 0; i != 50; ++i) {
                assert(interruption_poll(&pad, &router, &profile, events, &game) == 0);
                assert(pad.sample_serial == serial && !pad.core.pressed_edges && !pad.core.released_edges);
                assert(!router.active && !game.connected && !router.cycle_armed);
                assert(!router.pointer.x && !router.pointer.y);
                interruption_neutral_gamepad(&game);
            }

            /* A usable stream returns, but the same controls are still held.
             * Several genuinely fresh samples must remain suppressed until a
             * neutral sample, not merely until time has passed. */
            interruption_count = 1;
            interruption_sample.connected = 1;
            interruption_sample.buttons = CROSS | 8u;
            for (unsigned i = 0; i != 6; ++i) {
                interruption_sample.timestamp++;
                assert(interruption_poll(&pad, &router, &profile, events, &game) == 0);
                assert(router.active && router.analog_blocked && !router.held && !router.cycle_armed);
                assert(!router.pointer.x && !router.pointer.y);
                interruption_neutral_gamepad(&game);
                assert(game.connected == !mouse);
            }
            interruption_sample.buttons = 0;
            interruption_sample.left_stick = interruption_sample.right_stick = (PwPadPs5Stick){128,128};
            interruption_sample.l2 = interruption_sample.r2 = 0;
            interruption_sample.timestamp++;
            assert(interruption_poll(&pad, &router, &profile, events, &game) == 0);
            assert(!router.analog_blocked && !router.blocked && !router.cycle_armed);
            interruption_neutral_gamepad(&game);

            /* New input after neutral is usable, proving suppression is not
             * a permanent lockout. Finish with an actual disconnect release. */
            interruption_sample.buttons = CROSS;
            interruption_sample.left_stick.x = 255;
            interruption_sample.r2 = 200;
            interruption_sample.timestamp++;
            n = interruption_poll(&pad, &router, &profile, events, &game);
            if (mouse) assert(n == 2 && events[0].down && events[1].type == PW_WINE_INPUT_MOUSE_MOVE);
            else assert(!n && game.buttons == 0x1000u && game.thumb_lx > 0 && game.right_trigger == 200);
            interruption_sample.connected = 0;
            interruption_sample.timestamp++;
            n = interruption_poll(&pad, &router, &profile, events, &game);
            assert(n == mouse && !game.connected);
            if (mouse) assert(events[0].type == PW_WINE_INPUT_MOUSE_BUTTON && !events[0].down);
            assert(pw_pad_ps5_close(&pad) == PW_OK);
        }
    }
}

int main(void)
{
    test_native_interception_empty_regain();
    test_configured_controller();
    test_delivery_backpressure();
    test_input_router();
    test_frames();
    test_threads();
    test_inputs();
    test_pointer();
    test_pointer_fraction();
    test_pad();
    test_script_pad();
    printf("wine display passed: frame box copy, newest frame, refusals, concurrent put/take, "
           "profile bindings to keys and mouse buttons, stick pointer, resized frames, "
           "DualSense as XInput, scripted controller added to it\n");
    return 0;
}
