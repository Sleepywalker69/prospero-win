/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../src/pw_controller_settings.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define APP "[application]\nid = demo\nname = Demo\nexecutable = C:\\Game.exe\n" \
    "working_directory = C:\\\nprefix = default\nruntime = wine-wow64\narchitecture = pe32\ngraphics = gdi\n"
static const PwControllerValues values = { PW_GAME_START_MOUSE, 12, 1800, 150 };

static void updates(void)
{
    static const char before[] = APP "# untouched application comment\n[display]\ndesktop = 800x600\n"
        "[InPuT]\n  mouse_deadzone\t= 20  \nmouse_speed = 1200\npreset = demo\nui_circle = q\n"
        "cross = enter\n; keep this comment\n[debug]\nwinedebug = +seh\nenv = PW_CUSTOM=1\n"
        "[runtime]\ncpu = translator\nshared_input = true\n";
    static const char expected[] = APP "# untouched application comment\n[display]\ndesktop = 800x600\n"
        "[InPuT]\n  mouse_deadzone\t= 12  \nmouse_speed = 1200\npreset = demo\nui_circle = q\n"
        "cross = enter\n; keep this comment\nstart_mode = mouse\ntouch_speed = 150\n"
        "[debug]\nwinedebug = +seh\nenv = PW_CUSTOM=1\n[runtime]\ncpu = translator\nshared_input = true\n";
    uint8_t out[PW_APP_PROFILE_MAX_BYTES]; size_t size = 0;
    assert(pw_controller_profile_update((const uint8_t *)before, strlen(before), &values,
        PW_CONTROLLER_START | PW_CONTROLLER_DEADZONE | PW_CONTROLLER_TOUCH, out, sizeof(out), &size) == PW_OK);
    assert(size == strlen(expected) && !memcmp(out, expected, size));
    /* No-op preserves inheritance and every byte. */
    assert(pw_controller_profile_update((const uint8_t *)before, strlen(before), &values, 0, out, sizeof(out), &size) == PW_OK);
    assert(size == strlen(before) && !memcmp(out, before, size));
    /* No input section, and no trailing newline. In-place rewrite is safe. */
    memcpy(out, APP, strlen(APP) - 1); size = strlen(APP) - 1;
    assert(pw_controller_profile_update(out, size, &values, PW_CONTROLLER_FIELDS, out, sizeof(out), &size) == PW_OK);
    out[size] = 0;
    assert(strstr((const char *)out, "\n[input]\nstart_mode = mouse\nmouse_deadzone = 12\nmouse_speed = 1800\ntouch_speed = 150\n"));
    /* Last input line, CRLFs and standalone CRs preserve their delimiters. */
    const char *tail = "[input]\r\n  START_MODE = profile\t\r\n# keep\r\n";
    char input[PW_APP_PROFILE_MAX_BYTES]; strcpy(input, APP); strcat(input, tail);
    assert(pw_controller_profile_update((const uint8_t *)input, strlen(input), &values,
        PW_CONTROLLER_START, out, sizeof(out), &size) == PW_OK);
    out[size] = 0; assert(strstr((char *)out, "  START_MODE = mouse\t\r\n# keep\r\n"));
    size_t n = 0;
    for (size_t i = 0; i < strlen(APP); i++) { input[n++] = APP[i] == '\n' ? '\r' : APP[i]; }
    memcpy(input + n, "[input]\r", 8); n += 8;
    assert(pw_controller_profile_update((uint8_t *)input, n, &values, PW_CONTROLLER_TOUCH, out, sizeof(out), &size) == PW_OK);
    out[size] = 0; assert(strstr((char *)out, "[input]\rtouch_speed = 150\r"));
}
static void failures(void)
{
    uint8_t out[PW_APP_PROFILE_MAX_BYTES], before[PW_APP_PROFILE_MAX_BYTES];
    memset(out, 0xa5, sizeof(out)); memcpy(before, out, sizeof(out));
    PwControllerValues invalid = values; size_t length = 777;
    for (unsigned i = 0; i < 8; i++) {
        invalid = values;
        switch (i) {
        case 0: invalid.start_mode = (PwGameStartMode)-1; break;
        case 1: invalid.start_mode = (PwGameStartMode)2; break;
        case 2: invalid.mouse_deadzone = 121; break;
        case 3: invalid.mouse_speed = 0; break;
        case 4: invalid.mouse_speed = 20001; break;
        case 5: invalid.touch_speed = 24; break;
        case 6: invalid.touch_speed = 401; break;
        default: invalid.mouse_deadzone = UINT32_MAX; break;
        }
        assert(pw_controller_profile_update((uint8_t *)APP, strlen(APP), &invalid,
            PW_CONTROLLER_FIELDS, out, sizeof(out), &length) == PW_ERR_MALFORMED);
        assert(length == 777 && !memcmp(out, before, sizeof(out)));
    }
    assert(pw_controller_profile_update((uint8_t *)APP, strlen(APP), &values, 16, out, sizeof(out), &length) == PW_ERR_MALFORMED);
    assert(pw_controller_profile_update((uint8_t *)APP, strlen(APP), &values, PW_CONTROLLER_FIELDS, out, 1, &length) == PW_ERR_LIMIT);
    const char *duplicate = APP "[input]\nmouse_deadzone = 20\nmouse_deadzone = 10\n";
    assert(pw_controller_profile_update((uint8_t *)duplicate, strlen(duplicate), &values, PW_CONTROLLER_FIELDS, out, sizeof(out), &length) == PW_ERR_MALFORMED);
    const char *unknown = APP "[future]\nhello = 1\n";
    assert(pw_controller_profile_update((uint8_t *)unknown, strlen(unknown), &values, PW_CONTROLLER_FIELDS, out, sizeof(out), &length) != PW_OK);
    assert(length == 777 && !memcmp(out, before, sizeof(out)));
    uint8_t large[PW_APP_PROFILE_MAX_BYTES]; memcpy(large, APP, strlen(APP));
    large[strlen(APP)] = '#'; memset(large + strlen(APP) + 1, 'x', sizeof(large) - strlen(APP) - 2); large[sizeof(large) - 1] = '\n';
    assert(pw_controller_profile_update(large, sizeof(large), &values, PW_CONTROLLER_FIELDS, out, sizeof(out), &length) == PW_ERR_LIMIT);
    assert(length == 777 && !memcmp(out, before, sizeof(out)));
}
static int calls, save_result; static uint32_t saved_fields;
static int save(void *context, const PwControllerValues *v, uint32_t fields)
{
    assert(context == &calls && pw_controller_values_valid(v)); calls++; saved_fields = fields; return save_result;
}
static void controls(void)
{
    PwGameInput input; PwControllerSettings s;
    pw_game_input_init(&input);
    assert(pw_controller_settings_open(&s, &input) == PW_OK && s.active && s.selected == 0);
    assert(s.draft.mouse_speed == 1200 && s.draft.mouse_deadzone == 20 && s.draft.touch_speed == 100);
    pw_controller_settings_control(&s, PW_LAUNCHER_ACTION_UP, save, &calls); assert(!s.selected);
    pw_controller_settings_control(&s, PW_LAUNCHER_ACTION_RIGHT, save, &calls); assert(s.draft.start_mode == PW_GAME_START_MOUSE);
    pw_controller_settings_control(&s, PW_LAUNCHER_ACTION_DOWN, save, &calls); assert(s.selected == 1);
    pw_controller_settings_control(&s, PW_LAUNCHER_ACTION_LEFT, save, &calls); assert(s.draft.mouse_deadzone == 19);
    for (unsigned i = 0; i < 30; i++) pw_controller_settings_control(&s, PW_LAUNCHER_ACTION_PAGE_PREVIOUS, save, &calls);
    assert(!s.draft.mouse_deadzone);
    for (unsigned i = 0; i < 30; i++) pw_controller_settings_control(&s, PW_LAUNCHER_ACTION_PAGE_NEXT, save, &calls);
    assert(s.draft.mouse_deadzone == 120);
    pw_controller_settings_control(&s, PW_LAUNCHER_ACTION_DOWN, save, &calls);
    for (unsigned i = 0; i < 30; i++) pw_controller_settings_control(&s, PW_LAUNCHER_ACTION_PAGE_NEXT, save, &calls);
    assert(s.draft.mouse_speed == 20000);
    for (unsigned i = 0; i < 30; i++) pw_controller_settings_control(&s, PW_LAUNCHER_ACTION_PAGE_PREVIOUS, save, &calls);
    assert(s.draft.mouse_speed == 1);
    pw_controller_settings_control(&s, PW_LAUNCHER_ACTION_DOWN, save, &calls);
    for (unsigned i = 0; i < 90; i++) pw_controller_settings_control(&s, PW_LAUNCHER_ACTION_RIGHT, save, &calls);
    assert(s.draft.touch_speed == 400);
    for (unsigned i = 0; i < 90; i++) pw_controller_settings_control(&s, PW_LAUNCHER_ACTION_LEFT, save, &calls);
    assert(s.draft.touch_speed == 25);
    PwControllerValues original = s.original;
    assert(pw_controller_settings_control(&s, PW_LAUNCHER_ACTION_BACK, save, &calls) == PW_CONTROLLER_CANCELED);
    assert(!s.active && !calls && !pw_controller_values_changed(&s.draft, &original));
    /* Reopening after cancel has no leftover draft. */
    assert(pw_controller_settings_open(&s, &input) == PW_OK);
    s.selected = PW_CONTROLLER_APPLY;
    assert(pw_controller_settings_control(&s, PW_LAUNCHER_ACTION_CHOOSE, save, &calls) == PW_CONTROLLER_APPLIED && !calls);
    assert(pw_controller_settings_open(&s, &input) == PW_OK);
    s.draft.touch_speed = 200; s.selected = PW_CONTROLLER_APPLY; save_result = PW_ERR_VM;
    assert(pw_controller_settings_control(&s, PW_LAUNCHER_ACTION_CHOOSE, save, &calls) == PW_CONTROLLER_CONTINUE);
    assert(s.active && s.error == PW_ERR_VM && s.original.touch_speed == 100 && s.draft.touch_speed == 200 && calls == 1);
    save_result = PW_OK;
    assert(pw_controller_settings_control(&s, PW_LAUNCHER_ACTION_CHOOSE, save, &calls) == PW_CONTROLLER_APPLIED);
    assert(!s.active && s.original.touch_speed == 200 && calls == 2 && saved_fields == PW_CONTROLLER_TOUCH);
    /* A queued choose after dismissal never re-saves. */
    assert(pw_controller_settings_control(&s, PW_LAUNCHER_ACTION_CHOOSE, save, &calls) == PW_CONTROLLER_CONTINUE && calls == 2);
    assert(pw_controller_settings_open(&s, &input) == PW_OK);
    s.draft.mouse_speed = UINT32_MAX; s.selected = PW_CONTROLLER_APPLY;
    assert(pw_controller_settings_control(&s, PW_LAUNCHER_ACTION_CHOOSE, save, &calls) == PW_CONTROLLER_CONTINUE);
    assert(s.error == PW_ERR_MALFORMED && calls == 2 && s.active);
    s.selected = PW_CONTROLLER_CANCEL;
    pw_controller_settings_control(&s, PW_LAUNCHER_ACTION_DOWN, save, &calls); assert(s.selected == PW_CONTROLLER_CANCEL);
    assert(pw_controller_settings_control(&s, PW_LAUNCHER_ACTION_CHOOSE, save, &calls) == PW_CONTROLLER_CANCELED);
    assert(!pw_controller_values_changed(&s.draft, &s.original));
    input.mouse_speed = 0;
    PwControllerSettings old = s;
    assert(pw_controller_settings_open(&s, &input) == PW_ERR_MALFORMED && !memcmp(&s, &old, sizeof(s)));
}
int main(void) { updates(); failures(); controls(); puts("controller settings passed"); return 0; }
