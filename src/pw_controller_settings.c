/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_controller_settings.h"
#include <string.h>

int pw_controller_values_valid(const PwControllerValues *v)
{
    return v && (v->start_mode == PW_GAME_START_PROFILE || v->start_mode == PW_GAME_START_MOUSE) &&
        v->mouse_deadzone <= PW_GAME_MOUSE_DEADZONE_MAX && v->mouse_speed >= 1 &&
        v->mouse_speed <= PW_GAME_MOUSE_SPEED_MAX && v->touch_speed >= PW_GAME_TOUCH_SPEED_MIN &&
        v->touch_speed <= PW_GAME_TOUCH_SPEED_MAX;
}
void pw_controller_values_from_input(PwControllerValues *v, const PwGameInput *input)
{
    if (!v || !input) return;
    *v = (PwControllerValues){ input->start_mode, input->mouse_deadzone,
                              input->mouse_speed, input->touch_speed };
}
uint32_t pw_controller_values_changed(const PwControllerValues *a, const PwControllerValues *b)
{
    if (!a || !b) return 0;
    return (a->start_mode != b->start_mode ? PW_CONTROLLER_START : 0u) |
        (a->mouse_deadzone != b->mouse_deadzone ? PW_CONTROLLER_DEADZONE : 0u) |
        (a->mouse_speed != b->mouse_speed ? PW_CONTROLLER_STICK : 0u) |
        (a->touch_speed != b->touch_speed ? PW_CONTROLLER_TOUCH : 0u);
}
static const char *const keys[] = { "start_mode", "mouse_deadzone", "mouse_speed", "touch_speed" };
static int word(const uint8_t *begin, const uint8_t *end, const char *key)
{
    if ((size_t)(end - begin) != strlen(key)) return 0;
    for (; begin != end; begin++, key++) {
        uint8_t c = *begin;
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (c != (uint8_t)*key) return 0;
    }
    return 1;
}
static int whitespace(uint8_t c) { return c == ' ' || c == '\t'; }
static size_t value_text(const PwControllerValues *v, unsigned field, char *out)
{
    if (!field) {
        const char *mode = v->start_mode == PW_GAME_START_MOUSE ? "mouse" : "profile";
        size_t length = strlen(mode); memcpy(out, mode, length); return length;
    }
    uint32_t value = field == 1 ? v->mouse_deadzone : field == 2 ? v->mouse_speed : v->touch_speed;
    char digits[10]; size_t count = 0, length = 0;
    do { digits[count++] = (char)('0' + value % 10); value /= 10; } while (value);
    while (count) out[length++] = digits[--count];
    return length;
}
static int append(uint8_t *out, size_t *used, const void *bytes, size_t length)
{
    /* Keep strictly below the library loader's existing file-size limit. */
    if (length >= PW_APP_PROFILE_MAX_BYTES - *used) return PW_ERR_LIMIT;
    memcpy(out + *used, bytes, length); *used += length; return PW_OK;
}
static int missing(uint8_t *out, size_t *used, uint32_t fields, const PwControllerValues *values,
                    const char *newline, size_t newline_length)
{
    if (!fields) return PW_OK;
    if (*used && out[*used - 1] != '\r' && out[*used - 1] != '\n' &&
        append(out, used, newline, newline_length) != PW_OK) return PW_ERR_LIMIT;
    for (unsigned i = 0; i < 4; i++) if (fields & (1u << i)) {
        char number[10]; size_t length = value_text(values, i, number);
        if (append(out, used, keys[i], strlen(keys[i])) != PW_OK ||
            append(out, used, " = ", 3) != PW_OK || append(out, used, number, length) != PW_OK ||
            append(out, used, newline, newline_length) != PW_OK) return PW_ERR_LIMIT;
    }
    return PW_OK;
}
int pw_controller_profile_update(const uint8_t *bytes, size_t length,
                                 const PwControllerValues *values, uint32_t fields,
                                 uint8_t *output, size_t capacity, size_t *output_length)
{
    uint8_t result[PW_APP_PROFILE_MAX_BYTES];
    PwGameProfile parsed;
    size_t cursor = 0, used = 0, newline_length = 1;
    uint32_t remaining = fields;
    const char *newline = "\n";
    int input = 0, saw_input = 0, status;
    if (!bytes || !output || !output_length || !values) return PW_ERR_PRECONDITION;
    if (!pw_controller_values_valid(values) || (fields & ~PW_CONTROLLER_FIELDS)) return PW_ERR_MALFORMED;
    if ((status = pw_game_profile_parse(bytes, length, &parsed)) != PW_OK) return status;
    for (size_t i = 0; i < length; i++) if (bytes[i] == '\r' || bytes[i] == '\n') {
        if (bytes[i] == '\r') {
            newline = "\r";
            if (i + 1 < length && bytes[i + 1] == '\n') newline = "\r\n", newline_length = 2;
        }
        break;
    }
    while (cursor < length) {
        size_t start = cursor, end, next;
        while (cursor < length && bytes[cursor] != '\r' && bytes[cursor] != '\n') cursor++;
        end = cursor;
        if (cursor < length && bytes[cursor++] == '\r' && cursor < length && bytes[cursor] == '\n') cursor++;
        next = cursor;
        const uint8_t *begin = bytes + start, *finish = bytes + end;
        while (begin < finish && whitespace(*begin)) begin++;
        while (finish > begin && whitespace(finish[-1])) finish--;
        if (begin < finish && *begin == '[') {
            if (input) {
                if (missing(result, &used, remaining, values, newline, newline_length) != PW_OK) return PW_ERR_LIMIT;
                remaining = 0;
            }
            input = word(begin, finish, "[input]");
            if (input) saw_input = 1;
        }
        int field = -1;
        const uint8_t *value = NULL, *equals = NULL;
        if (input && begin < finish && *begin != '#' && *begin != ';' && *begin != '[') {
            equals = memchr(begin, '=', (size_t)(finish - begin));
            if (equals) {
                const uint8_t *key_end = equals;
                while (key_end > begin && whitespace(key_end[-1])) key_end--;
                for (unsigned i = 0; i < 4; i++)
                    if ((remaining & (1u << i)) && word(begin, key_end, keys[i])) field = (int)i;
                value = equals + 1;
                while (value < finish && whitespace(*value)) value++;
            }
        }
        if (field >= 0) {
            char number[10]; size_t count = value_text(values, (unsigned)field, number);
            if (append(result, &used, bytes + start, (size_t)(value - bytes - start)) != PW_OK ||
                append(result, &used, number, count) != PW_OK ||
                append(result, &used, finish, (size_t)(bytes + next - finish)) != PW_OK) return PW_ERR_LIMIT;
            remaining &= ~(1u << (unsigned)field);
        } else if (append(result, &used, bytes + start, next - start) != PW_OK) return PW_ERR_LIMIT;
    }
    if (remaining) {
        if (!saw_input) {
            if (used && result[used - 1] != '\n' && result[used - 1] != '\r' &&
                append(result, &used, newline, newline_length) != PW_OK) return PW_ERR_LIMIT;
            if (append(result, &used, "[input]", 7) != PW_OK ||
                append(result, &used, newline, newline_length) != PW_OK) return PW_ERR_LIMIT;
        }
        if (missing(result, &used, remaining, values, newline, newline_length) != PW_OK) return PW_ERR_LIMIT;
    }
    if (used > capacity) return PW_ERR_LIMIT;
    if ((status = pw_game_profile_parse(result, used, &parsed)) != PW_OK) return status;
    memcpy(output, result, used); *output_length = used;
    return PW_OK;
}

int pw_controller_settings_open(PwControllerSettings *settings, const PwGameInput *input)
{
    PwControllerSettings opened;
    if (!settings || !input) return PW_ERR_PRECONDITION;
    memset(&opened, 0, sizeof(opened));
    pw_controller_values_from_input(&opened.original, input);
    if (!pw_controller_values_valid(&opened.original)) return PW_ERR_MALFORMED;
    opened.draft = opened.original; opened.active = 1;
    *settings = opened;
    return PW_OK;
}
static uint32_t adjusted(uint32_t value, uint32_t minimum, uint32_t maximum, uint32_t step, int up)
{
    if (up) return maximum - value < step ? maximum : value + step;
    return value - minimum < step ? minimum : value - step;
}
int pw_controller_settings_control(PwControllerSettings *s, PwLauncherAction action,
                                    PwControllerSave save, void *context)
{
    if (!s || !s->active) return PW_CONTROLLER_CONTINUE;
    if (action == PW_LAUNCHER_ACTION_BACK ||
        (s->selected == PW_CONTROLLER_CANCEL && action == PW_LAUNCHER_ACTION_CHOOSE)) {
        s->draft = s->original; s->active = 0; s->error = PW_OK;
        return PW_CONTROLLER_CANCELED;
    }
    if (s->selected >= PW_CONTROLLER_ROWS) { s->error = PW_ERR_PRECONDITION; return PW_CONTROLLER_CONTINUE; }
    if (action == PW_LAUNCHER_ACTION_UP) { if (s->selected) s->selected--; }
    else if (action == PW_LAUNCHER_ACTION_DOWN) { if (s->selected + 1 < PW_CONTROLLER_ROWS) s->selected++; }
    else if (s->selected == PW_CONTROLLER_APPLY && action == PW_LAUNCHER_ACTION_CHOOSE) {
        if (!pw_controller_values_valid(&s->draft)) s->error = PW_ERR_MALFORMED;
        else {
            uint32_t fields = pw_controller_values_changed(&s->original, &s->draft);
            s->error = fields ? (save ? save(context, &s->draft, fields) : PW_ERR_PRECONDITION) : PW_OK;
            if (s->error == PW_OK) {
                s->original = s->draft; s->active = 0;
                return PW_CONTROLLER_APPLIED;
            }
        }
    } else if (s->selected < PW_CONTROLLER_APPLY &&
               (action == PW_LAUNCHER_ACTION_LEFT || action == PW_LAUNCHER_ACTION_RIGHT ||
                action == PW_LAUNCHER_ACTION_PAGE_PREVIOUS || action == PW_LAUNCHER_ACTION_PAGE_NEXT)) {
        if (!pw_controller_values_valid(&s->draft)) { s->error = PW_ERR_MALFORMED; return PW_CONTROLLER_CONTINUE; }
        int up = action == PW_LAUNCHER_ACTION_RIGHT || action == PW_LAUNCHER_ACTION_PAGE_NEXT;
        int coarse = action == PW_LAUNCHER_ACTION_PAGE_PREVIOUS || action == PW_LAUNCHER_ACTION_PAGE_NEXT;
        if (!s->selected) s->draft.start_mode = up ? PW_GAME_START_MOUSE : PW_GAME_START_PROFILE;
        else if (s->selected == 1)
            s->draft.mouse_deadzone = adjusted(s->draft.mouse_deadzone, 0, PW_GAME_MOUSE_DEADZONE_MAX, coarse ? 10 : 1, up);
        else if (s->selected == 2)
            s->draft.mouse_speed = adjusted(s->draft.mouse_speed, 1, PW_GAME_MOUSE_SPEED_MAX, coarse ? 1000 : 100, up);
        else s->draft.touch_speed = adjusted(s->draft.touch_speed, PW_GAME_TOUCH_SPEED_MIN,
                                             PW_GAME_TOUCH_SPEED_MAX, coarse ? 25 : 5, up);
        s->error = PW_OK;
    }
    return PW_CONTROLLER_CONTINUE;
}
