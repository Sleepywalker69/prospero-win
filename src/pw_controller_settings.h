/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_CONTROLLER_SETTINGS_H
#define PW_CONTROLLER_SETTINGS_H
#include "pw_game_profile.h"
#include "pw_launcher_render.h"

/* The launcher edits only these scalar settings, never bindings or game state. */
typedef struct PwControllerValues {
    PwGameStartMode start_mode;
    uint32_t mouse_deadzone, mouse_speed, touch_speed;
} PwControllerValues;
enum {
    PW_CONTROLLER_START = 1u, PW_CONTROLLER_DEADZONE = 2u,
    PW_CONTROLLER_STICK = 4u, PW_CONTROLLER_TOUCH = 8u,
    PW_CONTROLLER_FIELDS = 15u, PW_CONTROLLER_APPLY = 4,
    PW_CONTROLLER_CANCEL = 5, PW_CONTROLLER_ROWS = 6
};
int pw_controller_values_valid(const PwControllerValues *values);
void pw_controller_values_from_input(PwControllerValues *values, const PwGameInput *input);
uint32_t pw_controller_values_changed(const PwControllerValues *before,
                                      const PwControllerValues *after);
/* Validate the original profile, replace just the selected scalar VALUES,
 * and insert absent keys in [input]. All other bytes survive unchanged.
 * The caller's output and length remain untouched on failure. Input/output
 * may overlap. No allocator, I/O, or libc formatting dependency. */
int pw_controller_profile_update(const uint8_t *bytes, size_t length,
                                 const PwControllerValues *values, uint32_t fields,
                                 uint8_t *output, size_t capacity, size_t *output_length);

typedef struct PwControllerSettings {
    PwControllerValues original, draft;
    uint32_t selected;
    int active, error;
} PwControllerSettings;
/* Called only on Apply with valid changed values. PW_OK commits the draft;
 * failure keeps the dialog open with the original values intact. */
typedef int (*PwControllerSave)(void *context, const PwControllerValues *values,
                                uint32_t fields);
enum { PW_CONTROLLER_CONTINUE, PW_CONTROLLER_APPLIED, PW_CONTROLLER_CANCELED };
int pw_controller_settings_open(PwControllerSettings *settings, const PwGameInput *input);
int pw_controller_settings_control(PwControllerSettings *settings, PwLauncherAction action,
                                    PwControllerSave save, void *context);
#endif
