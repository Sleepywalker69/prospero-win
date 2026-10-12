/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_WINE_CONTROLLER_SETTINGS_H
#define PW_WINE_CONTROLLER_SETTINGS_H
#include "pw_wine_library.h"
#include "../src/pw_controller_settings.h"

typedef struct PwWineControllerEdit {
    char path[PW_WINE_LIBRARY_PATH + PW_WINE_LIBRARY_NAME];
    uint8_t before[PW_APP_PROFILE_MAX_BYTES];
    size_t before_length;
    PwGameProfile profile;
    PwControllerSettings screen;
    int preset_status;
} PwWineControllerEdit;
/* Read a fresh validated regular profile and its effective preset values.
 * Refuse symlinks. The caller's edit is unchanged on failure. */
int pw_wine_controller_edit_open(PwWineControllerEdit *edit, const char *root, const char *file);
/* Save callback: compare the open-time snapshot before changing anything,
 * write/fsync/close a new exclusive sibling, check the snapshot again, then
 * atomically rename it over the profile. Never overwrites a stale temporary.
 * The snapshot changes only on success. Use only while in the launcher;
 * concurrent external profile editing is unsupported (rename is not CAS).
 * Atomic visibility is guaranteed; power-loss directory durability is not. */
int pw_wine_controller_edit_save(void *context, const PwControllerValues *values, uint32_t fields);
#endif
