/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_WINE_CHILD_TITLE_H
#define PW_WINE_CHILD_TITLE_H
#include "../src/pw_game_profile.h"
#include "../wine/ps5/pw_wine_prx.h"

/* Compiled only in the explicit child experiment. A zero profile result does
 * not authorize an experimental launch; ordinary profiles retain their own
 * existing launch path. The exact two reserved identifiers must be refused by
 * the caller if their profile fails validation. */
extern const char pw_wine_child_title_marker[];
unsigned pw_wine_child_title_profile(const PwGameProfile *profile);
/* Fixture hash is copied into process-lifetime storage. NULL is required for
 * Battle mode, whose user-supplied images remain Wine's lookup authority. */
int pw_wine_child_title_prepare(unsigned profile, const char *fixture_child_sha256);
/* Call once, after validated module loading and before any Wine guest entry.
 * The descriptor and every installed callback remain pinned until title exit. */
int pw_wine_child_title_install(const PwPrxDescriptor *descriptor);
void pw_wine_child_title_cancel(void);
/* Safe for an ordinary title before activation. Once the supervisor starts,
 * only the owner's actual safe-release publication can permit replacement. */
int pw_wine_child_title_restart_ready(void);
#endif
