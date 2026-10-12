/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_WINE_CHILD_UI_CONFIG_H
#define PW_WINE_CHILD_UI_CONFIG_H
#ifndef PW_WINE_CHILD_UI_ENABLED
#define PW_WINE_CHILD_UI_ENABLED 0
#endif
#if PW_WINE_CHILD_UI_ENABLED != 0 && PW_WINE_CHILD_UI_ENABLED != 1
#error PW_WINE_CHILD_UI_ENABLED must be zero or one
#endif
/* Read-only child preview. Cross-process focus/input remains disabled. */
#define PW_WINE_CHILD_UI_INPUT_ENABLED 0
#endif
