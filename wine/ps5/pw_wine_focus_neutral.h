/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_WINE_FOCUS_NEUTRAL_H
#define PW_WINE_FOCUS_NEUTRAL_H
#ifndef PW_WINE_FOCUS_NEUTRAL
#define PW_WINE_FOCUS_NEUTRAL 0
#endif
#if PW_WINE_FOCUS_NEUTRAL != 0 && PW_WINE_FOCUS_NEUTRAL != 1
#error "PW_WINE_FOCUS_NEUTRAL must be zero or one"
#endif
#if PW_WINE_FOCUS_NEUTRAL
#include "wine/pw_focus_build.h"
#if PW_FOCUS_BUILD_MODE != 1 || PW_FOCUS_BUILD_PROTOCOL != 963
#error "focus-neutral requires the generated neutral 963 cohort"
#endif
_Static_assert(sizeof(PW_FOCUS_BUILD_SOURCE_SHA256)==65,"focus source identity");
#endif
/* Compile-only refusal. No prefix, including an existing 962 prefix, is
 * admissible. This must precede logging, bootstrap and filesystem entry.
 * There is deliberately no mode setter or mid-run untracked fallback. */
static inline int pw_wine_focus_native_entry_refused(void)
{
#if PW_WINE_FOCUS_NEUTRAL
    /* Volatile read preserves the complete target link/compile graph even
     * though this immutable cohort always refuses execution. No setter. */
    static const volatile int refused = 1;
    return refused;
#else
    return 0;
#endif
}
#endif
