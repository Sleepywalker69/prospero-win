/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_NATIVE_CHILD_PROBE_H
#define PW_NATIVE_CHILD_PROBE_H
#include <stddef.h>

/* One operator-selected attempt per title process. All socket ownership stays
 * with the controller; UI Stop never closes or reuses its descriptor. */
const char *pw_native_child_probe_title(void);
int pw_native_child_probe_start(void);
void pw_native_child_probe_cancel(void);
void pw_native_child_probe_tick(void); /* called after a successful UI-loop present */
void pw_native_child_probe_status(char *text, size_t capacity);
#endif
