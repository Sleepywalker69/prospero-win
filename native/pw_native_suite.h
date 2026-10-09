/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_NATIVE_SUITE_H
#define PW_NATIVE_SUITE_H
#include <stddef.h>
enum { PW_SUITE_SOCKET, PW_SUITE_SERVICE, PW_SUITE_LEGACY, PW_SUITE_COUNT };
const char *pw_native_suite_title(void);
const char *pw_native_suite_item(unsigned);
int pw_native_suite_available(unsigned);
int pw_native_suite_start(unsigned);
void pw_native_suite_cancel(void);
void pw_native_suite_tick(void);
void pw_native_suite_status(char *, size_t);
#endif
