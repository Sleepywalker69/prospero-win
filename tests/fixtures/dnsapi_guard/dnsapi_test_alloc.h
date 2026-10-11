/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Read real platform declarations before replacing only CRT allocation calls. */
#include <stdlib.h>
#include <wchar.h>
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "winerror.h"
#include "winnls.h"
#include "windns.h"
#include "nb30.h"
#include "ws2def.h"
#include "inaddr.h"
#include "in6addr.h"
#include "ip2string.h"
#include "wine/debug.h"
#include "wine/unixlib.h"
void *dns_test_malloc(size_t);
void *dns_test_calloc(size_t,size_t);
void dns_test_free(void *);
char *dns_test_strdup(const char *);
#define malloc dns_test_malloc
#define calloc dns_test_calloc
#define free dns_test_free
#define strdup dns_test_strdup
