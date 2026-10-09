/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Values/layouts from SDK v0.42 sys/event.h, sys/socket.h, sys/sysctl.h,
 * sys/wait.h. The fixture models responses; it cannot establish kernel support. */
#ifndef TEST_PEER_ABI_H
#define TEST_PEER_ABI_H
#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <sys/socket.h>
struct kevent { uintptr_t ident; short filter; unsigned short flags;
    unsigned int fflags; intptr_t data; void *udata; };
#define EVFILT_PROC (-5)
#define EV_ADD 0x0001
#define EV_ENABLE 0x0004
#define EV_RECEIPT 0x0040
#define EV_EOF 0x8000
#define EV_ERROR 0x4000
#define NOTE_EXIT 0x80000000u
#define EV_SET(k,a,b,c,d,e,f) (*(k)=(struct kevent){(a),(b),(c),(d),(e),(f)})
#define CTL_KERN 1
#define KERN_ARND 37
#define W_EXITCODE(ret,sig) ((ret)<<8|(sig))
_Static_assert(sizeof(struct cmsghdr)==12,"target cmsghdr");
_Static_assert(sizeof(struct cmsgcred)==84,"target cmsgcred");
_Static_assert(offsetof(struct cmsgcred,cmcred_groups)==20,"target groups");
_Static_assert(sizeof(struct kevent)==32,"target kevent");
_Static_assert(offsetof(struct kevent,data)==16,"target kevent data");
_Static_assert(sizeof(struct msghdr)==48,"target msghdr");
#endif
