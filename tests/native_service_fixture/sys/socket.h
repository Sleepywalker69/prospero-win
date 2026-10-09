/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Original mock-only subset of public SDK v0.42 sys/socket.h. */
#ifndef TEST_SERVICE_SOCKET_H
#define TEST_SERVICE_SOCKET_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/uio.h>
typedef uint32_t socklen_t;
struct msghdr { void *msg_name; socklen_t msg_namelen; struct iovec *msg_iov;
    int msg_iovlen; void *msg_control; socklen_t msg_controllen; int msg_flags; };
struct cmsghdr { socklen_t cmsg_len; int cmsg_level, cmsg_type; };
#define MOCK_ALIGN(n) (((n) + 7u) & ~7u)
#define CMSG_LEN(n) (MOCK_ALIGN(sizeof(struct cmsghdr)) + (n))
#define CMSG_SPACE(n) (MOCK_ALIGN(sizeof(struct cmsghdr)) + MOCK_ALIGN(n))
#define CMSG_DATA(c) ((unsigned char *)(c) + MOCK_ALIGN(sizeof(struct cmsghdr)))
#define SOL_SOCKET 0xffff
#define SO_TYPE 0x1008
#define SOCK_SEQPACKET 5
#define SCM_RIGHTS 1
#define MSG_EOR 0x8
#define MSG_TRUNC 0x10
#define MSG_CTRUNC 0x20
#define MSG_DONTWAIT 0x80
#define MSG_NOSIGNAL 0x20000
int getsockopt(int, int, int, void *, socklen_t *);
ssize_t recvmsg(int, struct msghdr *, int);
ssize_t sendmsg(int, const struct msghdr *, int);
_Static_assert(sizeof(struct cmsghdr) == 12, "SDK control header layout");
_Static_assert(sizeof(struct msghdr) == 48, "SDK message layout");
_Static_assert(offsetof(struct msghdr, msg_control) == 32, "SDK control offset");
_Static_assert(offsetof(struct msghdr, msg_flags) == 44, "SDK flags offset");
#endif
