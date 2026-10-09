/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Pure modeled subset of ps5-payload-sdk v0.42 target ABI. No system calls. */
#ifndef TEST_PEER_SOCKET_H
#define TEST_PEER_SOCKET_H
#include <stdint.h>
#include <sys/types.h>
#include <sys/uio.h>
typedef uint32_t socklen_t;
struct sockaddr { uint8_t sa_len, sa_family; char sa_data[14]; };
struct msghdr { void *msg_name; socklen_t msg_namelen; struct iovec *msg_iov;
    int msg_iovlen; void *msg_control; socklen_t msg_controllen; int msg_flags; };
struct cmsghdr { socklen_t cmsg_len; int cmsg_level, cmsg_type; };
#define CMGROUP_MAX 16
struct cmsgcred { int32_t cmcred_pid; uint32_t cmcred_uid,cmcred_euid,cmcred_gid;
    int16_t cmcred_ngroups; uint32_t cmcred_groups[CMGROUP_MAX]; };
#define TEST_ALIGN(n) (((n)+7u)&~7u)
#define CMSG_DATA(c) ((unsigned char *)(c)+TEST_ALIGN(sizeof(struct cmsghdr)))
#define CMSG_SPACE(n) (TEST_ALIGN(sizeof(struct cmsghdr))+TEST_ALIGN(n))
#define CMSG_LEN(n) (TEST_ALIGN(sizeof(struct cmsghdr))+(n))
#define CMSG_FIRSTHDR(m) ((m)->msg_controllen>=sizeof(struct cmsghdr)?(struct cmsghdr *)(m)->msg_control:NULL)
#define CMSG_NXTHDR(m,c) ((char *)(c)==NULL?CMSG_FIRSTHDR(m):((char *)(c)+TEST_ALIGN((c)->cmsg_len)+TEST_ALIGN(sizeof(struct cmsghdr))>(char *)(m)->msg_control+(m)->msg_controllen)?NULL:(struct cmsghdr *)(void *)((char *)(c)+TEST_ALIGN((c)->cmsg_len)))
#define AF_UNIX 1
#define SOCK_STREAM 1
#define SOL_SOCKET 0xffff
#define SCM_RIGHTS 1
#define SCM_CREDS 3
#define SO_NOSIGPIPE 0x0800
#define MSG_TRUNC 0x10
#define MSG_CTRUNC 0x20
#endif
