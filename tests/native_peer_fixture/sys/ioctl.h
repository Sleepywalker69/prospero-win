/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Pinned SDK ioctl ABI, consumed only by target-modeled OS mocks. */
#ifndef TEST_PEER_IOCTL_H
#define TEST_PEER_IOCTL_H
#define FIOCLEX 0x20006601UL
#define FIONBIO 0x8004667eUL
int ioctl(int, unsigned long, ...);
_Static_assert(sizeof(int)==4 && sizeof(unsigned long)==8,"target ioctl ABI");
#endif
