/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef TEST_PEER_UN_H
#define TEST_PEER_UN_H
struct sockaddr_un { unsigned char sun_len, sun_family; char sun_path[104]; };
#endif
