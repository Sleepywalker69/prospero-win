/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_WINDOWS_CHILD_NETWORK_CONTRACT_H
#define PW_WINDOWS_CHILD_NETWORK_CONTRACT_H
#include <stddef.h>
#include <stdint.h>
/* Windows IPv4/TCP output shape, with network-order bytes rather than a
 * second conversion API. Caller first checks the non-NULL address pointer. */
static inline int pw_net_ipv4_shape(unsigned family,size_t length,unsigned type,
                                   unsigned protocol,const unsigned char port[2],
                                   const unsigned char address[4],int loopback)
{
    if(family!=2||length!=16||type!=1||protocol!=6||!port||!address||
       port[0]!=0||port[1]!=80)return 0;
    return !loopback||(address[0]==127&&address[1]==0&&address[2]==0&&address[3]==1);
}
/* DNS_CONFIG_DNS_SERVER_LIST uses IP4_ARRAY: one DWORD count followed by
 * count DWORD addresses. No addresses are logged by this control. */
static inline int pw_net_dns_config_shape(uint32_t capacity,uint32_t length,uint32_t count)
{
    return length>=4&&length<=capacity&&count<=64&&count<=(length-4)/4;
}
#endif
