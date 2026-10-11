/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_SHA256_H
#define PW_SHA256_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
typedef struct PwSha256 { uint32_t h[8]; uint64_t bytes; unsigned used; unsigned char block[64]; } PwSha256;
static uint32_t pw_sha256_rotate(uint32_t v,unsigned n){return(v>>n)|(v<<(32-n));}
static inline void pw_sha256_block(PwSha256 *h)
{
    static const uint32_t k[64]={
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    uint32_t w[64];for(unsigned i=0;i<16;i++){const unsigned char*p=h->block+4*i;
        w[i]=((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];}
    for(unsigned i=16;i<64;i++)w[i]=w[i-16]+(pw_sha256_rotate(w[i-15],7)^pw_sha256_rotate(w[i-15],18)^(w[i-15]>>3))+
        w[i-7]+(pw_sha256_rotate(w[i-2],17)^pw_sha256_rotate(w[i-2],19)^(w[i-2]>>10));
    uint32_t a=h->h[0],b=h->h[1],c=h->h[2],d=h->h[3],e=h->h[4],f=h->h[5],g=h->h[6],v=h->h[7];
    for(unsigned i=0;i<64;i++){uint32_t t=v+(pw_sha256_rotate(e,6)^pw_sha256_rotate(e,11)^pw_sha256_rotate(e,25))+((e&f)^(~e&g))+k[i]+w[i];
        uint32_t u=(pw_sha256_rotate(a,2)^pw_sha256_rotate(a,13)^pw_sha256_rotate(a,22))+((a&b)^(a&c)^(b&c));
        v=g;g=f;f=e;e=d+t;d=c;c=b;b=a;a=t+u;}
    h->h[0]+=a;h->h[1]+=b;h->h[2]+=c;h->h[3]+=d;h->h[4]+=e;h->h[5]+=f;h->h[6]+=g;h->h[7]+=v;
}
static inline void pw_sha256_init(PwSha256 *h)
{
    static const uint32_t initial[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    memset(h,0,sizeof(*h));memcpy(h->h,initial,sizeof(initial));
}
static inline int pw_sha256_update(PwSha256 *h,const void *bytes,size_t size)
{
    if(!h||(!bytes&&size)||h->used>=64||h->bytes>UINT64_MAX/8||size>UINT64_MAX/8-h->bytes)return -1;
    const unsigned char*p=bytes;h->bytes+=size;
    while(size){size_t n=64-h->used;if(n>size)n=size;memcpy(h->block+h->used,p,n);
        h->used+=(unsigned)n;p+=n;size-=n;if(h->used==64){pw_sha256_block(h);h->used=0;}}
    return 0;
}
static inline void pw_sha256_final(PwSha256 *h,char hex[65])
{
    uint64_t bits=h->bytes*8;h->block[h->used++]=0x80;
    if(h->used>56){memset(h->block+h->used,0,64-h->used);pw_sha256_block(h);h->used=0;}
    memset(h->block+h->used,0,56-h->used);for(unsigned i=0;i<8;i++)h->block[63-i]=(unsigned char)(bits>>(8*i));
    pw_sha256_block(h);static const char digits[]="0123456789abcdef";
    for(unsigned i=0;i<32;i++){unsigned byte=h->h[i/4]>>(24-8*(i%4));hex[2*i]=digits[(byte>>4)&15];hex[2*i+1]=digits[byte&15];}
    hex[64]=0;
}
#endif
