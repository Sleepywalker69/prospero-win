/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Pure bytes only. No Wine, mapping, socket, native or guest code executes. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "wine/pw_private_dispatch_i386.h"

static unsigned char image[8192], original[8192];
static void put16(unsigned int at, unsigned int value)
{ image[at] = (unsigned char)value; image[at+1] = (unsigned char)(value >> 8); }
static void put32(unsigned int at, unsigned int value)
{ put16(at, value); put16(at+2, value >> 16); }
static void reset(void) { memcpy(image, original, sizeof image); }
static int valid(void)
{ return pw_private_dispatch_i386_image_valid(image, sizeof image, "NtClose", "__wine_syscall_dispatcher"); }
static void build(void)
{
    const unsigned char thunk[15] = {0xb8,15,0,0,0,0xba,0,0,0,0,0xff,0xd2,0xc2,4,0};
    image[0]='M'; image[1]='Z'; put32(60,0x80); put32(0x80,0x4550);
    put16(0x84,0x14c); put16(0x86,3); put16(0x94,0xe0); put16(0x98,0x10b);
    put32(0x98+28,0x10000000); put32(0x98+56,sizeof image); put32(0x98+60,0x400);
    put32(0x98+92,16); put32(0x98+96,0x1000); put32(0x98+100,0x80);
    put32(0x98+136,0x1400); put32(0x98+140,12);
    put32(0x178+8,0x400); put32(0x178+12,0x400); put32(0x178+36,0x60000020);
    put32(0x1a0+8,0x400); put32(0x1a0+12,0x800); put32(0x1a0+36,0xc0000040);
    put32(0x1c8+8,0x1000); put32(0x1c8+12,0x1000); put32(0x1c8+36,0x40000040);
    put32(0x1000+20,2); put32(0x1000+24,2); put32(0x1000+28,0x1100);
    put32(0x1000+32,0x1120); put32(0x1000+36,0x1140);
    put32(0x1100,0x400); put32(0x1104,0x800); put32(0x1120,0x1160); put32(0x1124,0x1180);
    put16(0x1140,0); put16(0x1142,1);
    memcpy(image+0x1160,"NtClose",8); memcpy(image+0x1180,"__wine_syscall_dispatcher",25);
    memcpy(image+0x400,thunk,sizeof thunk); put32(0x406,0x10000440);
    image[0x440]=0xff; image[0x441]=0x25; put32(0x442,0x10000800);
    put32(0x1400,0); put32(0x1404,12); put16(0x1408,0x3406); put16(0x140a,0x3442);
    memcpy(original,image,sizeof image);
}
int main(void)
{
    unsigned int i;
    build(); assert(valid());
    assert(!pw_private_dispatch_image_valid(image,sizeof image,"NtClose"));
    for (i=0;i<15;i++)
    {
        reset(); image[0x400+i]^=0x80;
        assert(valid() == (i>=1 && i<=4));
    }
    reset(); put32(0x98+28,0x30000000); put32(0x406,0x30000440); put32(0x442,0x30000800);
    assert(valid()); /* already dynamically relocated image */
    put32(0x406,0x10000440); assert(!valid()); reset();
    put32(0x442,0x7ffe1000); assert(!valid()); reset();
    put32(0x442,0x7ffe4000); assert(!valid()); reset();
    put32(0x800,1); assert(!valid()); reset();
    put32(0x98+140,14); put32(0x1404,14); put16(0x140c,0x3800); assert(!valid()); reset();
    put32(0x98+140,14); put32(0x1404,14); put16(0x140c,0x37fe); assert(!valid()); reset();
    put32(0x442,0x10000804); assert(!valid()); reset();
    put32(0x406,0x10000408); assert(!valid()); reset();
    put32(0x406,0x10001800); assert(!valid()); reset();
    put32(0x1a0+36,0xd0000040); assert(!valid()); reset(); /* shared data */
    put32(0x1a0+36,0x40000040); assert(!valid()); reset(); /* not writable */
    put32(0x1a0+36,0xe0000040); assert(!valid()); reset(); /* executable data */
    put32(0x178+36,0x40000020); assert(!valid()); reset(); /* not executable */
    put32(0x178+36,0xe0000020); assert(!valid()); reset(); /* writable code */
    put16(0x84,0x8664); assert(!valid()); reset();
    put16(0x98,0x20b); assert(!valid()); reset();
    put32(0x98+28,0xfffff000); assert(!valid()); reset();
    put32(0x98+92,5); assert(!valid()); reset();
    put32(0x98+136,0); assert(!valid()); reset();
    put32(0x98+136,0xfffffffc); assert(!valid()); reset();
    put32(0x98+140,11); assert(!valid()); reset();
    put32(0x1400,1); assert(!valid()); reset();
    put32(0x1404,6); assert(!valid()); reset();
    put32(0x1404,14); assert(!valid()); reset();
    put16(0x1408,0); assert(!valid()); reset(); /* absent thunk relocation */
    put16(0x140a,0); assert(!valid()); reset(); /* absent helper relocation */
    put16(0x1408,0x4406); assert(!valid()); reset(); /* wrong relocation type */
    put16(0x1408,0x3405); assert(!valid()); reset(); /* overlapping wrong slot */
    put16(0x140a,0x3441); assert(!valid()); reset();
    put32(0x98+140,14); put32(0x1404,14); put16(0x140c,0x3406); assert(!valid()); reset();
    put32(0x98+140,14); put32(0x1404,14); put16(0x140c,0x3442); assert(!valid()); reset();
    put32(0x98+140,14); put32(0x1404,14); put16(0x140c,0); assert(valid()); reset();
    put32(0x1000+24,3); put32(0x1128,0x1160); put16(0x1144,0); assert(!valid()); reset();
    put32(0x1000+24,3); put32(0x1128,0x1180); put16(0x1144,1); assert(!valid()); reset();
    put32(0x1100,0x1010); assert(!valid()); reset(); /* forwarded anchor */
    put32(0x1104,0x1010); assert(!valid()); reset(); /* forwarded dispatcher */
    put16(0x1142,2); assert(!valid()); reset();
    put32(0x1120,0xfffffffe); assert(!valid()); reset();
    memset(image+0x1160,'x',512); assert(!valid()); reset();
    put32(0x1a0+12,0x700); assert(!valid()); reset(); /* section overlap */
    for(i=0;i<64;i++) assert(!pw_private_dispatch_i386_image_valid(image,i,"NtClose","__wine_syscall_dispatcher"));
    memcpy(image+0x1180,"Wow64Transition",16);
    assert(pw_private_dispatch_i386_image_valid(image,sizeof image,"NtClose","Wow64Transition"));
    puts("private dispatcher I386 byte controls: PASS");
    return 0;
}
