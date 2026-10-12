/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define main legacy_wire_main
#include "test_pw_wine_child_wire.c"
#undef main
int main(void)
{
 unsigned checks=0;PwWineChildFrame f,got;unsigned char bytes[PW_WC_WIRE_BYTES];
#define T(x) do{++checks;assert(x);}while(0)
 for(unsigned mode=16;mode<=23;++mode){f=boot();f.profile=mode;T(!pw_wine_child_wire_encode(bytes,&f)&&!pw_wine_child_wire_decode(&got,bytes));T(got.profile==mode&&got.machine==0x8664&&PW_WC_WIRE_BYTES==136);got.profile=mode==23?16:mode+1;T(!pw_wine_child_wire_same_session(&f,&got));f.machine=0x14c;T(pw_wine_child_wire_encode(bytes,&f));}
 for(unsigned mode=5;mode<16;++mode){f=boot();f.profile=mode;T(pw_wine_child_wire_encode(bytes,&f));}
 f=boot();f.profile=24;T(pw_wine_child_wire_encode(bytes,&f));T(!legacy_wire_main());printf("IPC wire: %u mocked assertions\n",checks);return 0;
}
