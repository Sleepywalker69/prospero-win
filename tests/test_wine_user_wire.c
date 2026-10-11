/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define main legacy_wire_main
#include "test_pw_wine_child_wire.c"
#undef main
static unsigned user_checks;
#define T(x) do {++user_checks;assert(x);}while(0)
int main(int argc,char **argv)
{
 PwWineChildFrame f=boot(),got;unsigned char bytes[PW_WC_WIRE_BYTES];f.profile=3;
 if(argc==2&&!strcmp(argv[1],"baseline")){T(pw_wine_child_wire_encode(bytes,&f));puts("mode3 wire: expected prefeature refusal");return 0;}
 T(PW_WC_WIRE_BYTES==136);T(!pw_wine_child_wire_encode(bytes,&f)&&!pw_wine_child_wire_decode(&got,bytes));
 T(got.profile==3&&got.machine==0x8664&&bytes[8]==2&&bytes[128]==3&&bytes[132]==0x64&&bytes[133]==0x86);
 T(pw_wine_child_wire_same_session(&f,&got));got.profile=1;T(!pw_wine_child_wire_same_session(&f,&got));got=f;got.machine=0x14c;T(!pw_wine_child_wire_same_session(&f,&got));
 for(unsigned i=0;i<3;i++){uint32_t machine[]={0,0x14c,0xaa64};f.machine=machine[i];T(pw_wine_child_wire_encode(bytes,&f));}
 f=boot();f.profile=3;T(!pw_wine_child_wire_encode(bytes,&f));bytes[132]=0x4c;bytes[133]=1;T(pw_wine_child_wire_decode(&got,bytes));
 for(unsigned p=5;p<8;p++){f=boot();f.profile=p;T(pw_wine_child_wire_encode(bytes,&f));f.profile=3;T(!pw_wine_child_wire_encode(bytes,&f));bytes[128]=(unsigned char)p;T(pw_wine_child_wire_decode(&got,bytes));}
 f=hello();f.profile=3;T(pw_wine_child_wire_encode(bytes,&f));
 f=boot();f.profile=3;reset(f);int descriptors[]={9},fd=-1;rights(descriptors,1);T(receive(PW_WC_BOOTSTRAP,&fd)==PW_WC_RECORD&&fd==9&&!m.closes);pw_wine_child_wire_close(&fd,&r);T(fd==-1&&m.closes==1);
 reset(f);int duplicate[]={9,9};rights(duplicate,2);T(receive(PW_WC_BOOTSTRAP,&fd)<0&&m.closes==1&&r.ownership_uncertain);
 T(!legacy_wire_main());printf("mode3 wire: %u additive assertions; unchanged legacy suite also passed\n",user_checks);return 0;
}
