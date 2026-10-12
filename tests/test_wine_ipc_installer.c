/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define main legacy_creation_main
#include "test_pw_wine_creation_install.c"
#undef main
int main(void)
{
 for(unsigned mode=16;mode<=23;++mode){reset();child.profile=mode;
  PwWineCreationChild saved=child;CHECK(!pw_wine_creation_child_install(&child));const PwWineCreationChild*p=pw_wine_creation_child_get();
  CHECK(p&&p!=&child&&!memcmp(p,&saved,sizeof(saved))&&!pw_wine_fixture_get()&&!pw_wine_creation_get());
  memset(&child,0,sizeof(child));CHECK(!memcmp(p,&saved,sizeof(saved)));CHECK(pw_wine_creation_child_install(&saved)==-1);CHECK(pw_wine_fixture_install(&root)==-1);
  for(unsigned bad=0;bad<8;++bad){reset();child.profile=mode;
   if(bad<3){uint32_t machine[]={0,0x14c,0xaa64};child.machine=machine[bad];}
   if(bad==3)child.generation=0;
   if(bad==4)child.wine_pid=0;
   if(bad==5)child.wine_tid=0;
   if(bad==6)child.abi++;
   if(bad==7)child.bytes--;
   CHECK(pw_wine_creation_child_install(&child)==-1&&!pw_wine_creation_child_get()&&!atomic_load(&process_role));
  }
 }
 for(unsigned mode=5;mode<=24;++mode)if(mode<16||mode>23){reset();child.profile=mode;CHECK(pw_wine_creation_child_install(&child)==-1&&!pw_wine_creation_child_get()&&!atomic_load(&process_role));}
 unsigned additive=checks;CHECK(!legacy_creation_main());printf("IPC child identity install: %u additive assertions; old ABI and role gates retained\n",additive);return 0;
}
