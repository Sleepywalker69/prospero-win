/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define main legacy_creation_main
#include "test_pw_wine_creation_install.c"
#undef main
int main(int argc,char **argv)
{
 reset();child.profile=3;
 if(argc==2&&!strcmp(argv[1],"baseline")){CHECK(pw_wine_creation_child_install(&child)==-1&&!pw_wine_creation_child_get());puts("mode3 installer: expected prefeature refusal");return 0;}
 PwWineCreationChild saved=child;CHECK(!pw_wine_creation_child_install(&child));const PwWineCreationChild *p=pw_wine_creation_child_get();
 CHECK(p&&p!=&child&&!memcmp(p,&saved,sizeof(saved))&&!pw_wine_fixture_get()&&!pw_wine_creation_get());
 memset(&child,0,sizeof(child));CHECK(!memcmp(p,&saved,sizeof(saved)));CHECK(pw_wine_creation_child_install(&saved)==-1);CHECK(pw_wine_fixture_install(&root)==-1);
 for(unsigned i=0;i<5;i++){reset();child.profile=3;if(i<3){uint32_t machine[]={0,0x14c,0xaa64};child.machine=machine[i];}else child.profile=i==3?0:4;
 CHECK(pw_wine_creation_child_install(&child)==-1&&!pw_wine_creation_child_get()&&!atomic_load(&process_role));}
 printf("mode3 installer: %u assertions with modeled publication hooks\n",checks);return 0;
}
