/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define main legacy_owner_main
#include "test_pw_wine_fixture_owner.c"
#undef main
int main(void)
{
 CHECK(PW_WINE_IPC_PROFILE_ENABLED==0);
 for(unsigned mode=16;mode<=23;++mode){reset(1);PwWineFixtureOwnerConfig c=config(mode);c.child_unix_path=pw_wine_ipc_profile(mode)->native_image;
  PwWineFixtureProvider out,before;memset(&out,0xa5,sizeof(out));before=out;unsigned opens=m.opens;
  CHECK(pw_wine_fixture_owner_init(&owner,sizeof(owner),&c,&out)<0&&!memcmp(&out,&before,sizeof(out))&&m.opens==opens&&!m.adds);
 }
 puts("IPC actual owner default off: all eight exact configurations refused before I/O");return 0;
}
