/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define main legacy_title_main
#include "test_pw_wine_child_title.c"
#undef main
int main(void)
{
 assert(PW_WINE_IPC_PROFILE_ENABLED==0);
 for(unsigned mode=16;mode<=23;++mode){const PwWineIpcProfile *ipc=pw_wine_ipc_profile(mode);PwGameProfile p=profile(1);
  strcpy(p.app.id,ipc->id);strcpy(p.app.prefix,PW_WINE_IPC_SLUG);strcpy(p.app.executable,ipc->image);strcpy(p.app.working_directory,ipc->cwd);
  p.display.width=800;p.display.height=600;p.display.view=PW_GAME_VIEW_DESKTOP;
  assert(!pw_wine_child_title_profile(&p));reset();assert(pw_wine_child_title_prepare(mode,hash)<0&&!created_entry&&!provider_calls&&pw_wine_child_title_restart_ready());
 }
 assert(!legacy_title_main());puts("IPC default off: all eight exact profiles refused; original modes pass");return 0;
}
