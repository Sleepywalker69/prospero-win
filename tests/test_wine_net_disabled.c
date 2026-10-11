/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Actual default-off title, with the existing inert platform boundaries. */
#define main legacy_title_main
#include "test_pw_wine_child_title.c"
#undef main
int main(void)
{
 assert(PW_WINE_NET_PROFILE_ENABLED==0);
 PwGameProfile p=profile(1);strcpy(p.app.id,"windows-child-net-v1");strcpy(p.app.prefix,p.app.id);
 strcpy(p.app.executable,"C:\\windows-child-net\\net-parent.exe");strcpy(p.app.working_directory,"C:\\windows-child-net");
 p.display.width=800;p.display.height=600;p.display.view=PW_GAME_VIEW_DESKTOP;
 assert(!pw_wine_child_title_profile(&p));reset();assert(pw_wine_child_title_prepare(4,hash)<0&&!created_entry&&!provider_calls&&pw_wine_child_title_restart_ready());
 assert(!legacy_title_main());puts("optional mode4 default-off: exact valid profile/hash refused; original modes pass");return 0;
}
