/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Additive mode4 controls; included title/platform fixture stays unchanged. */
#define main legacy_title_main
#include "test_pw_wine_child_title.c"
#undef main
static unsigned net_checks;
#define T(x) do {++net_checks;assert(x);} while(0)
static PwGameProfile net_profile(void)
{
 PwGameProfile p=profile(1);strcpy(p.app.id,"windows-child-net-v1");strcpy(p.app.prefix,p.app.id);
 strcpy(p.app.executable,"C:\\windows-child-net\\net-parent.exe");strcpy(p.app.working_directory,"C:\\windows-child-net");
 p.display.width=800;p.display.height=600;p.display.view=PW_GAME_VIEW_DESKTOP;return p;
}
int main(int argc,char **argv)
{
 PwGameProfile good=net_profile(),p;
 if(argc==2&&!strcmp(argv[1],"baseline")){T(!pw_wine_child_title_profile(&good));reset();T(pw_wine_child_title_prepare(4,hash)<0&&!created_entry);puts("mode4 title: expected prefeature refusal");return 0;}
 T(pw_wine_child_title_profile(&good)==4);
#define BAD(change) do {p=good;change;T(!pw_wine_child_title_profile(&p));}while(0)
 BAD(p.app.id[0]='X');BAD(p.app.prefix[0]='X');BAD(p.app.executable[3]='X');BAD(p.app.working_directory[3]='X');
 BAD(strcpy(p.app.executable,"C:\\windows-child-fixture\\parent.exe"));BAD(strcpy(p.app.prefix,"battlenet-experimental-v1"));
 BAD(strcpy(p.app.id,"windows-child-user-v1"));BAD(p.app.architecture=PW_APP_ARCH_PE32);BAD(p.runtime.cpu=PW_GAME_CPU_TRANSLATOR);BAD(p.runtime.cpu=PW_GAME_CPU_NATIVE);
 BAD(p.display.width=799);BAD(p.display.height=601);BAD(p.display.view=PW_GAME_VIEW_WINDOW);BAD(p.display.show_fps=1);
 BAD(strcpy(p.winedebug,"+all"));BAD(strcpy(p.app.arguments,"x"));BAD(strcpy(p.app.dll_overrides,"ntdll=n"));
 BAD(p.app.startup_command_id=1);BAD(p.debug_env_count=1);BAD(p.runtime.fast_clock=1);BAD(p.runtime.shared_input=1);BAD(p.runtime.thread_scheduling=1);
 BAD(p.app.graphics=PW_APP_GRAPHICS_DXVK);BAD(p.app.runtime[0]='X');BAD(memset(p.app.executable,'x',sizeof(p.app.executable)));
#undef BAD
 reset();char copied[65];memcpy(copied,hash,65);T(!pw_wine_child_title_prepare(4,copied));copied[0]='f';
 T(captured.profile==4&&!strcmp(captured.child_sha256,hash)&&captured.child_sha256==title.child_hash);
 T(!strcmp(captured.child_unix_path,"/data/prospero-win/prefixes/windows-child-net-v1/drive_c/windows-child-net/net-child.exe"));
 T(captured.helper_image==pw_wine_child_image&&captured.helper_bytes==4&&!pw_wine_child_title_restart_ready());
 descriptor.exports[1].name="translated-capability-not-required";T(!pw_wine_child_title_install(desc()));
 T(abi_calls==1&&!wow64_calls&&sink_calls==1&&provider_calls==1);T(pw_wine_child_title_install(desc())<0&&provider_calls==1);
 for(unsigned i=0;i<7;i++){if(i==1)continue;reset();T(!pw_wine_child_title_prepare(4,hash));descriptor.exports[i].name="missing";T(pw_wine_child_title_install(desc())<0&&!sink_calls&&!provider_calls&&!pw_wine_child_title_restart_ready());}
 const char *bad_hashes[]={NULL,"bad","ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFAB"};
 for(unsigned i=0;i<3;i++){reset();T(pw_wine_child_title_prepare(4,bad_hashes[i])<0&&!created_entry);}
 reset();T(pw_wine_child_title_prepare(5,hash)<0&&!created_entry);
 T(!legacy_title_main());printf("mode4 title: %u additive assertions; unchanged legacy suite also passed\n",net_checks);return 0;
}
