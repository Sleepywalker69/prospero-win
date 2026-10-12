/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define main legacy_title_main
#include "test_pw_wine_child_title.c"
#undef main
static unsigned ipc_checks;
#define T(x) do {++ipc_checks;assert(x);} while(0)
static PwGameProfile ipc_profile(unsigned mode)
{
 const PwWineIpcProfile *ipc=pw_wine_ipc_profile(mode);PwGameProfile p=profile(1);
 strcpy(p.app.id,ipc->id);strcpy(p.app.prefix,PW_WINE_IPC_SLUG);strcpy(p.app.executable,ipc->image);
 strcpy(p.app.working_directory,ipc->cwd);p.display.width=800;p.display.height=600;p.display.view=PW_GAME_VIEW_DESKTOP;return p;
}
int main(void)
{
 for(unsigned mode=16;mode<=23;++mode){
  const PwWineIpcProfile *ipc=pw_wine_ipc_profile(mode);PwGameProfile good=ipc_profile(mode),p;
  T(pw_wine_child_title_profile(&good)==mode);
#define BAD(change) do {p=good;change;T(!pw_wine_child_title_profile(&p));}while(0)
  BAD(p.app.id[0]='X');BAD(p.app.prefix[0]='X');BAD(p.app.executable[3]='X');BAD(p.app.working_directory[3]='X');
  BAD(strcpy(p.app.arguments,"self-memory"));BAD(p.app.architecture=PW_APP_ARCH_PE32);BAD(p.runtime.cpu=PW_GAME_CPU_TRANSLATOR);
  BAD(p.display.width=799);BAD(p.display.height=601);BAD(p.display.show_fps=1);BAD(p.display.view=PW_GAME_VIEW_WINDOW);
  BAD(strcpy(p.winedebug,"+all"));BAD(strcpy(p.app.dll_overrides,"ntdll=n"));BAD(p.app.startup_command_id=1);
  BAD(p.debug_env_count=1);BAD(p.runtime.fast_clock=1);BAD(p.runtime.shared_input=1);BAD(p.runtime.thread_scheduling=1);
  BAD(p.app.graphics=PW_APP_GRAPHICS_DXVK);BAD(p.app.runtime[0]='X');BAD(memset(p.app.executable,'x',sizeof(p.app.executable)));
  for(unsigned other=16;other<=23;++other)if(other!=mode){BAD(strcpy(p.app.executable,pw_wine_ipc_profile(other)->image));BAD(strcpy(p.app.working_directory,pw_wine_ipc_profile(other)->cwd));}
#undef BAD
  reset();char copied[65];memcpy(copied,hash,65);T(!pw_wine_child_title_prepare(mode,copied));copied[0]='f';
  T(captured.profile==mode&&!strcmp(captured.child_sha256,hash)&&captured.child_sha256==title.child_hash);
  T(!strcmp(captured.child_unix_path,ipc->native_image)&&!pw_wine_child_title_restart_ready());
  descriptor.exports[1].name="translated-capability-not-required";T(!pw_wine_child_title_install(desc()));
  T(abi_calls==1&&!wow64_calls&&sink_calls==1&&provider_calls==1);
  const char *bad_hashes[]={NULL,"short","ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFAB"};
  for(unsigned i=0;i<3;++i){reset();T(pw_wine_child_title_prepare(mode,bad_hashes[i])<0&&!created_entry&&!provider_calls);}
 }
 reset();T(pw_wine_child_title_prepare(24,hash)<0&&!created_entry);T(!legacy_title_main());
 printf("IPC exact title profiles: %u mocked assertions; original modes retained\n",ipc_checks);return 0;
}
