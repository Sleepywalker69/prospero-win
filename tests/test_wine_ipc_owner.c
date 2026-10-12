/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifdef PW_IPC_COMPOSED
#ifndef AF_UNIX
#define AF_UNIX 1 /* Inert target socketpair ABI; no socket is opened. */
#endif
/* Keep the legacy owner's inert transport/hash model separate from the
 * actual codec/bootstrap/hash linked into the child-side test translation unit. */
#define pw_wine_child_hash_init ipc_owner_pw_wine_child_hash_init
#define pw_wine_child_hash_update ipc_owner_pw_wine_child_hash_update
#define pw_wine_child_hash_final ipc_owner_pw_wine_child_hash_final
#define pw_wine_child_wire_validate ipc_owner_pw_wine_child_wire_validate
#define pw_wine_child_wire_send ipc_owner_pw_wine_child_wire_send
#define pw_wine_child_wire_try_send ipc_owner_pw_wine_child_wire_try_send
#define pw_wine_child_wire_same_session ipc_owner_pw_wine_child_wire_same_session
#define pw_wine_child_wire_receive ipc_owner_pw_wine_child_wire_receive
#define pw_wine_child_wire_receive_step ipc_owner_pw_wine_child_wire_receive_step
#define pw_wine_child_wire_receive_nowait ipc_owner_pw_wine_child_wire_receive_nowait
#define pw_wine_child_wire_send_step ipc_owner_pw_wine_child_wire_send_step
#define pw_wine_child_wire_close ipc_owner_pw_wine_child_wire_close
#endif
#define main legacy_owner_main
#include "test_pw_wine_fixture_owner.c"
#undef main
#ifdef PW_IPC_COMPOSED
#undef pw_wine_child_hash_init
#undef pw_wine_child_hash_update
#undef pw_wine_child_hash_final
#undef pw_wine_child_wire_validate
#undef pw_wine_child_wire_send
#undef pw_wine_child_wire_try_send
#undef pw_wine_child_wire_same_session
#undef pw_wine_child_wire_receive
#undef pw_wine_child_wire_receive_step
#undef pw_wine_child_wire_receive_nowait
#undef pw_wine_child_wire_send_step
#undef pw_wine_child_wire_close
int ipc_bootstrap_from_owner(const PwWineChildFrame *);
#endif
static PwWineFixtureOwnerConfig ipc_config(unsigned mode)
{PwWineFixtureOwnerConfig c=config(mode);c.child_unix_path=pw_wine_ipc_profile(mode)->native_image;return c;}
static void ipc_reset(unsigned mode)
{reset(1);PwWineFixtureOwnerConfig c=ipc_config(mode);CHECK(!pw_wine_fixture_owner_init(&owner,sizeof(owner),&c,&provider));CHECK(m.opens==1&&m.reads==2&&!m.adds&&owner.end==181000&&!strcmp(m.last_open_path,c.child_unix_path));preflight();}
int main(void)
{
 for(unsigned mode=16;mode<=23;++mode){const PwWineIpcProfile *ipc=pw_wine_ipc_profile(mode);
  for(unsigned error=0;error<4;++error){reset(1);PwWineFixtureOwnerConfig c=ipc_config(mode);PwWineFixtureProvider out,before;memset(&out,0xa5,sizeof(out));before=out;
   if(error==0)m.hash_bad=1;
   if(error==1)m.open_error=1;
   if(error==2)m.read_error=1;
   if(error==3)m.stat_error=1;
   CHECK(pw_wine_fixture_owner_init(&owner,sizeof(owner),&c,&out)<0&&!memcmp(&out,&before,sizeof(out))&&!m.adds&&!atomic_load(&owner.count));
  }
  for(unsigned bad=0;bad<5;++bad){reset(1);PwWineFixtureOwnerConfig c=ipc_config(mode);char changed[65];memcpy(changed,hash64,65);
   if(bad==0)c.child_sha256=NULL;
   if(bad==1)c.child_sha256="short";
   if(bad==2){changed[0]='A';c.child_sha256=changed;}
   if(bad==3)c.child_unix_path=ipc->native_alias;
   if(bad==4)c.child_unix_path=NULL;
   unsigned opens=m.opens;CHECK(pw_wine_fixture_owner_init(&owner,sizeof(owner),&c,&provider)<0&&m.opens==opens&&!m.adds);
  }
  for(unsigned other=16;other<=23;++other)if(other!=mode){reset(1);PwWineFixtureOwnerConfig c=ipc_config(mode);c.child_unix_path=pw_wine_ipc_profile(other)->native_image;unsigned opens=m.opens;CHECK(pw_wine_fixture_owner_init(&owner,sizeof(owner),&c,&provider)<0&&m.opens==opens);}
  for(unsigned alias=0;alias<2;++alias){ipc_reset(mode);unsigned opens=m.opens,reads=m.reads;uint64_t id=999;
   uint32_t status=provider.admit(&owner,44,45,0x8664,alias?ipc->native_alias:ipc->native_image,&id);
   if(!ipc->direct_children){CHECK(status!=WF_OK&&id==999&&!atomic_load(&owner.count)&&m.opens==opens&&m.reads==reads&&!m.adds);continue;}
   CHECK(status==WF_OK&&id!=999&&atomic_load(&owner.count)==1&&m.opens==opens+1&&m.reads==reads+2);CHECK(!strcmp(m.last_open_path,alias?ipc->native_alias:ipc->native_image));
   Generation*g=find(&owner,id);CHECK(g&&g->depth==1&&g->end-g->started==60000);atomic_store(&g->state,G_RETIRED);
   id=999;CHECK(provider.admit(&owner,44,48,0x8664,ipc->native_image,&id)!=WF_OK&&id==999&&atomic_load(&owner.count)==1&&!m.adds);
  }
  ipc_reset(mode);for(unsigned other=16;other<=23;++other)if(other!=mode){uint64_t id=999;unsigned opens=m.opens;CHECK(provider.admit(&owner,44,45,0x8664,pw_wine_ipc_profile(other)->native_image,&id)==WF_UNSUPPORTED&&id==999&&m.opens==opens&&!atomic_load(&owner.count));}
  {const char *bad_paths[]={NULL,"",PW_WINE_IPC_PREFIX "/drive_c/windows-chromium-ipc/other.exe",PW_WINE_IPC_PREFIX "/drive_c/windows-chromium-ipc/../pw-ipc-live-memory.exe",PW_WINE_IPC_PREFIX "/drive_c/windows-chromium-ipc/pw-ipc-live-memory.exe/child",config(1).child_unix_path};
   for(unsigned bad=0;bad<sizeof(bad_paths)/sizeof(*bad_paths);++bad){uint64_t id=999;unsigned opens=m.opens;CHECK(provider.admit(&owner,44,45,0x8664,bad_paths[bad],&id)==WF_UNSUPPORTED&&id==999&&m.opens==opens&&!atomic_load(&owner.count));}
  }
  for(unsigned machine=0;machine<3;++machine){uint32_t bad[]={0,0x14c,0xaa64};uint64_t id=999;CHECK(provider.admit(&owner,44,45,bad[machine],ipc->native_image,&id)==WF_UNSUPPORTED&&id==999);}
  if(!ipc->direct_children){CHECK(!report_root_exit(&owner,0));pw_wine_fixture_owner_pump(&owner);CHECK(pw_wine_fixture_owner_release_ready(&owner)&&!m.adds&&!m.kills);continue;}
  ipc_reset(mode);m.hash_bad=1;uint64_t id=999;CHECK(provider.admit(&owner,44,45,0x8664,ipc->native_image,&id)!=WF_OK&&id==999&&!atomic_load(&owner.count)&&!m.adds);
  ipc_reset(mode);CHECK(!provider.admit(&owner,44,45,0x8664,ipc->native_image,&id));Generation*g=find(&owner,id);CHECK(!provider.bind_process(&owner,44,45,46,&id));
  PwWineCreationProvider creation;CHECK(!pw_wine_fixture_owner_creation(&owner,&creation));g->wine_tid=47;g->session.child_pid=600;g->ack=1;atomic_store(&g->identity_ready,1);atomic_store(&g->state,G_RUNNING);
  PwWineCreationRequest q={.origin=g->generation,.lease=1,.key=1,.now=m.now,.deadline=m.now+30000,.caller_pid=46,.caller_tid=47,.machine=0x8664,.image_bytes=2};q.image[0]='x';strcpy(q.path,ipc->native_image);q.path_bytes=(uint32_t)strlen(q.path)+1;id=999;
  CHECK(creation.prepare(&owner,&q,&id)==WF_UNSUPPORTED&&id==999&&atomic_load(&owner.count)==1&&!m.adds);
 }
 for(unsigned mode=17;mode<=22;++mode)for(unsigned wrong=0;wrong<2;++wrong){ipc_reset(mode);const PwWineIpcProfile *ipc=pw_wine_ipc_profile(mode);uint64_t id=0;
  CHECK(!provider.admit(&owner,44,45,0x8664,ipc->native_image,&id));CHECK(!provider.bind_process(&owner,44,45,46,&id));Generation*g=find(&owner,id);
  m.sleep_action=1;m.ack_bad=(int)wrong;uint32_t status=provider.spawn(&owner,id,70,46,47);CHECK(m.adds==1&&m.sent.profile==mode&&m.sent.machine==0x8664);
  if(wrong){CHECK(status!=WF_OK&&g->helper_possible&&atomic_load(&owner.uncertain)&&!m.kills);unsigned lists=m.lists;pw_wine_fixture_owner_cancel(&owner);m.now=owner.end;pw_wine_fixture_owner_pump(&owner);CHECK(!pw_wine_fixture_owner_release_ready(&owner)&&!m.kills&&m.lists==lists);}
  else {CHECK(status==WF_OK&&g->ack&&!g->helper_possible&&atomic_load(&g->state)==G_RUNNING);
#ifdef PW_IPC_COMPOSED
   CHECK(!ipc_bootstrap_from_owner(&m.sent));
#endif
  }
 }
 printf("IPC exact owner: %u mocked assertions; root hash, zero/one cap, descendants and uncertainty controls\n",checks);return 0;
}
