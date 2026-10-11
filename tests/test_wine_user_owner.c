/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Actual complete owner; reuse existing inert native/hash/transport boundaries. */
#define main legacy_owner_main
#include "test_pw_wine_fixture_owner.c"
#undef main
static const char user_path[]="/data/prospero-win/prefixes/windows-child-user-v1/drive_c/windows-child-user/user-child.exe";
static const char user_alias[]="/data/prospero-win/prefixes/windows-child-user-v1/dosdevices/c:/windows-child-user/user-child.exe";
static PwWineFixtureOwnerConfig user_config(void){PwWineFixtureOwnerConfig c=config(3);c.child_unix_path=user_path;return c;}
static void reset_user(void)
{
 reset(1);PwWineFixtureOwnerConfig c=user_config();CHECK(!pw_wine_fixture_owner_init(&owner,sizeof(owner),&c,&provider));
 CHECK(owner.started==1000&&owner.end==181000);preflight();
}
static Generation *user_admitted(int alias)
{reset_user();uint64_t id=0;CHECK(!provider.admit(&owner,44,45,0x8664,alias?user_alias:user_path,&id));Generation*g=find(&owner,id);CHECK(g&&g->depth==1&&g->machine==0x8664&&g->end-g->started==120000&&g->startup_end-g->started==30000);return g;}
static Generation *user_bound(void)
{Generation*g=user_admitted(0);uint64_t id=0;CHECK(!provider.bind_process(&owner,44,45,46,&id)&&id==g->generation);return g;}
int main(int argc,char **argv)
{
 reset(1);PwWineFixtureOwnerConfig c=user_config();
 if(argc==2&&!strcmp(argv[1],"baseline")){CHECK(pw_wine_fixture_owner_init(&owner,sizeof(owner),&c,&provider)<0);puts("mode3 owner: expected prefeature refusal");return 0;}
 CHECK(!pw_wine_fixture_owner_init(&owner,sizeof(owner),&c,&provider));
 for(unsigned i=0;i<8;i++){reset(1);c=user_config();char bad_hash[65];memcpy(bad_hash,hash64,65);
 switch(i){case 0:c.child_unix_path=NULL;break;case 1:c.child_unix_path=config(1).child_unix_path;break;case 2:c.child_sha256=NULL;break;case 3:c.child_sha256="short";break;case 4:bad_hash[0]='G';c.child_sha256=bad_hash;break;case 5:c.profile=5;break;case 6:c.child_unix_path=user_alias;break;default:bad_hash[0]='A';c.child_sha256=bad_hash;break;}
 PwWineFixtureProvider out,before;memset(&out,0xa5,sizeof(out));before=out;CHECK(pw_wine_fixture_owner_init(&owner,sizeof(owner),&c,&out)<0&&!memcmp(&out,&before,sizeof(out)));}
 const char *bad[]={NULL,"",config(1).child_unix_path,"/data/prospero-win/prefixes/battlenet-experimental-v1/drive_c/Agent.exe","/data/prospero-win/prefixes/windows-child-user-v1/drive_c/windows-child-user/other.exe","/data/prospero-win/prefixes/windows-child-user-v1/drive_c/windows-child-user/../user-child.exe","/data/prospero-win/prefixes/windows-child-user-v1/drive_c/windows-child-user/user-child.exe/x","/data/prospero-win/prefixes/windows-child-user-v1/drive_c/windows-child-user/USER-CHILD.EXE"};
 for(unsigned i=0;i<sizeof(bad)/sizeof(*bad);i++){reset_user();unsigned reads=m.reads,opens=m.opens;uint64_t id=999;CHECK(provider.admit(&owner,44,45,0x8664,bad[i],&id)==WF_UNSUPPORTED&&id==999&&!atomic_load(&owner.count)&&m.opens==opens&&m.reads==reads&&!m.adds);}
 for(unsigned i=0;i<3;i++){uint32_t machine[]={0,0x14c,0xaa64};reset_user();uint64_t id=999;CHECK(provider.admit(&owner,44,45,machine[i],user_path,&id)==WF_UNSUPPORTED&&id==999&&!atomic_load(&owner.count));}
 for(unsigned alias=0;alias<2;alias++){Generation*g=user_admitted(alias);CHECK(m.reads>=4);uint64_t id=999;unsigned count=atomic_load(&owner.count);CHECK(provider.admit(&owner,44,45,0x8664,user_path,&id)!=WF_OK&&id==999);atomic_store(&g->state,G_RETIRED);CHECK(provider.admit(&owner,44,48,0x8664,user_path,&id)!=WF_OK&&atomic_load(&owner.count)==count&&id==999&&!m.adds);}
 for(unsigned bad_image=0;bad_image<4;bad_image++){reset_user();if(bad_image==0)m.hash_bad=1;if(bad_image==1)m.open_error=1;if(bad_image==2)m.read_error=1;if(bad_image==3)m.stat_error=1;uint64_t id=999;CHECK(provider.admit(&owner,44,45,0x8664,user_path,&id)!=WF_OK&&id==999&&!atomic_load(&owner.count)&&!m.adds);}
 reset_user();m.now=owner.end-5000;uint64_t id=999;CHECK(provider.admit(&owner,44,45,0x8664,user_path,&id)!=WF_OK&&id==999&&!m.adds);
 reset_user();m.now=owner.end-5000-100;CHECK(!provider.admit(&owner,44,45,0x8664,user_path,&id));Generation*g=find(&owner,id);CHECK(g->end==owner.end-5000&&g->startup_end==g->end);
 g=user_admitted(0);m.now=g->startup_end;CHECK(!provider.startup_remaining_ms(&owner,g->generation)&&!m.adds);
 g=user_admitted(0);pw_wine_fixture_owner_cancel(&owner);CHECK(!provider.startup_remaining_ms(&owner,g->generation)&&!m.adds);
 g=user_bound();PwWineCreationProvider creation;CHECK(!pw_wine_fixture_owner_creation(&owner,&creation));g->wine_tid=47;g->session.child_pid=600;g->ack=1;atomic_store(&g->identity_ready,1);atomic_store(&g->state,G_RUNNING);
 PwWineCreationRequest q={.origin=g->generation,.lease=1,.key=1,.now=m.now,.deadline=m.now+30000,.caller_pid=46,.caller_tid=47,.machine=0x8664,.image_bytes=2};q.image[0]='x';strcpy(q.path,user_path);q.path_bytes=sizeof(user_path);id=999;CHECK(creation.prepare(&owner,&q,&id)==WF_UNSUPPORTED&&id==999&&atomic_load(&owner.count)==1&&!m.adds);
 strcpy(q.path,"/data/prospero-win/prefixes/battlenet-experimental-v1/drive_c/Agent.exe");q.path_bytes=(uint32_t)strlen(q.path)+1;CHECK(creation.prepare(&owner,&q,&id)==WF_UNSUPPORTED&&id==999);
 /* A completed helper-capable bootstrap clears hold only on the exact ACK. */
 for(unsigned wrong_ack=0;wrong_ack<2;wrong_ack++){g=user_bound();m.sleep_action=1;m.ack_bad=wrong_ack;uint32_t status=provider.spawn(&owner,g->generation,70,46,47);CHECK(m.adds==1&&m.sent.profile==3&&m.sent.machine==0x8664);
 if(wrong_ack){CHECK(status!=WF_OK&&g->helper_possible&&atomic_load(&owner.uncertain)&&atomic_load(&g->state)==G_UNCERTAIN&&!m.kills);unsigned lists=m.lists;pw_wine_fixture_owner_cancel(&owner);m.now=owner.end;pw_wine_fixture_owner_pump(&owner);CHECK(!pw_wine_fixture_owner_release_ready(&owner)&&!m.kills&&m.lists==lists);}
 else CHECK(status==WF_OK&&g->ack&&!g->helper_possible&&atomic_load(&g->state)==G_RUNNING);}
 printf("mode3 actual owner: %u assertions with inert native/transport/hash boundaries\n",checks);return 0;
}
