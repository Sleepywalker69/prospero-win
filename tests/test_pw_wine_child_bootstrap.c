/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../native/pw_wine_child_bootstrap.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
enum{EXPORTS=10};
_Alignas(PW_PRX_ALIGN) static struct{struct{uint64_t magic;uint32_t version,count;PwPrxExport exports[EXPORTS];}d;char names[EXPORTS][64];}module;
static struct{uint64_t now;int cancel,envs,loads,starts,adopts,bindings,cwds,sinks,threads;
    uint32_t profile,machine;int wow64_abi;
    int env_fail,load_fail,abi,cwd_fail,register_fail,sink_fail,thread_fail,late_thread,wrong_path;
    int missing,log[64],logs;void(*entry)(void*);void *arg;}m;
static PwWineChildBootstrap b;static PwNativeChildIo io;
static const char hash[]="0123456789012345678901234567890123456789012345678901234567890123";
static void fake_main(int argc,char **argv){assert(argc==2&&!strcmp(argv[1],PW_WINE_CHILD_IMAGE)&&!argv[2]);}
static int module_start(size_t n,const void*p){assert(!n&&!p);m.starts++;return 0;}
static void *adopt(const char *p,int32_t h){assert(strstr(p,"ntdll.prx")&&h==7);m.adopts++;return &module;}
static unsigned abi(void){return(unsigned)m.abi;}
static unsigned wow64_abi(void){return(unsigned)m.wow64_abi;}
static int cwd(const char *p){assert(!strcmp(p,m.profile==PW_WC_PROFILE_FIXTURE?PW_WINE_CHILD_CWD:PW_WINE_CHILD_BATTLENET_CWD));m.cwds++;return m.cwd_fail;}
static void output(const char *p,size_t n){(void)p;(void)n;}
static void sink(void(*f)(const char*,size_t)){assert(f==output);m.sinks++;}
static int add(long id,pthread_t thread){(void)id;(void)thread;return 0;}
static void remove_thread(long id){(void)id;}
static int bind_threads(int(*a)(long,pthread_t),void(*r)(long))
{assert(a==add&&r==remove_thread);m.bindings++;return m.register_fail;}
static void socket_sink(void *context,const PwWineFixtureSocketResult *r){(void)context;(void)r;}
static int set_socket_sink(PwWineFixtureSocketSink s,void*c){assert(s==socket_sink&&c==&m);return m.sink_fail;}
static int socket_failure(PwWineFixtureSocketResult *r){(void)r;return 0;}
static int32_t load(const char *p,size_t argc,const void*argv,uint32_t flags,const void*option,int*result)
{assert(m.envs==16&&!strcmp(p,PW_WINE_CHILD_RUNTIME "/ntdll.prx")&&!argc&&!argv&&!flags&&!option);*result=0;m.loads++;return m.load_fail?-9:7;}
static int info(int32_t h,void *buffer)
{
    assert(h==7);unsigned char *p=buffer;uint64_t address;uint32_t bytes,prot=1,count=2;
    uintptr_t low=(uintptr_t)fake_main,high=low;
    for(unsigned i=0;i<EXPORTS;i++){uintptr_t f=(uintptr_t)module.d.exports[i].address;if(f<low)low=f;if(f>high)high=f;}
    address=(uintptr_t)&module;bytes=sizeof(module);memcpy(p+0x108,&address,8);memcpy(p+0x110,&bytes,4);memcpy(p+0x114,&prot,4);
    address=low;bytes=(uint32_t)(high-low+64);memcpy(p+0x118,&address,8);memcpy(p+0x120,&bytes,4);memcpy(p+0x124,&prot,4);memcpy(p+0x148,&count,4);return 0;
}
static int set_env(const char *name,const char *value)
{
    assert(!m.loads);m.envs++;
    if(!strcmp(name,"WINESERVERSOCKET"))assert(!strcmp(value,"9"));
    if(!strcmp(name,"HOME")||!strcmp(name,"WINEPREFIX"))assert(!strcmp(value,m.profile==PW_WC_PROFILE_FIXTURE?PW_WINE_CHILD_PREFIX:PW_WINE_CHILD_BATTLENET_PREFIX));
    if(!strcmp(name,"WINE_PS5_WOW64_CPU"))assert(!strcmp(value,"wowprospero.dll"));
    if(!strcmp(name,"WINE_PRX_DIR"))assert(!strcmp(value,PW_WINE_CHILD_RUNTIME));
    if(!strcmp(name,"WINE_PS5_SCHED")||!strcmp(name,"WINE_PS5_SERVER_DIRECT"))assert(!strcmp(value,"0"));
    return m.env_fail==m.envs?-3:0;
}
static int thread(void(*entry)(void*),void*arg,size_t stack)
{assert(m.bindings&&m.cwds&&m.sinks&&stack==(16u<<20));m.threads++;m.entry=entry;m.arg=arg;if(m.late_thread)m.now=1000;return m.thread_fail;}
static int runtime(void *c,const char *h,char*out,size_t size)
{assert(c==&m&&!strcmp(h,hash)&&size>100);strcpy(out,m.wrong_path?"/untrusted":PW_WINE_CHILD_RUNTIME);return 0;}
static int directory(void*c,const char*p){assert(c==&m&&(!strcmp(p,m.profile==PW_WC_PROFILE_FIXTURE?PW_WINE_CHILD_PREFIX:PW_WINE_CHILD_BATTLENET_PREFIX)||!strcmp(p,m.profile==PW_WC_PROFILE_FIXTURE?PW_WINE_CHILD_CWD:PW_WINE_CHILD_BATTLENET_CWD)));return 0;}
static void record(void*c,unsigned stage,int status){assert(c==&m);(void)status;assert(m.logs<64);m.log[m.logs++]=(int)stage;}
static int clock_ms(void*c,uint64_t*out){(void)c;*out=m.now;return 0;}
static int cancelled(void*c){(void)c;return m.cancel;}
static PwWineChildBootstrapOps ops;
static void reset(void)
{
    memset(&m,0,sizeof(m));memset(&b,0,sizeof(b));memset(&module,0,sizeof(module));m.now=100;m.abi=1;m.wow64_abi=1;m.profile=PW_WC_PROFILE_FIXTURE;m.machine=PW_WC_MACHINE_AMD64;
    const char *names[]={"__wine_main","module_start","pw_wine_dl_adopt","__wine_ps5_private_dispatch_abi",
        "pw_cwd_set","__wine_ps5_set_output_sink","pw_wine_fixture_local_threads","pw_wine_fixture_socket_set_sink","pw_wine_fixture_socket_failure","__wine_ps5_private_dispatch_wow64_abi"};
    const void *fns[]={(void*)fake_main,(void*)module_start,(void*)adopt,(void*)abi,(void*)cwd,(void*)sink,(void*)bind_threads,(void*)set_socket_sink,(void*)socket_failure,(void*)wow64_abi};
    module.d.magic=PW_PRX_MAGIC;module.d.version=PW_PRX_VERSION;module.d.count=EXPORTS;
    for(unsigned i=0;i<EXPORTS;i++){strcpy(module.names[i],names[i]);module.d.exports[i]=(PwPrxExport){module.names[i],fns[i]};}
    io=(PwNativeChildIo){.clock_ms=clock_ms,.cancelled=cancelled,.ready=1,.last_clock=100,.stage_end=500,.total_end=1000};
    ops=(PwWineChildBootstrapOps){.context=&m,.wine={load,info,set_env,thread},.runtime=runtime,.directory=directory,
        .register_thread=add,.unregister_thread=remove_thread,.output=output,.socket_sink=socket_sink,.record=record};
}
static int prepare(void){return pw_wine_child_bootstrap_prepare(&b,&io,9,hash,1,m.profile,m.machine,&ops);}
static void hashes(void)
{
    PwWineChildHash h;char out[65];pw_wine_child_hash_init(&h);pw_wine_child_hash_final(&h,out);
    assert(!strcmp(out,"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    pw_wine_child_hash_init(&h);assert(!pw_wine_child_hash_update(&h,"a",1));assert(!pw_wine_child_hash_update(&h,"bc",2));pw_wine_child_hash_final(&h,out);
    assert(!strcmp(out,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    const char *longer="abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    pw_wine_child_hash_init(&h);assert(!pw_wine_child_hash_update(&h,longer,strlen(longer)));pw_wine_child_hash_final(&h,out);
    assert(!strcmp(out,"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
    pw_wine_child_hash_init(&h);for(unsigned i=0;i<1000000;i++)assert(!pw_wine_child_hash_update(&h,"a",1));pw_wine_child_hash_final(&h,out);
    assert(!strcmp(out,"cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
    pw_wine_child_hash_init(&h);h.bytes=UINT64_MAX/8;assert(pw_wine_child_hash_update(&h,"a",1));
}
int main(void)
{
    hashes();reset();assert(!prepare()&&b.prepared&&!b.started&&m.envs==16&&m.loads==1&&m.starts==1&&m.adopts==1);
    assert(prepare());assert(!pw_wine_child_bootstrap_start(&b,&io,&ops)&&b.started&&m.threads==1);m.entry(m.arg);
    assert(pw_wine_child_bootstrap_start(&b,&io,&ops));
    for(int n=1;n<=16;n++){reset();m.env_fail=n;assert(prepare()&&b.stage==PW_WCB_ENVIRONMENT&&!m.loads&&!m.threads);}
    reset();m.cancel=1;assert(prepare()&&!m.envs&&!m.loads);
    reset();m.wrong_path=1;assert(prepare()&&!m.envs&&!m.loads);
    reset();m.load_fail=1;assert(prepare()&&b.stage==PW_WCB_LOAD&&!m.threads);
    for(unsigned i=1;i<EXPORTS-1;i++){reset();strcpy(module.names[i],"missing");assert(prepare()&&!m.threads);}
    reset();m.abi=0;assert(prepare()&&b.stage==PW_WCB_ABI&&!m.bindings);
    reset();m.cwd_fail=-1;assert(prepare()&&b.stage==PW_WCB_CWD&&!m.bindings);
    reset();m.register_fail=-1;assert(prepare()&&b.stage==PW_WCB_REGISTRY&&!m.threads);
    reset();m.sink_fail=-1;assert(prepare()&&b.stage==PW_WCB_SOCKET&&!m.threads);
    reset();assert(!prepare());m.thread_fail=-7;assert(pw_wine_child_bootstrap_start(&b,&io,&ops)&&!b.started);
    reset();assert(!prepare());m.late_thread=1;assert(pw_wine_child_bootstrap_start(&b,&io,&ops)&&b.started);
    reset();m.profile=PW_WC_PROFILE_BATTLENET;m.machine=PW_WC_MACHINE_I386;
    assert(!prepare()&&!strcmp(b.config.prefix,PW_WINE_CHILD_BATTLENET_PREFIX)&&!strcmp(b.argv[1],PW_WINE_CHILD_BATTLENET_IMAGE));
    reset();m.profile=PW_WC_PROFILE_BATTLENET;assert(!prepare());
    reset();m.profile=PW_WC_PROFILE_BATTLENET;strcpy(module.names[EXPORTS-1],"missing");assert(prepare()&&!m.bindings);
    reset();m.profile=PW_WC_PROFILE_BATTLENET;m.wow64_abi=0;assert(prepare()&&b.stage==PW_WCB_ABI&&!m.bindings);
    reset();m.machine=PW_WC_MACHINE_I386;assert(prepare()&&!m.loads&&!m.envs);
    reset();m.profile=3;assert(prepare()&&!m.loads&&!m.envs);
    reset();m.profile=PW_WC_PROFILE_BATTLENET;m.machine=0xaa64;assert(prepare()&&!m.loads&&!m.envs);
    puts("wine child bootstrap: all mocked controls and SHA256 vectors passed");return 0;
}
