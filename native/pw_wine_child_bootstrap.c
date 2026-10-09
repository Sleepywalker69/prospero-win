/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_wine_child_bootstrap.h"
#include <stdio.h>
#include <string.h>
static int step(PwWineChildBootstrap *b,PwNativeChildIo *io,const PwWineChildBootstrapOps *o,unsigned stage,int status)
{
    unsigned left;b->stage=stage;
    if(!status&&pw_native_child_remaining(io,&left))status=-1;
    if(status&&!b->status)b->status=status;
    if(o->record)o->record(o->context,stage,status);
    if(!b->status&&pw_native_child_remaining(io,&left))b->status=-1;
    return b->status?-1:0;
}
int pw_wine_child_bootstrap_prepare(PwWineChildBootstrap *b,PwNativeChildIo *io,int fd,
                                    const char *hash,unsigned abi,uint32_t profile,uint32_t machine,const PwWineChildBootstrapOps *o)
{
    if(!b||!io||!o||!o->runtime||!o->directory||!o->register_thread||!o->unregister_thread||
       !o->output||!o->socket_sink||!o->context||!o->wine.load_start||!o->wine.module_info||!o->wine.set_env||
       !o->wine.start_thread||fd<0||!hash||abi!=1||strlen(hash)!=64)return -1;
    if((profile!=PW_WC_PROFILE_FIXTURE&&profile!=PW_WC_PROFILE_BATTLENET)||
       (machine!=PW_WC_MACHINE_AMD64&&machine!=PW_WC_MACHINE_I386)||
       (profile==PW_WC_PROFILE_FIXTURE&&machine!=PW_WC_MACHINE_AMD64))return -1;
    const char *prefix=profile==PW_WC_PROFILE_FIXTURE?PW_WINE_CHILD_PREFIX:PW_WINE_CHILD_BATTLENET_PREFIX;
    const char *logical_cwd=profile==PW_WC_PROFILE_FIXTURE?PW_WINE_CHILD_CWD:PW_WINE_CHILD_BATTLENET_CWD;
    const char *placeholder=profile==PW_WC_PROFILE_FIXTURE?PW_WINE_CHILD_IMAGE:PW_WINE_CHILD_BATTLENET_IMAGE;
    for(unsigned i=0;i<64;i++)if(!((hash[i]>='0'&&hash[i]<='9')||(hash[i]>='a'&&hash[i]<='f')))return -1;
    if(b->stage||b->prepared||b->started||b->status)return -1;
    if(step(b,io,o,PW_WCB_PATHS,0))return -1;
    int rc=o->directory(o->context,prefix);
    if(step(b,io,o,PW_WCB_PATHS,rc))return -1;
    rc=o->directory(o->context,logical_cwd);
    if(step(b,io,o,PW_WCB_PATHS,rc))return -1;
    memset(b->runtime,0,sizeof(b->runtime));
    rc=o->runtime(o->context,hash,b->runtime,sizeof(b->runtime));
    if(step(b,io,o,PW_WCB_PATHS,rc))return -1;
    if(!memchr(b->runtime,0,sizeof(b->runtime))||
       (strcmp(b->runtime,PW_WINE_CHILD_RUNTIME)&&strcmp(b->runtime,PW_WINE_CHILD_RUNTIME_ALIAS)))
        return step(b,io,o,PW_WCB_PATHS,-1);
    int n=snprintf(b->ntdll,sizeof(b->ntdll),"%s/ntdll.prx",b->runtime);
    int s=snprintf(b->socket_text,sizeof(b->socket_text),"%d",fd);
    if(n<=0||(size_t)n>=sizeof(b->ntdll)||s<=0||(size_t)s>=sizeof(b->socket_text))return step(b,io,o,PW_WCB_PATHS,-1);
    const PwWineStartEnv env[]={
        {"HOME",prefix},{"USER","prospero"},{"WINEARCH","wow64"},
        {"WINE_PRX_DIR",b->runtime},{"WINESERVERSOCKET",b->socket_text},
        {"WINE_PS5_SERVER_DIRECT","0"},{"WINE_PS5_MUTEX_FAST","0"},
        {"WINE_PS5_MUTEX_SHARED","0"},{"WINE_PS5_SYNC_SHARED","0"},
        {"WINE_PS5_SCHED","0"},{"WINE_PS5_TRACE_STARTUP","1"},{"WINEDEBUG","err+all,+process"},{"WINE_PS5_WOW64_CPU","wowprospero.dll"}};
    memcpy(b->env,env,sizeof(env));b->argv[0]="wine";b->argv[1]=placeholder;b->argv[2]=NULL;
    b->config=(PwWineStartConfig){b->ntdll,b->runtime,prefix,b->env,13,2,b->argv,16u<<20};
    rc=pw_wine_start_environment(&b->start,&b->config,&o->wine);
    if(step(b,io,o,PW_WCB_ENVIRONMENT,rc))return -1;
    rc=pw_wine_start_load(&b->start,&b->config,&o->wine);
    if(step(b,io,o,PW_WCB_LOAD,rc))return -1;
    unsigned(*private_abi)(void)=(unsigned(*)(void))(uintptr_t)pw_prx_lookup(b->start.descriptor,"__wine_ps5_private_dispatch_abi");
    unsigned(*wow64_abi)(void)=(unsigned(*)(void))(uintptr_t)pw_prx_lookup(b->start.descriptor,"__wine_ps5_private_dispatch_wow64_abi");
    int(*local_threads)(int(*)(long,pthread_t),void(*)(long))=
        (int(*)(int(*)(long,pthread_t),void(*)(long)))(uintptr_t)pw_prx_lookup(b->start.descriptor,"pw_wine_fixture_local_threads");
    int(*cwd)(const char*)=(int(*)(const char*))(uintptr_t)pw_prx_lookup(b->start.descriptor,"pw_cwd_set");
    void(*sink)(void(*)(const char*,size_t))=(void(*)(void(*)(const char*,size_t)))(uintptr_t)
        pw_prx_lookup(b->start.descriptor,"__wine_ps5_set_output_sink");
    int(*socket_sink)(PwWineFixtureSocketSink,void*)=(int(*)(PwWineFixtureSocketSink,void*))(uintptr_t)
        pw_prx_lookup(b->start.descriptor,"pw_wine_fixture_socket_set_sink");
    b->socket_failure=(int(*)(PwWineFixtureSocketResult*))(uintptr_t)
        pw_prx_lookup(b->start.descriptor,"pw_wine_fixture_socket_failure");
    if((profile==PW_WC_PROFILE_BATTLENET&&!wow64_abi)||!private_abi||!local_threads||!cwd||!sink||!socket_sink||!b->socket_failure||!b->start.adopted||
       !pw_prx_lookup(b->start.descriptor,"module_start"))return step(b,io,o,PW_WCB_EXPORTS,-1);
    if(step(b,io,o,PW_WCB_EXPORTS,0))return -1;
    if(step(b,io,o,PW_WCB_ABI,private_abi()==abi?0:-1))return -1;
    if(profile==PW_WC_PROFILE_BATTLENET&&step(b,io,o,PW_WCB_ABI,wow64_abi()==1?0:-1))return -1;
    sink(o->output);
    if(step(b,io,o,PW_WCB_CWD,cwd(logical_cwd)))return -1;
    if(step(b,io,o,PW_WCB_REGISTRY,local_threads(o->register_thread,o->unregister_thread)))return -1;
    if(step(b,io,o,PW_WCB_SOCKET,socket_sink(o->socket_sink,o->context)))return -1;
    if(step(b,io,o,PW_WCB_PREPARED,0))return -1;
    b->prepared=1;return 0;
}
int pw_wine_child_bootstrap_start(PwWineChildBootstrap *b,PwNativeChildIo *io,const PwWineChildBootstrapOps *o)
{
    if(!b||!io||!o||!b->prepared||b->started||b->status)return -1;
    if(step(b,io,o,PW_WCB_THREAD,0))return -1;
    int rc=pw_wine_start_run(&b->start,&b->config,&o->wine);
    /* A successful start consumes fd ownership even if a late deadline fails:
     * the new Wine thread may already be using/closing that descriptor. */
    if(!rc)b->started=1;
    return step(b,io,o,rc?PW_WCB_THREAD:PW_WCB_RUNNING,rc);
}
static uint32_t rotate(uint32_t v,unsigned n){return(v>>n)|(v<<(32-n));}
static void hash_block(PwWineChildHash *h)
{
    static const uint32_t k[64]={
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    uint32_t w[64];for(unsigned i=0;i<16;i++){const unsigned char*p=h->block+4*i;
        w[i]=((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];}
    for(unsigned i=16;i<64;i++)w[i]=w[i-16]+(rotate(w[i-15],7)^rotate(w[i-15],18)^(w[i-15]>>3))+
        w[i-7]+(rotate(w[i-2],17)^rotate(w[i-2],19)^(w[i-2]>>10));
    uint32_t a=h->h[0],b=h->h[1],c=h->h[2],d=h->h[3],e=h->h[4],f=h->h[5],g=h->h[6],v=h->h[7];
    for(unsigned i=0;i<64;i++){uint32_t t=v+(rotate(e,6)^rotate(e,11)^rotate(e,25))+((e&f)^(~e&g))+k[i]+w[i];
        uint32_t u=(rotate(a,2)^rotate(a,13)^rotate(a,22))+((a&b)^(a&c)^(b&c));
        v=g;g=f;f=e;e=d+t;d=c;c=b;b=a;a=t+u;}
    h->h[0]+=a;h->h[1]+=b;h->h[2]+=c;h->h[3]+=d;h->h[4]+=e;h->h[5]+=f;h->h[6]+=g;h->h[7]+=v;
}
void pw_wine_child_hash_init(PwWineChildHash *h)
{
    static const uint32_t initial[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    memset(h,0,sizeof(*h));memcpy(h->h,initial,sizeof(initial));
}
int pw_wine_child_hash_update(PwWineChildHash *h,const void *bytes,size_t size)
{
    if(!h||(!bytes&&size)||h->used>=64||h->bytes>UINT64_MAX/8||size>UINT64_MAX/8-h->bytes)return -1;
    const unsigned char*p=bytes;h->bytes+=size;
    while(size){size_t n=64-h->used;if(n>size)n=size;memcpy(h->block+h->used,p,n);
        h->used+=(unsigned)n;p+=n;size-=n;if(h->used==64){hash_block(h);h->used=0;}}
    return 0;
}
void pw_wine_child_hash_final(PwWineChildHash *h,char hex[65])
{
    uint64_t bits=h->bytes*8;h->block[h->used++]=0x80;
    if(h->used>56){memset(h->block+h->used,0,64-h->used);hash_block(h);h->used=0;}
    memset(h->block+h->used,0,56-h->used);for(unsigned i=0;i<8;i++)h->block[63-i]=(unsigned char)(bits>>(8*i));
    hash_block(h);static const char digits[]="0123456789abcdef";
    for(unsigned i=0;i<32;i++){unsigned byte=h->h[i/4]>>(24-8*(i%4));hex[2*i]=digits[(byte>>4)&15];hex[2*i+1]=digits[byte&15];}
    hex[64]=0;
}
