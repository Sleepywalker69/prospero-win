/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Actual adapter; all native boundaries are deterministic mocks. */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "../native/pw_wine_child_data.h"
#include "../native/pw_wine_child_bootstrap.h"
#include "../native/lapy_elevation_protocol.h"
static unsigned checks;
#define CHECK(c) do{++checks;assert(c);}while(0)
static int test_open(const char*,int,...),test_fstat(int,struct stat*),test_close(int),test_stat(const char*,struct stat*);
int test_lstat(const char*,struct stat*);
static ssize_t test_read(int,void*,size_t);
static int test_poll(struct pollfd*,nfds_t,int),test_sleep(const struct timespec*,struct timespec*);
static pid_t test_pid(void);static uid_t test_uid(void);static int test_setuid(uid_t);
int32_t test_module(const char*,size_t,const void*,uint32_t,const void*,int*);
static int test_symbol(int32_t,const char*,void**);
int net_load(unsigned,...);
int net_handle(uint32_t,int32_t*);
#define open test_open
#define fstat test_fstat
#define close test_close
#define stat(...) test_stat(__VA_ARGS__)
#define lstat(...) test_lstat(__VA_ARGS__)
#define read test_read
#define poll test_poll
#define nanosleep test_sleep
#define getpid test_pid
#define geteuid test_uid
#define seteuid test_setuid
#define sceKernelLoadStartModule test_module
#define sceKernelDlsym test_symbol
#define sceSysmoduleLoadModuleInternal net_load
#define sceSysmoduleGetModuleHandleInternal net_handle
#include "../native/pw_wine_child_data.c"
#undef open
#undef fstat
#undef close
#undef stat
#undef lstat
#undef read
#undef poll
#undef nanosleep
#undef getpid
#undef geteuid
#undef seteuid
#undef sceKernelLoadStartModule
#undef sceKernelDlsym
#undef sceSysmoduleLoadModuleInternal
#undef sceSysmoduleGetModuleHandleInternal

enum { F_STAT=1,F_OPEN,F_FSTAT,F_READ,F_CLOSE,F_MODULE,F_SYMBOL,F_NET_LOAD,F_NET_HANDLE,F_NET_INIT,F_SOCKET,F_OPTION,F_CONNECT,F_SEND,F_RECEIVE,F_SETUID,F_SLEEP,F_NET_CLOSE,F_LSTAT };
static struct {
 uint64_t now;int cancel,clock_fail,data_before,lstat_error,lstat_error_always,lstat_retry_count,lstat_success,lstat_type,stat_type,stat_error,missing_pair_count,missing_pair_always,no_data,poll_error,poll_flags,poll_at,hup_after_symbol,hup_after_request,fail_at,fail_result,expired_at,cancelled_at;
 unsigned calls,after_stop,stopped,stats,lstats,opens,fstats,reads,closes,modules,symbols,loads,handles,inits,sockets,options,connects,sends,receives,net_closes,clones,sleeps;
 unsigned partial,file_at,rx_at,rx_size,tx_size,phase,bad_hash,extra_byte,changed,mutate_after_close,header_bad;
 int native_errno,net_errno,setuid_error,net_close_error,close_error,socket_value,module_value,module_started,null_symbol,net_module_value,sleep_interrupts,short_sleep,backward_at;
 unsigned char helper[8],upload[256],incoming[128];int ops[1024];unsigned tx_before[1024],rx_before[1024];
}m;
static uint64_t *shared_clock;
static PwWineChildData result;
static PwNativeChildIo io;
static const unsigned char original_helper[8]={0x7f,'E','L','F','a','b','c','!'};
static char helper_hash[65];
static int boundary(int operation)
{
 CHECK(m.calls<1024);m.tx_before[m.calls]=m.tx_size;m.rx_before[m.calls]=m.rx_at;m.ops[m.calls++]=operation;
 if(m.stopped&&operation!=F_CLOSE&&operation!=F_NET_CLOSE)m.after_stop++;
 if(m.expired_at==(int)m.calls){m.now=io.stage_end;m.stopped=1;}
 if(m.cancelled_at==(int)m.calls){m.cancel=1;m.stopped=1;}
 if(m.backward_at==(int)m.calls)m.now=1500;
 if(shared_clock)*shared_clock=m.now;
 errno=m.native_errno;return m.fail_at==(int)m.calls;
}
static int now(void *unused,uint64_t *out){(void)unused;*out=m.now;errno=ERANGE;return m.clock_fail;}
static int stop(void *unused){(void)unused;return m.cancel;}
static int test_poll(struct pollfd*p,nfds_t n,int timeout)
{CHECK(n==1&&p->fd==3&&p->events==POLLIN&&timeout==0);p->revents=(short)((m.poll_at&&m.calls>=(unsigned)m.poll_at)||(m.hup_after_symbol&&m.symbols>=1)||(m.hup_after_request&&m.tx_size>8)?POLLHUP:m.poll_flags);if(m.poll_error){errno=EIO;return -1;}return p->revents?1:0;}
static int test_stat(const char *path,struct stat *st)
{CHECK(!strcmp(path,"/data"));m.stats++;int fail=boundary(F_STAT);memset(st,0,sizeof(*st));if(fail)return m.fail_result;if(m.stat_error){errno=m.stat_error;return -1;}
 if(m.missing_pair_always||m.stats<=(unsigned)m.missing_pair_count){errno=ENOENT;return -1;}
 if(m.data_before||(!m.no_data&&m.stats>1)){st->st_mode=m.stat_type?S_IFREG:S_IFDIR;return 0;}errno=ENOENT;return -1;}
int test_lstat(const char *path,struct stat *st)
{CHECK(!strcmp(path,"/data"));m.lstats++;int fail=boundary(F_LSTAT);memset(st,0,sizeof(*st));if(fail)return m.fail_result;if(m.missing_pair_always||m.lstats<=(unsigned)m.missing_pair_count){errno=ENOENT;return -1;}if((m.lstat_retry_count&&m.lstats<=(unsigned)m.lstat_retry_count)||(m.lstat_error&&(m.lstats==1||m.lstat_error_always))||(!m.lstat_success&&!m.data_before&&m.lstats==1)){errno=m.lstat_error?m.lstat_error:EPERM;return -1;}st->st_mode=m.lstat_type?S_IFREG:S_IFDIR;return 0;}
static int test_open(const char *path,int flags,...)
{CHECK(!strcmp(path,"/app0/lapy.elf")&&(flags&(O_NOFOLLOW|O_NONBLOCK))==(O_NOFOLLOW|O_NONBLOCK));m.opens++;if(boundary(F_OPEN))return m.fail_result;return 9;}
static int test_fstat(int fd,struct stat *st)
{CHECK(fd==9);m.fstats++;int fail=boundary(F_FSTAT);memset(st,0,sizeof(*st));st->st_mode=S_IFREG;st->st_size=8;st->st_dev=1;st->st_ino=m.changed&&m.fstats>1?2:1;return fail?m.fail_result:0;}
static ssize_t test_read(int fd,void *out,size_t n)
{CHECK(fd==9&&out&&n);m.reads++;if(boundary(F_READ))return m.fail_result;
 if(m.file_at==8){if(m.extra_byte){*(unsigned char*)out=99;return 1;}return 0;}
 size_t left=8-m.file_at;if(n>left)n=left;if(m.partial&&n>3)n=3;memcpy(out,m.helper+m.file_at,n);m.file_at+=(unsigned)n;return (ssize_t)n;}
static int test_close(int fd)
{CHECK(fd==9&&!m.closes);m.closes++;int fail=boundary(F_CLOSE);if(m.mutate_after_close)memset(m.helper,0xff,sizeof(m.helper));errno=EBADF;return fail?m.fail_result:m.close_error;}
static pid_t test_pid(void){return 600;}
static uid_t test_uid(void){return 1000;}
static int test_setuid(uid_t uid){CHECK(uid==1000);m.clones++;int fail=boundary(F_SETUID);errno=EPERM;return fail?m.fail_result:m.setuid_error;}
static int test_sleep(const struct timespec *duration,struct timespec *rest)
{CHECK(duration&&!rest&&duration->tv_sec==0&&duration->tv_nsec>0&&duration->tv_nsec<=100000000);m.sleeps++;if(boundary(F_SLEEP))return m.fail_result;
 if(m.sleep_interrupts){m.sleep_interrupts--;errno=EINTR;return -1;}
 uint64_t elapsed=(uint64_t)duration->tv_nsec/1000000;if(m.short_sleep&&elapsed>1)elapsed/=2;m.now+=elapsed;if(shared_clock)*shared_clock=m.now;return 0;}
int net_load(unsigned id,...){CHECK(id==UINT32_C(0x8000001c)&&!m.modules&&!m.loads&&!m.handles&&!m.symbols);m.loads++;return boundary(F_NET_LOAD)?m.fail_result:0;}
int net_handle(uint32_t id,int32_t *handle){CHECK(id==UINT32_C(0x8000001c)&&handle&&*handle==-1&&m.loads==1&&!m.modules&&!m.handles&&!m.symbols);m.handles++;int fail=boundary(F_NET_HANDLE);*handle=m.net_module_value;return fail?m.fail_result:0;}
static int net_init(void){CHECK(m.loads==1&&m.handles==1&&m.symbols==8&&!m.modules);m.inits++;return boundary(F_NET_INIT)?m.fail_result:0;}
static int net_socket(const char *name,int family,int type,int protocol)
{CHECK(name&&family==2&&type==1&&protocol==6);m.sockets++;if(boundary(F_SOCKET))return m.fail_result;return m.socket_value;}
static int net_connect(int fd,const struct sockaddr *address,socklen_t size)
{static const unsigned char expected[16]={16,2,0x23,0x3d,127,0,0,1,0,0,0,0,0,0,0,0};CHECK(fd==m.socket_value&&address&&size==16&&!memcmp(address,expected,16));m.connects++;return boundary(F_CONNECT)?m.fail_result:0;}
static int net_option(int fd,int level,int option,const void *value,socklen_t size)
{CHECK(fd==m.socket_value&&level==0xffff&&value&&size==4&&(option==0x1105||option==0x1106||option==0x1109));uint32_t n;memcpy(&n,value,4);CHECK(n>0&&n<=5000000&&n<=(io.stage_end-m.now)*1000);m.options++;return boundary(F_OPTION)?m.fail_result:0;}
static int net_send(int fd,const void *bytes,size_t n,int flags)
{CHECK(fd==m.socket_value&&bytes&&n&&!flags);m.sends++;if(!shared_clock&&m.tx_size>=8)CHECK(result.possible_apply);if(boundary(F_SEND))return m.fail_result;
 if(m.partial&&n>3)n=3;
 CHECK(m.tx_size+n<=sizeof(m.upload));memcpy(m.upload+m.tx_size,bytes,n);m.tx_size+=(unsigned)n;return (int)n;}
static int net_receive(int fd,void *bytes,size_t n,int flags)
{CHECK(fd==m.socket_value&&bytes&&n&&!flags);if(!shared_clock)CHECK(result.possible_apply);m.receives++;if(boundary(F_RECEIVE))return m.fail_result;
 size_t left=m.rx_size-m.rx_at;if(n>left)n=left;if(m.partial&&n>5)n=5;memcpy(bytes,m.incoming+m.rx_at,n);m.rx_at+=(unsigned)n;return (int)n;}
static int net_close(int fd){CHECK(fd==m.socket_value&&!m.net_closes);m.net_closes++;int fail=boundary(F_NET_CLOSE);m.net_errno=EBADF;return fail?m.fail_result:m.net_close_error;}
static int *net_errno(void){return &m.net_errno;}
int32_t test_module(const char *path,size_t n,const void*a,uint32_t flags,const void*b,int *started)
{CHECK(!strcmp(path,"/system/common/lib/libSceSysmodule.sprx")&&!n&&!a&&!flags&&!b&&started);m.modules++;int fail=boundary(F_MODULE);*started=m.module_started;return fail?m.fail_result:m.module_value;}
#define RESOLVE(name,fn) if(!strcmp(symbol,name)){__typeof__(&fn) pointer=&fn;memcpy(address,&pointer,sizeof(pointer));return 0;}
static int test_symbol(int32_t module,const char *symbol,void **address)
{CHECK(symbol&&address&&!*address&&module==m.net_module_value&&m.loads==1&&m.handles==1&&!m.modules);m.symbols++;if(boundary(F_SYMBOL))return m.fail_result;
 if(m.null_symbol==(int)m.symbols)return 0;
 RESOLVE("sceNetInit",net_init) RESOLVE("sceNetSocket",net_socket) RESOLVE("sceNetConnect",net_connect)
 RESOLVE("sceNetSend",net_send) RESOLVE("sceNetRecv",net_receive) RESOLVE("sceNetSetsockopt",net_option)
 RESOLVE("sceNetSocketClose",net_close) RESOLVE("sceNetErrnoLoc",net_errno)
 CHECK(0);return -1;}
#undef RESOLVE
static void message(unsigned kind,unsigned status)
{struct lapy_elevation_message f={LAPY_ELEVATION_MAGIC,LAPY_ELEVATION_VERSION,sizeof(f),kind,LAPY_ELEVATION_FILESYSTEM,600,status};CHECK(m.rx_size+sizeof(f)<=sizeof(m.incoming));memcpy(m.incoming+m.rx_size,&f,sizeof(f));m.rx_size+=sizeof(f);}
static void reset(void)
{shared_clock=NULL;memset(&m,0,sizeof(m));memset(&result,0,sizeof(result));m.now=1000;m.module_value=(int32_t)UINT32_C(0x80020002);m.net_module_value=33;m.socket_value=42;m.native_errno=EACCES;m.net_errno=EIO;m.fail_result=-1;memcpy(m.helper,original_helper,8);
 io=(PwNativeChildIo){.clock_ms=now,.cancelled=stop,.ready=1,.last_clock=1000,.stage_end=31000,.total_end=61000};
 PwWineChildHash h;pw_wine_child_hash_init(&h);CHECK(!pw_wine_child_hash_update(&h,m.helper,8));pw_wine_child_hash_final(&h,helper_hash);}
static void success_responses(void){message(LAPY_ELEVATION_PREPARE,0);message(LAPY_ELEVATION_RESPONSE,0);}
void data_adapter_fixture_reset(uint64_t *clock,unsigned mode)
{reset();shared_clock=clock;m.now=*clock;m.data_before=mode==0;m.partial=1;if(mode==1)success_responses();else if(mode==2)message(LAPY_ELEVATION_PREPARE,0);else if(mode==3)message(LAPY_ELEVATION_RESPONSE,LAPY_ELEVATION_TARGET_MISMATCH);else if(mode==4)m.poll_flags=POLLHUP;else if(mode==5)m.null_symbol=1;else if(mode==6){m.null_symbol=1;m.hup_after_symbol=1;}else if(mode==7){success_responses();m.hup_after_request=1;}else if(mode==8){success_responses();m.data_before=1;m.lstat_error=EPERM;}else if(mode==9){success_responses();m.missing_pair_count=3;}}
void data_adapter_fixture_counts(unsigned *calls,unsigned *clones,unsigned *sends)
{*calls=m.calls;*clones=m.clones;*sends=m.sends;}
#ifndef PW_WINE_DATA_COMPOSED
static int run(void){return pw_wine_child_data_prepare(&result,&io,helper_hash);}
int main(void)
{
#ifdef PW_DATA_MODULE_ROUTE_RED
 reset();success_responses();int module_rc=run();
 printf("Sysmodule route: rc=%d api=%u raw=%d absolute_loads=%u static_loads=%u static_handles=%u Net_symbols=%u ready=%u\n",module_rc,result.api,result.raw,m.modules,m.loads,m.handles,m.symbols,result.ready);fflush(stdout);
 CHECK(!module_rc&&result.ready&&!m.modules&&m.loads==1&&m.handles==1&&m.symbols==8);return 0;
#endif
#ifdef PW_DATA_ABSENT_RED
 reset();m.lstat_error=ENOENT;success_responses();int missing=run();
 printf("paired absence: rc=%d ready=%u stat_error=%d lstat_error=%d helper_opens=%u local_preparations=%u\n",missing,result.ready,result.stat_before_error,result.lstat_before_error,m.opens,m.clones);fflush(stdout);
 CHECK(!missing&&result.ready&&m.opens==1&&m.clones==1);return 0;
#endif
#ifdef PW_DATA_LSTAT_RED
 reset();m.data_before=1;m.lstat_error=EPERM;success_responses();int red=run();
 printf("stat visible/lstat EPERM: rc=%d ready=%u lstats=%u helper_opens=%u local_preparations=%u\n",red,result.ready,m.lstats,m.opens,m.clones);fflush(stdout);
 CHECK(m.lstats>=1&&m.opens==1&&m.clones==1);return 0;
#endif
 reset();m.data_before=1;CHECK(!run()&&result.ready&&result.data_before&&result.data_after&&!result.possible_apply&&!m.opens&&!m.modules&&!m.loads&&!m.handles&&!m.symbols&&!m.clones&&!m.sleeps);
 reset();success_responses();CHECK(!run());CHECK(result.ready&&result.possible_apply&&result.terminal&&result.data_after&&result.settled_ms>=1000&&m.clones==1&&m.closes==1&&m.net_closes==1);
 CHECK(!m.modules&&m.loads==1&&m.handles==1&&m.symbols==8);
 CHECK(m.tx_size==56&&!memcmp(m.upload,original_helper,8));CHECK(io.stage_end==31000&&io.total_end==61000);
 reset();m.partial=1;m.mutate_after_close=1;success_responses();CHECK(!run()&&!memcmp(m.upload,original_helper,8));
 for(unsigned status=0;status<=11;status++){
  reset();message(LAPY_ELEVATION_RESPONSE,status);CHECK(run());CHECK(!result.ready&&!m.clones);CHECK(result.possible_apply);CHECK(result.terminal==(status>=1&&status<=4));
  reset();message(LAPY_ELEVATION_PREPARE,0);message(LAPY_ELEVATION_RESPONSE,status);int rc=run();int terminal=status==0||status==4||status==5||status==6||status==7||status==9||status==10;
  CHECK(result.terminal==(unsigned)terminal);CHECK((rc==0)==(status==0));CHECK(result.ready==(status==0));
 }
 reset();m.setuid_error=-1;success_responses();CHECK(run()&&!result.terminal&&!result.ready&&result.possible_apply&&result.api==PW_WCD_LOCAL_PREPARE&&result.native_error==EPERM);
 reset();message(LAPY_ELEVATION_PREPARE,0);CHECK(run()&&result.possible_apply&&!result.terminal&&!result.ready);
 reset();success_responses();m.incoming[16]^=1;CHECK(run()&&!m.clones&&!result.terminal&&result.possible_apply);
 reset();success_responses();m.incoming[24+16]^=1;CHECK(run()&&m.clones==1&&!result.terminal&&result.possible_apply);
 reset();m.helper[7]^=1;success_responses();CHECK(run()&&result.api==PW_WCD_HELPER_HASH&&!m.sends&&!result.possible_apply);
 reset();m.extra_byte=1;success_responses();CHECK(run()&&result.api==PW_WCD_HELPER_READ&&!m.sends&&!result.possible_apply);
 reset();m.changed=1;success_responses();CHECK(run()&&result.api==PW_WCD_HELPER_CHANGED&&!m.sends&&!result.possible_apply);
 reset();success_responses();CHECK(!run());unsigned calls=m.calls;int operations[1024];memcpy(operations,m.ops,calls*sizeof(int));
 for(unsigned position=1;position<=calls;position++)for(int mode=1;mode<=2;mode++){
  reset();success_responses();if(mode==1)m.expired_at=(int)position;else m.cancelled_at=(int)position;
  int rc=run();if(!rc||result.ready||m.after_stop){printf("post-call boundary position=%u operation=%d mode=%d rc=%d ready=%u later=%u\n",position,operations[position-1],mode,rc,result.ready,m.after_stop);fflush(stdout);}
  CHECK(rc&&!result.ready&&!m.after_stop);if(mode==2)CHECK(result.control_refused);CHECK(io.stage_end==31000&&io.total_end==61000);
 }
 for(unsigned position=2;position<=calls;position++){
  if(operations[position-1]==F_STAT)continue; /* visibility polling can legitimately recover */
  reset();success_responses();m.fail_at=(int)position;CHECK(run()&&!result.ready&&result.api);CHECK(m.closes<=1&&m.net_closes<=1);
 }
 for(unsigned i=0;i<2;i++){
  reset();m.socket_value=i?3:0;success_responses();CHECK(!run()&&result.ready&&m.net_closes==1&&m.closes==1);
 }
 reset();success_responses();CHECK(!run());calls=m.calls;CHECK(run()&&m.calls==calls); /* no repeated request */
 reset();m.no_data=1;success_responses();CHECK(run()&&result.terminal&&!result.ready&&result.api==PW_WCD_DATA_STAT&&result.native_error==ENOENT&&m.now==1000);
 for(unsigned i=0;i<4;i++){int flags[]={POLLHUP,POLLERR,POLLNVAL,POLLIN};reset();m.poll_flags=flags[i];CHECK(run()&&!m.opens&&!m.modules&&!result.possible_apply&&result.control_refused&&result.control_revents==(unsigned)flags[i]);}
 reset();m.poll_error=1;CHECK(run()&&!m.opens&&!m.modules&&result.api==PW_WCD_CONTROL&&result.native_error==EIO);

 /* The complete final response may settle ownership even if its return is late;
  * the earlier PREPARE response cannot. Neither can admit Wine late. */
 reset();success_responses();CHECK(!run());unsigned prepare_return=0,final_return=0;
 for(unsigned i=0;i<m.calls;i++)if(m.ops[i]==F_RECEIVE){if(!prepare_return)prepare_return=i+1;else final_return=i+1;}
 CHECK(prepare_return&&final_return);
 reset();success_responses();m.expired_at=(int)prepare_return;CHECK(run()&&result.possible_apply&&!result.terminal&&!result.ready&&!m.clones);
 reset();success_responses();m.expired_at=(int)final_return;CHECK(run()&&result.possible_apply&&result.terminal&&!result.ready&&m.clones==1);
 for(unsigned size=0;size<48;size++){
  reset();m.partial=1;success_responses();m.rx_size=size;CHECK(run()&&result.possible_apply&&!result.terminal&&!result.ready);
 }
 const unsigned corrupt_offsets[]={0,4,6,8,12,16};
 for(unsigned i=0;i<sizeof(corrupt_offsets)/sizeof(corrupt_offsets[0]);i++){
  reset();success_responses();m.incoming[corrupt_offsets[i]]^=0x40;
  CHECK(run()&&result.possible_apply&&!result.terminal&&!result.ready&&!m.clones);
 }
 /* First native error survives close changing its own error domain. */
 reset();m.partial=1;success_responses();CHECK(!run());unsigned request_piece=0,prepared_piece=0;
 for(unsigned i=0;i<m.calls;i++)if(m.ops[i]==F_SEND){
  if(m.tx_before[i]>8&&m.tx_before[i]<32&&!request_piece)request_piece=i+1;
  if(m.tx_before[i]>32&&!prepared_piece)prepared_piece=i+1;
 }
 CHECK(request_piece&&prepared_piece);
 reset();m.partial=1;success_responses();m.poll_at=(int)request_piece;
 CHECK(run()&&result.possible_apply&&!result.terminal&&!result.ready&&result.api==PW_WCD_CONTROL&&result.control_refused&&result.control_revents==POLLHUP);
 CHECK(m.tx_size>8&&m.tx_size<32&&!m.receives&&!m.clones&&m.net_closes==1&&m.closes==1);
 for(unsigned which=0;which<2;which++){
  reset();m.partial=1;success_responses();m.fail_at=(int)(which?prepared_piece:request_piece);m.net_close_error=-1;
  CHECK(run()&&result.possible_apply&&!result.terminal&&!result.ready&&result.errno_valid&&result.native_error==EIO);
  CHECK(result.api==(which?PW_WCD_PREPARED:PW_WCD_REQUEST)&&m.net_closes==1&&m.closes==1);
 }

 const unsigned symbols[]={PW_WCD_NET_INIT_SYMBOL,PW_WCD_NET_SOCKET_SYMBOL,PW_WCD_NET_CONNECT_SYMBOL,PW_WCD_NET_SEND_SYMBOL,PW_WCD_NET_RECV_SYMBOL,PW_WCD_NET_OPTION_SYMBOL,PW_WCD_NET_CLOSE_SYMBOL,PW_WCD_NET_ERRNO_SYMBOL};
 for(unsigned i=0;i<8;i++){
  reset();m.null_symbol=(int)i+1;CHECK(run()&&result.api==PW_WCD_RESOLVE&&result.raw==0&&!result.errno_valid&&result.resolution_index==symbols[i]&&!result.possible_apply&&!m.sends);
 }
 /* The old path-load failures are historical controls. No absolute Sysmodule
  * loader call is allowed on the new static-import route. */
 reset();m.module_value=0;m.module_started=7;success_responses();CHECK(!run()&&result.ready&&!m.modules&&m.loads==1&&m.handles==1);
 reset();success_responses();CHECK(!run());calls=m.calls;memcpy(operations,m.ops,calls*sizeof(int));
 for(unsigned i=0;i<calls;i++)if(operations[i]==F_SYMBOL||operations[i]==F_NET_LOAD||operations[i]==F_NET_HANDLE||operations[i]==F_NET_INIT||operations[i]==F_OPTION||operations[i]==F_CONNECT){
  reset();success_responses();m.fail_at=(int)i+1;m.fail_result=7;CHECK(run()&&!result.ready&&result.raw==7&&!result.errno_valid);
 }
 /* Static Sysmodule failures retain their native return, not stale errno. */
 reset();success_responses();CHECK(!run());unsigned load_position=0,handle_position=0;
 for(unsigned i=0;i<m.calls;i++){
  if(m.ops[i]==F_NET_LOAD)load_position=i+1;
  if(m.ops[i]==F_NET_HANDLE)handle_position=i+1;
 }
 CHECK(load_position&&handle_position&&load_position<handle_position);
 const int native_failures[]={(int32_t)UINT32_C(0x80020002),-1,7};
 for(unsigned which=0;which<2;which++)for(unsigned code=0;code<3;code++){
  reset();m.fail_at=(int)(which?handle_position:load_position);m.fail_result=native_failures[code];
  CHECK(run()&&!result.ready&&!result.possible_apply);
  CHECK(result.api==(which?PW_WCD_NET_HANDLE:PW_WCD_NET_LOAD)&&result.raw==native_failures[code]&&!result.errno_valid&&!result.native_error);
  CHECK(!m.modules&&m.loads==1&&m.handles==which&&!m.symbols&&!m.sockets&&!m.sends&&m.closes==1&&!m.net_closes);
 }
 /* A zero return with an untouched/negative module handle is still refusal. */
 for(unsigned which=0;which<2;which++){
  reset();m.net_module_value=which?-7:-1;
  CHECK(run()&&!result.ready&&result.api==PW_WCD_NET_HANDLE&&result.raw==0&&!result.errno_valid);
  CHECK(m.loads==1&&m.handles==1&&!m.symbols&&!m.sockets&&!result.possible_apply&&m.closes==1);
 }
 /* stat-visible does not establish child access without the lstat probe. */
 reset();m.data_before=1;m.lstat_error=EPERM;success_responses();CHECK(!run()&&result.ready&&m.opens==1&&m.clones==1&&result.data_before&&!result.lstat_before&&result.lstat_after);
 CHECK(result.before_observations==3&&result.after_observations==3&&result.stat_before_raw==0&&result.lstat_before_raw==-1&&result.lstat_before_error==EPERM&&result.lstat_after_raw==0);
 reset();m.data_before=1;CHECK(!run()&&m.stats==1&&m.lstats==1&&!m.opens&&!m.modules&&result.lstat_before&&!result.lstat_after&&result.before_observations==3&&!result.after_observations);
 const int refused_errors[]={EACCES,ENOENT,ENOTDIR,ELOOP,EIO};
 for(unsigned i=0;i<sizeof(refused_errors)/sizeof(refused_errors[0]);i++){
  reset();m.data_before=1;m.lstat_error=refused_errors[i];CHECK(run()&&!result.ready&&!m.opens&&!m.modules&&!result.possible_apply);
  CHECK(result.api==PW_WCD_DATA_LSTAT&&result.raw==-1&&result.errno_valid&&result.native_error==refused_errors[i]&&result.lstat_before_error==refused_errors[i]);
 }
 reset();m.data_before=1;m.lstat_type=1;CHECK(run()&&result.api==PW_WCD_DATA_LSTAT_TYPE&&!result.errno_valid&&!m.opens);
 reset();m.lstat_success=1;CHECK(run()&&result.api==PW_WCD_DATA_STAT&&result.native_error==ENOENT&&!m.opens);
 reset();m.data_before=1;m.stat_type=1;CHECK(run()&&result.api==PW_WCD_DATA_STAT&&!result.errno_valid&&!m.opens);
 reset();m.data_before=1;m.lstat_retry_count=3;success_responses();CHECK(!run()&&result.ready&&result.terminal&&m.clones==1&&m.opens==1&&m.lstats==4&&result.settled_ms==1000&&m.now==2200);
 reset();m.data_before=1;m.lstat_error=EPERM;m.lstat_error_always=1;success_responses();CHECK(run()&&result.terminal&&!result.ready&&result.api==PW_WCD_DATA_LSTAT&&result.native_error==EPERM&&m.now==6000&&m.opens==1&&m.clones==1);
 for(unsigned position=1;position<=2;position++)for(unsigned mode=0;mode<2;mode++){
  reset();m.data_before=1;if(mode)m.cancelled_at=(int)position;else m.expired_at=(int)position;
  CHECK(run()&&!result.ready&&!m.opens&&!m.modules&&m.lstats==(position==2)&&!m.after_stop);
 }
 reset();m.missing_pair_count=1;success_responses();CHECK(!run()&&result.ready&&m.opens==1&&m.clones==1&&result.stat_before_error==ENOENT&&result.lstat_before_error==ENOENT&&result.lstat_after);
 reset();m.missing_pair_count=3;success_responses();CHECK(!run()&&result.ready&&m.opens==1&&m.clones==1&&m.stats==4&&m.lstats==4&&result.settled_ms==1000&&m.now==2200);
 reset();m.missing_pair_always=1;success_responses();CHECK(run()&&result.terminal&&!result.ready&&result.native_error==ENOENT&&m.now==6000&&m.opens==1&&m.clones==1);
 reset();m.data_before=1;m.fail_at=2;m.fail_result=7;CHECK(run()&&result.api==PW_WCD_DATA_LSTAT&&result.raw==7&&!result.errno_valid&&!m.opens);
 reset();m.data_before=1;m.fail_at=1;m.fail_result=7;CHECK(run()&&result.api==PW_WCD_DATA_STAT&&result.raw==7&&!result.errno_valid&&!m.opens);
 for(unsigned i=0;i<2;i++){reset();m.stat_error=i?EIO:EACCES;CHECK(run()&&result.api==PW_WCD_DATA_STAT&&result.native_error==m.stat_error&&!m.opens);CHECK(result.before_observations==3&&result.lstat_before_error==EPERM);}
 /* Native sleep duration is not elapsed-clock evidence. */
 reset();m.sleep_interrupts=3;success_responses();CHECK(!run()&&result.ready&&result.settled_ms==1000&&m.sleeps==13&&m.now==2000);
 reset();m.short_sleep=1;success_responses();CHECK(!run()&&result.ready&&result.settled_ms==1000&&m.sleeps>10&&m.now==2000);
 /* A successful static GetModuleHandle output0 remains a valid Net handle. */
 reset();m.net_module_value=0;success_responses();CHECK(!run()&&result.ready&&m.symbols==8&&m.handles==1&&!m.modules);
 reset();m.clock_fail=1;CHECK(run()&&result.api==PW_WCD_BUDGET&&!m.calls&&io.last_clock==1000);
 reset();m.now=999;CHECK(run()&&result.api==PW_WCD_BUDGET&&!m.calls&&io.last_clock==1000);
 reset();success_responses();CHECK(!run());unsigned module_position=0;
 for(unsigned i=0;i<m.calls;i++)if(m.ops[i]==F_NET_LOAD)module_position=i+1;
 CHECK(module_position);reset();m.now=2000;m.backward_at=(int)module_position;success_responses();
 CHECK(run()&&result.api==PW_WCD_BUDGET&&io.last_clock==2000&&!m.symbols&&!m.sockets&&!result.ready);
 printf("Actual child-data adapter with mocked native boundaries: %u checks passed\n",checks);return 0;
}

#endif
