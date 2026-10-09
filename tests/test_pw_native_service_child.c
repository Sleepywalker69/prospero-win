/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Actual service parent and actual frame engine; native/file APIs and packet
 * transport are mocked. No file, socket, process, or service operation runs. */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#ifndef SOCK_SEQPACKET
#define SOCK_SEQPACKET 5
#endif
_Static_assert(AF_UNIX==1&&SOCK_SEQPACKET==5,"target socket family/type");
static int mock_open(const char *,int,...),mock_fstat(int,struct stat *),mock_close(int);
static ssize_t mock_read(int,void *,size_t);
static int mock_socketpair(int,int,int,int *),mock_nanosleep(const struct timespec *,struct timespec *);
static pid_t mock_getpid(void);
#define open mock_open
#define fstat mock_fstat
#define read mock_read
#define close mock_close
#define socketpair mock_socketpair
#define nanosleep mock_nanosleep
#define getpid mock_getpid
#include "../native/pw_native_service_child.c"
#undef open
#undef fstat
#undef read
#undef close
#undef socketpair
#undef nanosleep
#undef getpid
const unsigned char pw_native_service_image[PW_NATIVE_SERVICE_SELF_BYTES]={0x50,0x57,0x53,0x43};
const size_t pw_native_service_image_size=sizeof(pw_native_service_image);
static struct {
 uint64_t now;unsigned ticks;int cancel,clock_error,app_rc,app_mode,baseline_mode,list_mode,list_bad_after;
 int add_return,kill_return,pair_mode,validate_error,packet_error,packet_cleanup,packet_ownership;
 int opens,reads,stats,app_calls,list_calls,pair_calls,add_calls,kill_calls,validate_calls,send_calls,receive_calls,sleeps;
 int close_error,close_return,close_count[256],file_missing_mask,file_bad_mode,file_bad_size,file_bad_bytes,file_read_error,file_extra;
 int record_effect_phase,record_effect,add_effect,tick_short,hello_missing;
 unsigned read_chunk,positions[2],phases[32],phase_count;PwNativeChildFrame request;
} m;
static unsigned checks;
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);return 1;}}while(0)
static void reset(void){memset(&m,0,sizeof(m));m.now=100;m.add_return=404;m.close_error=-1;m.close_return=-1;m.record_effect_phase=-1;atomic_store(&service_claim,0);}
static void effect(int e){if(e==1)m.now=20100;if(e==2)m.cancel=1;if(e==3)m.clock_error=1;if(e==4)m.now=0;}
static int clock_cb(void *p,uint64_t *value){(void)p;errno=EBADF;*value=m.now;return m.clock_error;}
static int cancel_cb(void *p){(void)p;errno=EBADF;return m.cancel;}
static unsigned ticks_cb(void *p){(void)p;return m.ticks;}
static void record_cb(void *p,const PwNativeServiceChildResult *r)
{(void)p;assert(m.phase_count<32);m.phases[m.phase_count++]=r->phase;if((int)r->phase==m.record_effect_phase)effect(m.record_effect);}
static PwNativeServiceChildContext context={NULL,clock_cb,cancel_cb,ticks_cb,record_cb};
static int mock_open(const char *path,int flags,...)
{int i=!strcmp(path,helper_paths[0])?0:!strcmp(path,helper_paths[1])?1:-1;assert(i>=0&&flags==(O_RDONLY|O_NOFOLLOW|O_NONBLOCK));m.opens++;if(m.file_missing_mask&(1<<i)){errno=ENOENT;return -1;}return 10+i;}
static int mock_fstat(int fd,struct stat *info)
{assert(fd==10||fd==11);m.stats++;memset(info,0,sizeof(*info));info->st_mode=m.file_bad_mode?0010000:0100000;info->st_size=m.file_bad_size?63:PW_NATIVE_SERVICE_SELF_BYTES;return 0;}
static ssize_t mock_read(int fd,void *bytes,size_t size)
{assert(fd==10||fd==11);unsigned *at=&m.positions[fd-10];m.reads++;if(m.file_read_error){errno=EIO;return -1;}if(*at==PW_NATIVE_SERVICE_SELF_BYTES){if(m.file_extra){*(unsigned char *)bytes=1;return 1;}return 0;}size_t n=PW_NATIVE_SERVICE_SELF_BYTES-*at;if(n>size)n=size;if(m.read_chunk&&n>m.read_chunk)n=m.read_chunk;memcpy(bytes,pw_native_service_image+*at,n);if(m.file_bad_bytes)*(unsigned char *)bytes^=1;*at+=(unsigned)n;return (ssize_t)n;}
static int mock_close(int fd){assert(fd>=0&&fd<256);m.close_count[fd]++;assert(m.close_count[fd]==1);if(fd==m.close_error){errno=EINTR;return m.close_return;}return 0;}
static int mock_socketpair(int family,int type,int protocol,int *pair)
{assert(family==AF_UNIX&&type==SOCK_SEQPACKET&&!protocol&&pair[0]==-1&&pair[1]==-1);m.pair_calls++;if(m.pair_mode==1){errno=EACCES;return -1;}if(m.pair_mode==2){pair[0]=80;pair[1]=81;errno=EACCES;return -1;}if(m.pair_mode==3)return 0;pair[0]=20;pair[1]=m.pair_mode==4?20:21;return 0;}
static int mock_nanosleep(const struct timespec *delay,struct timespec *remaining)
{assert(delay&&!remaining&&delay->tv_sec==0&&delay->tv_nsec>=0&&delay->tv_nsec<=100000000);m.sleeps++;m.now+=(uint64_t)delay->tv_nsec/1000000;return 0;}
static pid_t mock_getpid(void){return 101;}
int sceSystemServiceGetAppStatus(void *data)
{uint32_t *words=data;m.app_calls++;for(int i=0;i<4;i++)assert(!words[i]);if(m.app_rc)return m.app_rc;if(m.app_mode==1)return 0;words[0]=m.app_mode==2?UINT32_MAX:77;if(m.app_mode==3)words[4]=0;return 0;}
int sceSystemServiceGetLocalProcessStatusList(void *data,unsigned capacity,unsigned *count)
{
 ServiceEntry *entries=data;assert(capacity==16&&*count==UINT_MAX);m.list_calls++;
 for(unsigned i=0;i<capacity;i++){assert(!entries[i].id);for(unsigned j=0;j<32;j++)assert(!entries[i].name[j]);}
 int mode=m.list_calls==1?m.baseline_mode:(m.list_bad_after?m.list_bad_after:0);
 if(mode==1)return -5;
 if(mode==2)return 0;
 if(mode==3){*count=16;return 0;}if(mode==4){*count=17;return 0;}
 if(mode==5){*count=1;entries[0].id=0;return 0;}if(mode==6){*count=2;entries[0].id=entries[1].id=303;return 0;}
 if(mode==7){*count=0;*(uint32_t *)((unsigned char *)data+capacity*sizeof(ServiceEntry))=0;return 0;}
 if(m.list_calls==1){*count=2;entries[0].id=303;entries[1].id=304;return 0;}
 *count=(m.list_mode==2||(m.list_mode==1&&!m.kill_calls)||(m.list_mode==3&&m.list_calls>=3)||m.list_mode==4)?1:0;
 if(*count)entries[0].id=m.list_mode==4?202:404;
 return 0;
}
int sceSystemServiceAddLocalProcess(int app,const char *path,const char *const *argv,const void *options)
{
 const ServiceOptions *o=options;assert(app==77);
 assert(!strcmp(path,helper_paths[m.file_missing_mask==1?1:0]));assert(argv[0]==path&&!strcmp(argv[1],"native-service-probe-v1")&&!argv[2]);
 assert(o->size==72&&o->fd==21&&o->crash_report==1);
 for(unsigned i=0;i<15;i++)assert(o->other[i]==(i==0?UINT32_MAX:i==3?2:i==4?UINT32_C(0x80000000):0));
 assert(m.phases[m.phase_count-1]==PW_SC_LAUNCH_POSSIBLE&&m.list_calls==1&&m.app_calls==1);
 m.add_calls++;assert(m.add_calls==1);effect(m.add_effect);return m.add_return;
}
int sceSystemServiceKillLocalProcess(int app,int id)
{assert(app==77&&id==404&&id!=202&&m.list_calls>=2);m.kill_calls++;assert(m.kill_calls==1);return m.kill_return;}
int pw_native_service_packet_validate(PwNativeChildIo *io,int fd,PwNativeServicePacketResult *r)
{assert(io&&io->total_end==15100&&fd==20);m.validate_calls++;if(m.validate_error){r->status=PW_NS_PACKET_PROTOCOL;r->raw_result=-99;return -1;}return 0;}
long pw_native_service_packet_send(PwNativeChildIo *io,int fd,const void *bytes,size_t size,PwNativeServicePacketResult *r)
{assert(io&&fd==20&&size==96);assert(!pw_native_child_decode(&m.request,bytes));m.send_calls++;if(!m.tick_short)m.ticks++;(void)r;return (long)size;}
long pw_native_service_packet_receive(PwNativeChildIo *io,int fd,void *bytes,size_t size,PwNativeServicePacketResult *r)
{
 assert(io&&fd==20);m.receive_calls++;
 if(m.packet_error){r->status=PW_NS_PACKET_OS;r->raw_result=-77;r->cleanup_failed=m.packet_cleanup;r->ownership_uncertain=m.packet_ownership;return -1;}
 if(size==1){if(!m.tick_short)m.ticks+=2;return 0;}
 assert(size==96);PwNativeChildFrame frame={0};
 if(m.receive_calls==1){frame.kind=PW_NC_HELLO;frame.child_pid=m.hello_missing?0:202;frame.child_ppid=303;strcpy(frame.build_id,PW_NATIVE_SERVICE_BUILD_ID);}
 else{frame=m.request;frame.kind=frame.kind==PW_NC_STOP?PW_NC_STOP_ACK:PW_NC_ECHO_REPLY;}
 assert(!pw_native_child_encode(bytes,&frame));return 96;
}
static int run(PwNativeServiceChildResult *r){return pw_native_service_child_run(&context,r);}
static int test_success(void)
{
 reset();PwNativeServiceChildResult r;CHECK(!run(&r));CHECK(r.protocol_complete&&r.child.child_pid==202&&r.service_id==404&&r.app_id==77);
 CHECK(r.absent&&r.retired&&!r.cleanup_uncertain&&!r.kill_attempted&&r.parent_closed&&r.passed_closed);
 CHECK(m.add_calls==1&&!m.kill_calls&&m.close_count[20]==1&&m.close_count[21]==1&&m.close_count[10]==1&&m.close_count[11]==1);
 CHECK(!r.app_status_return&&r.app_status_canary_valid&&r.app_status_words[0]==77);
 CHECK(r.ui_ticks>=2&&r.baseline_valid&&r.baseline_count==2&&r.list_calls==2);
 unsigned calls=m.add_calls;CHECK(run(&r)<0&&r.status==PW_SC_ALREADY_ATTEMPTED&&m.add_calls==(int)calls);return 0;
}
static int test_kill_budget(void)
{
 reset();m.list_mode=1;m.record_effect_phase=PW_SC_KILL_POSSIBLE;m.record_effect=1;PwNativeServiceChildResult r;
 CHECK(run(&r)<0&&r.cleanup_uncertain&&r.protocol_complete);
 fprintf(stderr,"kill record deadline actual_calls=%d attempted=%u raw=%d forced=%u\n",m.kill_calls,r.kill_attempted,r.kill_return,r.forced_cleanup);
 CHECK(!m.kill_calls&&!r.kill_attempted&&!r.forced_cleanup);return 0;
}
static int test_done_boundary(int cancelled)
{
 reset();m.record_effect_phase=PW_SC_DONE;m.record_effect=cancelled?2:1;
 PwNativeServiceChildResult r;int rc=run(&r);
 fprintf(stderr,"done callback cancel=%d rc=%d status=%u uncertain=%u\n",cancelled,rc,r.status,r.cleanup_uncertain);
 CHECK(rc<0&&r.status==(cancelled?PW_SC_CANCELLED:PW_SC_TIMEOUT)&&r.retired&&!r.cleanup_uncertain);
 CHECK(m.add_calls==1&&!m.kill_calls&&m.close_count[20]==1&&m.close_count[21]==1);return 0;
}
static int test_preflight(void)
{
 PwNativeServiceChildResult r;
 for(int missing=1;missing<=3;missing++){
  reset();m.file_missing_mask=missing;int rc=run(&r);
  if(missing==3)CHECK(rc<0&&r.status==PW_SC_FILE&&!m.app_calls&&!m.add_calls);
  else CHECK(!rc&&r.selected_path==(missing==1?1:0)&&m.add_calls==1);
  CHECK(!m.close_count[(missing==1)?10:11]);
 }
 for(int which=0;which<6;which++){
  reset();if(which==0)m.file_bad_mode=1;
  if(which==1)m.file_bad_size=1;
  if(which==2)m.file_bad_bytes=1;
  if(which==3)m.file_read_error=1;
  if(which==4)m.file_extra=1;
  if(which==5)m.close_error=10;
  CHECK(run(&r)<0&&!m.app_calls&&!m.pair_calls&&!m.add_calls);
  CHECK(m.close_count[10]==1&&!m.close_count[11]);
  CHECK(r.cleanup_uncertain==(unsigned)(which==5));
 }
 for(unsigned chunk=1;chunk<=64;chunk++){
  reset();m.read_chunk=chunk;CHECK(!run(&r)&&r.path[0].bytes_match&&r.path[1].bytes_match&&m.add_calls==1);
 }
 reset();m.cancel=1;CHECK(run(&r)<0&&r.status==PW_SC_CANCELLED&&!m.opens&&!m.add_calls);
 reset();m.clock_error=1;CHECK(run(&r)<0&&r.status==PW_SC_CLOCK&&!m.opens&&!m.add_calls);
 reset();m.now=UINT64_MAX-19999;CHECK(run(&r)<0&&r.status==PW_SC_CLOCK&&!m.opens&&!m.add_calls);
 return 0;
}
static int test_baseline(void)
{
 PwNativeServiceChildResult r;
 for(int mode=1;mode<=3;mode++){
  reset();m.app_mode=mode;CHECK(run(&r)<0&&r.status==PW_SC_ABI&&!m.list_calls&&!m.pair_calls&&!m.add_calls);
  CHECK(r.app_status_words[0]==(mode==1?0u:mode==2?UINT32_MAX:77u)&&r.app_status_canary_valid==(unsigned)(mode!=3));
 }
 for(int raw=-1;raw<=1;raw+=2){reset();m.app_rc=raw;CHECK(run(&r)<0&&r.status==PW_SC_OS&&r.raw_result==raw&&!r.native_error&&!m.add_calls);}
 for(int mode=1;mode<=7;mode++){
  reset();m.baseline_mode=mode;CHECK(run(&r)<0&&!r.baseline_valid&&!m.pair_calls&&!m.add_calls&&!m.kill_calls);
  CHECK(r.status==(mode==1?PW_SC_OS:PW_SC_ABI));
 }
 for(int mode=1;mode<=4;mode++){
  reset();m.pair_mode=mode;CHECK(run(&r)<0&&!m.add_calls&&!m.validate_calls&&!m.kill_calls);
  CHECK(!m.close_count[80]&&!m.close_count[81]);
  CHECK(r.cleanup_uncertain==(unsigned)(mode!=1));
  CHECK(m.close_count[20]==(mode==4)&&!m.close_count[21]);
 }
 reset();m.validate_error=1;CHECK(run(&r)<0&&!m.add_calls&&m.close_count[20]==1&&m.close_count[21]==1);
 return 0;
}
static int test_launch_cleanup(void)
{
 PwNativeServiceChildResult r;
 const int bad[]={-5,0,303,304};
 for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++){
  reset();m.add_return=bad[i];CHECK(run(&r)<0&&r.launch_possible&&r.cleanup_uncertain&&r.service_id==0);
  CHECK(m.add_calls==1&&!m.kill_calls&&!m.send_calls&&m.close_count[20]==1&&m.close_count[21]==1);
  CHECK(r.raw_result==bad[i]&&r.api==PW_SC_API_ADD);
  CHECK(run(&r)<0&&r.status==PW_SC_ALREADY_ATTEMPTED&&m.add_calls==1);
 }
 reset();m.packet_error=1;CHECK(run(&r)<0&&r.status==PW_SC_PROTOCOL&&r.cleanup_uncertain&&r.absent&&r.retired&&!m.kill_calls);
 for(int extra=0;extra<2;extra++){
  reset();m.packet_error=1;m.list_mode=1;if(extra)m.packet_cleanup=1;else m.packet_ownership=1;
  CHECK(run(&r)<0&&r.status==PW_SC_PROTOCOL&&r.cleanup_uncertain&&m.kill_calls==1&&r.kill_attempted&&r.forced_cleanup&&r.absent&&r.retired);
  CHECK(r.raw_result==-77); /* cleanup never erases the original protocol failure */
 }
 reset();m.list_mode=1;CHECK(run(&r)<0&&r.status==PW_SC_FORCED_CLEANUP&&r.protocol_complete&&r.kill_attempted&&r.absent&&r.retired&&!r.cleanup_uncertain);
 reset();m.list_mode=1;m.kill_return=-88;CHECK(run(&r)<0&&r.cleanup_uncertain&&r.kill_return==-88&&m.kill_calls==1&&!r.absent);
 reset();m.list_mode=2;CHECK(run(&r)<0&&r.cleanup_uncertain&&m.kill_calls==1&&m.list_calls<=PW_SC_LIST_CALL_CAP&&!r.absent);
 for(int mode=1;mode<=7;mode++){
  reset();m.list_bad_after=mode;CHECK(run(&r)<0&&r.cleanup_uncertain&&!r.absent&&!r.retired&&!m.kill_calls);
 }
 for(int fd=20;fd<=21;fd++)for(int positive=0;positive<2;positive++){
  reset();m.close_error=fd;m.close_return=positive?1:-1;CHECK(run(&r)<0&&r.cleanup_uncertain&&m.close_count[20]==1&&m.close_count[21]==1);
  CHECK(r.status==PW_SC_OWNERSHIP&&r.native_error==(positive?0:EINTR)&&r.raw_result==m.close_return);
 }
 reset();m.tick_short=1;CHECK(run(&r)<0&&r.status==PW_SC_PROTOCOL&&r.protocol_complete&&r.ui_ticks<2);
 /* First complete absence retires the ID and ends enumeration permanently. */
 for(int mode=3;mode<=4;mode++){reset();m.list_mode=mode;CHECK(!run(&r));CHECK(r.retired&&m.list_calls==2&&!m.kill_calls);}
 return 0;
}
static int test_callback_boundaries(void)
{
 PwNativeServiceChildResult r;
 for(int phase=PW_SC_PREFLIGHT;phase<=PW_SC_EXCHANGING;phase++){
  if(phase==PW_SC_INITIAL)continue;
  for(int e=1;e<=4;e++){
   reset();m.record_effect_phase=phase;m.record_effect=e;
   CHECK(run(&r)<0);CHECK(!m.kill_calls);
   if(phase<PW_SC_EXCHANGING)CHECK(!m.add_calls&&!r.launch_possible);
   else CHECK(m.add_calls==1&&r.launch_possible);
  }
 }
 for(int e=1;e<=4;e++){
  reset();m.add_effect=e;CHECK(run(&r)<0&&r.launch_possible&&m.add_calls==1&&!m.send_calls);
  CHECK(m.close_count[20]==1&&m.close_count[21]==1);
 }
 return 0;
}
int main(int argc,char **argv)
{
 if(argc>1){if(!strcmp(argv[1],"done-expiry"))return test_done_boundary(0);if(!strcmp(argv[1],"done-cancel"))return test_done_boundary(1);if(!strcmp(argv[1],"kill-budget"))return test_kill_budget();return 2;}
 if(test_success()||test_kill_budget()||test_done_boundary(0)||test_done_boundary(1)||test_preflight()||test_baseline()||test_launch_cleanup()||test_callback_boundaries())return 1;
 printf("service parent pure mocks: %u checks passed; no native capabilities verified\n",checks);return 0;
}
