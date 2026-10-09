/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Actual diagnostic C with every native boundary mocked. No socket traffic. */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#undef O_NONBLOCK
#define O_NONBLOCK 0x0004
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef SOCK_SEQPACKET
#define SOCK_SEQPACKET 5
#endif
#ifndef SO_TYPE
#define SO_TYPE 0x1008
#endif
_Static_assert(F_GETFD==1&&F_GETFL==3&&F_SETFL==4,"reviewed target commands");
_Static_assert(SOL_SOCKET==0xffff&&SO_TYPE==0x1008&&AF_UNIX==1&&AF_INET==2&&
               SOCK_STREAM==1&&SOCK_SEQPACKET==5&&FD_CLOEXEC==1,
               "reviewed target socket constants; compile with native_peer_fixture");
_Static_assert(FIOCLEX==0x20006601UL&&FIONBIO==0x8004667eUL,
               "reviewed target ioctl requests; never host Linux values");
static int mock_socket(int,int,int),mock_socketpair(int,int,int,int *),mock_close(int);
static int mock_fcntl(int,int,...),mock_ioctl(int,unsigned long,...);
static int mock_getsockopt(int,int,int,void *,socklen_t *);
static int mock_setsockopt(int,int,int,const void *,socklen_t);
#define socket mock_socket
#define socketpair mock_socketpair
#define close mock_close
#define fcntl mock_fcntl
#define ioctl mock_ioctl
#define getsockopt mock_getsockopt
#define setsockopt mock_setsockopt
#include "../native/pw_native_socket_diagnostic.c"
#undef socket
#undef socketpair
#undef close
#undef fcntl
#undef ioctl
#undef getsockopt
#undef setsockopt

enum { T_CREATE,T_TYPE,T_GETFD,T_GETFL,T_NBIO,T_CLEX,T_SET,T_CLOSE };
static struct {
 uint64_t now;int cancelled,clock_error,next_fd,zero_fd,active,max_active;
 unsigned calls,creates,pairs,setters,closes,trigger,effect,fail_at;
 int fail_result,pair_mode,pair_failure,foreign_closes,close_error,bad_baseline,bad_type,output_mode;
 struct { int owned,closed,flags,descriptor_flags,socket_type,foreign;unsigned nbio_reads; } fd[256];
 struct { unsigned operation;int fd; } trace[160];
} m;
static unsigned checks;
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);return 1;}}while(0)
static int clock_cb(void *unused,uint64_t *now)
{(void)unused;errno=EBADF;*now=m.now;return m.clock_error;}
static int cancel_cb(void *unused){(void)unused;errno=EBADF;return m.cancelled;}
static PwNativeSocketDiagnosticContext context={NULL,clock_cb,cancel_cb};
static void reset(void){memset(&m,0,sizeof(m));m.now=100;m.next_fd=10;m.fail_result=-1;}
static int allocated(void)
{int fd=m.zero_fd?0:m.next_fd++;m.zero_fd=0;assert(fd>=0&&fd<256&&!m.fd[fd].owned&&!m.fd[fd].closed);m.fd[fd].owned=1;m.fd[fd].flags=0x2a;m.fd[fd].descriptor_flags=0x40;m.active++;if(m.active>m.max_active)m.max_active=m.active;return fd;}
static void called(unsigned operation,int fd)
{
 assert(m.calls<160);m.trace[m.calls].operation=operation;m.trace[m.calls].fd=fd;m.calls++;
 if(m.calls==m.trigger){if(m.effect==1)m.now=5100;if(m.effect==2)m.cancelled=1;if(m.effect==3)m.clock_error=1;if(m.effect==4)m.now=99;}
}
static int fail_now(void){if(m.calls!=m.fail_at)return 0;errno=EACCES;return 1;}
static void owned(int fd){assert(fd>=0&&fd<256&&m.fd[fd].owned&&!m.fd[fd].closed);}
static int mock_socket(int family,int type,int protocol)
{
 assert((family==AF_UNIX||family==AF_INET)&&type==SOCK_STREAM&&!protocol);called(T_CREATE,-1);m.creates++;
 if(fail_now())return -1;
 int fd=allocated();m.fd[fd].socket_type=type;return fd;
}
static int mock_socketpair(int family,int type,int protocol,int *pair)
{
 assert(family==AF_UNIX&&(type==SOCK_STREAM||type==SOCK_SEQPACKET)&&!protocol&&pair&&pair[0]==-1&&pair[1]==-1);called(T_CREATE,-1);m.creates++;m.pairs++;
 if(m.pair_mode==1)return 0; /* rc0, both outputs untouched */
 if(m.pair_mode==4||m.pair_mode==5){errno=EACCES;return m.pair_mode==4?-1:1;}
 if(m.pair_mode==6){pair[0]=-2;errno=EACCES;return -1;}
 if(m.pair_failure){
  pair[0]=200;pair[1]=201;m.fd[200].owned=m.fd[201].owned=1;m.fd[200].foreign=m.fd[201].foreign=1;
  errno=EACCES;return m.pair_failure==1?-1:1;
 }
 pair[0]=allocated();m.fd[pair[0]].socket_type=type;
 if(m.pair_mode==2)return 0; /* rc0, only one endpoint */
 pair[1]=m.pair_mode==3?pair[0]:allocated();m.fd[pair[1]].socket_type=type;
 return 0;
}
static int mock_close(int fd)
{
 owned(fd);called(T_CLOSE,fd);if(m.fd[fd].foreign){m.foreign_closes++;return 0;}m.fd[fd].owned=0;m.fd[fd].closed++;assert(m.fd[fd].closed==1);m.active--;m.closes++;
 if(m.close_error){errno=EINTR;return -1;}return 0;
}
static int mock_fcntl(int fd,int command,...)
{
 owned(fd);va_list args;va_start(args,command);int value=va_arg(args,int);va_end(args);
 if(command==F_GETFD||command==F_GETFL){assert(value==0);called(command==F_GETFD?T_GETFD:T_GETFL,fd);if(fail_now())return m.fail_result;return command==F_GETFD?m.fd[fd].descriptor_flags:m.fd[fd].flags;}
 assert(command==F_SETFL&&value==(m.fd[fd].flags|O_NONBLOCK));called(T_SET,fd);m.setters++;if(fail_now())return m.fail_result;m.fd[fd].flags=value;return 0;
}
static int mock_ioctl(int fd,unsigned long request,...)
{
 owned(fd);va_list args;va_start(args,request);
 if(request==FIOCLEX){assert(va_arg(args,void *)==NULL);called(T_CLEX,fd);}
 else{assert(request==FIONBIO);int *v=va_arg(args,int *);assert(v&&*v==1);called(T_SET,fd);m.setters++;}
 va_end(args);if(fail_now())return m.fail_result;
 if(request==FIOCLEX)m.fd[fd].descriptor_flags|=FD_CLOEXEC;else m.fd[fd].flags|=O_NONBLOCK;return 0;
}
static int mock_setsockopt(int fd,int level,int option,const void *value,socklen_t size)
{
 owned(fd);assert(level==SOL_SOCKET&&option==0x1200&&value&&size==4&&*(const int *)value==1);called(T_SET,fd);m.setters++;if(fail_now())return m.fail_result;m.fd[fd].flags|=O_NONBLOCK;return 0;
}
static int mock_getsockopt(int fd,int level,int option,void *value,socklen_t *size)
{
 owned(fd);assert(level==SOL_SOCKET&&(option==SO_TYPE||option==0x1200)&&value&&size&&*size==4);
 uint32_t initial;memcpy(&initial,value,4);assert(initial==UINT32_C(0xa5a5a5a5));called(option==SO_TYPE?T_TYPE:T_NBIO,fd);
 if(fail_now())return m.fail_result;
 if(option==SO_TYPE){*(int *)value=m.bad_type?2:m.fd[fd].socket_type;return 0;}
 unsigned before=m.fd[fd].nbio_reads++==0;
 if(before&&m.bad_baseline){errno=EACCES;return -1;}
 if(m.output_mode==1)return 0;
 *(int *)value=m.fd[fd].flags&O_NONBLOCK;
 if(m.output_mode==2)*size=0;
 if(m.output_mode==3)*size=3;
 if(m.output_mode==4)*size=5;
 if(m.output_mode==5)*size=UINT32_MAX;
 if(m.output_mode==6)*(int *)value=0x1200;
 if(m.output_mode==7)*(int *)value=INT32_MIN;
 if(m.output_mode==8){memset(value,0xa5,4);*(unsigned char *)value=0x19;*size=1;}
 return 0;
}
static int baseline_getter_failure(void)
{
 reset();m.bad_baseline=1;PwNativeSocketDiagnosticResult r;int rc=pw_native_socket_diagnostic_run(&context,&r);
 fprintf(stderr,"baseline NBIO failure rc=%d complete=%u setters=%u cases=%u\n",rc,r.collection_complete,m.setters,r.cases_finished);
 CHECK(!rc&&r.collection_complete&&r.cases_finished==12);CHECK(m.setters==12);CHECK(!m.active&&m.max_active<=2);return 0;
}
static int pair_untouched(void)
{
 reset();m.pair_mode=1;PwNativeSocketDiagnosticResult r;int rc=pw_native_socket_diagnostic_run(&context,&r);
 fprintf(stderr,"untouched pair rc=%d complete=%u status=%u uncertain=%u\n",rc,r.collection_complete,r.status,r.cleanup_uncertain);
 CHECK(rc<0&&r.status==PW_SD_OWNERSHIP&&r.cleanup_uncertain&&!r.collection_complete);CHECK(!m.active);return 0;
}
static int test_complete(void)
{
 reset();PwNativeSocketDiagnosticResult r;CHECK(!pw_native_socket_diagnostic_run(&context,&r));
 CHECK(r.collection_complete&&!r.status&&!r.cleanup_uncertain&&r.cases_started==12&&r.cases_finished==12);
 CHECK(r.native_calls==138&&m.calls==138&&r.rows==138&&m.creates==12&&m.pairs==6&&m.setters==12&&m.closes==18);
 CHECK(!m.active&&m.max_active==2&&!r.failed_calls&&!r.malformed_readbacks&&!r.skipped_setters);
 unsigned at=0;
 for(unsigned c=0;c<12;c++){
  for(unsigned op=PW_SD_CREATE;op<=PW_SD_CLOSE;op++){
   PwNativeSocketDiagnosticRow *v=&r.row[at++];
   CHECK(v->case_id==c&&v->topology==c/3&&v->method==c%3&&v->operation==op&&v->disposition==PW_SD_EXECUTED);
   CHECK(!v->errno_valid&&!v->native_error);
   if(op==PW_SD_CREATE){CHECK(v->descriptor>=0);CHECK((v->companion>=0)==(c/3==PW_SD_UNIX_PAIR||c/3==PW_SD_UNIX_SEQPACKET_PAIR));}
   if(op==PW_SD_TYPE)CHECK(v->type_control_matches);
   if(op==PW_SD_SET_NONBLOCK)CHECK(v->input_value==(c%3==PW_SD_FCNTL?(0x2a|O_NONBLOCK):1));
   if(op==PW_SD_TYPE||op==PW_SD_NBIO_BEFORE||op==PW_SD_NBIO_AFTER){
    CHECK(v->has_buffer&&v->input_length==4&&v->output_length==4&&v->length_matches&&!v->buffer_unchanged);
    for(unsigned b=0;b<4;b++)CHECK(v->input_bytes[b]==0xa5);
    uint32_t hex;memcpy(&hex,v->output_bytes,4);CHECK(hex==v->output_hex&&hex==(uint32_t)v->output_value);
   }
  }
  if(c/3==PW_SD_UNIX_PAIR||c/3==PW_SD_UNIX_SEQPACKET_PAIR){PwNativeSocketDiagnosticRow *v=&r.row[at++];CHECK(v->operation==PW_SD_CLOSE&&v->case_id==c);}
 }
 CHECK(at==r.rows);return 0;
}
static int test_observations(void)
{
 PwNativeSocketDiagnosticResult r;
 reset();m.bad_type=1;CHECK(!pw_native_socket_diagnostic_run(&context,&r));CHECK(r.collection_complete&&r.malformed_readbacks==12&&m.setters==12&&!m.active);
 for(int mode=1;mode<=8;mode++){
  reset();m.output_mode=mode;CHECK(!pw_native_socket_diagnostic_run(&context,&r));
  CHECK(r.collection_complete&&m.setters==12&&!m.active);
  CHECK(r.malformed_readbacks==((mode<=5||mode==8)?24u:0u));
  for(unsigned i=0;i<r.rows;i++)if(r.row[i].operation==PW_SD_NBIO_BEFORE||r.row[i].operation==PW_SD_NBIO_AFTER){
   PwNativeSocketDiagnosticRow *v=&r.row[i];CHECK(!v->raw_return&&!v->errno_valid&&!v->native_error);
   CHECK(v->buffer_unchanged==(mode==1));
   CHECK(v->output_length==(mode==2?0u:mode==3?3u:mode==4?5u:mode==5?UINT32_MAX:mode==8?1u:4u));
   if(mode==1)CHECK(v->output_hex==UINT32_C(0xa5a5a5a5));
   if(mode==6)CHECK(v->output_hex==0x1200);
   if(mode==7)CHECK(v->output_hex==UINT32_C(0x80000000));
   if(mode==8)CHECK(v->output_bytes[0]==0x19&&v->output_bytes[1]==0xa5&&v->output_bytes[2]==0xa5&&v->output_bytes[3]==0xa5);
  }
 }
 /* Negative GETFL is not a flags value: its F_SETFL row must be skipped. */
 reset();m.fail_at=4;CHECK(!pw_native_socket_diagnostic_run(&context,&r));
 CHECK(r.collection_complete&&r.skipped_setters==1&&m.setters==11&&r.native_calls==137&&r.rows==138);
 CHECK(r.row[7].operation==PW_SD_SET_NONBLOCK&&r.row[7].disposition==PW_SD_SKIP_GETFL);
 CHECK(r.row[3].errno_valid&&r.row[3].native_error==EACCES);
 /* Type, descriptor metadata, CLEX and setter errors remain independent observations. */
 const unsigned failures[]={2,3,5,6,8,10};
 for(unsigned j=0;j<sizeof(failures)/sizeof(failures[0]);j++)for(int positive=0;positive<2;positive++){
  reset();m.fail_at=failures[j];m.fail_result=positive?1:-1;CHECK(!pw_native_socket_diagnostic_run(&context,&r));
  PwNativeSocketDiagnosticRow *v=&r.row[failures[j]-1];
  CHECK(r.collection_complete&&m.setters==12&&!m.active&&v->raw_return==m.fail_result);
  CHECK(v->errno_valid==(unsigned)!positive&&v->native_error==(positive?0:EACCES));
 }
 return 0;
}
static int test_ownership(void)
{
 PwNativeSocketDiagnosticResult r;
 reset();m.zero_fd=1;CHECK(!pw_native_socket_diagnostic_run(&context,&r));CHECK(m.fd[0].closed==1&&!m.active);
 for(int mode=1;mode<=3;mode++){
  reset();m.pair_mode=mode;CHECK(pw_native_socket_diagnostic_run(&context,&r)<0);
  CHECK(r.status==PW_SD_OWNERSHIP&&r.cleanup_uncertain&&!r.collection_complete&&!m.active);
  CHECK(m.creates==4&&m.closes==(mode==1?3u:4u));
 }
 reset();m.pair_mode=4;CHECK(!pw_native_socket_diagnostic_run(&context,&r));
 CHECK(r.collection_complete&&r.failed_calls==6&&!r.cleanup_uncertain&&!m.active&&m.closes==6);
 for(int mode=5;mode<=6;mode++){
  reset();m.pair_mode=mode;CHECK(pw_native_socket_diagnostic_run(&context,&r)<0);
  CHECK(!r.collection_complete&&r.cleanup_uncertain&&!m.active&&m.closes==3);
 }
 for(int failure=1;failure<=2;failure++){
  reset();m.pair_failure=failure;CHECK(pw_native_socket_diagnostic_run(&context,&r)<0);
  CHECK(r.cleanup_uncertain&&!m.active&&m.closes==3&&!m.foreign_closes);
  CHECK(r.row[33].descriptor==200&&r.row[33].companion==201&&r.row[33].raw_return==(failure==1?-1:1));
 }
 reset();m.close_error=1;CHECK(pw_native_socket_diagnostic_run(&context,&r)<0);CHECK(r.cleanup_uncertain&&!r.collection_complete&&m.creates==1&&m.closes==1&&!m.active);
 CHECK(r.row[r.rows-1].operation==PW_SD_CLOSE&&r.row[r.rows-1].native_error==EINTR);
 reset();m.fail_at=1;CHECK(!pw_native_socket_diagnostic_run(&context,&r));CHECK(r.collection_complete&&r.failed_calls==1&&m.closes==17&&!m.active);
 return 0;
}
static int test_boundaries(void)
{
 PwNativeSocketDiagnosticResult r;
 for(unsigned call=1;call<=138;call++)for(unsigned effect=1;effect<=4;effect++){
  reset();m.trigger=call;m.effect=effect;CHECK(pw_native_socket_diagnostic_run(&context,&r)<0);
  CHECK(!r.collection_complete&&!m.active&&m.max_active<=2&&r.native_calls==m.calls&&r.rows<=PW_SD_MAX_ROWS);
  CHECK(r.status==(effect==1?PW_SD_TIMEOUT:effect==2?PW_SD_CANCELLED:PW_SD_CLOCK));
  for(unsigned i=call;i<m.calls;i++)CHECK(m.trace[i].operation==T_CLOSE);
 }
 reset();m.cancelled=1;CHECK(pw_native_socket_diagnostic_run(&context,&r)<0&&r.status==PW_SD_CANCELLED&&!m.calls);
 reset();m.clock_error=1;CHECK(pw_native_socket_diagnostic_run(&context,&r)<0&&r.status==PW_SD_CLOCK&&!m.calls);
 reset();m.now=0;CHECK(!pw_native_socket_diagnostic_run(&context,&r)&&r.started==0&&r.deadline==5000);
 reset();m.now=UINT64_MAX-4999;CHECK(pw_native_socket_diagnostic_run(&context,&r)<0&&r.status==PW_SD_CLOCK&&!m.calls);
 reset();m.now=UINT64_MAX-5000;CHECK(!pw_native_socket_diagnostic_run(&context,&r)&&r.deadline==UINT64_MAX);
 CHECK(pw_native_socket_diagnostic_run(NULL,&r)<0&&r.status==PW_SD_INVALID);
 PwNativeSocketDiagnosticContext invalid={0};CHECK(pw_native_socket_diagnostic_run(&invalid,&r)<0&&r.status==PW_SD_INVALID);
 CHECK(pw_native_socket_diagnostic_run(&context,NULL)<0);return 0;
}
static int test_failed_pair_outputs(int selected)
{
 for(int failure=selected?selected:1;failure<=(selected?selected:2);failure++){
  reset();m.pair_failure=failure;PwNativeSocketDiagnosticResult r;
  CHECK(pw_native_socket_diagnostic_run(&context,&r)<0&&r.cleanup_uncertain&&!r.collection_complete);
  fprintf(stderr,"failed pair raw=%d foreign_closes=%d owned_closes=%u\n",failure==1?-1:1,m.foreign_closes,m.closes);
  CHECK(!m.foreign_closes&&m.closes==3&&!m.active);
  CHECK(r.row[33].descriptor==200&&r.row[33].companion==201&&r.row[33].raw_return==(failure==1?-1:1));
 }
 return 0;
}
int main(int argc,char **argv)
{
 if(argc>1){if(!strcmp(argv[1],"positive-pair-outputs"))return test_failed_pair_outputs(2);if(!strcmp(argv[1],"failed-pair-outputs"))return test_failed_pair_outputs(0);if(!strcmp(argv[1],"baseline-getter-failure"))return baseline_getter_failure();if(!strcmp(argv[1],"pair-untouched"))return pair_untouched();return 2;}
 if(baseline_getter_failure()||pair_untouched()||test_complete()||test_observations()||test_ownership()||test_failed_pair_outputs(0)||test_boundaries())return 1;
 printf("socket matrix pure mocks: %u checks passed; no native capabilities verified\n",checks);return 0;
}
