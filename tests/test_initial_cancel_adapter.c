/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Independent actual-source helper protocol review: every external boundary is mocked. */
#define PW_LAPY_INITIAL_CANCEL_ONLY 1
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#define PW_LAPY_HELPER_SHA256 "132bad75b1586e7949595b174c71d5d80a3bf6ebce9bfdffb95a2d0a509bcf83"
#include "native/pw_lapy_elevation.h"
#include "native/lapy_elevation_protocol.h"
static int mock_open(const char *,int,...), mock_fstat(int,struct stat *), mock_close(int);
static ssize_t mock_read(int,void *,size_t);
static int mock_clock_gettime(clockid_t,struct timespec *);
#define clock_gettime mock_clock_gettime
#define open mock_open
#define fstat mock_fstat
#define close mock_close
#define read mock_read
#define seteuid PW_FORBIDDEN_PREPARE
#define geteuid PW_FORBIDDEN_GETEUID
#include "native/pw_lapy_elevation.c"
#undef clock_gettime
#undef open
#undef fstat
#undef close
#undef read
#undef seteuid
#undef geteuid
struct Mock {
 unsigned char rx[128],tx[128];size_t rxn,rxi,txn,filei;
 int fail_open,fail_stat,fail_read,fail_socket,fail_connect,fail_option,fail_close;
 int nonregular,clone_fail,send_failure_kind,recv_failure_kind;
 long fail_send_at,fail_recv_at;
 int opens,closes,sockets,netcloses,clones,options,reads,neterror;
 size_t chunk;
 uint64_t now;size_t expire_after_tx;unsigned recovery_expired;
}m;
static unsigned checks,cases;
#define CHECK(x) do {++checks;if(!(x)){fprintf(stderr,"case=%u line=%d assertion=%s tx=%zu rx=%zu\n",cases,__LINE__,#x,m.txn,m.rxi);assert(x);}}while(0)
static int mock_open(const char *p,int flags,...){CHECK(!strcmp(p,PW_LAPY_HELPER_PATH)&&flags==(O_RDONLY|O_NOFOLLOW|O_NONBLOCK));m.opens++;if(m.fail_open){errno=ENOENT;return -1;}return 90;}
static int mock_fstat(int fd,struct stat *st){CHECK(fd==90);if(m.fail_stat){errno=EIO;return -1;}memset(st,0,sizeof(*st));st->st_mode=m.nonregular?S_IFDIR:S_IFREG;st->st_size=8;return 0;}
static int mock_close(int fd){CHECK(fd==90);m.closes++;if(m.fail_close){errno=EBADF;return -1;}return 0;}
static ssize_t mock_read(int fd,void *p,size_t n){CHECK(fd==90);m.reads++;if(m.fail_read){errno=EIO;return -1;}size_t left=8-m.filei;if(n>left)n=left;memcpy(p,&"\177ELFabc!"[m.filei],n);m.filei+=n;return (ssize_t)n;}
static int mock_clock_gettime(clockid_t kind,struct timespec *t){CHECK(kind==CLOCK_MONOTONIC);t->tv_sec=(time_t)(m.now/1000);t->tv_nsec=(long)(m.now%1000)*1000000;return 0;}
int ps5log_ps5_socket(int d,int t,int p){CHECK(d==AF_INET&&t==SOCK_STREAM&&p==IPPROTO_TCP);m.sockets++;if(m.fail_socket){errno=ENOBUFS;return -1;}return 42;}
int ps5log_ps5_connect(int fd,const struct sockaddr *p,socklen_t n){CHECK(fd==42&&p&&n==16);if(m.fail_connect){errno=ECONNREFUSED;return -1;}return 0;}
int ps5log_ps5_setsockopt(int fd,int level,int option,const void *p,socklen_t n){CHECK(fd==42&&level==0xffff&&p&&n==4&&(option==0x1105||option==0x1106||option==0x1109));m.options++;if(m.fail_option==m.options){errno=EIO;return -1;}return 0;}
int ps5log_ps5_close(int fd){CHECK(fd==42);m.netcloses++;if(m.fail_close){errno=EBADF;return -1;}return 0;}
long ps5log_ps5_send(int fd,const void *p,size_t n,int flags){CHECK(fd==42&&p&&flags==0);if(m.fail_send_at>=0&&(long)m.txn>=m.fail_send_at){errno=EPIPE;return m.send_failure_kind==1?0:m.send_failure_kind==2?(long)n+1:-1;}if(n>m.chunk)n=m.chunk;CHECK(m.txn+n<=sizeof(m.tx));memcpy(m.tx+m.txn,p,n);m.txn+=n;if(m.expire_after_tx&&m.txn>=m.expire_after_tx)m.now=31000;if(m.recovery_expired&&m.txn>=40)m.now=61000;return (long)n;}
int sceNetRecv(int fd,void *p,size_t n,int flags){CHECK(fd==42&&p&&flags==0);if(m.fail_recv_at>=0&&(long)m.rxi>=m.fail_recv_at){m.neterror=ETIMEDOUT;return m.recv_failure_kind==1?0:m.recv_failure_kind==2?(int)n+1:-1;}if(n>m.chunk)n=m.chunk;if(n>m.rxn-m.rxi)n=m.rxn-m.rxi;memcpy(p,m.rx+m.rxi,n);m.rxi+=n;return (int)n;}
int *sceNetErrnoLoc(void){return &m.neterror;}
static void reset(void){memset(&m,0,sizeof(m));m.fail_send_at=m.fail_recv_at=-1;m.chunk=1;m.now=1000;cases++;}
static struct lapy_elevation_message frame(unsigned kind,unsigned status){struct lapy_elevation_message f={LAPY_ELEVATION_MAGIC,LAPY_ELEVATION_VERSION,sizeof(f),kind,LAPY_ELEVATION_FILESYSTEM,1234,status,((uint64_t)1234<<32)^1000};return f;}
static void queue(struct lapy_elevation_message f){CHECK(m.rxn+sizeof(f)<=sizeof(m.rx));memcpy(m.rx+m.rxn,&f,sizeof(f));m.rxn+=sizeof(f);}
static int invoke(PwLapyElevationResult *r){memset(r,0xa5,sizeof(*r));errno=E2BIG;return pw_lapy_initial_cancel_result(1234,r);}

#include "native/pw_lapy_initial_cancel_fixture.h"
int main(void)
{
 PwLapyElevationResult r;
 for(unsigned status=0;status<16;status++){
  reset();queue(frame(LAPY_ELEVATION_RESPONSE,status));int rc=invoke(&r);
  CHECK((rc==0)==(status==LAPY_ELEVATION_CANCELLED));
  CHECK(!r.no_dispatch&&r.no_request&&!r.possible_apply&&r.cancel_attempted);
  CHECK(r.terminal==(status==LAPY_ELEVATION_CANCELLED));
  CHECK(m.txn==40&&m.sockets==1&&!m.clones&&m.closes==1&&m.netcloses==1);
  struct lapy_elevation_message f;memcpy(&f,m.tx+8,sizeof(f));CHECK(f.kind==LAPY_ELEVATION_CANCEL&&f.transaction_id==r.transaction_id);
  CHECK(pw_initial_cancel_classify(&r)==(status==LAPY_ELEVATION_CANCELLED?PW_INITIAL_CANCEL_RECEIPT_ONLY:PW_INITIAL_CANCEL_HELD));
 }
 for(unsigned field=0;field<8;field++){
  reset();struct lapy_elevation_message f=frame(LAPY_ELEVATION_RESPONSE,LAPY_ELEVATION_CANCELLED);
  switch(field){case 0:f.magic^=1;break;case 1:f.version++;break;case 2:f.size--;break;case 3:f.kind=LAPY_ELEVATION_PREPARE;break;case 4:f.capability++;break;case 5:f.pid++;break;case 6:f.status=LAPY_ELEVATION_OK;break;case 7:f.transaction_id^=1;break;}
  queue(f);CHECK(invoke(&r)<0&&!r.terminal&&pw_initial_cancel_classify(&r)==PW_INITIAL_CANCEL_HELD);
 }
 for(unsigned at=0;at<40;at++){
  reset();queue(frame(LAPY_ELEVATION_RESPONSE,LAPY_ELEVATION_CANCELLED));m.fail_send_at=at;
  CHECK(invoke(&r)<0&&!r.no_dispatch&&!r.terminal&&!r.possible_apply&&r.no_request);
  CHECK(pw_initial_cancel_classify(&r)==PW_INITIAL_CANCEL_HELD&&m.sockets==1&&!m.clones);
 }
 for(unsigned at=0;at<32;at++){
  reset();queue(frame(LAPY_ELEVATION_RESPONSE,LAPY_ELEVATION_CANCELLED));m.fail_recv_at=at;m.recv_failure_kind=1;
  CHECK(invoke(&r)<0&&!r.terminal&&pw_initial_cancel_classify(&r)==PW_INITIAL_CANCEL_HELD);
 }
 reset();m.fail_open=1;CHECK(invoke(&r)<0&&pw_initial_cancel_classify(&r)==PW_INITIAL_CANCEL_NO_DISPATCH&&!m.sockets);
 reset();m.fail_connect=1;CHECK(invoke(&r)<0&&pw_initial_cancel_classify(&r)==PW_INITIAL_CANCEL_NO_DISPATCH&&!m.txn);
 reset();m.expire_after_tx=8;queue(frame(LAPY_ELEVATION_RESPONSE,LAPY_ELEVATION_CANCELLED));CHECK(invoke(&r)==0&&r.terminal&&m.txn==40);
 reset();m.expire_after_tx=40;queue(frame(LAPY_ELEVATION_RESPONSE,LAPY_ELEVATION_CANCELLED));CHECK(invoke(&r)==0&&r.terminal&&m.txn==40);
 reset();memset(&r,0,sizeof(r));RootClient transport={.socket=42,.detail=&r,.operation_end=31000,.recovery_end=61000,.last_clock=1000};
 struct lapy_elevation_message forbidden=frame(LAPY_ELEVATION_REQUEST,0);int error=0;
 CHECK(root_send(&transport,&forbidden,sizeof(forbidden),100,PW_LC_REQUEST,1,&error)<0&&error==EPROTO&&!m.options&&!m.txn);
 CHECK(root_send(&transport,&forbidden,sizeof(forbidden),100,PW_LC_PREPARED,1,&error)<0&&error==EPROTO&&!m.options&&!m.txn);
 CHECK(root_receive(&transport,&forbidden,sizeof(forbidden),100,PW_LC_PREPARE,1,&error)<0&&error==EPROTO&&!m.options&&!m.rxi);
 reset();m.recovery_expired=1;queue(frame(LAPY_ELEVATION_RESPONSE,LAPY_ELEVATION_CANCELLED));
 CHECK(invoke(&r)<0&&!r.terminal&&m.txn==40&&!m.rxi&&pw_initial_cancel_classify(&r)==PW_INITIAL_CANCEL_HELD);
 CHECK(pw_initial_cancel_classify(NULL)==PW_INITIAL_CANCEL_HELD);
 printf("Initial-CANCEL actual adapter: %u cases, %u checks; receipt-only, no helper-exit claim; all platform boundaries inert\n",cases,checks);return 0;
}
