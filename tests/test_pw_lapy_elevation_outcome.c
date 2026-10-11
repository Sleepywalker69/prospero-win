/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Independent actual-source helper protocol review: every external boundary is mocked. */
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
#include "native/pw_lapy_elevation.h"
#include "native/lapy_elevation_protocol.h"
static int mock_open(const char *,int,...), mock_fstat(int,struct stat *), mock_close(int);
static ssize_t mock_read(int,void *,size_t);
static int mock_seteuid(uid_t);
static uid_t mock_geteuid(void);
#define open mock_open
#define fstat mock_fstat
#define close mock_close
#define read mock_read
#define seteuid mock_seteuid
#define geteuid mock_geteuid
#include "native/pw_lapy_elevation.c"
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
}m;
static unsigned checks,cases;
#define CHECK(x) do {++checks;if(!(x)){fprintf(stderr,"case=%u line=%d assertion=%s tx=%zu rx=%zu\n",cases,__LINE__,#x,m.txn,m.rxi);assert(x);}}while(0)
static int mock_open(const char *p,int flags,...){CHECK(!strcmp(p,PW_LAPY_HELPER_PATH)&&flags==O_RDONLY);m.opens++;if(m.fail_open){errno=ENOENT;return -1;}return 90;}
static int mock_fstat(int fd,struct stat *st){CHECK(fd==90);if(m.fail_stat){errno=EIO;return -1;}memset(st,0,sizeof(*st));st->st_mode=m.nonregular?S_IFDIR:S_IFREG;st->st_size=7;return 0;}
static int mock_close(int fd){CHECK(fd==90);m.closes++;if(m.fail_close){errno=EBADF;return -1;}return 0;}
static ssize_t mock_read(int fd,void *p,size_t n){CHECK(fd==90);m.reads++;if(m.fail_read){errno=EIO;return -1;}size_t left=7-m.filei;if(n>left)n=left;memcpy(p,&"ELFTEST"[m.filei],n);m.filei+=n;return (ssize_t)n;}
static uid_t mock_geteuid(void){return 1000;}
static int mock_seteuid(uid_t uid){CHECK(uid==1000);m.clones++;if(m.clone_fail){errno=EPERM;return -1;}return 0;}
int ps5log_ps5_socket(int d,int t,int p){CHECK(d==AF_INET&&t==SOCK_STREAM&&p==IPPROTO_TCP);m.sockets++;if(m.fail_socket){errno=ENOBUFS;return -1;}return 42;}
int ps5log_ps5_connect(int fd,const struct sockaddr *p,socklen_t n){CHECK(fd==42&&p&&n==16);if(m.fail_connect){errno=ECONNREFUSED;return -1;}return 0;}
int ps5log_ps5_setsockopt(int fd,int level,int option,const void *p,socklen_t n){CHECK(fd==42&&level==0xffff&&p&&n==4&&(option==0x1105||option==0x1106||option==0x1109));m.options++;if(m.fail_option==m.options){errno=EIO;return -1;}return 0;}
int ps5log_ps5_close(int fd){CHECK(fd==42);m.netcloses++;if(m.fail_close){errno=EBADF;return -1;}return 0;}
long ps5log_ps5_send(int fd,const void *p,size_t n,int flags){CHECK(fd==42&&p&&flags==0);if(m.fail_send_at>=0&&(long)m.txn>=m.fail_send_at){errno=EPIPE;return m.send_failure_kind==1?0:m.send_failure_kind==2?(long)n+1:-1;}if(n>m.chunk)n=m.chunk;CHECK(m.txn+n<=sizeof(m.tx));memcpy(m.tx+m.txn,p,n);m.txn+=n;return (long)n;}
int sceNetRecv(int fd,void *p,size_t n,int flags){CHECK(fd==42&&p&&flags==0);if(m.fail_recv_at>=0&&(long)m.rxi>=m.fail_recv_at){m.neterror=ETIMEDOUT;return m.recv_failure_kind==1?0:m.recv_failure_kind==2?(int)n+1:-1;}if(n>m.chunk)n=m.chunk;if(n>m.rxn-m.rxi)n=m.rxn-m.rxi;memcpy(p,m.rx+m.rxi,n);m.rxi+=n;return (int)n;}
int *sceNetErrnoLoc(void){return &m.neterror;}
static void reset(void){memset(&m,0,sizeof(m));m.fail_send_at=m.fail_recv_at=-1;m.chunk=1;cases++;}
static struct lapy_elevation_message frame(unsigned kind,unsigned status){struct lapy_elevation_message f={LAPY_ELEVATION_MAGIC,LAPY_ELEVATION_VERSION,sizeof(f),kind,LAPY_ELEVATION_FILESYSTEM,1234,status};return f;}
static void queue(struct lapy_elevation_message f){CHECK(m.rxn+sizeof(f)<=sizeof(m.rx));memcpy(m.rx+m.rxn,&f,sizeof(f));m.rxn+=sizeof(f);}
static int invoke(PwLapyElevationResult *r){memset(r,0xa5,sizeof(*r));errno=E2BIG;return pw_lapy_elevation_request_result(1234,r);}
static int is_terminal(unsigned s,int phase){return phase?(s==0||s==4||s==5||s==6||s==7||s==9||s==10):(s>=1&&s<=4);}
static void good(void){queue(frame(LAPY_ELEVATION_PREPARE,0));queue(frame(LAPY_ELEVATION_RESPONSE,0));}
int main(void){PwLapyElevationResult r;
 reset();good();CHECK(invoke(&r)==0);CHECK(r.possible_apply==1&&r.terminal==1&&r.helper_status==0&&m.clones==1&&m.closes==1&&m.netcloses==1);
 for(unsigned phase=0;phase<2;phase++)for(unsigned s=0;s<16;s++){reset();if(phase)queue(frame(LAPY_ELEVATION_PREPARE,0));queue(frame(LAPY_ELEVATION_RESPONSE,s));int rc=invoke(&r);CHECK((rc==0)==(phase&&s==0));CHECK(r.possible_apply==1);CHECK((r.terminal!=0)==is_terminal(s,phase));CHECK(m.clones==(int)phase&&m.closes==1&&m.netcloses==1);}
 for(unsigned phase=0;phase<2;phase++)for(unsigned field=0;field<7;field++){reset();struct lapy_elevation_message f=frame(phase?LAPY_ELEVATION_RESPONSE:LAPY_ELEVATION_PREPARE,0);if(phase)queue(frame(LAPY_ELEVATION_PREPARE,0));switch(field){case 0:f.magic^=1;break;case 1:f.version++;break;case 2:f.size--;break;case 3:f.kind=77;break;case 4:f.capability++;break;case 5:f.pid++;break;case 6:f.status=0xffffffff;break;}queue(f);CHECK(invoke(&r)<0);CHECK(r.possible_apply==1&&!r.terminal);}
 for(int kind=0;kind<3;kind++)for(long at=0;at<55;at++){reset();good();m.fail_send_at=at;m.send_failure_kind=kind;CHECK(invoke(&r)<0);CHECK((r.possible_apply!=0)==(at>=7));CHECK(!r.terminal&&m.closes==1&&m.netcloses==1);}
 for(int kind=0;kind<3;kind++)for(long at=0;at<48;at++){reset();good();m.fail_recv_at=at;m.recv_failure_kind=kind;CHECK(invoke(&r)<0);CHECK(r.possible_apply==1&&!r.terminal&&m.closes==1&&m.netcloses==1);}
 for(unsigned i=0;i<8;i++){reset();good();switch(i){case 0:m.fail_open=1;break;case 1:m.fail_stat=1;break;case 2:m.nonregular=1;break;case 3:m.fail_socket=1;break;case 4:m.fail_connect=1;break;case 5:m.fail_option=1;break;case 6:m.fail_option=3;break;case 7:m.fail_read=1;break;}CHECK(invoke(&r)<0);CHECK(!r.possible_apply&&!r.terminal);}
 for(unsigned s=0;s<16;s++){reset();m.clone_fail=1;queue(frame(LAPY_ELEVATION_PREPARE,0));queue(frame(LAPY_ELEVATION_RESPONSE,s));CHECK(invoke(&r)<0);CHECK(r.possible_apply==1);CHECK((r.terminal!=0)==(s&&is_terminal(s,1)));CHECK(m.clones==1);}
 for(unsigned at=0;at<2;at++){reset();good();m.fail_close=1;if(at)m.fail_recv_at=47;int rc=invoke(&r);CHECK(r.possible_apply==1);CHECK((r.terminal!=0)==!at);CHECK(!at||rc<0);}
 for(int pid=-1;pid<=1;pid++){reset();memset(&r,0xa5,sizeof(r));CHECK(pw_lapy_elevation_request_result(pid,&r)<0);CHECK(!r.possible_apply&&!r.terminal&&!m.opens);}
 printf("Independent actual root helper: %u checks in %u cases; all file/network/native boundaries mocked\n",checks,cases);return 0;
}
