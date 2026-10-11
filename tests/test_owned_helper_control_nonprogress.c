/* Independent host-only no-progress guard oracle. All callbacks inert. */
#include <errno.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "owned_helper_control.h"
#define LIMIT 1024U
#define HARNESS_LIMIT 40000U
static unsigned cases,checks;
static const char *label;
#define C(x) do {++checks;if(!(x)){fprintf(stderr,"FAIL case=%u %s line=%d: %s\n",cases,label,__LINE__,#x);exit(1);}}while(0)
static jmp_buf budget;
static struct {
 unsigned waits,clocks,reads,writes,idle,period,bytes,chunk,after,action,writing;
 unsigned long calls;
 uint64_t now;
 int ready_fault,io_fault;
 struct lapy_elevation_message input;
} m;
static struct lapy_helper_control ctl;
static int clock_cb(void *context,uint64_t *out)
{
 C(context==&m);++m.clocks;
 if(++m.calls>HARNESS_LIMIT)longjmp(budget,1);
 if(m.after&&m.waits>=m.after){
  if(m.action==1)m.now++;
  else if(m.action==2)m.now=120100;
  else if(m.action==3)m.now=99;
  else if(m.action==4)return -1;
  if(m.action==1)m.after=0;
 }
 *out=m.now;return 0;
}
static int wait_cb(void *context,int writing,unsigned milliseconds)
{
 C(context==&m);C(milliseconds<=100);C((unsigned)writing==m.writing);++m.waits;
 if(m.ready_fault)return -1;
 if(m.action==5)m.now+=milliseconds;
 if(m.action==6&&m.waits%8==0)m.now++;
 if(m.idle<m.period){++m.idle;return 0;}
 return 1;
}
static long read_cb(void *context,void *out,size_t size)
{
 C(context==&m);++m.reads;
 if(m.io_fault){errno=m.io_fault;return -1;}
 if(m.action==7)return 0;
 if(m.action==8)return (long)size+1;
 size_t n=m.chunk&&m.chunk<size?m.chunk:size;
 C(m.bytes+n<=32);memcpy(out,(const unsigned char*)&m.input+m.bytes,n);
 m.bytes+=(unsigned)n;m.idle=0;if(m.action==9)m.period=100000;return (long)n;
}
static long write_cb(void *context,const void *bytes,size_t size)
{
 C(context==&m&&bytes);++m.writes;
 if(m.io_fault){errno=m.io_fault;return -1;}
 if(m.action==7)return 0;
 if(m.action==8)return (long)size+1;
 size_t n=m.chunk&&m.chunk<size?m.chunk:size;
 m.bytes+=(unsigned)n;m.idle=0;if(m.action==9)m.period=100000;return (long)n;
}
static void reset(const char *name,unsigned writing)
{
 ++cases;label=name;memset(&m,0,sizeof(m));m.now=100;m.writing=writing;
 struct lapy_control_io io={&m,clock_cb,wait_cb,read_cb,write_cb};
 C(!lapy_control_init(&ctl,&io,120100));
 m.input=(struct lapy_elevation_message){LAPY_ELEVATION_MAGIC,2,32,LAPY_ELEVATION_CANCEL,1,600,0,UINT64_C(0x76543210abcdef98)};
}
static enum lapy_control_result transfer(void)
{
 static unsigned char bytes[32];
 if(setjmp(budget)){fprintf(stderr,"HARNESS_BUDGET_EXCEEDED case=%u %s waits=%u clocks=%u bytes=%u\n",cases,label,m.waits,m.clocks,m.bytes);exit(1);}
 return lapy_control_transfer(&ctl,bytes,32,(int)m.writing);
}
static void boundary_matrix(void)
{
 for(unsigned writing=0;writing<2;++writing)for(unsigned zeros=LIMIT-1;zeros<=LIMIT+1;++zeros){
  reset("threshold minus/at/plus",writing);m.period=zeros;
  C(transfer()==(zeros<LIMIT?LAPY_CTL_CONTINUE:LAPY_CTL_IO));
  C(m.waits==(zeros<LIMIT?LIMIT:LIMIT));C(m.bytes==(zeros<LIMIT?32:0));
 }
 for(unsigned writing=0;writing<2;++writing)for(unsigned action=1;action<=4;++action){
  reset("clock precedence at exhausted guard",writing);m.period=LIMIT;m.after=LIMIT;m.action=action;
  enum lapy_control_result expected=action==1?LAPY_CTL_CONTINUE:action==2?LAPY_CTL_TIMEOUT:LAPY_CTL_IO;
  C(transfer()==expected);C(m.waits==(action==1?LIMIT+1:LIMIT));C(m.bytes==(action==1?32:0));
 }
 for(unsigned writing=0;writing<2;++writing){
  reset("advancing full120second deadline",writing);m.period=100000;m.action=5;
  C(transfer()==LAPY_CTL_TIMEOUT);C(m.waits==1200&&!m.bytes);
  reset("slow quantized clock progresses every8waits",writing);m.period=4096;m.action=6;
  C(transfer()==LAPY_CTL_CONTINUE);C(m.waits==4097&&m.bytes==32);
  reset("constant clock many positive byte fragments",writing);m.chunk=1;
  C(transfer()==LAPY_CTL_CONTINUE);C(m.waits==32&&m.bytes==32);
 }
}
static void partial_and_errors(void)
{
 for(unsigned writing=0;writing<2;++writing)for(unsigned chunk=1;chunk<=16;chunk*=2){
  reset("partial byte progress resets near-bound idle count",writing);m.period=LIMIT-1;m.chunk=chunk;
  C(transfer()==LAPY_CTL_CONTINUE);C(m.bytes==32);C(m.waits==LIMIT*(32/chunk));
 }
 const int errors[]={EINTR,EAGAIN,EIO,EPERM};
 for(unsigned writing=0;writing<2;++writing)for(unsigned delayed=0;delayed<2;++delayed)for(unsigned e=0;e<4;++e){
  reset("ready but negative IO is immediate failure",writing);m.period=delayed?LIMIT-1:0;m.io_fault=errors[e];
  C(transfer()==LAPY_CTL_IO);C(m.waits==m.period+1);C(m.reads+m.writes==1&&!m.bytes);
 }
 for(unsigned writing=0;writing<2;++writing)for(unsigned action=7;action<=8;++action){
  reset("ready zero/oversized IO refuses without retry",writing);m.period=LIMIT-1;m.action=action;
  C(transfer()==(!writing&&action==7?LAPY_CTL_EOF:LAPY_CTL_IO));C(m.waits==LIMIT&&m.reads+m.writes==1);
 }
 for(unsigned writing=0;writing<2;++writing){
  reset("wait error is not a no-progress retry",writing);m.ready_fault=1;
  C(transfer()==LAPY_CTL_IO);C(m.waits==1&&!m.reads&&!m.writes);
 }
}
static void checkpoint_latch(void)
{
 reset("partial CANCEL then stalled clock latches IO",0);
 struct lapy_elevation_message req=m.input;req.kind=LAPY_ELEVATION_REQUEST;C(!lapy_control_bind(&ctl,&req));
 /* Checkpoint ready probe then first byte, thereafter idle beyond the limit. */
 m.chunk=1;m.period=0;
 /* Use the ordinary transfer for one byte then checkpoint with remaining
    scripted shortage: a separate mode below flips after first read. */
 m.action=9;
 if(setjmp(budget)){fprintf(stderr,"HARNESS_BUDGET_EXCEEDED checkpoint\n");exit(1);}
 enum lapy_control_result got=lapy_control_checkpoint(&ctl);
 C(got==LAPY_CTL_IO&&ctl.cancellation==LAPY_CTL_IO);
 C(m.bytes==1&&m.reads==1&&m.waits==LIMIT+2);
 unsigned calls=m.clocks+m.waits+m.reads+m.writes;m.now=200;m.period=0;m.action=0;
 C(lapy_control_checkpoint(&ctl)==LAPY_CTL_IO);C(m.clocks+m.waits+m.reads+m.writes==calls);
}
int main(void)
{
 boundary_matrix();partial_and_errors();checkpoint_latch();
 printf("PASS nonprogress cases=%u checks=%u; observation counts only; callbacks inert\n",cases,checks);return 0;
}
