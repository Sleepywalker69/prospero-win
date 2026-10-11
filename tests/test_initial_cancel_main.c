/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Exact fixture entry with logger, PID, adapter and hold boundaries inert. */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
static pid_t fixture_pid(void);
static int fixture_sleep(const struct timespec *,struct timespec *);
#define PW_LAPY_INITIAL_CANCEL_ONLY 1
#define PW_BUILD_ID "host-mock-only"
#define getpid fixture_pid
#define nanosleep fixture_sleep
#define pw_lapy_initial_cancel_result fixture_cancel
#define main fixture_main
#include "../native/pw_lapy_initial_cancel_main.c"
#undef main
#undef pw_lapy_initial_cancel_result
#undef nanosleep
#undef getpid
static unsigned checks;
#define CHECK(x) do{checks++;assert(x);}while(0)
static struct {unsigned mode,config_error,init_error,fail_log,logs,cancels,sleeps,closes;} m;
static jmp_buf held;
static pid_t fixture_pid(void){return 600;}
static int fixture_sleep(const struct timespec *duration,struct timespec *rest)
{CHECK(duration&&duration->tv_sec==1&&!duration->tv_nsec&&!rest);m.sleeps++;longjmp(held,1);}
void ps5log_config_defaults(ps5log_config *config){memset(config,0,sizeof(*config));}
int ps5log_load_config(const char *const *paths,size_t count,ps5log_config *config,const char **used)
{CHECK(count==1&&!strcmp(paths[0],"/app0/dev.conf")&&config&&!used);return (int)m.config_error;}
uint64_t ps5log_monotonic_ns(void){return 1000;}
int ps5log_init(const ps5log_config *config,const char *title,const char *app,uint64_t token)
{CHECK(config&&!strcmp(title,"PPSA99995")&&!strcmp(app,"prospero-win-initial-cancel")&&token==1000);return (int)m.init_error;}
int ps5log_printf(const char *level,const char *format,...)
{
 char output[1024];va_list args;va_start(args,format);int n=vsnprintf(output,sizeof(output),format,args);va_end(args);
 CHECK(level&&n>0&&(size_t)n<sizeof(output)&&!strstr(output,"PASS")&&!strstr(output,"helper_exited"));
 m.logs++;return m.fail_log==m.logs?-1:0;
}
void ps5log_close(const char *reason){CHECK(!strcmp(reason,"not-dispatched"));m.closes++;}
int fixture_cancel(int32_t pid,PwLapyElevationResult *result)
{
 CHECK(pid==600&&result);m.cancels++;CHECK(m.cancels==1);
 *result=(PwLapyElevationResult){.no_dispatch=m.mode==0,.no_request=1,.transaction_id=123,
   .terminal=m.mode==1,.settled_failure=m.mode==1,.cancel_attempted=m.mode!=0,
   .helper_status=m.mode==1?LAPY_ELEVATION_CANCELLED:0};
 return m.mode==1?0:-1;
}
static void run_entry(unsigned mode)
{
 memset(&m,0,sizeof(m));m.mode=mode;
 if(!setjmp(held)){int rc=fixture_main();CHECK(mode==0&&rc==1&&!m.sleeps&&m.closes==1);}
 else CHECK(mode!=0&&m.sleeps==1&&!m.closes);
 CHECK(m.cancels==1);
}
int main(void)
{
 run_entry(0);run_entry(1);run_entry(2);
 for(unsigned which=0;which<3;which++){
  memset(&m,0,sizeof(m));m.config_error=which==0;m.init_error=which==1;m.fail_log=which==2?1:0;
  CHECK(fixture_main()==(which==2?3:2)&&!m.cancels&&!m.sleeps);
 }
 for(unsigned flags=0;flags<64;flags++)for(unsigned status=0;status<16;status++)for(unsigned nonce=0;nonce<2;nonce++){
  PwLapyElevationResult r={.possible_apply=!!(flags&1),.terminal=!!(flags&2),.no_dispatch=!!(flags&4),
   .no_request=!!(flags&8),.settled_failure=!!(flags&16),.cancel_attempted=!!(flags&32),
   .transaction_id=nonce,.helper_status=status};
  unsigned expected=flags==12&&status==0?PW_INITIAL_CANCEL_NO_DISPATCH:
   flags==58&&nonce&&status==LAPY_ELEVATION_CANCELLED?PW_INITIAL_CANCEL_RECEIPT_ONLY:PW_INITIAL_CANCEL_HELD;
  CHECK(pw_initial_cancel_classify(&r)==expected);
 }
 for(unsigned base=0;base<2;base++)for(unsigned field=0;field<6;field++){
  PwLapyElevationResult r={.no_dispatch=!base,.no_request=1,.terminal=base,.settled_failure=base,
   .cancel_attempted=base,.transaction_id=123,.helper_status=base?LAPY_ELEVATION_CANCELLED:0};
  unsigned *flags[]={&r.possible_apply,&r.terminal,&r.no_dispatch,&r.no_request,&r.settled_failure,&r.cancel_attempted};
  *flags[field]=2;CHECK(pw_initial_cancel_classify(&r)==PW_INITIAL_CANCEL_HELD);
 }
 printf("Initial-CANCEL title entry: %u checks; no dispatched outcome claims helper exit or returns from HELD; all boundaries inert\n",checks);
 return 0;
}
