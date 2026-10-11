/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Verbatim extracted production functions; native/OS observations only are
 * replaced. No source-string assertions substitute for execution. */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "pw_wine_fixture_provider.h"
typedef uint32_t NTSTATUS;
static int nb_threads;
static sigset_t server_block_set;
static jmp_buf finished;
static struct {unsigned installed,root_calls,detach_calls,queries,sleeps,diagnostics,mask_calls,thread_exits,process_exits;uint32_t status,return_value;int sleep_error,exit_code;} m;
static uint32_t root_exit(void *context,uint32_t status)
{assert(context==&m);m.root_calls++;m.status=status;return m.return_value;}
static void root_detached(void *context,uint32_t success,int32_t raw,int32_t error)
{(void)context;(void)success;(void)raw;(void)error;m.detach_calls++;assert(!"fatal abort must never claim detach");}
static const PwWineFixtureProvider provider={.abi=PW_WINE_FIXTURE_ABI,.bytes=sizeof(PwWineFixtureProvider),.context=&m,.root_exit=root_exit,.root_detached=root_detached};
const PwWineFixtureProvider *pw_wine_fixture_get(void){m.queries++;return m.installed?&provider:NULL;}
static void __attribute__((unused)) wine_write_stderr(const char *text,size_t size)
{assert(size>0&&size<128);assert(strstr(text,"root_abort_held"));m.diagnostics++;}
static int __attribute__((unused)) usleep(unsigned delay)
{assert(delay==10000);if(++m.sleeps==3)longjmp(finished,3);errno=m.sleep_error;return m.sleep_error?-1:0;}
static int mocked_pthread_sigmask(int how,const sigset_t *set,sigset_t *old)
{assert(how==SIG_BLOCK&&set==&server_block_set&&!old);m.mask_calls++;return 0;}
static int InterlockedDecrement(int *value){return --*value;}
static void pthread_exit_wrapper(int status) __attribute__((noreturn));
static void pthread_exit_wrapper(int status){m.thread_exits++;m.exit_code=status;longjmp(finished,2);}
static void mocked_exit(int status) __attribute__((noreturn));
static void mocked_exit(int status){m.process_exits++;m.exit_code=status;longjmp(finished,1);}
#define _exit mocked_exit
#define pthread_sigmask mocked_pthread_sigmask
void abort_process(int);

#include "root-abort.inc"
static unsigned checks;
static void one(unsigned installed,unsigned thread_entry,unsigned threads,uint32_t status,unsigned root_return,int sleep_error)
{
    memset(&m,0,sizeof(m));m.installed=installed;m.return_value=root_return;m.sleep_error=sleep_error;nb_threads=(int)threads;
    int observed=setjmp(finished);
    if(!observed){if(thread_entry)abort_thread((int)status);else abort_process((int)status);assert(!"exit path unexpectedly returned");}
    if(thread_entry&&threads>1){
        assert(observed==2&&m.thread_exits==1&&!m.process_exits&&!m.root_calls&&!m.sleeps);
        assert(m.exit_code==(int)status&&nb_threads==(int)threads-1&&m.mask_calls==1);
    }else if(EXPECT_GUARD&&installed){
        assert(observed==3&&m.root_calls==1&&m.status==status&&m.sleeps==3&&m.diagnostics==1);
        assert(!m.process_exits&&!m.thread_exits&&!m.detach_calls&&m.queries==1);
    }else{
        assert(observed==1&&m.process_exits==1&&!m.thread_exits&&!m.root_calls&&!m.detach_calls&&!m.sleeps);
        assert(m.exit_code==get_unix_exit_code(status));
    }
    checks++;
}
int main(void)
{
    const uint32_t statuses[]={0,0x100,0xc00000b5u,0xffffffffu};
    for(unsigned s=0;s<4;s++)for(unsigned installed=0;installed<2;installed++){
        one(installed,0,1,statuses[s],0,0);
        one(installed,1,1,statuses[s],0,0);
        one(installed,1,2,statuses[s],0,0);
    }
    one(1,0,1,0xc00000b5u,1,0);
    one(1,0,1,0xc00000b5u,0,EINTR);
    one(1,1,1,0xc00000b5u,1,EINVAL);
    printf("PASS: root abort %s: %u executable control-flow checks\n",EXPECT_GUARD?"candidate held":"baseline bypass reproduced",checks);
    return 0;
}
