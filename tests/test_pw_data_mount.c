/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _DEFAULT_SOURCE
#include "../native/pw_data_mount.h"
#include "../native/lapy_elevation_protocol.h"
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

typedef struct Pair { int sr, se, st, lr, le, lt; } Pair;
static const Pair ready = {0,0,S_IFDIR,0,0,S_IFDIR};
static const Pair denied = {0,0,S_IFDIR,-1,EPERM,0};
static const Pair absent = {-1,ENOENT,0,-1,ENOENT,0};
static Pair observations[8];
static unsigned count, at, stat_calls, lstat_calls, request_calls, sleeps;
static int total_sleep, sleep_failure, request_result, request_error;
static int32_t requested_pid;
static PwLapyElevationResult outcome;
static unsigned checks;
#define CHECK(x) do { checks++; assert(x); } while (0)
static int fake_request(int32_t pid, PwLapyElevationResult *result)
{
    request_calls++; requested_pid = pid; *result = outcome;
    errno = request_error;
    return request_result;
}
static int fake_stat(const char *path, struct stat *st)
{
    CHECK(!strcmp(path,PW_DATA_MOUNT_PATH)); stat_calls++;
    CHECK(errno == 0);
    Pair p=observations[at]; memset(st,0,sizeof(*st)); st->st_mode=p.st;
    errno=p.se; return p.sr;
}
static int fake_lstat(const char *path, struct stat *st)
{
    CHECK(!strcmp(path,PW_DATA_MOUNT_PATH)); lstat_calls++;
    CHECK(errno == 0);
    Pair p=observations[at]; if(at+1<count)at++;
    memset(st,0,sizeof(*st)); st->st_mode=p.lt;
    errno=p.le; return p.lr;
}
static int fake_sleep(int ms)
{
    CHECK(ms >= 0); sleeps++;
    if (sleep_failure && sleeps == (unsigned)sleep_failure) { errno = EIO; return -1; }
    total_sleep += ms; return 0;
}
static const PwDataMountOps ops = {fake_request,fake_stat,fake_lstat,fake_sleep};
static void reset(Pair first, Pair second)
{
    memset(observations,0,sizeof(observations)); observations[0]=first; observations[1]=second;
    count=2; at=stat_calls=lstat_calls=request_calls=sleeps=0;
    total_sleep=sleep_failure=request_result=request_error=0; requested_pid=0;
    outcome=(PwLapyElevationResult){.possible_apply=1,.terminal=1,.helper_status=LAPY_ELEVATION_OK}; errno=EIO;
}
static int run(PwDataMountResult *r,int wait)
{return pw_data_mount_request_with(&ops,2595,wait,r);}
int main(void)
{
    PwDataMountResult r;
    reset(ready,ready); CHECK(!run(&r,5000));
    CHECK(r.ready && r.data_before && r.data_after && !request_calls && !sleeps);
    CHECK(r.before.observed==3 && !r.after.observed && !r.helper.possible_apply);
    CHECK(!r.before.stat_errno && !r.before.lstat_errno);
    const Pair starts[]={denied,absent,{-1,ENOENT,0,-1,EPERM,0}};
    for(unsigned i=0;i<sizeof(starts)/sizeof(starts[0]);i++) {
        reset(starts[i],ready); CHECK(!run(&r,5000));
        CHECK(r.ready && r.helper_completed && r.helper.possible_apply && r.helper.terminal);
        CHECK(request_calls==1 && requested_pid==2595 && sleeps==1);
        CHECK(total_sleep==PW_DATA_MOUNT_SETTLE_MS && r.settled_ms==PW_DATA_MOUNT_SETTLE_MS);
        CHECK(r.after.observed==3 && r.after.stat_directory && r.after.lstat_directory);
    }
    const Pair refused[]={
        {0,0,S_IFDIR,-1,ENOENT,0}, {0,0,S_IFDIR,-1,EACCES,0},
        {0,0,S_IFDIR,-1,EIO,0}, {0,0,S_IFDIR,-1,ENOSYS,0},
        {0,0,S_IFDIR,-1,0,0}, {0,0,S_IFDIR,7,EPERM,0},
        {0,0,S_IFDIR,-2,EPERM,0}, {0,0,S_IFREG,0,0,S_IFDIR},
        {0,0,S_IFDIR,0,0,S_IFREG}, {0,0,S_IFDIR,0,0,S_IFLNK},
        {-1,ENOENT,0,0,0,S_IFDIR}, {-1,EPERM,0,-1,EPERM,0},
        {-1,EACCES,0,-1,EPERM,0}, {-1,EIO,0,-1,EPERM,0},
        {7,ENOENT,0,-1,EPERM,0}, {-1,0,0,-1,EPERM,0}
    };
    for(unsigned i=0;i<sizeof(refused)/sizeof(refused[0]);i++) {
        reset(refused[i],ready); CHECK(run(&r,5000)==-1);
        CHECK(!r.ready && !request_calls && !sleeps && r.before.observed==3);
        reset(denied,refused[i]); CHECK(run(&r,5000)==-1);
        CHECK(!r.ready && request_calls==1 && !sleeps && r.helper_completed && r.after.observed==3);
    }
    reset(denied,denied); CHECK(run(&r,250)==-1);
    CHECK(request_calls==1 && r.waited_ms==250 && total_sleep==250 && sleeps==3);
    CHECK(r.data_before && r.data_after && !r.ready && !r.settled_ms);
    reset(absent,absent); CHECK(run(&r,0)==-1);
    CHECK(!sleeps && !r.waited_ms && !r.ready && !r.data_after);
    reset(denied,ready); CHECK(!run(&r,0)); CHECK(r.ready && r.waited_ms==0);
    reset(denied,denied); count=4; observations[2]=denied; observations[3]=ready;
    CHECK(!run(&r,200)); CHECK(r.ready && r.waited_ms==200 && sleeps==3);
    reset(denied,denied); count=3; observations[2]=ready;
    CHECK(!run(&r,INT_MAX)); CHECK(r.waited_ms==PW_DATA_MOUNT_POLL_MS);
    for(unsigned i=0;i<3;i++) {
        reset(denied,ready); request_result=-1; request_error=i?ETIMEDOUT:0;
        outcome=(PwLapyElevationResult){.possible_apply=i!=0,.terminal=i==2,.helper_status=LAPY_ELEVATION_APPLY_FAILED};
        CHECK(run(&r,5000)==-1); CHECK(!r.ready && !r.helper_completed && request_calls==1);
        CHECK(r.helper_errno==(i?ETIMEDOUT:EIO) && stat_calls==1 && !sleeps);
        CHECK(r.helper.possible_apply==(i!=0) && r.helper.terminal==(i==2));
    }
    const PwLapyElevationResult bad[]={{0},{.possible_apply=1},{.terminal=1},
        {.possible_apply=1,.terminal=1,.helper_status=LAPY_ELEVATION_APPLY_FAILED}};
    for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++) {
        reset(denied,ready); outcome=bad[i]; CHECK(run(&r,100)==-1);
        CHECK(!r.ready && !r.helper_completed && r.helper_errno==EPROTO && !sleeps);
    }
    reset(denied,ready); sleep_failure=1; CHECK(run(&r,100)==-1);
    CHECK(!r.ready && !r.settled_ms && !r.waited_ms);
    CHECK(r.sleep_stage==2 && r.sleep_raw==-1 && r.sleep_errno==EIO);
    reset(denied,denied); sleep_failure=1; CHECK(run(&r,100)==-1);
    CHECK(!r.ready && !r.settled_ms && !r.waited_ms);
    CHECK(r.sleep_stage==1 && r.sleep_raw==-1 && r.sleep_errno==EIO);
    reset(ready,ready); observations[0].se=EIO;observations[0].le=EPERM;
    CHECK(!run(&r,100));CHECK(!r.before.stat_errno && !r.before.lstat_errno);
    for(unsigned i=0;i<4;i++) {
        PwDataMountOps invalid=ops;
        if(i==0)invalid.request=NULL;
        if(i==1)invalid.stat_path=NULL;
        if(i==2)invalid.lstat_path=NULL;
        if(i==3)invalid.sleep_ms=NULL;
        memset(&r,0xff,sizeof(r)); CHECK(pw_data_mount_request_with(&invalid,2595,100,&r)==-1);
        CHECK(!r.before.observed && !r.helper.possible_apply && !r.ready);
    }
    CHECK(pw_data_mount_request_with(NULL,2595,100,&r)==-1);
    CHECK(pw_data_mount_request_with(&ops,1,100,&r)==-1);
    CHECK(pw_data_mount_request_with(&ops,2595,-1,&r)==-1);
    reset(ready,ready);CHECK(!pw_data_mount_request_with(&ops,2595,100,NULL));
    printf("root data readiness: %u checks passed\n",checks);
    return 0;
}
