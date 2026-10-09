/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_wine_fixture_socket.h"
#include <errno.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

static atomic_uint failure_state, sink_state;
static PwWineFixtureSocketResult first_failure;
static PwWineFixtureSocketSink failure_sink;
static void *failure_context;
int pw_wine_fixture_socket_set_sink(PwWineFixtureSocketSink sink, void *context)
{
    unsigned expected=0;
    if (!sink || !context || !atomic_compare_exchange_strong(&sink_state,&expected,1)) return -1;
    failure_sink=sink; failure_context=context;
    atomic_store_explicit(&sink_state,2,memory_order_release);
    return 0;
}
int pw_wine_fixture_socket_forward_sink(int (*install)(PwWineFixtureSocketSink,void *))
{
    if (!install || atomic_load_explicit(&sink_state,memory_order_acquire)!=2) return -1;
    return install(failure_sink,failure_context);
}
int pw_wine_fixture_socket_failure(PwWineFixtureSocketResult *out)
{
    if (!out || atomic_load_explicit(&failure_state,memory_order_acquire)!=2) return 0;
    *out=first_failure;
    return 1;
}
static int failed(PwWineFixtureSocketResult *r, int api, int raw, int native)
{
    r->status=-1; r->api=api; r->raw_result=raw;
    r->errno_valid=raw<0; r->native_error=raw<0?native:0;
    errno=raw<0?native:EPROTO;
    return -1;
}
int pw_wine_fixture_socket_prepare(int fd, unsigned flags, PwWineFixtureSocketResult *out)
{
    PwWineFixtureSocketResult local, *r=out?out:&local;
    int value=0, one=1, raw, saved;
    socklen_t length=sizeof(value);
    memset(r,0,sizeof(*r));
    if (fd<0 || (flags&~(PW_WF_SOCKET_CLOEXEC|PW_WF_SOCKET_NONBLOCK))) {
        r->status=-1; r->api=PW_WF_SOCKET_ARGUMENT; errno=EINVAL; return -1;
    }
    raw=getsockopt(fd,SOL_SOCKET,SO_TYPE,&value,&length); saved=raw<0?errno:0;
    r->returned_length=(uint32_t)length; r->returned_value=value;
    if (raw!=0 || length!=sizeof(value) || value!=SOCK_STREAM)
        return failed(r,PW_WF_SOCKET_TYPE,raw,saved);
    if (flags&PW_WF_SOCKET_CLOEXEC) {
        raw=ioctl(fd,FIOCLEX,(void *)0); saved=raw<0?errno:0;
        if (raw!=0) return failed(r,PW_WF_SOCKET_CLEX,raw,saved);
    }
    if (flags&PW_WF_SOCKET_NONBLOCK) {
        raw=setsockopt(fd,SOL_SOCKET,PW_WF_SO_NBIO,&one,sizeof(one)); saved=raw<0?errno:0;
        if (raw!=0) return failed(r,PW_WF_SOCKET_NBIO_SET,raw,saved);
        value=0; length=sizeof(value);
        raw=getsockopt(fd,SOL_SOCKET,PW_WF_SO_NBIO,&value,&length); saved=raw<0?errno:0;
        r->returned_length=(uint32_t)length; r->returned_value=value;
        if (raw!=0 || length!=sizeof(value) || value==0)
            return failed(r,PW_WF_SOCKET_NBIO_GET,raw,saved);
    }
    return 0;
}
int pw_wine_fixture_socket(int fd, unsigned flags)
{
    PwWineFixtureSocketResult r;
    int status=pw_wine_fixture_socket_prepare(fd,flags,&r), saved=errno;
    unsigned expected=0;
    if (status && atomic_compare_exchange_strong(&failure_state,&expected,1)) {
        first_failure=r;
        atomic_store_explicit(&failure_state,2,memory_order_release);
        if (atomic_load_explicit(&sink_state,memory_order_acquire)==2)
            failure_sink(failure_context,&r);
    }
    errno=saved;
    return status;
}
