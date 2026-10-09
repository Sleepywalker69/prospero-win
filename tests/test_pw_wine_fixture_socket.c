/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Every socket boundary is replaced before the production implementation. */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <stdatomic.h>
#define SO_TYPE 0x1008
_Static_assert(SOL_SOCKET==0xffff && SOCK_STREAM==1 && FIOCLEX==0x20006601UL,"target ABI");
int mock_getsockopt(int,int,int,void *,socklen_t *);
int mock_setsockopt(int,int,int,const void *,socklen_t);
int mock_ioctl(int,unsigned long,...);
static void publication_hook(atomic_uint *);
static int checked_compare(atomic_uint *p,unsigned *expected,unsigned desired)
{
    int rc=atomic_compare_exchange_strong(p,expected,desired);
    if(rc)publication_hook(p);
    return rc;
}
#undef atomic_compare_exchange_strong
#define atomic_compare_exchange_strong checked_compare
#define getsockopt mock_getsockopt
#define setsockopt mock_setsockopt
#define ioctl mock_ioctl
#include "../wine/ps5/pw_wine_fixture_socket.c"
#undef getsockopt
#undef setsockopt
#undef ioctl
#undef atomic_compare_exchange_strong
static struct { unsigned calls,fail,positive,malformed,unwritten,override_stage; uint32_t override_length; int expected_fd,flags,descriptor_flags,nbio,type_value; } m;
static unsigned checks, sink_calls, forward_calls, incomplete_failure, incomplete_sink;
static int sink_context, forward_result;
#define CHECK(x) do { ++checks; assert(x); } while(0)
static void checked_sink(void *,const PwWineFixtureSocketResult *);
static int forward_install(PwWineFixtureSocketSink sink,void *context)
{ CHECK(sink==checked_sink && context==&sink_context);++forward_calls;return forward_result; }
static void publication_hook(atomic_uint *p)
{
    if(p==&failure_state) {
        PwWineFixtureSocketResult before,out;memset(&out,0xa5,sizeof(out));before=out;
        CHECK(!pw_wine_fixture_socket_failure(&out));CHECK(!memcmp(&out,&before,sizeof(out)));
        ++incomplete_failure;
        /* Reentrant failure while the first record is still being copied. */
        CHECK(pw_wine_fixture_socket(-1,0)==-1);
    } else {
        CHECK(p==&sink_state);++incomplete_sink;
        CHECK(pw_wine_fixture_socket_forward_sink(forward_install)==-1);
        CHECK(pw_wine_fixture_socket_set_sink(checked_sink,&sink_context)==-1);
    }
}
static void checked_sink(void *context,const PwWineFixtureSocketResult *r)
{
    PwWineFixtureSocketResult snapshot;
    CHECK(context==&sink_context);++sink_calls;
    CHECK(pw_wine_fixture_socket_failure(&snapshot)==1);
    CHECK(!memcmp(r,&snapshot,sizeof(snapshot)));
    CHECK(pw_wine_fixture_socket(-1,0)==-1);
    errno=ERANGE; /* Caller must recover the original operation's errno. */
}
static int native_result(void) { ++m.calls; if(m.calls==m.fail){errno=EACCES;return m.positive?1:-1;} return 0; }
int mock_getsockopt(int fd,int level,int option,void *value,socklen_t *length)
{
    assert(fd==m.expected_fd && level==SOL_SOCKET && *length==sizeof(int));
    assert(*(int *)value==0); assert(option==SO_TYPE || option==PW_WF_SO_NBIO);
    int rc=native_result();if(rc)return rc;
    if(m.unwritten==m.calls)return 0;
    *(int *)value=option==SO_TYPE?m.type_value:m.nbio;
    if(m.malformed==m.calls)*length=sizeof(int)-1;
    if(m.override_stage==m.calls)*length=m.override_length;
    return 0;
}
int mock_setsockopt(int fd,int level,int option,const void *value,socklen_t length)
{
    assert(fd==m.expected_fd && level==SOL_SOCKET && option==PW_WF_SO_NBIO);
    assert(length==sizeof(int) && *(const int *)value==1);
    int rc=native_result();if(!rc)m.flags|=4;return rc;
}
int mock_ioctl(int fd,unsigned long request,...)
{
    va_list args;va_start(args,request);assert(va_arg(args,void *)==NULL);va_end(args);
    assert(fd==m.expected_fd && request==FIOCLEX && request==0x20006601UL);
    int rc=native_result();if(!rc)m.descriptor_flags|=1;return rc;
}
static void reset(void){memset(&m,0,sizeof(m));m.expected_fd=0;m.flags=0x82;m.descriptor_flags=0x20;m.nbio=256;m.type_value=SOCK_STREAM;errno=EDOM;}
static void reset_publication(void)
{
    atomic_init(&failure_state,0);atomic_init(&sink_state,0);memset(&first_failure,0,sizeof(first_failure));
    failure_sink=NULL;failure_context=NULL;sink_calls=forward_calls=incomplete_failure=incomplete_sink=0;forward_result=0;
}
static void publication_tests(void)
{
    PwWineFixtureSocketResult before,out;
    const unsigned flags=PW_WF_SOCKET_CLOEXEC|PW_WF_SOCKET_NONBLOCK;
    reset_publication();reset();memset(&out,0xa5,sizeof(out));before=out;
    CHECK(!pw_wine_fixture_socket_failure(NULL));CHECK(!pw_wine_fixture_socket_failure(&out));
    CHECK(!memcmp(&out,&before,sizeof(out)));
    CHECK(pw_wine_fixture_socket_set_sink(NULL,&sink_context)==-1);
    CHECK(pw_wine_fixture_socket_set_sink(checked_sink,NULL)==-1);
    CHECK(pw_wine_fixture_socket_forward_sink(forward_install)==-1);
    CHECK(!pw_wine_fixture_socket_set_sink(checked_sink,&sink_context));CHECK(incomplete_sink==1);
    CHECK(pw_wine_fixture_socket_set_sink(checked_sink,&sink_context)==-1);
    CHECK(pw_wine_fixture_socket_forward_sink(NULL)==-1);
    CHECK(!pw_wine_fixture_socket_forward_sink(forward_install));CHECK(forward_calls==1);
    forward_result=-7;CHECK(pw_wine_fixture_socket_forward_sink(forward_install)==-7);
    forward_result=1;CHECK(pw_wine_fixture_socket_forward_sink(forward_install)==1);
    m.fail=1;CHECK(pw_wine_fixture_socket(0,flags)==-1);CHECK(errno==EACCES);
    CHECK(sink_calls==1&&incomplete_failure==1&&m.calls==1);
    CHECK(pw_wine_fixture_socket_failure(&before)==1);
    CHECK(before.api==PW_WF_SOCKET_TYPE&&before.raw_result==-1&&before.native_error==EACCES&&before.errno_valid);
    reset();m.fail=2;CHECK(pw_wine_fixture_socket(0,flags)==-1);CHECK(errno==EACCES);
    CHECK(pw_wine_fixture_socket_failure(&out)==1);CHECK(!memcmp(&out,&before,sizeof(out)));CHECK(sink_calls==1);
    reset();CHECK(!pw_wine_fixture_socket(0,flags));CHECK(pw_wine_fixture_socket_failure(&out)==1);
    CHECK(!memcmp(&out,&before,sizeof(out)));CHECK(sink_calls==1);
    reset_publication();reset();m.fail=1;CHECK(pw_wine_fixture_socket_prepare(0,flags,&out)==-1);
    CHECK(!pw_wine_fixture_socket_failure(&before));CHECK(!sink_calls);
    reset_publication();reset();m.fail=1;CHECK(pw_wine_fixture_socket(0,flags)==-1);
    CHECK(!sink_calls&&pw_wine_fixture_socket_failure(&before)==1);
    CHECK(!pw_wine_fixture_socket_set_sink(checked_sink,&sink_context));CHECK(!sink_calls);
    CHECK(pw_wine_fixture_socket(-1,flags)==-1&&errno==EINVAL);CHECK(!sink_calls);
    CHECK(pw_wine_fixture_socket_failure(&out)==1&&!memcmp(&out,&before,sizeof(out)));
}
static void additional_outputs(void)
{
    PwWineFixtureSocketResult r;
    const unsigned flags=PW_WF_SOCKET_CLOEXEC|PW_WF_SOCKET_NONBLOCK;
    const uint32_t lengths[]={0,1,2,3,5,8,UINT32_MAX};
    for(unsigned stage=1;stage<=4;stage+=3)for(unsigned i=0;i<sizeof(lengths)/sizeof(lengths[0]);i++) {
        reset();m.override_stage=stage;m.override_length=lengths[i];
        CHECK(pw_wine_fixture_socket_prepare(0,flags,&r)==-1);CHECK(m.calls==stage);
        CHECK(r.api==(stage==1?PW_WF_SOCKET_TYPE:PW_WF_SOCKET_NBIO_GET));
        CHECK(!r.errno_valid&&!r.native_error&&r.raw_result==0&&errno==EPROTO);
        CHECK(r.returned_length==lengths[i]);
    }
    const int types[]={0,2,5,-1,INT_MIN,INT_MAX};
    for(unsigned i=0;i<sizeof(types)/sizeof(types[0]);i++) {
        reset();m.type_value=types[i];CHECK(pw_wine_fixture_socket_prepare(0,flags,&r)==-1);
        CHECK(m.calls==1&&r.api==PW_WF_SOCKET_TYPE&&!r.errno_valid&&errno==EPROTO);
    }
    reset();CHECK(!pw_wine_fixture_socket_prepare(0,0,&r));CHECK(m.calls==1&&m.flags==0x82&&m.descriptor_flags==0x20);
}
int main(void)
{
    PwWineFixtureSocketResult r;
    const unsigned flags=PW_WF_SOCKET_CLOEXEC|PW_WF_SOCKET_NONBLOCK;
    for(unsigned i=1;i<=4;i++)for(unsigned positive=0;positive<2;positive++){
        reset();m.fail=i;m.positive=positive;
        assert(pw_wine_fixture_socket_prepare(0,flags,&r)==-1 && m.calls==i);
        assert(r.api==(int)i+1 && r.raw_result==(positive?1:-1));
        assert(r.errno_valid==!positive && r.native_error==(positive?0:EACCES));
        assert(errno==(positive?EPROTO:EACCES));
    }
    const int values[]={1,2,256,-1,INT_MIN,INT_MAX};
    for(unsigned i=0;i<sizeof(values)/sizeof(values[0]);i++){
        reset();m.nbio=values[i];assert(!pw_wine_fixture_socket_prepare(0,flags,&r));
        assert(m.calls==4 && m.flags==0x86 && m.descriptor_flags==0x21);
        assert(!r.status && !r.errno_valid && !r.native_error && r.returned_value==values[i]);
        assert(r.returned_length==sizeof(int));
    }
    for(unsigned stage=1;stage<=4;stage+=3){
        reset();m.malformed=stage;assert(pw_wine_fixture_socket_prepare(0,flags,&r)==-1);
        assert(m.calls==stage && !r.errno_valid && r.raw_result==0 && errno==EPROTO);
        reset();m.unwritten=stage;assert(pw_wine_fixture_socket_prepare(0,flags,&r)==-1);
        assert(m.calls==stage && r.returned_value==0 && !r.errno_valid);
    }
    reset();m.nbio=0;assert(pw_wine_fixture_socket_prepare(0,flags,&r)==-1 && r.api==PW_WF_SOCKET_NBIO_GET);
    reset();assert(!pw_wine_fixture_socket_prepare(0,PW_WF_SOCKET_CLOEXEC,&r));assert(m.calls==2 && m.flags==0x82);
    reset();assert(!pw_wine_fixture_socket_prepare(0,PW_WF_SOCKET_NONBLOCK,&r));assert(m.calls==3 && m.descriptor_flags==0x20);
    reset();assert(pw_wine_fixture_socket_prepare(-1,flags,&r)==-1 && !m.calls);
    reset();assert(pw_wine_fixture_socket_prepare(0,8,&r)==-1 && !m.calls);
    reset();assert(!pw_wine_fixture_socket_prepare(0,flags,NULL));
    additional_outputs();publication_tests();
    printf("Additional Wine fixture socket controls: %u checks passed\n",checks);
    puts("Wine fixture stream setup controls passed; no native sockets executed");
    return 0;
}
