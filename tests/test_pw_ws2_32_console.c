/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Compile the actual __PROSPERO__ resolver path with bounded libSceNet
 * responses. This checks adapter behavior, not a console or live DNS. */
#include <arpa/inet.h>
#include <assert.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../wine/ps5/pw_ws2_32_resolver.h"

int *__h_errno(void);

static int pool_result, resolver_result, ipv4_result, ipv6_result;
static int live_pools, live_resolvers;
static unsigned ipv4_calls, ipv6_calls;
static char calls[64];
static unsigned call_count;
static long long now = 1000;
static const unsigned char ipv6_bytes[16] = {0x20, 0x01, 0x0d, 0xb8, [15] = 0x19};

static void called(char c)
{
    assert(call_count + 1 < sizeof(calls));
    calls[call_count++] = c;
    calls[call_count] = 0;
}
static void reset(void)
{
    assert(!live_pools && !live_resolvers);
    pool_result = 17;
    resolver_result = 29;
    ipv4_result = ipv6_result = 0;
    ipv4_calls = ipv6_calls = call_count = 0;
    calls[0] = 0;
    now += 100;
}
static long long fake_clock(void) { return now; }
int sceNetInit(void) { called('I'); return 0; }
int sceNetPoolCreate(const char *name, int size, int flags)
{
    called('P');
    assert(!strcmp(name, "prospero-win") && size == 0x4000 && !flags);
    assert(!live_pools && !live_resolvers);
    if (pool_result >= 0) ++live_pools;
    return pool_result;
}
int sceNetPoolDestroy(int pool)
{
    called('p');
    assert(pool == pool_result && live_pools == 1 && !live_resolvers);
    --live_pools;
    return 0;
}
int sceNetResolverCreate(const char *name, int pool, int flags)
{
    called('R');
    assert(!strcmp(name, "prospero-win") && pool == pool_result && !flags);
    assert(live_pools == 1 && !live_resolvers);
    if (resolver_result >= 0) ++live_resolvers;
    return resolver_result;
}
int sceNetResolverDestroy(int resolver)
{
    called('r');
    assert(resolver == resolver_result && live_resolvers == 1 && live_pools == 1);
    --live_resolvers;
    return 0;
}
static void query(int resolver, const char *name, int timeout, int retries, int flags)
{
    assert(resolver == resolver_result && live_resolvers == 1 && live_pools == 1);
    assert(name && strchr(name, '.') && timeout == 5000000 && retries == 2 && !flags);
}
int sceNetResolverStartNtoa(int resolver, const char *name, struct in_addr *address,
                          int timeout, int retries, int flags)
{
    called('4'); ++ipv4_calls;
    query(resolver, name, timeout, retries, flags);
    if (ipv4_result >= 0) address->s_addr = htonl(0x7f000013u); /* 127.0.0.19 */
    return ipv4_result;
}
int sceNetResolverStartNtoa6(int resolver, const char *name, struct in6_addr *address,
                           int timeout, int retries, int flags)
{
    called('6'); ++ipv6_calls;
    query(resolver, name, timeout, retries, flags);
    if (ipv6_result >= 0) memcpy(address, ipv6_bytes, sizeof(*address));
    return ipv6_result;
}
static struct addrinfo hint(int family)
{
    struct addrinfo h = {0};
    h.ai_family = family;
    h.ai_socktype = SOCK_STREAM;
    return h;
}
static void check_address(const struct addrinfo *p, int family)
{
    assert(p && p->ai_family == family && p->ai_socktype == SOCK_STREAM &&
           p->ai_protocol == IPPROTO_TCP);
    if (family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)p->ai_addr;
        assert(p->ai_addrlen == sizeof(*a) && a->sin_family == AF_INET);
        assert(a->sin_port == htons(443) && a->sin_addr.s_addr == htonl(0x7f000013u));
    } else {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)p->ai_addr;
        assert(p->ai_addrlen == sizeof(*a) && a->sin6_family == AF_INET6);
        assert(a->sin6_port == htons(443) && !memcmp(&a->sin6_addr, ipv6_bytes, 16));
    }
}
static void test_success_and_partial_family(void)
{
    struct addrinfo h = hint(AF_UNSPEC), *p = NULL;
    reset();
    assert(!getaddrinfo("dual.example", "443", &h, &p));
    assert(!strcmp(calls, "IPR46rp"));
    check_address(p, AF_INET); check_address(p->ai_next, AF_INET6);
    assert(!p->ai_next->ai_next); freeaddrinfo(p);
    assert(!getaddrinfo("dual.example", "443", &h, &p));
    assert(ipv4_calls == 2 && ipv6_calls == 2); freeaddrinfo(p);

    reset(); ipv4_result = -123;
    assert(!getaddrinfo("v6only.example", "443", &h, &p));
    check_address(p, AF_INET6); assert(!p->ai_next && !strcmp(calls, "IPR46rp")); freeaddrinfo(p);
    reset(); ipv6_result = -456;
    assert(!getaddrinfo("v4only.example", "443", &h, &p));
    check_address(p, AF_INET); assert(!p->ai_next && !strcmp(calls, "IPR46rp")); freeaddrinfo(p);

    reset(); h = hint(AF_INET);
    assert(!getaddrinfo("ipv4.example", "443", &h, &p));
    check_address(p, AF_INET); assert(!p->ai_next && !strcmp(calls, "IPR4rp")); freeaddrinfo(p);
    reset(); h = hint(AF_INET6); pool_result = resolver_result = 0; /* zero is valid */
    assert(!getaddrinfo("ipv6.example", "443", &h, &p));
    check_address(p, AF_INET6); assert(!p->ai_next && !strcmp(calls, "IPR6rp")); freeaddrinfo(p);
}
static void test_setup_failure_cleanup(void)
{
    struct addrinfo h = hint(AF_INET), *p = (void *)(uintptr_t)1;
    reset(); pool_result = -11;
    assert(getaddrinfo("pool-fail.example", "443", &h, &p) == EAI_FAIL && !p);
    assert(!strcmp(calls, "IP") && !live_pools && !live_resolvers);
    pool_result = 17; /* Setup failures are immediately retryable. */
    assert(!getaddrinfo("pool-fail.example", "443", &h, &p));
    assert(!strcmp(calls, "IPIPR4rp")); freeaddrinfo(p);
    reset(); resolver_result = -12; p = (void *)(uintptr_t)1;
    assert(getaddrinfo("resolver-fail.example", "443", &h, &p) == EAI_FAIL && !p);
    assert(!strcmp(calls, "IPRp") && !live_pools && !live_resolvers);
    resolver_result = 29;
    assert(!getaddrinfo("resolver-fail.example", "443", &h, &p));
    assert(!strcmp(calls, "IPRpIPR4rp")); freeaddrinfo(p);
    reset();
    assert(!getaddrinfo("after-setup-fail.example", "443", &h, &p));
    assert(!strcmp(calls, "IPR4rp")); freeaddrinfo(p);
}
static void test_transient_error_cache(void)
{
    struct addrinfo h = hint(AF_INET), *p = (void *)(uintptr_t)1;
    reset(); ipv4_result = -123;
    assert(getaddrinfo("retry.example", "443", &h, &p) == EAI_AGAIN && !p);
    assert(!strcmp(calls, "IPR4rp") && !live_pools && !live_resolvers);
    ipv4_result = 0;
    assert(getaddrinfo("RETRY.example", "443", &h, &p) == EAI_AGAIN && !p && ipv4_calls == 1);
    assert(!gethostbyname("retry.example") && *__h_errno() == TRY_AGAIN && ipv4_calls == 1);
    now += PW_WS2_32_NEGATIVE_SECONDS - 1;
    assert(getaddrinfo("retry.example", "443", &h, &p) == EAI_AGAIN && !p && ipv4_calls == 1);
    ++now;
    assert(!getaddrinfo("retry.example", "443", &h, &p) && ipv4_calls == 2);
    check_address(p, AF_INET); freeaddrinfo(p);

    reset(); ipv4_result = ipv6_result = -789; h = hint(AF_UNSPEC);
    assert(getaddrinfo("both-fail.example", "443", &h, &p) == EAI_AGAIN && !p);
    assert(!strcmp(calls, "IPR46rp") && !live_pools && !live_resolvers);
    ipv4_result = ipv6_result = 0;
    assert(getaddrinfo("both-fail.example", "443", &h, &p) == EAI_AGAIN && !p);
    h = hint(AF_INET6); /* A separate family has a separate failure cache. */
    assert(!getaddrinfo("both-fail.example", "443", &h, &p) && ipv6_calls == 2);
    check_address(p, AF_INET6); freeaddrinfo(p);
}
static void test_no_network_routes(void)
{
    struct addrinfo h = hint(AF_INET6), *p;
    reset();
    assert(getaddrinfo("127.0.0.19", "443", &h, &p) == EAI_NONAME && !p);
    h = hint(AF_INET);
    assert(getaddrinfo("::1", "443", &h, &p) == EAI_NONAME && !p);
    h.ai_flags = AI_NUMERICHOST;
    assert(getaddrinfo("numeric-only.example", "443", &h, &p) == EAI_NONAME && !p);
    h.ai_flags = 0;
    assert(getaddrinfo("PREFIX-HOST", "443", &h, &p) == EAI_NONAME && !p);
    assert(!getaddrinfo("localhost", "443", &h, &p)); freeaddrinfo(p);
    assert(!getaddrinfo("127.0.0.19", "443", &h, &p)); freeaddrinfo(p);
    assert(!call_count && !live_pools && !live_resolvers);
}
int main(void)
{
    assert(pw_ws2_32_resolve); /* Native default must be linked and selected. */
    pw_ws2_32_now = fake_clock;
    test_success_and_partial_family();
    test_setup_failure_cleanup();
    test_transient_error_cache();
    test_no_network_routes();
    assert(!live_pools && !live_resolvers);
    puts("console resolver adapter passed: native default, bounded queries, family selection, "
         "partial success, setup cleanup, transient status and retry, no-network routes");
    return 0;
}
