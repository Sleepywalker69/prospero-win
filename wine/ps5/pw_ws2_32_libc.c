/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* The resolver calls Winsock's Unix side (ws2_32.prx) makes that a title
 * cannot reach. The SDK's stubs offer getaddrinfo, freeaddrinfo, getnameinfo
 * and gethostbyname only from libScePosixForWebKit, which only the WebKit
 * process gets: in a title those imports stay NULL, and every lookup faulted
 * (measured: GTA IV, tens of thousands of times a minute). gethostbyaddr and
 * h_errno are in no stub at all.
 *
 * These answer what needs no name server themselves: numeric addresses,
 * the wildcard and loopback addresses, and "localhost" and the console's
 * stable host name "PS5", both loopback. A name with a dot in it goes to the
 * console's own resolver, libSceNet's, the way the payload SDK's libc does
 * it (a pool and a resolver per lookup; libSceNet is the title's, which
 * ps5log already uses for its sockets), with explicit timeout and retry
 * inputs below: Battle.net's client, offline until then, resolved nothing
 * ("Could not resolve host:
 * account.battle.net"). A name without a dot is EAI_NONAME at once, as
 * every name was before: the computer name a prefix made on a PC carries is
 * single-label and is not the stable local name returned by gethostname;
 * GTA IV looks it up tens of thousands of times a minute, and resolving it,
 * which a home router that answers for DHCP host names would, made the game
 * believe it was online and wait forever on "Starting a new game"
 * (measured), while the failure Wine reports for it (one "Failed to resolve
 * your host name IP" line per lookup) is what lets the game carry on
 * offline. Resolver failures are remembered briefly with their error class
 * so repeated calls do not block on the same outage. Native lookup errors
 * remain retryable: without a verified native NXDOMAIN mapping, a timeout
 * must not tell Winsock that the host does not exist. There is no services
 * database, so a service must be a port number. inet_pton and inet_ntop
 * are the title's own. A successful local-address probe still needs game
 * loading checks as well as resolver unit tests.
 *
 * The host test builds this file with these names prefixed (Makefile), so
 * glibc's stay in place. */
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "pw_ws2_32_resolver.h"

/* getnameinfo's buffer sizes: size_t on FreeBSD, socklen_t in glibc. */
#ifdef __GLIBC__
typedef socklen_t pw_name_size;
#else
typedef size_t pw_name_size;
#endif

static _Thread_local int pw_h_errno;

int *__h_errno(void)
{
    return &pw_h_errno;
}

/* One answer: an address family and the address's bytes. */
#define pw_address pw_ws2_address

#ifdef __PROSPERO__
/* The console's resolver. libSceNet's declarations are not in the payload
 * SDK's headers; these are the calls the payload SDK's libc makes. */
int sceNetInit(void);
int sceNetPoolCreate(const char *name, int size, int flags);
int sceNetPoolDestroy(int pool);
int sceNetResolverCreate(const char *name, int pool, int flags);
int sceNetResolverDestroy(int resolver);
int sceNetResolverStartNtoa(int resolver, const char *name, struct in_addr *address,
                            int timeout_us, int retries, int flags);
int sceNetResolverStartNtoa6(int resolver, const char *name, struct in6_addr *address,
                             int timeout_us, int retries, int flags);

/* Explicit per-call timeout/retry inputs. Actual elapsed-time bounds still
 * need validation on the console; the two families are queried serially. */
#define PW_RESOLVE_TIMEOUT_US 5000000
#define PW_RESOLVE_RETRIES 2

static int pw_console_resolve(const char *name, int family, struct pw_address answers[2], int *count)
{
    int pool, resolver, found = 0;

    *count = 0;
    /* Initialises libSceNet once; every later call returns SCE_NET_EBUSY,
     * which is the expected answer here, so the result is not looked at. */
    sceNetInit();
    if ((pool = sceNetPoolCreate("prospero-win", 0x4000, 0)) < 0)
        return EAI_FAIL;
    if ((resolver = sceNetResolverCreate("prospero-win", pool, 0)) < 0) {
        sceNetPoolDestroy(pool);
        return EAI_FAIL;
    }
    if (family != AF_INET6) {
        struct in_addr address;
        if (sceNetResolverStartNtoa(resolver, name, &address, PW_RESOLVE_TIMEOUT_US, PW_RESOLVE_RETRIES, 0) >= 0) {
            answers[found].family = AF_INET;
            memcpy(answers[found].bytes, &address, sizeof(address));
            found++;
        }
    }
    if (family != AF_INET) {
        struct in6_addr address;
        if (sceNetResolverStartNtoa6(resolver, name, &address, PW_RESOLVE_TIMEOUT_US, PW_RESOLVE_RETRIES, 0) >= 0) {
            answers[found].family = AF_INET6;
            memcpy(answers[found].bytes, &address, sizeof(address));
            found++;
        }
    }
    sceNetResolverDestroy(resolver);
    sceNetPoolDestroy(pool);
    *count = found;
    return found ? 0 : EAI_AGAIN;
}

int (*pw_ws2_32_resolve)(const char *, int, struct pw_address[2], int *) = pw_console_resolve;
#else
/* The host test installs a backend; without one every other name is unknown. */
int (*pw_ws2_32_resolve)(const char *, int, struct pw_address[2], int *) = NULL;
#endif

static long long pw_monotonic_seconds(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now))
        return -1;
    return now.tv_sec;
}

long long (*pw_ws2_32_now)(void) = pw_monotonic_seconds;

/* Unknown names and temporary failures, separately for each address
 * family, kept PW_WS2_32_NEGATIVE_SECONDS. Preserve the error so an outage
 * never becomes HOST_NOT_FOUND. The oldest entry is replaced under a lock. */
#define PW_NEGATIVE_SLOTS 16
struct pw_negative {
    char name[256];
    int family;
    int error;
    long long until;
};
static struct pw_negative pw_negatives[PW_NEGATIVE_SLOTS];
static unsigned pw_negative_next;
static pthread_mutex_t pw_negative_lock = PTHREAD_MUTEX_INITIALIZER;

static int pw_negative_known(const char *name, int family)
{
    long long now = pw_ws2_32_now();
    int error = 0;
    unsigned i;

    if (now < 0 || now > LLONG_MAX - PW_WS2_32_NEGATIVE_SECONDS)
        return 0;
    pthread_mutex_lock(&pw_negative_lock);
    for (i = 0; i < PW_NEGATIVE_SLOTS; i++) {
        if (pw_negatives[i].until > now && pw_negatives[i].family == family &&
            !strcasecmp(pw_negatives[i].name, name)) {
            error = pw_negatives[i].error;
            break;
        }
    }
    pthread_mutex_unlock(&pw_negative_lock);
    return error;
}

static void pw_negative_remember(const char *name, int family, int error)
{
    struct pw_negative *slot;
    long long now = pw_ws2_32_now();

    if (strlen(name) >= sizeof(slot->name) || now < 0 ||
        now > LLONG_MAX - PW_WS2_32_NEGATIVE_SECONDS)
        return;
    pthread_mutex_lock(&pw_negative_lock);
    slot = &pw_negatives[pw_negative_next++ % PW_NEGATIVE_SLOTS];
    strcpy(slot->name, name);
    slot->family = family;
    slot->error = error;
    slot->until = now + PW_WS2_32_NEGATIVE_SECONDS;
    pthread_mutex_unlock(&pw_negative_lock);
}

/* An addrinfo and everything it points to, freed in one piece. */
struct pw_addrinfo {
    struct addrinfo info;
    struct sockaddr_storage address;
    char name[];
};

static socklen_t pw_sockaddr(struct sockaddr_storage *storage, const struct pw_address *address,
                             unsigned short port)
{
    memset(storage, 0, sizeof(*storage));
    if (address->family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)storage;
#ifdef SIN6_LEN
        in->sin_len = sizeof(*in);
#endif
        in->sin_family = AF_INET;
        in->sin_port = htons(port);
        memcpy(&in->sin_addr, address->bytes, sizeof(in->sin_addr));
        return sizeof(*in);
    }
    struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)storage;
#ifdef SIN6_LEN
    in6->sin6_len = sizeof(*in6);
#endif
    in6->sin6_family = AF_INET6;
    in6->sin6_port = htons(port);
    memcpy(&in6->sin6_addr, address->bytes, sizeof(in6->sin6_addr));
    return sizeof(*in6);
}

/* The title's gethostname may return an empty name. Wine then substitutes
 * the PC prefix's registry name for an empty lookup, which is not resolvable
 * here. Keep the name returned by Winsock and our local resolver identical. */
static const char pw_hostname[] = "PS5";

int gethostname(char *name, size_t size)
{
    if (size < sizeof(pw_hostname)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(name, pw_hostname, sizeof(pw_hostname));
    return 0;
}

static int pw_is_local_name(const char *name)
{
    return !strcasecmp(name, "localhost") || !strcasecmp(name, pw_hostname);
}

/* The addresses NODE stands for in FAMILY, IPv4 first: that is what a
 * title's sockets use. */
static int pw_lookup(const char *node, int family, int flags, struct pw_address addresses[2], int *count)
{
    int wildcard = !node && (flags & AI_PASSIVE);

    memset(addresses, 0, 2 * sizeof(*addresses));
    *count = 1;
    if (node) {
        if (inet_pton(AF_INET, node, addresses[0].bytes) == 1) {
            if (family == AF_INET6)
                return EAI_NONAME;
            addresses[0].family = AF_INET;
            return 0;
        }
        if (inet_pton(AF_INET6, node, addresses[0].bytes) == 1) {
            if (family == AF_INET)
                return EAI_NONAME;
            addresses[0].family = AF_INET6;
            return 0;
        }
        if (flags & AI_NUMERICHOST)
            return EAI_NONAME;
        if (!pw_is_local_name(node)) {
            int error;
            /* Only a dotted name is asked of the resolver (see the top). */
            if (!*node || !strchr(node, '.') || !pw_ws2_32_resolve)
                return EAI_NONAME;
            if ((error = pw_negative_known(node, family)))
                return error;
            *count = 0;
            error = pw_ws2_32_resolve(node, family, addresses, count);
            if (error) {
                if (error == EAI_NONAME || error == EAI_AGAIN)
                    pw_negative_remember(node, family, error);
                return error;
            }
            if (*count < 0 || *count > 2)
                return EAI_FAIL;
            if (!*count) {
                pw_negative_remember(node, family, EAI_NONAME);
                return EAI_NONAME;
            }
            for (int i = 0; i < *count; i++)
                if ((addresses[i].family != AF_INET && addresses[i].family != AF_INET6) ||
                    (family != AF_UNSPEC && addresses[i].family != family))
                    return EAI_FAIL;
            return 0;
        }
    }
    *count = 0;
    if (family != AF_INET6) {
        addresses[*count].family = AF_INET;
        if (!wildcard) {
            addresses[*count].bytes[0] = 127;
            addresses[*count].bytes[3] = 1;
        }
        ++*count;
    }
    if (family != AF_INET) {
        addresses[*count].family = AF_INET6;
        if (!wildcard)
            addresses[*count].bytes[15] = 1;
        ++*count;
    }
    return 0;
}

/* A port number, the only kind of service there is. */
static int pw_port(const char *service, int flags, unsigned short *port)
{
    char *end;
    unsigned long value;

    *port = 0;
    if (!service)
        return 0;
    if (service[0] >= '0' && service[0] <= '9') {
        value = strtoul(service, &end, 10);
        if (!*end && value <= 65535) {
            *port = (unsigned short)value;
            return 0;
        }
    }
    return flags & AI_NUMERICSERV ? EAI_NONAME : EAI_SERVICE;
}

void freeaddrinfo(struct addrinfo *info)
{
    while (info) {
        struct addrinfo *next = info->ai_next;
        free(info);
        info = next;
    }
}

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints,
                struct addrinfo **result)
{
    static const struct addrinfo no_hints;
    struct pw_kind { int socktype, protocol; } kinds[2];
    struct pw_address addresses[2];
    struct addrinfo *head = NULL, **tail = &head;
    unsigned short port;
    int count, kind_count = 0, error;

    *result = NULL;
    if (!hints)
        hints = &no_hints;
    if (!node && !service)
        return EAI_NONAME;
    if (hints->ai_family != AF_UNSPEC && hints->ai_family != AF_INET && hints->ai_family != AF_INET6)
        return EAI_FAMILY;
    if (!node && (hints->ai_flags & AI_CANONNAME))
        return EAI_BADFLAGS;
    /* One answer per address and socket type: TCP and UDP when neither the
     * type nor the protocol is given. */
    if (hints->ai_socktype == SOCK_STREAM || hints->ai_socktype == SOCK_DGRAM ||
        hints->ai_socktype == SOCK_RAW) {
        int protocol = hints->ai_protocol ? hints->ai_protocol :
                       hints->ai_socktype == SOCK_STREAM ? IPPROTO_TCP :
                       hints->ai_socktype == SOCK_DGRAM ? IPPROTO_UDP : 0;
        kinds[kind_count++] = (struct pw_kind){ hints->ai_socktype, protocol };
    } else if (hints->ai_socktype) {
        return EAI_SOCKTYPE;
    } else {
        if (!hints->ai_protocol || hints->ai_protocol == IPPROTO_TCP)
            kinds[kind_count++] = (struct pw_kind){ SOCK_STREAM, IPPROTO_TCP };
        if (!hints->ai_protocol || hints->ai_protocol == IPPROTO_UDP)
            kinds[kind_count++] = (struct pw_kind){ SOCK_DGRAM, IPPROTO_UDP };
        if (!kind_count)
            kinds[kind_count++] = (struct pw_kind){ SOCK_RAW, hints->ai_protocol };
    }
    if ((error = pw_port(service, hints->ai_flags, &port)))
        return error;
    if ((error = pw_lookup(node, hints->ai_family, hints->ai_flags, addresses, &count)))
        return error;

    for (int a = 0; a < count; a++) {
        for (int k = 0; k < kind_count; k++) {
            /* The canonical name, the name as given, goes on the first. */
            size_t name_size = head || !(hints->ai_flags & AI_CANONNAME) ? 0 : strlen(node) + 1;
            struct pw_addrinfo *entry = calloc(1, sizeof(*entry) + name_size);

            if (!entry) {
                freeaddrinfo(head);
                return EAI_MEMORY;
            }
            entry->info.ai_flags = hints->ai_flags;
            entry->info.ai_family = addresses[a].family;
            entry->info.ai_socktype = kinds[k].socktype;
            entry->info.ai_protocol = kinds[k].protocol;
            entry->info.ai_addrlen = pw_sockaddr(&entry->address, &addresses[a], port);
            entry->info.ai_addr = (struct sockaddr *)&entry->address;
            if (name_size) {
                memcpy(entry->name, node, name_size);
                entry->info.ai_canonname = entry->name;
            }
            *tail = &entry->info;
            tail = &entry->info.ai_next;
        }
    }
    *result = head;
    return 0;
}

int getnameinfo(const struct sockaddr *address, socklen_t length, char *host, pw_name_size host_size,
                char *service, pw_name_size service_size, int flags)
{
    const void *bytes;
    unsigned short port;
    int loopback;

    if (!address)
        return EAI_FAMILY;
    if (address->sa_family == AF_INET && length >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)address;
        bytes = &in->sin_addr;
        port = ntohs(in->sin_port);
        loopback = ((const unsigned char *)bytes)[0] == 127;
    } else if (address->sa_family == AF_INET6 && length >= sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)address;
        static const unsigned char one[sizeof(struct in6_addr)] = {[15] = 1};
        bytes = &in6->sin6_addr;
        port = ntohs(in6->sin6_port);
        loopback = !memcmp(bytes, one, sizeof(one));
    } else {
        return EAI_FAMILY;
    }
    if ((!host || !host_size) && (!service || !service_size))
        return EAI_NONAME;
    if (host && host_size) {
        /* The only name an address has here is loopback's. */
        if (!(flags & NI_NUMERICHOST) && loopback) {
            if (strlen("localhost") >= host_size)
                return EAI_OVERFLOW;
            strcpy(host, "localhost");
        } else if (flags & NI_NAMEREQD) {
            return EAI_NONAME;
        } else if (!inet_ntop(address->sa_family, bytes, host, host_size)) {
            return EAI_OVERFLOW;
        }
    }
    if (service && service_size && (size_t)snprintf(service, service_size, "%u", port) >= service_size)
        return EAI_OVERFLOW;
    return 0;
}

/* The old resolver's single answer, in per-thread storage as FreeBSD's is. */
static struct hostent *pw_hostent(const char *name, int family, const void *address, int length)
{
    static _Thread_local struct hostent host;
    static _Thread_local char host_name[NI_MAXHOST];
    static _Thread_local char addresses[1][sizeof(struct in6_addr)];
    static _Thread_local char *address_list[2];
    static _Thread_local char *aliases[1];

    snprintf(host_name, sizeof(host_name), "%s", name);
    memcpy(addresses[0], address, length);
    address_list[0] = addresses[0];
    address_list[1] = NULL;
    aliases[0] = NULL;
    host.h_name = host_name;
    host.h_aliases = aliases;
    host.h_addrtype = family;
    host.h_length = length;
    host.h_addr_list = address_list;
    return &host;
}

struct hostent *gethostbyname(const char *name)
{
    struct addrinfo hints = {0}, *info;
    struct hostent *host;
    int error;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    error = name ? getaddrinfo(name, NULL, &hints, &info) : EAI_NONAME;
    if (error) {
        pw_h_errno = error == EAI_NONAME ? HOST_NOT_FOUND :
                     error == EAI_AGAIN ? TRY_AGAIN : NO_RECOVERY;
        return NULL;
    }
    host = pw_hostent(info->ai_canonname, AF_INET, &((struct sockaddr_in *)info->ai_addr)->sin_addr,
                      sizeof(struct in_addr));
    freeaddrinfo(info);
    return host;
}

/* A reverse lookup through getnameinfo. */
struct hostent *gethostbyaddr(const void *address, socklen_t length, int family)
{
    struct sockaddr_storage storage;
    struct pw_address answer = { family, {0} };
    char name[NI_MAXHOST];

    if ((family != AF_INET || length != sizeof(struct in_addr)) &&
        (family != AF_INET6 || length != sizeof(struct in6_addr))) {
        pw_h_errno = NO_RECOVERY;
        return NULL;
    }
    memcpy(answer.bytes, address, length);
    if (getnameinfo((struct sockaddr *)&storage, pw_sockaddr(&storage, &answer, 0), name, sizeof(name),
                    NULL, 0, NI_NAMEREQD)) {
        pw_h_errno = HOST_NOT_FOUND;
        return NULL;
    }
    return pw_hostent(name, family, address, (int)length);
}
