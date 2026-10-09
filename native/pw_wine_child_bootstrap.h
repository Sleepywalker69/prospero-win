/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_WINE_CHILD_BOOTSTRAP_H
#define PW_WINE_CHILD_BOOTSTRAP_H
#include "pw_wine_child_wire.h"
#include "../src/pw_wine_start.h"
#include "../wine/ps5/pw_wine_fixture_socket.h"
#include <pthread.h>
#define PW_WINE_CHILD_PREFIX "/data/prospero-win/prefixes/windows-child-fixture-v1"
#define PW_WINE_CHILD_CWD PW_WINE_CHILD_PREFIX "/drive_c/windows-child-fixture"
#define PW_WINE_CHILD_IMAGE "C:\\windows-child-fixture\\child.exe"
#define PW_WINE_CHILD_BATTLENET_PREFIX "/data/prospero-win/prefixes/battlenet-experimental-v1"
#define PW_WINE_CHILD_BATTLENET_CWD PW_WINE_CHILD_BATTLENET_PREFIX "/drive_c"
#define PW_WINE_CHILD_BATTLENET_IMAGE "C:\\installer\\Battle.net-Setup.exe"
#define PW_WINE_CHILD_RUNTIME "/app0/win/wine/lib/wine/x86_64-unix"
#define PW_WINE_CHILD_RUNTIME_ALIAS "/mnt/sandbox/PPSA99995_000/app0/win/wine/lib/wine/x86_64-unix"
enum { PW_WCB_INITIAL, PW_WCB_PATHS, PW_WCB_ENVIRONMENT, PW_WCB_LOAD,
       PW_WCB_EXPORTS, PW_WCB_ABI, PW_WCB_CWD, PW_WCB_REGISTRY,
       PW_WCB_PREPARED, PW_WCB_THREAD, PW_WCB_RUNNING, PW_WCB_SOCKET };
typedef struct PwWineChildBootstrapOps {
    void *context;
    PwWineStartOps wine;
    /* Select only one of the two fixed runtime directories after exact-byte
     * hash validation; refuse a readable mismatching candidate. */
    int (*runtime)(void *, const char *sha256, char *directory, size_t size);
    int (*directory)(void *, const char *path);
    int (*register_thread)(long, pthread_t);
    void (*unregister_thread)(long);
    void (*output)(const char *, size_t);
    PwWineFixtureSocketSink socket_sink;
    void (*record)(void *, unsigned stage, int status); /* optional bounded observer */
} PwWineChildBootstrapOps;
typedef struct PwWineChildBootstrap {
    PwWineStart start;
    PwWineStartConfig config;
    PwWineStartEnv env[13];
    const char *argv[3];
    char runtime[256], ntdll[272], socket_text[16];
    unsigned stage, prepared, started;
    int status;
    int (*socket_failure)(PwWineFixtureSocketResult *);
} PwWineChildBootstrap;
/* All required native env precedes module load/constructors. No ownership of
 * server_fd is consumed here. It passes to ntdll only after start succeeds.
 * Session data stays in the caller; no parent pointers cross the channel. */
int pw_wine_child_bootstrap_prepare(PwWineChildBootstrap *, PwNativeChildIo *, int server_fd,
                                    const char *ntdll_sha256, unsigned private_abi, uint32_t profile, uint32_t machine,
                                    const PwWineChildBootstrapOps *);
int pw_wine_child_bootstrap_start(PwWineChildBootstrap *, PwNativeChildIo *,
                                  const PwWineChildBootstrapOps *);
/* Small streaming SHA256 used only to bind the opened ntdll bytes. */
typedef struct PwWineChildHash { uint32_t h[8]; uint64_t bytes; unsigned used; unsigned char block[64]; } PwWineChildHash;
void pw_wine_child_hash_init(PwWineChildHash *);
int pw_wine_child_hash_update(PwWineChildHash *, const void *, size_t);
void pw_wine_child_hash_final(PwWineChildHash *, char hex[65]);
#endif
