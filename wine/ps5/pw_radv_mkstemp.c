/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* ACO's optional disassembler needs an ordinary private temporary file.
 * The title cannot import mkstemp from libScePosixForWebKit. Use the same
 * platform randomness as RADV and return ownership of a real open file. */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#if defined(__PROSPERO__)
#include <ps5platform/libc.h>
#else
/* Public PS5 platform ABI; the host contract supplies deterministic entropy. */
extern uint32_t ps5_arc4random_uniform(uint32_t bound);
#endif

int __wrap_mkstemp(char *pattern);
int __wrap_mkstemp(char *pattern)
{
    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    size_t length = 0;
    char *suffix;

    if (!pattern) {
        errno = EINVAL;
        return -1;
    }
    while (length < PATH_MAX && pattern[length]) ++length;
    if (length == PATH_MAX) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (length < 6 || memcmp(pattern + length - 6, "XXXXXX", 6)) {
        errno = EINVAL;
        return -1;
    }
    suffix = pattern + length - 6;
    for (unsigned attempt = 0; attempt < 1000; ++attempt) {
        for (unsigned i = 0; i < 6; ++i)
            suffix[i] = alphabet[ps5_arc4random_uniform(sizeof(alphabet) - 1)];
        int fd = open(pattern, O_RDWR | O_CREAT | O_EXCL, 0600);
        if (fd >= 0) return fd;
        if (errno != EEXIST) return -1;
    }
    memcpy(suffix, "XXXXXX", 6);
    errno = EEXIST;
    return -1;
}
