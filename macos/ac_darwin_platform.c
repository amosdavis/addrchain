/*
 * ac_darwin_platform.c — macOS platform backend for addrchain
 *
 * Provides crypto (CommonCrypto SHA-256, bundled Ed25519), memory,
 * mutex, time, and logging for macOS kernel and userspace.
 *
 * Mitigates: K20,P32
 *
 * NOTE: macOS-only. For kernel builds, integrates with IOKit.
 *       For userspace (daemon/CLI), use ac_userspace_platform.c instead.
 */

#ifdef __APPLE__

#include <CommonCrypto/CommonDigest.h>
#include <Security/SecRandom.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/time.h>
#include <mach/mach_time.h>

#include "ac_proto.h"
#include "ac_platform.h"

/* ================================================================== */
/*  SHA-256 via CommonCrypto                                           */
/* ================================================================== */

int ac_platform_sha256(const void *data, size_t len,
                       uint8_t out[AC_HASH_LEN])
{
    CC_SHA256(data, (CC_LONG)len, out);
    return AC_OK;
}

/* ================================================================== */
/*  CSPRNG via SecRandomCopyBytes                                      */
/* ================================================================== */

int ac_platform_random(void *buf, size_t len)
{
    if (SecRandomCopyBytes(kSecRandomDefault, len, buf) == errSecSuccess)
        return AC_OK;
    return AC_ERR_CRYPTO;
}

/* ================================================================== */
/*  Memory                                                             */
/* ================================================================== */

void *ac_platform_alloc(size_t size)
{
    return malloc(size);
}

void ac_platform_free(void *ptr)
{
    free(ptr);
}

/* ================================================================== */
/*  Mutex (pthread_mutex)                                              */
/* ================================================================== */

void ac_mutex_init(ac_mutex_t *m)
{
    pthread_mutex_init(&m->mutex, NULL);
}

void ac_mutex_lock(ac_mutex_t *m)
{
    pthread_mutex_lock(&m->mutex);
}

void ac_mutex_unlock(ac_mutex_t *m)
{
    pthread_mutex_unlock(&m->mutex);
}

void ac_mutex_destroy(ac_mutex_t *m)
{
    pthread_mutex_destroy(&m->mutex);
}

/* ================================================================== */
/*  Time                                                               */
/* ================================================================== */

uint64_t ac_time_unix_sec(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec;
}

uint64_t ac_time_mono_ns(void)
{
    static mach_timebase_info_data_t info = {0, 0};
    if (info.denom == 0)
        mach_timebase_info(&info);
    return mach_absolute_time() * info.numer / info.denom;
}

/* ================================================================== */
/*  Logging                                                            */
/* ================================================================== */

void ac_platform_log(int level, const char *fmt, ...)
{
    const char *prefix = "[INFO]";
    if (level >= 2) prefix = "[ERROR]";
    else if (level == 1) prefix = "[WARN]";

    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "addrchain %s ", prefix);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

/* ================================================================== */
/*  Zeroize                                                            */
/* ================================================================== */

void ac_platform_zeroize(void *buf, size_t len)
{
    memset_s(buf, len, 0, len);
}

#endif /* __APPLE__ */
