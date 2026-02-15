/*
 * ac_win_platform.c — Windows platform backend for addrchain
 *
 * Provides crypto (BCrypt SHA-256, bundled Ed25519), memory, mutex,
 * time, and logging implementations for Windows kernel and userspace.
 *
 * Mitigates: K20,P30,P31
 *
 * NOTE: For WDK kernel builds, define _KERNEL_MODE.
 *       For userspace (daemon/CLI), use ac_userspace_platform.c instead.
 */

#ifdef _KERNEL_MODE

#include <ntddk.h>
#include <bcrypt.h>

#include "ac_proto.h"
#include "ac_platform.h"

/* ================================================================== */
/*  BCrypt SHA-256                                                     */
/* ================================================================== */

int ac_platform_sha256(const void *data, size_t len,
                       uint8_t out[AC_HASH_LEN])
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM,
                                         NULL, 0);
    if (!NT_SUCCESS(status))
        return AC_ERR_CRYPTO;

    status = BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return AC_ERR_CRYPTO;
    }

    BCryptHashData(hash, (PUCHAR)data, (ULONG)len, 0);
    BCryptFinishHash(hash, out, AC_HASH_LEN, 0);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);

    return AC_OK;
}

/* ================================================================== */
/*  CSPRNG                                                             */
/* ================================================================== */

int ac_platform_random(void *buf, size_t len)
{
    NTSTATUS status = BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)len,
                                      BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return NT_SUCCESS(status) ? AC_OK : AC_ERR_CRYPTO;
}

/* ================================================================== */
/*  Memory                                                             */
/* ================================================================== */

void *ac_platform_alloc(size_t size)
{
    return ExAllocatePoolWithTag(NonPagedPool, size, 'CRDA');
}

void ac_platform_free(void *ptr)
{
    if (ptr)
        ExFreePoolWithTag(ptr, 'CRDA');
}

/* ================================================================== */
/*  Mutex (FAST_MUTEX in kernel)                                       */
/* ================================================================== */

void ac_mutex_init(ac_mutex_t *m)
{
    ExInitializeFastMutex(&m->mutex);
}

void ac_mutex_lock(ac_mutex_t *m)
{
    ExAcquireFastMutex(&m->mutex);
}

void ac_mutex_unlock(ac_mutex_t *m)
{
    ExReleaseFastMutex(&m->mutex);
}

void ac_mutex_destroy(ac_mutex_t *m)
{
    /* No-op for FAST_MUTEX */
    (void)m;
}

/* ================================================================== */
/*  Time                                                               */
/* ================================================================== */

uint64_t ac_time_unix_sec(void)
{
    LARGE_INTEGER system_time, unix_epoch;
    KeQuerySystemTime(&system_time);
    /* Windows epoch: 1601-01-01. Unix epoch diff: 116444736000000000 */
    unix_epoch.QuadPart = 116444736000000000LL;
    return (uint64_t)((system_time.QuadPart - unix_epoch.QuadPart) / 10000000);
}

uint64_t ac_time_mono_ns(void)
{
    LARGE_INTEGER counter, freq;
    counter = KeQueryPerformanceCounter(&freq);
    return (uint64_t)(counter.QuadPart * 1000000000ULL / freq.QuadPart);
}

/* ================================================================== */
/*  Logging                                                            */
/* ================================================================== */

void ac_platform_log(int level, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vDbgPrintExWithPrefix("addrchain: ", DPFLTR_DEFAULT_ID,
                           (ULONG)level, fmt, args);
    va_end(args);
}

/* ================================================================== */
/*  Zeroize                                                            */
/* ================================================================== */

void ac_platform_zeroize(void *buf, size_t len)
{
    RtlSecureZeroMemory(buf, len);
}

#endif /* _KERNEL_MODE */
