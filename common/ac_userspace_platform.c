/*
 * ac_userspace_platform.c — Userspace platform backend for addrchain
 *
 * Provides platform abstractions for:
 *   - Memory allocation (malloc/calloc/free)
 *   - Mutex (CRITICAL_SECTION on Windows, pthread_mutex on POSIX)
 *   - Time (wall clock and monotonic)
 *   - Logging (stderr with level prefix)
 */

#include "ac_platform.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#endif

/* ================================================================== */
/*  Memory allocation                                                  */
/* ================================================================== */

void *ac_alloc(size_t size, int flags)
{
    (void)flags;
    return malloc(size);
}

void *ac_zalloc(size_t size, int flags)
{
    (void)flags;
    return calloc(1, size);
}

void ac_free(void *ptr)
{
    free(ptr);
}

/* ================================================================== */
/*  Mutex                                                              */
/* ================================================================== */

#ifdef _WIN32

int ac_mutex_init(ac_mutex_t *m)
{
    CRITICAL_SECTION *cs = (CRITICAL_SECTION *)malloc(sizeof(CRITICAL_SECTION));
    if (!cs)
        return AC_ERR_NOMEM;
    InitializeCriticalSection(cs);
    *m = cs;
    return AC_OK;
}

void ac_mutex_lock(ac_mutex_t *m)
{
    EnterCriticalSection((CRITICAL_SECTION *)*m);
}

void ac_mutex_unlock(ac_mutex_t *m)
{
    LeaveCriticalSection((CRITICAL_SECTION *)*m);
}

void ac_mutex_destroy(ac_mutex_t *m)
{
    DeleteCriticalSection((CRITICAL_SECTION *)*m);
    free(*m);
    *m = NULL;
}

#else /* POSIX */

int ac_mutex_init(ac_mutex_t *m)
{
    pthread_mutex_t *mtx = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
    if (!mtx)
        return AC_ERR_NOMEM;
    if (pthread_mutex_init(mtx, NULL) != 0) {
        free(mtx);
        return AC_ERR;
    }
    *m = mtx;
    return AC_OK;
}

void ac_mutex_lock(ac_mutex_t *m)
{
    pthread_mutex_lock((pthread_mutex_t *)*m);
}

void ac_mutex_unlock(ac_mutex_t *m)
{
    pthread_mutex_unlock((pthread_mutex_t *)*m);
}

void ac_mutex_destroy(ac_mutex_t *m)
{
    pthread_mutex_destroy((pthread_mutex_t *)*m);
    free(*m);
    *m = NULL;
}

#endif

/* ================================================================== */
/*  Time                                                               */
/* ================================================================== */

#ifdef _WIN32

uint64_t ac_time_unix_sec(void)
{
    FILETIME ft;
    ULARGE_INTEGER uli;
    GetSystemTimeAsFileTime(&ft);
    uli.LowPart  = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    /* FILETIME epoch: 1601-01-01. Subtract offset to Unix epoch. */
    return (uint64_t)((uli.QuadPart - 116444736000000000ULL) / 10000000ULL);
}

uint64_t ac_time_mono_ns(void)
{
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (uint64_t)((double)count.QuadPart / (double)freq.QuadPart * 1e9);
}

#else /* POSIX */

uint64_t ac_time_unix_sec(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec;
}

uint64_t ac_time_mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

#endif

/* ================================================================== */
/*  Logging                                                            */
/* ================================================================== */

void ac_log(ac_log_level_t level, const char *fmt, ...)
{
    static const char *prefix[] = { "DEBUG", "INFO", "WARN", "ERROR" };
    va_list ap;

    if ((unsigned)level > AC_LOG_ERROR)
        level = AC_LOG_ERROR;

    fprintf(stderr, "[%s] ", prefix[level]);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}
