/*
 * ac_platform.h — Platform abstraction for addrchain
 *
 * Modeled on POOL's pool_platform.h.  Each platform (Linux kernel,
 * Windows kernel, macOS, userspace) provides an implementation of
 * these functions.
 *
 * Mitigates:
 *   K08  — Lock ordering documented, mutex API prevents misuse
 *   K48  — Fixed-width types, explicit endian conversion, static_assert
 */

#ifndef AC_PLATFORM_H
#define AC_PLATFORM_H

#include "ac_proto.h"

/* ------------------------------------------------------------------ */
/*  Fixed-width types (K48: no platform-dependent sizes)               */
/* ------------------------------------------------------------------ */

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/string.h>
#else
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#endif

/* ------------------------------------------------------------------ */
/*  Endian conversion (K48: explicit, never assume host order)         */
/* ------------------------------------------------------------------ */

#ifdef __KERNEL__
#include <linux/byteorder/generic.h>
#define ac_cpu_to_le16(x) cpu_to_le16(x)
#define ac_cpu_to_le32(x) cpu_to_le32(x)
#define ac_cpu_to_le64(x) cpu_to_le64(x)
#define ac_le16_to_cpu(x) le16_to_cpu(x)
#define ac_le32_to_cpu(x) le32_to_cpu(x)
#define ac_le64_to_cpu(x) le64_to_cpu(x)
#else
/* Userspace: assume little-endian for now; add byteswap for big-endian */
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#include <byteswap.h>
#define ac_cpu_to_le16(x) ((uint16_t)bswap_16(x))
#define ac_cpu_to_le32(x) ((uint32_t)bswap_32(x))
#define ac_cpu_to_le64(x) ((uint64_t)bswap_64(x))
#define ac_le16_to_cpu(x) ((uint16_t)bswap_16(x))
#define ac_le32_to_cpu(x) ((uint32_t)bswap_32(x))
#define ac_le64_to_cpu(x) ((uint64_t)bswap_64(x))
#else
#define ac_cpu_to_le16(x) (x)
#define ac_cpu_to_le32(x) (x)
#define ac_cpu_to_le64(x) (x)
#define ac_le16_to_cpu(x) (x)
#define ac_le32_to_cpu(x) (x)
#define ac_le64_to_cpu(x) (x)
#endif
#endif

/* ------------------------------------------------------------------ */
/*  Return codes                                                       */
/* ------------------------------------------------------------------ */

#define AC_OK           0
#define AC_ERR         -1
#define AC_ERR_NOMEM   -2
#define AC_ERR_INVAL   -3
#define AC_ERR_EXIST   -4       /* address/subnet already exists       */
#define AC_ERR_NOENT   -5       /* not found                           */
#define AC_ERR_PERM    -6       /* permission denied                   */
#define AC_ERR_FULL    -7       /* pool/table full                     */
#define AC_ERR_EXPIRED -8       /* lease expired                       */
#define AC_ERR_CONFLICT -9      /* DAD or chain conflict               */
#define AC_ERR_CRYPTO  -10      /* crypto operation failed             */
#define AC_ERR_OVERLAP -11      /* CIDR/subnet overlap                 */
#define AC_ERR_RATELIM -12      /* rate limit exceeded                 */
#define AC_ERR_POOL    -13      /* POOL module not available           */

/* ------------------------------------------------------------------ */
/*  Opaque handle types                                                */
/* ------------------------------------------------------------------ */

typedef void *ac_mutex_t;

/* ------------------------------------------------------------------ */
/*  Memory allocation                                                  */
/*                                                                     */
/*  K05: every alloc must have a matching free.                        */
/*  K14: kernel implementations use GFP_KERNEL in process context,     */
/*       GFP_ATOMIC in interrupt context.  The `flags` parameter       */
/*       distinguishes them.                                           */
/* ------------------------------------------------------------------ */

#define AC_MEM_NORMAL   0       /* process context (GFP_KERNEL)        */
#define AC_MEM_ATOMIC   1       /* interrupt/spinlock context           */

void *ac_alloc(size_t size, int flags);
void *ac_zalloc(size_t size, int flags);
void  ac_free(void *ptr);

/* ------------------------------------------------------------------ */
/*  Cryptography                                                       */
/*                                                                     */
/*  K20: use platform crypto APIs, never hand-rolled.                  */
/*  K40: Ed25519 verify is MANDATORY in both kernel and daemon.        */
/* ------------------------------------------------------------------ */

/* SHA-256: hash `data` of `len` bytes into `out` (32 bytes) */
int ac_crypto_sha256(const void *data, size_t len, uint8_t out[AC_HASH_LEN]);

/* Ed25519 key generation: derive keypair from 32-byte seed */
int ac_crypto_ed25519_keypair(const uint8_t seed[32],
                              uint8_t pubkey[AC_PUBKEY_LEN],
                              uint8_t privkey[64]);

/* Ed25519 sign: sign `msg` of `msg_len` with `privkey`, write to `sig` */
int ac_crypto_ed25519_sign(const uint8_t privkey[64],
                           const void *msg, size_t msg_len,
                           uint8_t sig[AC_SIG_LEN]);

/* Ed25519 verify: verify `sig` over `msg` with `pubkey`. Returns AC_OK or AC_ERR_CRYPTO. */
int ac_crypto_ed25519_verify(const uint8_t pubkey[AC_PUBKEY_LEN],
                             const void *msg, size_t msg_len,
                             const uint8_t sig[AC_SIG_LEN]);

/* Cryptographically secure random bytes */
int ac_crypto_random(void *buf, size_t len);

/* Zeroize sensitive memory (not optimized away by compiler) */
void ac_crypto_zeroize(void *buf, size_t len);

/* ------------------------------------------------------------------ */
/*  Mutex / locking                                                    */
/*                                                                     */
/*  K08 LOCK ORDERING (document here, enforce in code):                */
/*    1. chain_lock   (outermost)                                      */
/*    2. claim_lock                                                    */
/*    3. subnet_lock                                                   */
/*    4. partition_lock                                                */
/*    5. vpn_lock                                                      */
/*    6. discover_lock (innermost)                                     */
/*                                                                     */
/*  Never acquire a higher-numbered lock while holding a lower one.    */
/*  Never sleep while holding a spinlock.                              */
/* ------------------------------------------------------------------ */

int  ac_mutex_init(ac_mutex_t *m);
void ac_mutex_lock(ac_mutex_t *m);
void ac_mutex_unlock(ac_mutex_t *m);
void ac_mutex_destroy(ac_mutex_t *m);

/* ------------------------------------------------------------------ */
/*  Time                                                               */
/*                                                                     */
/*  N30: timestamps are informational; lease TTL uses block count.     */
/*       ac_time_unix_sec() used for clock sanity check only.          */
/* ------------------------------------------------------------------ */

/* Current time in Unix seconds */
uint64_t ac_time_unix_sec(void);

/* Monotonic nanoseconds (for internal timing, not for chain) */
uint64_t ac_time_mono_ns(void);

/* ------------------------------------------------------------------ */
/*  Logging                                                            */
/* ------------------------------------------------------------------ */

typedef enum {
    AC_LOG_DEBUG = 0,
    AC_LOG_INFO  = 1,
    AC_LOG_WARN  = 2,
    AC_LOG_ERROR = 3,
} ac_log_level_t;

void ac_log(ac_log_level_t level, const char *fmt, ...);

#define ac_log_debug(fmt, ...) ac_log(AC_LOG_DEBUG, fmt, ##__VA_ARGS__)
#define ac_log_info(fmt, ...)  ac_log(AC_LOG_INFO,  fmt, ##__VA_ARGS__)
#define ac_log_warn(fmt, ...)  ac_log(AC_LOG_WARN,  fmt, ##__VA_ARGS__)
#define ac_log_error(fmt, ...) ac_log(AC_LOG_ERROR, fmt, ##__VA_ARGS__)

/* ------------------------------------------------------------------ */
/*  Address utility helpers                                            */
/* ------------------------------------------------------------------ */

/* Compare two ac_address_t values. Returns 0 if equal. */
static inline int ac_addr_cmp(const ac_address_t *a, const ac_address_t *b)
{
    if (a->family != b->family)
        return (int)a->family - (int)b->family;
    return memcmp(a->addr, b->addr, AC_MAX_ADDR_LEN);
}

/* Check if an address is zero (unset) */
static inline int ac_addr_is_zero(const ac_address_t *a)
{
    size_t i;
    for (i = 0; i < AC_MAX_ADDR_LEN; i++) {
        if (a->addr[i] != 0)
            return 0;
    }
    return 1;
}

/* Get the byte length used by an address family */
static inline size_t ac_addr_len(uint8_t family)
{
    switch (family) {
    case AC_AF_IPV4: return AC_IPV4_ADDR_LEN;
    case AC_AF_IPV6: return AC_IPV6_ADDR_LEN;
    case AC_AF_POOL: return AC_POOL_ADDR_LEN;
    default:         return 0;
    }
}

/* Check if `addr` is within the prefix defined by `prefix` */
static inline int ac_addr_in_prefix(const ac_address_t *addr,
                                    const ac_address_t *prefix)
{
    size_t len;
    uint8_t full_bytes, remainder;
    size_t i;

    if (addr->family != prefix->family)
        return 0;

    len = ac_addr_len(addr->family);
    if (len == 0)
        return 0;

    full_bytes = prefix->prefix_len / 8;
    remainder  = prefix->prefix_len % 8;

    /* Compare full bytes of the prefix */
    for (i = 0; i < full_bytes && i < len; i++) {
        if (addr->addr[i] != prefix->addr[i])
            return 0;
    }

    /* Compare remaining bits */
    if (remainder > 0 && full_bytes < len) {
        uint8_t mask = (uint8_t)(0xFF << (8 - remainder));
        if ((addr->addr[full_bytes] & mask) != (prefix->addr[full_bytes] & mask))
            return 0;
    }

    return 1;
}

/* Check if two prefixes overlap (either contains the other) */
static inline int ac_prefix_overlaps(const ac_address_t *a,
                                     const ac_address_t *b)
{
    if (a->family != b->family)
        return 0;

    /* If A's prefix is shorter (larger network), check if B is within A */
    if (a->prefix_len <= b->prefix_len)
        return ac_addr_in_prefix(b, a);

    /* Otherwise check if A is within B */
    return ac_addr_in_prefix(a, b);
}

/* ------------------------------------------------------------------ */
/*  Compile-time assertions (K48)                                      */
/* ------------------------------------------------------------------ */

#ifdef __KERNEL__
#define AC_STATIC_ASSERT(cond, msg) BUILD_BUG_ON_MSG(!(cond), msg)
#else
#define AC_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#endif

#endif /* AC_PLATFORM_H */
