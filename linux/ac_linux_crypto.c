/*
 * ac_linux_crypto.c — Linux kernel crypto backend for addrchain
 *
 * Implements ac_platform.h crypto interface using the kernel crypto API:
 *   - SHA-256 via crypto_shash (crypto_alloc_shash + crypto_shash_digest)
 *   - Ed25519 via the TweetNaCl implementation compiled into the module
 *   - CSPRNG via get_random_bytes()
 *   - Key zeroization via memzero_explicit()
 *
 * Also implements platform memory, mutex, time, and logging for kernel context.
 *
 * Mitigates: K01,K02,K03,K04,K05,K07,K08,K09,K14,K18,K20,K40
 *
 * NOTE: This file is only compiled when building the kernel module (obj-m).
 *       Userspace builds use ac_userspace_platform.c + ac_crypto.c instead.
 *       The Ed25519 code from ac_crypto.c is linked separately into the
 *       kernel module objects (common/ac_crypto.o).
 */

#ifdef __KERNEL__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/time.h>
#include <linux/random.h>
#include <linux/string.h>
#include <crypto/hash.h>

#include "ac_platform.h"
#include "ac_proto.h"

/* ================================================================== */
/*  SHA-256 via kernel crypto API                                      */
/* ================================================================== */

static struct crypto_shash *ac_sha256_tfm;

int ac_linux_crypto_init(void)
{
    ac_sha256_tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(ac_sha256_tfm)) {
        pr_err("addrchain: failed to allocate sha256 transform: %ld\n",
               PTR_ERR(ac_sha256_tfm));
        ac_sha256_tfm = NULL;
        return -ENOMEM;
    }
    pr_info("addrchain: kernel crypto SHA-256 initialized\n");
    return 0;
}

void ac_linux_crypto_exit(void)
{
    if (ac_sha256_tfm) {
        crypto_free_shash(ac_sha256_tfm);
        ac_sha256_tfm = NULL;
    }
}

int ac_crypto_sha256(const void *data, size_t len, uint8_t out[AC_HASH_LEN])
{
    SHASH_DESC_ON_STACK(desc, ac_sha256_tfm);
    int ret;

    if (!data || !out || !ac_sha256_tfm)
        return AC_ERR_INVAL;

    desc->tfm = ac_sha256_tfm;
    ret = crypto_shash_digest(desc, data, (unsigned int)len, out);
    shash_desc_zero(desc);

    return ret == 0 ? AC_OK : AC_ERR_CRYPTO;
}

/* ================================================================== */
/*  Ed25519 — delegates to the TweetNaCl functions in ac_crypto.c      */
/*                                                                     */
/*  ac_crypto_ed25519_keypair, ac_crypto_ed25519_sign,                 */
/*  ac_crypto_ed25519_verify are provided by ac_crypto.c               */
/*  which is compiled as a separate object in the kernel module.       */
/* ================================================================== */

/* ================================================================== */
/*  CSPRNG                                                             */
/* ================================================================== */

int ac_crypto_random(void *buf, size_t len)
{
    if (!buf)
        return AC_ERR_INVAL;
    get_random_bytes(buf, len);
    return AC_OK;
}

/* ================================================================== */
/*  Key zeroization                                                    */
/* ================================================================== */

void ac_crypto_zeroize(void *buf, size_t len)
{
    if (buf && len > 0)
        memzero_explicit(buf, len);
}

/* ================================================================== */
/*  Memory allocation                                                  */
/* ================================================================== */

void *ac_alloc(size_t size, int flags)
{
    gfp_t gfp = (flags & AC_MEM_ATOMIC) ? GFP_ATOMIC : GFP_KERNEL;
    return kmalloc(size, gfp);
}

void *ac_zalloc(size_t size, int flags)
{
    gfp_t gfp = (flags & AC_MEM_ATOMIC) ? GFP_ATOMIC : GFP_KERNEL;
    return kzalloc(size, gfp);
}

void ac_free(void *ptr)
{
    kfree(ptr); /* kfree(NULL) is safe */
}

/* ================================================================== */
/*  Mutex                                                              */
/* ================================================================== */

void ac_mutex_init(ac_mutex_t *m)
{
    struct mutex *km;
    if (!m)
        return;
    km = kmalloc(sizeof(struct mutex), GFP_KERNEL);
    if (km) {
        mutex_init(km);
        *m = km;
    }
}

void ac_mutex_destroy(ac_mutex_t *m)
{
    if (m && *m) {
        mutex_destroy(*m);
        kfree(*m);
        *m = NULL;
    }
}

void ac_mutex_lock(ac_mutex_t *m)
{
    if (m && *m)
        mutex_lock(*m);
}

void ac_mutex_unlock(ac_mutex_t *m)
{
    if (m && *m)
        mutex_unlock(*m);
}

/* ================================================================== */
/*  Time                                                               */
/* ================================================================== */

uint64_t ac_time_unix_sec(void)
{
    return ktime_get_real_seconds();
}

/* ================================================================== */
/*  Logging                                                            */
/* ================================================================== */

void ac_log(int level, const char *fmt, ...)
{
    va_list args;
    char buf[256];

    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    switch (level) {
    case AC_LOG_ERR:
        pr_err("addrchain: %s\n", buf);
        break;
    case AC_LOG_WARN:
        pr_warn("addrchain: %s\n", buf);
        break;
    case AC_LOG_INFO:
        pr_info("addrchain: %s\n", buf);
        break;
    case AC_LOG_DEBUG:
        pr_debug("addrchain: %s\n", buf);
        break;
    default:
        pr_info("addrchain: %s\n", buf);
        break;
    }
}

#endif /* __KERNEL__ */
