/*
 * ac_pool_bridge.c — POOL protocol integration for addrchain
 *
 * Bridge to pool.ko: query POOL sessions, map 256-bit addresses,
 * use POOL discovery for chain synchronization.
 *
 * FAIL-FAST policy:
 *   - If POOL addresses are configured but pool.ko is NOT loaded,
 *     module init FAILS with a clear error message.
 *   - If only IPv4/IPv6 is configured, pool.ko is truly optional
 *     and this module provides no-op stubs.
 *
 * Mitigates: K46,P01,P02,P03,P04,P05,P06,P07,P08,P09,P10
 *
 * NOTE: Kernel-only. Compiled via Kbuild.
 */

#ifdef __KERNEL__

#include <linux/module.h>
#include <linux/kernel.h>

#include "ac_proto.h"
#include "ac_platform.h"

/* ================================================================== */
/*  POOL module detection                                              */
/* ================================================================== */

static int pool_module_loaded;

/*
 * ac_pool_bridge_init — Check if pool.ko is available.
 *
 * If require_pool is true (POOL addresses configured), FAIL-FAST
 * if pool.ko is not loaded. Otherwise, silently disable POOL support.
 */
int ac_pool_bridge_init(int require_pool)
{
    struct module *pool_mod;

    mutex_lock(&module_mutex);
    pool_mod = find_module("pool");
    mutex_unlock(&module_mutex);

    pool_module_loaded = (pool_mod != NULL);

    if (require_pool && !pool_module_loaded) {
        pr_err("addrchain: POOL addresses configured but pool.ko is NOT loaded.\n"
               "addrchain: Load pool.ko first: modprobe pool\n"
               "addrchain: Or remove POOL address configuration.\n");
        return -ENODEV; /* FAIL-FAST */
    }

    if (pool_module_loaded) {
        pr_info("addrchain: pool.ko detected, POOL 256-bit addresses enabled\n");
    } else {
        pr_info("addrchain: pool.ko not loaded, POOL addresses disabled (IPv4/IPv6 only)\n");
    }

    return 0;
}

void ac_pool_bridge_exit(void)
{
    pool_module_loaded = 0;
    pr_info("addrchain: POOL bridge cleaned up\n");
}

/*
 * ac_pool_bridge_available — Check if POOL transport is available.
 * Returns 1 if pool.ko is loaded, 0 otherwise.
 */
int ac_pool_bridge_available(void)
{
    return pool_module_loaded;
}

/*
 * ac_pool_validate_address — Validate a POOL 256-bit address.
 *
 * POOL address format (256 bits):
 *   [type:8][version:8][org:64][subnet:64][node:96][crc32:32]
 *
 * Returns AC_OK if valid, AC_ERR_INVAL otherwise.
 */
int ac_pool_validate_address(const ac_address_t *addr)
{
    uint32_t crc, computed_crc;

    if (!addr)
        return AC_ERR_INVAL;

    if (addr->family != AC_AF_POOL)
        return AC_ERR_INVAL;

    if (!pool_module_loaded)
        return AC_ERR_POOL;

    /* Type must be nonzero */
    if (addr->addr[0] == 0) {
        pr_warn("addrchain: POOL address type is zero\n");
        return AC_ERR_INVAL;
    }

    /* Version check */
    if (addr->addr[1] != 1) {
        pr_warn("addrchain: POOL address version %u unsupported\n",
                addr->addr[1]);
        return AC_ERR_INVAL;
    }

    /* CRC32 check: last 4 bytes are CRC of first 28 bytes */
    memcpy(&crc, &addr->addr[28], sizeof(uint32_t));

    /* Simple CRC32 — in production, use crc32() from <linux/crc32.h> */
    computed_crc = crc32(0, addr->addr, 28);

    if (crc != computed_crc) {
        pr_warn("addrchain: POOL address CRC mismatch\n");
        return AC_ERR_INVAL;
    }

    return AC_OK;
}

#endif /* __KERNEL__ */
