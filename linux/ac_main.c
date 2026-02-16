/*
 * ac_main.c — addrchain Linux kernel module entry point
 *
 * Module init/exit, char device /dev/addrchain, ioctl dispatch,
 * netlink socket registration. Coordinates all kernel-side subsystems.
 *
 * Mitigates: K06,K10,K17,K21,K22,K23,K24,K25,K36,K37,K39
 *
 * NOTE: This file requires Linux kernel headers and is compiled via
 *       Kbuild (obj-m). It cannot be compiled with userspace gcc.
 */

#ifdef __KERNEL__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/version.h>

#include "ac_proto.h"
#include "ac_platform.h"
#include "ac_chain.h"
#include "ac_claims.h"
#include "ac_subnet.h"
#include "ac_partition.h"
#include "ac_vpn.h"
#include "ac_discover.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("addrchain contributors");
MODULE_DESCRIPTION("Blockchain-based network address management");
MODULE_VERSION("2.0.0");

/* Minimum kernel version: 5.15 (K22) */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0)
#error "addrchain requires Linux kernel 5.15 or later"
#endif

/* ================================================================== */
/*  Global state                                                       */
/* ================================================================== */

/* Char device */
static dev_t            ac_devno;
static struct cdev      ac_cdev;
static struct class    *ac_class;
static struct device   *ac_device;

/* Blockchain subsystems — K08: allocated in documented lock order */
static ac_block_t      *ac_chain;       /* chain storage */
static uint32_t         ac_chain_len;   /* current chain length */
static ac_mutex_t       ac_chain_lock;  /* lock order: 1 (outermost) */

static ac_claim_store_t     ac_claims;  /* lock order: 2 */
static ac_subnet_store_t    ac_subnets; /* lock order: 3 */
static ac_partition_store_t ac_parts;   /* lock order: 4 */
static ac_vpn_store_t       ac_vpns;    /* lock order: 5 */
static ac_discover_state_t  ac_disc;    /* lock order: 6 (innermost) */

/* ================================================================== */
/*  IOCTL definitions                                                  */
/* ================================================================== */

#define AC_IOC_MAGIC    'A'

/* Query chain status */
#define AC_IOC_STATUS       _IOR(AC_IOC_MAGIC, 0x01, struct ac_ioctl_status)
/* Submit a block (from daemon) */
#define AC_IOC_ADD_BLOCK    _IOW(AC_IOC_MAGIC, 0x02, ac_block_t)
/* Get chain height */
#define AC_IOC_GET_HEIGHT   _IOR(AC_IOC_MAGIC, 0x03, uint32_t)

struct ac_ioctl_status {
    uint32_t chain_height;
    uint32_t claim_count;
    uint32_t subnet_count;
    uint32_t partition_count;
    uint32_t vpn_count;
    uint32_t peer_count;
    uint16_t version;
    uint8_t  pad[2];
};

/* ================================================================== */
/*  Char device file operations                                        */
/* ================================================================== */

static int ac_dev_open(struct inode *inode, struct file *filp)
{
    (void)inode;
    (void)filp;
    if (!try_module_get(THIS_MODULE)) /* K10: prevent unload during use */
        return -EBUSY;
    return 0;
}

static int ac_dev_release(struct inode *inode, struct file *filp)
{
    (void)inode;
    (void)filp;
    module_put(THIS_MODULE); /* K10: allow unload */
    return 0;
}

static long ac_dev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    (void)filp;

    switch (cmd) {
    case AC_IOC_STATUS: {
        struct ac_ioctl_status st;
        memset(&st, 0, sizeof(st)); /* K18: zero all fields before copy */

        ac_mutex_lock(&ac_chain_lock);
        st.chain_height = ac_chain_len;
        ac_mutex_unlock(&ac_chain_lock);

        st.claim_count = ac_claims_count(&ac_claims);
        st.subnet_count = ac_subnet_count(&ac_subnets);
        st.partition_count = ac_partition_count(&ac_parts);
        st.vpn_count = ac_vpn_count(&ac_vpns);
        st.peer_count = ac_discover_peer_count(&ac_disc);
        st.version = AC_VERSION;

        if (copy_to_user((void __user *)arg, &st, sizeof(st)))
            return -EFAULT;
        return 0;
    }

    case AC_IOC_ADD_BLOCK: {
        ac_block_t *blk;
        int rc;

        blk = kmalloc(sizeof(ac_block_t), GFP_KERNEL);
        if (!blk)
            return -ENOMEM;

        if (copy_from_user(blk, (void __user *)arg, sizeof(ac_block_t))) {
            kfree(blk);
            return -EFAULT;
        }

        /* K03: validate before trusting any field */
        if (blk->tx_count > AC_MAX_TX_PER_BLOCK) {
            kfree(blk);
            return -EINVAL;
        }

        /* Validate block against current chain */
        ac_mutex_lock(&ac_chain_lock);

        if (ac_chain_len >= AC_MAX_CHAIN_BLOCKS) {
            ac_mutex_unlock(&ac_chain_lock);
            kfree(blk);
            return -ENOSPC; /* K37: bounded chain growth */
        }

        if (ac_chain_len > 0) {
            rc = ac_block_validate(blk, &ac_chain[ac_chain_len - 1]);
        } else {
            /* Accept genesis */
            rc = AC_OK;
        }

        if (rc != AC_OK) {
            ac_mutex_unlock(&ac_chain_lock);
            kfree(blk);
            return -EINVAL;
        }

        /* Validate against claims, subnets, partitions, VPN */
        rc = ac_claims_validate_block(&ac_claims, blk);
        if (rc != AC_OK) {
            ac_mutex_unlock(&ac_chain_lock);
            kfree(blk);
            return -EINVAL;
        }

        rc = ac_subnet_validate_block(&ac_subnets, blk);
        if (rc != AC_OK) {
            ac_mutex_unlock(&ac_chain_lock);
            kfree(blk);
            return -EINVAL;
        }

        rc = ac_partition_validate_block(&ac_parts, blk);
        if (rc != AC_OK) {
            ac_mutex_unlock(&ac_chain_lock);
            kfree(blk);
            return -EINVAL;
        }

        rc = ac_vpn_validate_block(&ac_vpns, blk);
        if (rc != AC_OK) {
            ac_mutex_unlock(&ac_chain_lock);
            kfree(blk);
            return -EINVAL;
        }

        /* All validation passed — apply */
        memcpy(&ac_chain[ac_chain_len], blk, sizeof(ac_block_t));
        ac_chain_len++;

        ac_claims_apply_block(&ac_claims, blk);
        ac_subnet_apply_block(&ac_subnets, blk);
        ac_partition_apply_block(&ac_parts, blk);
        ac_vpn_apply_block(&ac_vpns, blk);

        ac_mutex_unlock(&ac_chain_lock);
        kfree(blk);

        pr_info("addrchain: block %u added (txs=%u)\n",
                ac_chain_len - 1, blk->tx_count);
        return 0;
    }

    case AC_IOC_GET_HEIGHT: {
        uint32_t height;

        ac_mutex_lock(&ac_chain_lock);
        height = ac_chain_len;
        ac_mutex_unlock(&ac_chain_lock);

        if (copy_to_user((void __user *)arg, &height, sizeof(height)))
            return -EFAULT;
        return 0;
    }

    default:
        return -ENOTTY;
    }
}

static const struct file_operations ac_fops = {
    .owner          = THIS_MODULE,
    .open           = ac_dev_open,
    .release        = ac_dev_release,
    .unlocked_ioctl = ac_dev_ioctl,
    .compat_ioctl   = ac_dev_ioctl,
};

/* ================================================================== */
/*  Module init / exit                                                 */
/*                                                                     */
/*  K21: goto-chain cleanup, unwind in reverse order on failure.       */
/* ================================================================== */

/* External from ac_linux_crypto.c */
extern int  ac_linux_crypto_init(void);
extern void ac_linux_crypto_exit(void);

static int __init ac_module_init(void)
{
    int ret;
    uint8_t local_pubkey[AC_PUBKEY_LEN];
    uint8_t seed[32];

    pr_info("addrchain: initializing v%u.%u\n",
            AC_VERSION_MAJOR, AC_VERSION_MINOR);

    /* Verify struct packing (K03) */
    ac_proto_verify_sizes();

    /* Step 1: Kernel crypto */
    ret = ac_linux_crypto_init();
    if (ret)
        goto fail_crypto;

    /* Step 2: Chain storage */
    ac_chain = kvmalloc_array(AC_MAX_CHAIN_BLOCKS, sizeof(ac_block_t),
                              GFP_KERNEL | __GFP_ZERO);
    if (!ac_chain) {
        ret = -ENOMEM;
        goto fail_chain_alloc;
    }
    ac_chain_len = 0;
    ac_mutex_init(&ac_chain_lock);

    /* Step 3: Subsystems — K08: init in lock order */
    ret = ac_claims_init(&ac_claims, AC_DEFAULT_LEASE_BLOCKS, 0);
    if (ret != AC_OK) {
        ret = -ENOMEM;
        goto fail_claims;
    }

    ret = ac_subnet_init(&ac_subnets, 0, 0);
    if (ret != AC_OK) {
        ret = -ENOMEM;
        goto fail_subnets;
    }

    ret = ac_partition_init(&ac_parts, 0, 0);
    if (ret != AC_OK) {
        ret = -ENOMEM;
        goto fail_parts;
    }

    ret = ac_vpn_init(&ac_vpns, 0);
    if (ret != AC_OK) {
        ret = -ENOMEM;
        goto fail_vpns;
    }

    /* Generate ephemeral identity for discovery */
    get_random_bytes(seed, sizeof(seed));
    ac_crypto_ed25519_keypair(seed, local_pubkey, NULL);
    memzero_explicit(seed, sizeof(seed));

    ret = ac_discover_init(&ac_disc, local_pubkey, AC_SYNC_PORT,
                           AC_DISC_IPV6_MCAST | AC_DISC_IPV4_BCAST, 0);
    if (ret != AC_OK) {
        ret = -ENOMEM;
        goto fail_disc;
    }

    /* Step 4: Char device */
    ret = alloc_chrdev_region(&ac_devno, 0, 1, "addrchain");
    if (ret)
        goto fail_chrdev;

    cdev_init(&ac_cdev, &ac_fops);
    ac_cdev.owner = THIS_MODULE;
    ret = cdev_add(&ac_cdev, ac_devno, 1);
    if (ret)
        goto fail_cdev;

    ac_class = class_create("addrchain");
    if (IS_ERR(ac_class)) {
        ret = PTR_ERR(ac_class);
        goto fail_class;
    }

    ac_device = device_create(ac_class, NULL, ac_devno, NULL, "addrchain");
    if (IS_ERR(ac_device)) {
        ret = PTR_ERR(ac_device);
        goto fail_device;
    }

    /* Create genesis block */
    ac_mutex_lock(&ac_chain_lock);
    ac_genesis_block(&ac_chain[0]);
    ac_chain_len = 1;
    ac_mutex_unlock(&ac_chain_lock);

    pr_info("addrchain: module loaded, /dev/addrchain ready\n");
    return 0;

    /* K21: reverse-order cleanup */
fail_device:
    class_destroy(ac_class);
fail_class:
    cdev_del(&ac_cdev);
fail_cdev:
    unregister_chrdev_region(ac_devno, 1);
fail_chrdev:
    ac_discover_destroy(&ac_disc);
fail_disc:
    ac_vpn_destroy(&ac_vpns);
fail_vpns:
    ac_partition_destroy(&ac_parts);
fail_parts:
    ac_subnet_destroy(&ac_subnets);
fail_subnets:
    ac_claims_destroy(&ac_claims);
fail_claims:
    ac_mutex_destroy(&ac_chain_lock);
    kvfree(ac_chain);
    ac_chain = NULL;
fail_chain_alloc:
    ac_linux_crypto_exit();
fail_crypto:
    pr_err("addrchain: init failed (%d)\n", ret);
    return ret;
}

static void __exit ac_module_exit(void)
{
    pr_info("addrchain: unloading...\n");

    /* K10: char device first to stop new ioctls */
    device_destroy(ac_class, ac_devno);
    class_destroy(ac_class);
    cdev_del(&ac_cdev);
    unregister_chrdev_region(ac_devno, 1);

    /* K08: destroy in reverse lock order */
    ac_discover_destroy(&ac_disc);
    ac_vpn_destroy(&ac_vpns);
    ac_partition_destroy(&ac_parts);
    ac_subnet_destroy(&ac_subnets);
    ac_claims_destroy(&ac_claims);

    /* Chain storage */
    ac_mutex_destroy(&ac_chain_lock);
    if (ac_chain) {
        kvfree(ac_chain);
        ac_chain = NULL;
    }
    ac_chain_len = 0;

    /* Crypto last */
    ac_linux_crypto_exit();

    pr_info("addrchain: module unloaded\n");
}

module_init(ac_module_init);
module_exit(ac_module_exit);

#endif /* __KERNEL__ */
