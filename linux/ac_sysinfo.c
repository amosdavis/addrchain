/*
 * ac_sysinfo.c — procfs reporting for addrchain kernel module
 *
 * Creates /proc/addrchain/ with entries:
 *   chain      — chain height, tip hash
 *   claims     — active claims with lease info
 *   subnets    — defined subnets
 *   vpn        — VPN tunnel status
 *   partitions — partition info
 *
 * Mitigates: K24 (proper cleanup on module exit)
 *
 * NOTE: Kernel-only. Compiled via Kbuild.
 */

#ifdef __KERNEL__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "ac_proto.h"
#include "ac_platform.h"
#include "ac_chain.h"
#include "ac_claims.h"
#include "ac_subnet.h"
#include "ac_partition.h"
#include "ac_vpn.h"
#include "ac_discover.h"

/* External globals from ac_main.c */
extern ac_block_t          *ac_chain;
extern uint32_t             ac_chain_len;
extern ac_mutex_t           ac_chain_lock;
extern ac_claim_store_t     ac_claims;
extern ac_subnet_store_t    ac_subnets;
extern ac_partition_store_t ac_parts;
extern ac_vpn_store_t       ac_vpns;
extern ac_discover_state_t  ac_disc;

static struct proc_dir_entry *ac_proc_dir;

/* ================================================================== */
/*  /proc/addrchain/chain                                              */
/* ================================================================== */

static int ac_proc_chain_show(struct seq_file *m, void *v)
{
    (void)v;

    ac_mutex_lock(&ac_chain_lock);
    seq_printf(m, "chain_height: %u\n", ac_chain_len);
    if (ac_chain_len > 0) {
        ac_block_t *tip = &ac_chain[ac_chain_len - 1];
        int i;
        seq_printf(m, "tip_index: %u\n", tip->index);
        seq_printf(m, "tip_hash: ");
        for (i = 0; i < AC_HASH_LEN; i++)
            seq_printf(m, "%02x", tip->hash[i]);
        seq_printf(m, "\n");
        seq_printf(m, "tip_tx_count: %u\n", tip->tx_count);
    }
    ac_mutex_unlock(&ac_chain_lock);

    return 0;
}

static int ac_proc_chain_open(struct inode *inode, struct file *file)
{
    return single_open(file, ac_proc_chain_show, NULL);
}

static const struct proc_ops ac_proc_chain_ops = {
    .proc_open    = ac_proc_chain_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

/* ================================================================== */
/*  /proc/addrchain/claims                                             */
/* ================================================================== */

static int ac_proc_claims_show(struct seq_file *m, void *v)
{
    (void)v;
    seq_printf(m, "active_claims: %u\n", ac_claims_count(&ac_claims));
    return 0;
}

static int ac_proc_claims_open(struct inode *inode, struct file *file)
{
    return single_open(file, ac_proc_claims_show, NULL);
}

static const struct proc_ops ac_proc_claims_ops = {
    .proc_open    = ac_proc_claims_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

/* ================================================================== */
/*  /proc/addrchain/subnets                                            */
/* ================================================================== */

static int ac_proc_subnets_show(struct seq_file *m, void *v)
{
    (void)v;
    seq_printf(m, "active_subnets: %u\n", ac_subnet_count(&ac_subnets));
    seq_printf(m, "subnet_members: %u\n", ac_subnet_member_count(&ac_subnets));
    return 0;
}

static int ac_proc_subnets_open(struct inode *inode, struct file *file)
{
    return single_open(file, ac_proc_subnets_show, NULL);
}

static const struct proc_ops ac_proc_subnets_ops = {
    .proc_open    = ac_proc_subnets_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

/* ================================================================== */
/*  /proc/addrchain/vpn                                                */
/* ================================================================== */

static int ac_proc_vpn_show(struct seq_file *m, void *v)
{
    (void)v;
    seq_printf(m, "active_tunnels: %u\n", ac_vpn_count(&ac_vpns));
    return 0;
}

static int ac_proc_vpn_open(struct inode *inode, struct file *file)
{
    return single_open(file, ac_proc_vpn_show, NULL);
}

static const struct proc_ops ac_proc_vpn_ops = {
    .proc_open    = ac_proc_vpn_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

/* ================================================================== */
/*  /proc/addrchain/partitions                                         */
/* ================================================================== */

static int ac_proc_parts_show(struct seq_file *m, void *v)
{
    (void)v;
    seq_printf(m, "active_partitions: %u\n", ac_partition_count(&ac_parts));
    return 0;
}

static int ac_proc_parts_open(struct inode *inode, struct file *file)
{
    return single_open(file, ac_proc_parts_show, NULL);
}

static const struct proc_ops ac_proc_parts_ops = {
    .proc_open    = ac_proc_parts_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

/* ================================================================== */
/*  Init / Exit                                                        */
/* ================================================================== */

int ac_sysinfo_init(void)
{
    ac_proc_dir = proc_mkdir("addrchain", NULL);
    if (!ac_proc_dir) {
        pr_err("addrchain: failed to create /proc/addrchain\n");
        return -ENOMEM;
    }

    if (!proc_create("chain", 0444, ac_proc_dir, &ac_proc_chain_ops))
        goto fail;
    if (!proc_create("claims", 0444, ac_proc_dir, &ac_proc_claims_ops))
        goto fail;
    if (!proc_create("subnets", 0444, ac_proc_dir, &ac_proc_subnets_ops))
        goto fail;
    if (!proc_create("vpn", 0444, ac_proc_dir, &ac_proc_vpn_ops))
        goto fail;
    if (!proc_create("partitions", 0444, ac_proc_dir, &ac_proc_parts_ops))
        goto fail;

    pr_info("addrchain: /proc/addrchain/ created\n");
    return 0;

fail:
    /* K24: clean up partial creation */
    remove_proc_subtree("addrchain", NULL);
    ac_proc_dir = NULL;
    pr_err("addrchain: failed to create proc entries\n");
    return -ENOMEM;
}

void ac_sysinfo_exit(void)
{
    if (ac_proc_dir) {
        remove_proc_subtree("addrchain", NULL);
        ac_proc_dir = NULL;
        pr_info("addrchain: /proc/addrchain/ removed\n");
    }
}

#endif /* __KERNEL__ */
