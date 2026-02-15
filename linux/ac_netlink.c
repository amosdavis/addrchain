/*
 * ac_netlink.c — Netlink message handling for addrchain kernel module
 *
 * Defines ADDRCHAIN_CMD_* commands and handlers for daemon communication.
 * Uses Generic Netlink (genetlink) for structured message passing.
 *
 * Mitigates: K12,K13,K15,K39
 *
 * NOTE: Kernel-only. Compiled via Kbuild.
 */

#ifdef __KERNEL__

#include <linux/module.h>
#include <linux/kernel.h>
#include <net/genetlink.h>

#include "ac_proto.h"
#include "ac_platform.h"

/* ================================================================== */
/*  Generic Netlink family definition                                  */
/* ================================================================== */

/* Netlink command IDs */
enum {
    ADDRCHAIN_CMD_UNSPEC = 0,
    ADDRCHAIN_CMD_STATUS,       /* query chain status */
    ADDRCHAIN_CMD_ADD_BLOCK,    /* daemon submits a new block */
    ADDRCHAIN_CMD_GET_CHAIN,    /* request chain segment */
    ADDRCHAIN_CMD_CLAIM,        /* request address claim */
    ADDRCHAIN_CMD_RELEASE,      /* request address release */
    ADDRCHAIN_CMD_SUBNET_CREATE,/* create a subnet */
    ADDRCHAIN_CMD_SUBNET_LIST,  /* list subnets */
    ADDRCHAIN_CMD_HEARTBEAT,    /* daemon heartbeat (K39) */
    __ADDRCHAIN_CMD_MAX,
};
#define ADDRCHAIN_CMD_MAX (__ADDRCHAIN_CMD_MAX - 1)

/* Netlink attribute IDs */
enum {
    ADDRCHAIN_ATTR_UNSPEC = 0,
    ADDRCHAIN_ATTR_BLOCK,       /* binary: ac_block_t */
    ADDRCHAIN_ATTR_HEIGHT,      /* u32: chain height */
    ADDRCHAIN_ATTR_CLAIM_COUNT, /* u32 */
    ADDRCHAIN_ATTR_SUBNET_COUNT,/* u32 */
    ADDRCHAIN_ATTR_VERSION,     /* u16 */
    ADDRCHAIN_ATTR_ADDRESS,     /* binary: ac_address_t */
    ADDRCHAIN_ATTR_PUBKEY,      /* binary: 32 bytes */
    ADDRCHAIN_ATTR_SUBNET_ID,   /* string: subnet name */
    ADDRCHAIN_ATTR_SEQ,         /* u32: sequence number for sync (K39) */
    __ADDRCHAIN_ATTR_MAX,
};
#define ADDRCHAIN_ATTR_MAX (__ADDRCHAIN_ATTR_MAX - 1)

/* Attribute policy — strict validation (K15) */
static const struct nla_policy ac_nl_policy[ADDRCHAIN_ATTR_MAX + 1] = {
    [ADDRCHAIN_ATTR_BLOCK]       = { .type = NLA_BINARY,
                                     .len  = sizeof(ac_block_t) },
    [ADDRCHAIN_ATTR_HEIGHT]      = { .type = NLA_U32 },
    [ADDRCHAIN_ATTR_CLAIM_COUNT] = { .type = NLA_U32 },
    [ADDRCHAIN_ATTR_SUBNET_COUNT]= { .type = NLA_U32 },
    [ADDRCHAIN_ATTR_VERSION]     = { .type = NLA_U16 },
    [ADDRCHAIN_ATTR_ADDRESS]     = { .type = NLA_BINARY,
                                     .len  = sizeof(ac_address_t) },
    [ADDRCHAIN_ATTR_PUBKEY]      = { .type = NLA_BINARY,
                                     .len  = AC_PUBKEY_LEN },
    [ADDRCHAIN_ATTR_SUBNET_ID]   = { .type = NLA_NUL_STRING,
                                     .len  = AC_SUBNET_ID_LEN },
    [ADDRCHAIN_ATTR_SEQ]         = { .type = NLA_U32 },
};

/* ================================================================== */
/*  Command handlers                                                   */
/* ================================================================== */

/* External globals from ac_main.c */
extern ac_block_t      *ac_chain;
extern uint32_t         ac_chain_len;
extern ac_mutex_t       ac_chain_lock;

static int ac_nl_cmd_status(struct sk_buff *skb, struct genl_info *info)
{
    struct sk_buff *reply;
    void *hdr;

    (void)info;

    reply = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (!reply)
        return -ENOMEM;

    hdr = genlmsg_put_reply(reply, info, &ac_nl_family, 0,
                            ADDRCHAIN_CMD_STATUS);
    if (!hdr) {
        nlmsg_free(reply);
        return -EMSGSIZE;
    }

    ac_mutex_lock(&ac_chain_lock);
    nla_put_u32(reply, ADDRCHAIN_ATTR_HEIGHT, ac_chain_len);
    ac_mutex_unlock(&ac_chain_lock);

    nla_put_u16(reply, ADDRCHAIN_ATTR_VERSION, AC_VERSION);

    genlmsg_end(reply, hdr);
    return genlmsg_reply(reply, info);
}

static int ac_nl_cmd_heartbeat(struct sk_buff *skb, struct genl_info *info)
{
    /* K39: daemon heartbeat — just acknowledge */
    (void)skb;
    (void)info;
    pr_debug("addrchain: daemon heartbeat received\n");
    return 0;
}

/* ================================================================== */
/*  Generic Netlink operations                                         */
/* ================================================================== */

static const struct genl_small_ops ac_nl_ops[] = {
    {
        .cmd    = ADDRCHAIN_CMD_STATUS,
        .doit   = ac_nl_cmd_status,
    },
    {
        .cmd    = ADDRCHAIN_CMD_HEARTBEAT,
        .doit   = ac_nl_cmd_heartbeat,
    },
};

static struct genl_family ac_nl_family = {
    .name       = "ADDRCHAIN",
    .version    = 1,
    .maxattr    = ADDRCHAIN_ATTR_MAX,
    .policy     = ac_nl_policy,
    .module     = THIS_MODULE,
    .small_ops  = ac_nl_ops,
    .n_small_ops = ARRAY_SIZE(ac_nl_ops),
};

/* ================================================================== */
/*  Init / Exit                                                        */
/* ================================================================== */

int ac_netlink_init(void)
{
    int ret;

    ret = genl_register_family(&ac_nl_family);
    if (ret) {
        pr_err("addrchain: failed to register netlink family: %d\n", ret);
        return ret;
    }

    pr_info("addrchain: netlink family 'ADDRCHAIN' registered\n");
    return 0;
}

void ac_netlink_exit(void)
{
    genl_unregister_family(&ac_nl_family);
    pr_info("addrchain: netlink family unregistered\n");
}

#endif /* __KERNEL__ */
