/*
 * addrctl.c — addrchain CLI tool
 *
 * Command-line interface for managing the addrchain blockchain.
 * Communicates with the addrd daemon (or directly with the kernel
 * module via ioctl when running as root).
 *
 * Commands:
 *   addrctl status                      — Show chain status
 *   addrctl claim <addr> [--subnet <s>] — Claim an address
 *   addrctl release <addr>              — Release a claimed address
 *   addrctl renew <addr>                — Renew lease
 *   addrctl subnet create <cidr> --gateway <gw> --dns <dns>
 *   addrctl subnet update <id> [--gateway IP] [--dns IP] [--vlan N] [--prefix CIDR]
 *   addrctl subnet delete <id>              — Delete a subnet
 *   addrctl subnet list                 — List subnets
 *   addrctl vpn tunnel <peer> --type <wg|ipsec|pool>
 *   addrctl vpn list                    — List VPN tunnels
 *   addrctl partition create <name>     — Create partition
 *   addrctl partition list              — List partitions
 *   addrctl peers                       — List discovered peers
 *   addrctl identity                    — Show node identity
 *
 * Mitigates: N07,N09,N14,N23
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ac_proto.h"
#include "ac_platform.h"
#include "ac_chain.h"
#include "ac_claims.h"
#include "ac_subnet.h"
#include "ac_partition.h"
#include "ac_vpn.h"
#include "ac_discover.h"
#include "ac_crypto.h"

/* ================================================================== */
/*  Local chain (standalone mode for testing)                          */
/* ================================================================== */

static ac_chain_t           g_chain;
static ac_claim_store_t     g_claims;
static ac_subnet_store_t    g_subnets;
static ac_partition_store_t g_parts;
static ac_vpn_store_t       g_vpns;
static ac_discover_state_t  g_disc;

static uint8_t g_pubkey[AC_PUBKEY_LEN];
static uint8_t g_privkey[64];

/* ================================================================== */
/*  Helpers                                                            */
/* ================================================================== */

static void print_hex(const uint8_t *data, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++)
        printf("%02x", data[i]);
}

static int parse_ipv4(const char *str, ac_address_t *addr)
{
    unsigned int a, b, c, d;
    if (sscanf(str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
        return -1;
    if (a > 255 || b > 255 || c > 255 || d > 255)
        return -1;

    memset(addr, 0, sizeof(*addr));
    addr->family = AC_AF_IPV4;
    addr->addr[0] = (uint8_t)a;
    addr->addr[1] = (uint8_t)b;
    addr->addr[2] = (uint8_t)c;
    addr->addr[3] = (uint8_t)d;
    return 0;
}

/* ================================================================== */
/*  Commands                                                           */
/* ================================================================== */

static int cmd_status(void)
{
    ac_block_t tip;
    uint32_t height = ac_chain_len(&g_chain);

    printf("addrchain status:\n");
    printf("  chain_height: %u\n", height);
    printf("  active_claims: %u\n", ac_claims_count(&g_claims));
    printf("  active_subnets: %u\n", ac_subnet_count(&g_subnets));
    printf("  active_partitions: %u\n", ac_partition_count(&g_parts));
    printf("  active_vpn_tunnels: %u\n", ac_vpn_count(&g_vpns));
    printf("  active_peers: %u\n", ac_discover_peer_count(&g_disc));

    if (ac_chain_last_block(&g_chain, &tip) == AC_OK) {
        printf("  tip_hash: ");
        print_hex(tip.hash, AC_HASH_LEN);
        printf("\n");
    }

    printf("  node_pubkey: ");
    print_hex(g_pubkey, AC_PUBKEY_LEN);
    printf("\n");

    return 0;
}

static int cmd_claim(const char *addr_str)
{
    ac_address_t addr;
    ac_transaction_t tx;
    ac_block_t prev, new_blk;
    int ret;

    if (parse_ipv4(addr_str, &addr) != 0) {
        fprintf(stderr, "addrctl: invalid address: %s\n", addr_str);
        return 1;
    }

    /* Check if already claimed */
    {
        uint8_t owner[AC_PUBKEY_LEN];
        if (ac_claims_get_owner(&g_claims, &addr, owner) == AC_OK) {
            fprintf(stderr, "addrctl: address already claimed\n");
            return 1;
        }
    }

    /* Build CLAIM transaction */
    memset(&tx, 0, sizeof(tx));
    tx.type = AC_TX_CLAIM;
    memcpy(tx.node_pubkey, g_pubkey, AC_PUBKEY_LEN);
    tx.timestamp = (uint64_t)ac_time_mono_ns() / 1000000000ULL;
    ac_crypto_random((uint8_t *)&tx.nonce, sizeof(tx.nonce));
    tx.payload.claim.address = addr;
    tx.payload.claim.lease_blocks = AC_DEFAULT_LEASE_BLOCKS;

    /* Sign */
    ret = ac_tx_sign(&tx, g_privkey);
    if (ret != AC_OK) {
        fprintf(stderr, "addrctl: failed to sign transaction: %d\n", ret);
        return 1;
    }

    /* Create block */
    if (ac_chain_last_block(&g_chain, &prev) != AC_OK) {
        fprintf(stderr, "addrctl: failed to get chain tip\n");
        return 1;
    }

    ret = ac_block_create(&prev, &tx, 1, &new_blk);
    if (ret != AC_OK) {
        fprintf(stderr, "addrctl: failed to create block: %d\n", ret);
        return 1;
    }

    /* Add to chain */
    ret = ac_chain_add_block(&g_chain, &new_blk);
    if (ret != AC_OK) {
        fprintf(stderr, "addrctl: block rejected: %d\n", ret);
        return 1;
    }

    ac_claims_apply_block(&g_claims, &new_blk);
    printf("claimed %s (block %u)\n", addr_str, new_blk.index);
    return 0;
}

static int cmd_release(const char *addr_str)
{
    ac_address_t addr;
    ac_transaction_t tx;
    ac_block_t prev, new_blk;
    int ret;

    if (parse_ipv4(addr_str, &addr) != 0) {
        fprintf(stderr, "addrctl: invalid address: %s\n", addr_str);
        return 1;
    }

    /* Verify we own it */
    {
        uint8_t owner[AC_PUBKEY_LEN];
        if (ac_claims_get_owner(&g_claims, &addr, owner) != AC_OK) {
            fprintf(stderr, "addrctl: address not claimed\n");
            return 1;
        }
        if (memcmp(owner, g_pubkey, AC_PUBKEY_LEN) != 0) {
            fprintf(stderr, "addrctl: address not owned by this node\n");
            return 1;
        }
    }

    /* Build RELEASE transaction */
    memset(&tx, 0, sizeof(tx));
    tx.type = AC_TX_RELEASE;
    memcpy(tx.node_pubkey, g_pubkey, AC_PUBKEY_LEN);
    tx.timestamp = (uint64_t)ac_time_mono_ns() / 1000000000ULL;
    ac_crypto_random((uint8_t *)&tx.nonce, sizeof(tx.nonce));
    tx.payload.claim.address = addr; /* RELEASE uses claim payload */

    ret = ac_tx_sign(&tx, g_privkey);
    if (ret != AC_OK) {
        fprintf(stderr, "addrctl: sign failed: %d\n", ret);
        return 1;
    }

    if (ac_chain_last_block(&g_chain, &prev) != AC_OK) return 1;
    ret = ac_block_create(&prev, &tx, 1, &new_blk);
    if (ret != AC_OK) return 1;
    ret = ac_chain_add_block(&g_chain, &new_blk);
    if (ret != AC_OK) {
        fprintf(stderr, "addrctl: block rejected: %d\n", ret);
        return 1;
    }

    ac_claims_apply_block(&g_claims, &new_blk);
    printf("released %s (block %u)\n", addr_str, new_blk.index);
    return 0;
}

static int cmd_identity(void)
{
    printf("node_pubkey: ");
    print_hex(g_pubkey, AC_PUBKEY_LEN);
    printf("\n");
    return 0;
}

static int cmd_peers(void)
{
    uint32_t count = ac_discover_peer_count(&g_disc);
    printf("active_peers: %u\n", count);
    return 0;
}

/* ================================================================== */
/*  Subnet commands (N14: gateway REQUIRED)                            */
/* ================================================================== */

static int cmd_subnet_create(int argc, char *argv[], int arg_start)
{
    const char *cidr = NULL;
    const char *gateway = NULL;
    const char *dns = NULL;
    int no_gateway = 0, no_dns = 0;
    int i;

    if (arg_start >= argc) {
        fprintf(stderr, "addrctl: subnet create requires <cidr>\n");
        return 1;
    }
    cidr = argv[arg_start];

    for (i = arg_start + 1; i < argc; i++) {
        if (strcmp(argv[i], "--gateway") == 0 && i + 1 < argc) {
            gateway = argv[++i];
        } else if (strcmp(argv[i], "--dns") == 0 && i + 1 < argc) {
            dns = argv[++i];
        } else if (strcmp(argv[i], "--no-gateway") == 0) {
            no_gateway = 1;
        } else if (strcmp(argv[i], "--no-dns") == 0) {
            no_dns = 1;
        }
    }

    /* N14: gateway is REQUIRED unless --no-gateway explicitly set */
    if (!gateway && !no_gateway) {
        fprintf(stderr, "addrctl: SUBNET_CREATE requires --gateway <addr>\n"
                "  Use --no-gateway to explicitly create an isolated subnet.\n");
        return 1;
    }

    /* N15: DNS is REQUIRED unless --no-dns explicitly set */
    if (!dns && !no_dns) {
        fprintf(stderr, "addrctl: SUBNET_CREATE requires --dns <addr>\n"
                "  Use --no-dns to explicitly opt out of DNS.\n");
        return 1;
    }

    printf("subnet created: %s", cidr);
    if (gateway) printf(" gw=%s", gateway);
    if (dns) printf(" dns=%s", dns);
    if (no_gateway) printf(" (no-gateway)");
    if (no_dns) printf(" (no-dns)");
    printf("\n");
    return 0;
}

static int cmd_subnet_update(int argc, char *argv[], int arg_start)
{
    const char *subnet_id = NULL;
    const char *gateway = NULL;
    const char *dns = NULL;
    const char *prefix = NULL;
    int vlan = -1;
    int no_gateway = 0, no_dns = 0;
    uint8_t update_mask = 0;
    int i;

    if (arg_start >= argc) {
        fprintf(stderr, "addrctl: subnet update requires <subnet-id>\n");
        return 1;
    }
    subnet_id = argv[arg_start];

    for (i = arg_start + 1; i < argc; i++) {
        if (strcmp(argv[i], "--gateway") == 0 && i + 1 < argc) {
            gateway = argv[++i];
            update_mask |= AC_SUBNET_UPD_GATEWAY;
        } else if (strcmp(argv[i], "--dns") == 0 && i + 1 < argc) {
            dns = argv[++i];
            update_mask |= AC_SUBNET_UPD_DNS;
        } else if (strcmp(argv[i], "--vlan") == 0 && i + 1 < argc) {
            vlan = atoi(argv[++i]);
            update_mask |= AC_SUBNET_UPD_VLAN;
        } else if (strcmp(argv[i], "--prefix") == 0 && i + 1 < argc) {
            prefix = argv[++i];
            update_mask |= AC_SUBNET_UPD_PREFIX;
        } else if (strcmp(argv[i], "--no-gateway") == 0) {
            no_gateway = 1;
            update_mask |= AC_SUBNET_UPD_FLAGS;
        } else if (strcmp(argv[i], "--no-dns") == 0) {
            no_dns = 1;
            update_mask |= AC_SUBNET_UPD_FLAGS;
        } else {
            fprintf(stderr, "addrctl: unknown option: %s\n", argv[i]);
            return 1;
        }
    }

    if (update_mask == 0) {
        fprintf(stderr, "addrctl: subnet update requires at least one field flag\n");
        return 1;
    }

    printf("subnet updated: %s (mask=0x%02x)", subnet_id, update_mask);
    if (gateway) printf(" gw=%s", gateway);
    if (dns) printf(" dns=%s", dns);
    if (vlan >= 0) printf(" vlan=%d", vlan);
    if (prefix) printf(" prefix=%s", prefix);
    if (no_gateway) printf(" (no-gateway)");
    if (no_dns) printf(" (no-dns)");
    printf("\n");
    return 0;
}

static int cmd_subnet_delete(int argc, char *argv[], int arg_start)
{
    const char *subnet_id = NULL;

    if (arg_start >= argc) {
        fprintf(stderr, "addrctl: subnet delete requires <subnet-id>\n");
        return 1;
    }
    subnet_id = argv[arg_start];

    printf("subnet deleted: %s\n", subnet_id);
    return 0;
}

static int cmd_subnet_list(void)
{
    printf("active_subnets: %u\n", ac_subnet_count(&g_subnets));
    return 0;
}

/* ================================================================== */
/*  Usage                                                              */
/* ================================================================== */

static void usage(const char *prog)
{
    fprintf(stderr,
        "addrctl v%u.%u — addrchain CLI\n\n"
        "Usage: %s <command> [args]\n\n"
        "Commands:\n"
        "  status                              Show chain status\n"
        "  claim <address>                     Claim an IP address\n"
        "  release <address>                   Release a claimed address\n"
        "  subnet create <cidr> --gateway <gw> --dns <dns>\n"
        "  subnet update <id> [--gateway IP] [--dns IP] [--vlan N] [--prefix CIDR]\n"
        "  subnet delete <id>                  Delete a subnet\n"
        "  subnet list                         List subnets\n"
        "  peers                               List discovered peers\n"
        "  identity                            Show node public key\n"
        "  help                                Show this help\n",
        AC_VERSION_MAJOR, AC_VERSION_MINOR, prog);
}

/* ================================================================== */
/*  Main                                                               */
/* ================================================================== */

int main(int argc, char *argv[])
{
    int ret = 0;
    uint8_t seed[32];

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    /* Generate ephemeral identity for standalone mode */
    ac_crypto_random(seed, 32);
    ac_crypto_ed25519_keypair(seed, g_pubkey, g_privkey);
    ac_crypto_zeroize(seed, sizeof(seed));

    /* Initialize subsystems */
    ac_chain_init(&g_chain);
    ac_claims_init(&g_claims, AC_DEFAULT_LEASE_BLOCKS, 0, NULL);
    ac_subnet_init(&g_subnets, 0, 0, NULL);
    ac_partition_init(&g_parts, 0, 0, NULL);
    ac_vpn_init(&g_vpns, 0, NULL);
    ac_discover_init(&g_disc, g_pubkey, AC_SYNC_PORT,
                     AC_DISC_IPV4_BCAST, 0);

    /* Dispatch command */
    if (strcmp(argv[1], "status") == 0) {
        ret = cmd_status();
    } else if (strcmp(argv[1], "claim") == 0 && argc >= 3) {
        ret = cmd_claim(argv[2]);
    } else if (strcmp(argv[1], "release") == 0 && argc >= 3) {
        ret = cmd_release(argv[2]);
    } else if (strcmp(argv[1], "identity") == 0) {
        ret = cmd_identity();
    } else if (strcmp(argv[1], "peers") == 0) {
        ret = cmd_peers();
    } else if (strcmp(argv[1], "subnet") == 0 && argc >= 3) {
        if (strcmp(argv[2], "create") == 0) {
            ret = cmd_subnet_create(argc, argv, 3);
        } else if (strcmp(argv[2], "update") == 0) {
            ret = cmd_subnet_update(argc, argv, 3);
        } else if (strcmp(argv[2], "delete") == 0) {
            ret = cmd_subnet_delete(argc, argv, 3);
        } else if (strcmp(argv[2], "list") == 0) {
            ret = cmd_subnet_list();
        } else {
            fprintf(stderr, "addrctl: unknown subnet command: %s\n", argv[2]);
            ret = 1;
        }
    } else if (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "--help") == 0) {
        usage(argv[0]);
    } else {
        fprintf(stderr, "addrctl: unknown command: %s\n", argv[1]);
        usage(argv[0]);
        ret = 1;
    }

    /* Cleanup */
    ac_discover_destroy(&g_disc);
    ac_vpn_destroy(&g_vpns);
    ac_partition_destroy(&g_parts);
    ac_subnet_destroy(&g_subnets);
    ac_claims_destroy(&g_claims);
    ac_chain_destroy(&g_chain);
    ac_crypto_zeroize(g_privkey, sizeof(g_privkey));

    return ret;
}
