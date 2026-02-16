/*
 * ac_dag_integration_test.c — Integration tests verifying the DAG dependency
 * graph when wired into the claim, subnet, VPN, and partition modules.
 *
 * Build:
 *   gcc -Wall -Wextra -Werror -std=c11 -O2 \
 *       -o tests/ac_dag_integration_test.exe \
 *       tests/ac_dag_integration_test.c \
 *       common/ac_dag.c common/ac_chain.c common/ac_claims.c \
 *       common/ac_crypto.c common/ac_subnet.c common/ac_partition.c \
 *       common/ac_vpn.c common/ac_discover.c common/ac_hashmap.c \
 *       common/ac_userspace_platform.c \
 *       -I common -ladvapi32
 */

#include "ac_dag.h"
#include "ac_claims.h"
#include "ac_subnet.h"
#include "ac_partition.h"
#include "ac_vpn.h"
#include "ac_chain.h"
#include "ac_crypto.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ── Test harness ────────────────────────────────────────────────────── */

static int test_count;
static int pass_count;
static int fail_count;

#define TEST(name)          do { test_count++; \
    printf("  [%02d] %-55s ", test_count, (name)); } while (0)
#define PASS()              do { pass_count++; printf("PASS\n"); } while (0)
#define FAIL(msg)           do { fail_count++; printf("FAIL: %s\n", (msg)); } while (0)
#define ASSERT_EQ(a, b, msg)  do { if ((a) != (b)) { FAIL(msg); return; } } while (0)
#define ASSERT_NE(a, b, msg)  do { if ((a) == (b)) { FAIL(msg); return; } } while (0)
#define ASSERT_OK(rc, msg)    ASSERT_EQ((rc), AC_OK, (msg))

/* ── Helpers ─────────────────────────────────────────────────────────── */

static void make_keypair(uint8_t pub[AC_PUBKEY_LEN], uint8_t priv[64])
{
    uint8_t seed[32];
    ac_crypto_random(seed, sizeof(seed));
    ac_crypto_ed25519_keypair(seed, pub, priv);
}

static void set_ipv4_addr(ac_address_t *addr, uint8_t a, uint8_t b,
                          uint8_t c, uint8_t d, uint8_t prefix)
{
    memset(addr, 0, sizeof(*addr));
    addr->family = AC_AF_IPV4;
    addr->addr[0] = a;
    addr->addr[1] = b;
    addr->addr[2] = c;
    addr->addr[3] = d;
    addr->prefix_len = prefix;
}

static void make_ipv4_addr(ac_address_t *addr, uint8_t a, uint8_t b,
                           uint8_t c, uint8_t d)
{
    set_ipv4_addr(addr, a, b, c, d, 24);
}

static void pad_subnet_id(uint8_t out[AC_SUBNET_ID_LEN], const char *id)
{
    memset(out, 0, AC_SUBNET_ID_LEN);
    if (id) {
        size_t len = strlen(id);
        if (len >= AC_SUBNET_ID_LEN)
            len = AC_SUBNET_ID_LEN - 1;
        memcpy(out, id, len);
    }
}

static void pad_dag_id(uint8_t out[AC_MAX_ADDR_LEN], const char *id, size_t id_max)
{
    memset(out, 0, AC_MAX_ADDR_LEN);
    if (id) {
        size_t len = strlen(id);
        if (len >= id_max)
            len = id_max - 1;
        memcpy(out, id, len);
    }
}

/* Build a SUBNET_CREATE block */
static void make_subnet_create_block(ac_block_t *blk,
                                     const ac_block_t *prev,
                                     const uint8_t pub[AC_PUBKEY_LEN],
                                     const uint8_t priv[64],
                                     const char *subnet_id,
                                     uint8_t net_a, uint8_t net_b,
                                     uint8_t net_c, uint8_t net_d,
                                     uint8_t prefix_len,
                                     uint8_t gw_last_byte,
                                     uint8_t flags,
                                     uint32_t nonce)
{
    ac_transaction_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.type = AC_TX_SUBNET_CREATE;
    memcpy(tx.node_pubkey, pub, AC_PUBKEY_LEN);
    tx.timestamp = ac_time_unix_sec();
    tx.nonce = nonce;

    {
        ac_tx_subnet_create_t *sc = &tx.payload.subnet_create;
        memset(sc, 0, sizeof(*sc));
        if (subnet_id) {
            size_t len = strlen(subnet_id);
            if (len >= AC_SUBNET_ID_LEN)
                len = AC_SUBNET_ID_LEN - 1;
            memcpy(sc->subnet_id, subnet_id, len);
        }
        set_ipv4_addr(&sc->prefix, net_a, net_b, net_c, net_d, prefix_len);
        sc->flags = flags;

        if (!(flags & AC_SUBNET_FLAG_NO_GATEWAY))
            set_ipv4_addr(&sc->gateway, net_a, net_b, net_c, gw_last_byte,
                          prefix_len);
        if (!(flags & AC_SUBNET_FLAG_NO_DNS)) {
            set_ipv4_addr(&sc->dns[0], 8, 8, 8, 8, 32);
            sc->dns_count = 1;
        }
    }

    ac_tx_sign(&tx, priv);
    ac_block_create(prev, &tx, 1, blk);
}

/* Build a SUBNET_DELETE block */
static void make_subnet_delete_block(ac_block_t *blk,
                                     const ac_block_t *prev,
                                     const uint8_t pub[AC_PUBKEY_LEN],
                                     const uint8_t priv[64],
                                     const char *subnet_id,
                                     uint32_t nonce)
{
    ac_transaction_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.type = AC_TX_SUBNET_DELETE;
    memcpy(tx.node_pubkey, pub, AC_PUBKEY_LEN);
    tx.timestamp = ac_time_unix_sec();
    tx.nonce = nonce;

    {
        ac_tx_subnet_delete_t *sd = &tx.payload.subnet_delete;
        size_t len = strlen(subnet_id);
        if (len >= AC_SUBNET_ID_LEN)
            len = AC_SUBNET_ID_LEN - 1;
        memcpy(sd->subnet_id, subnet_id, len);
    }

    ac_tx_sign(&tx, priv);
    ac_block_create(prev, &tx, 1, blk);
}

/* Build a CLAIM or RELEASE block with a subnet_id wired in */
static void make_claim_block_with_subnet(ac_block_t *blk,
                                         const ac_block_t *prev,
                                         const uint8_t pub[AC_PUBKEY_LEN],
                                         const uint8_t priv[64],
                                         uint8_t tx_type,
                                         uint8_t ip_d,
                                         const char *subnet_id,
                                         uint32_t lease_blocks,
                                         uint32_t nonce)
{
    ac_transaction_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.type = tx_type;
    memcpy(tx.node_pubkey, pub, AC_PUBKEY_LEN);
    tx.timestamp = ac_time_unix_sec();
    tx.nonce = nonce;
    make_ipv4_addr(&tx.payload.claim.address, 10, 0, 0, ip_d);
    tx.payload.claim.lease_blocks = lease_blocks;
    if (subnet_id)
        pad_subnet_id(tx.payload.claim.subnet_id, subnet_id);

    ac_tx_sign(&tx, priv);
    ac_block_create(prev, &tx, 1, blk);
}

/* Build a PARTITION block */
static void make_partition_block(ac_block_t *blk,
                                 const ac_block_t *prev,
                                 const uint8_t pub[AC_PUBKEY_LEN],
                                 const uint8_t priv[64],
                                 const char *part_id,
                                 uint8_t action,
                                 const char *target_subnet,
                                 const char *target_partition,
                                 uint16_t vlan_id,
                                 uint32_t nonce)
{
    ac_transaction_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.type = AC_TX_PARTITION;
    memcpy(tx.node_pubkey, pub, AC_PUBKEY_LEN);
    tx.timestamp = ac_time_unix_sec();
    tx.nonce = nonce;

    {
        ac_tx_partition_t *pt = &tx.payload.partition;
        if (part_id) {
            size_t len = strlen(part_id);
            if (len >= AC_PARTITION_ID_LEN)
                len = AC_PARTITION_ID_LEN - 1;
            memcpy(pt->partition_id, part_id, len);
        }
        pt->action = action;
        pt->vlan_id = vlan_id;

        if (target_subnet) {
            size_t len = strlen(target_subnet);
            if (len >= AC_SUBNET_ID_LEN)
                len = AC_SUBNET_ID_LEN - 1;
            memcpy(pt->target_subnet_id, target_subnet, len);
        }
        if (target_partition) {
            size_t len = strlen(target_partition);
            if (len >= AC_PARTITION_ID_LEN)
                len = AC_PARTITION_ID_LEN - 1;
            memcpy(pt->target_partition_id, target_partition, len);
        }
    }

    ac_tx_sign(&tx, priv);
    ac_block_create(prev, &tx, 1, blk);
}

/*
 * Build a synthetic block at a specific index. This lets us advance
 * the chain height to trigger lease expiry without building many
 * intermediate blocks.
 */
static void make_block_at_index(ac_block_t *blk,
                                const ac_block_t *prev,
                                uint32_t target_index)
{
    ac_block_create(prev, NULL, 0, blk);
    blk->index = target_index;
}

/* ── Dependency Chain Tests ──────────────────────────────────────────── */

/*
 * 1. delete_subnet_with_active_claims_fails
 *    Create subnet, claim in that subnet (DAG wired), try DELETE the subnet.
 *    Must fail with AC_ERR_EXIST because the claim depends on the subnet.
 */
static void test_delete_subnet_with_active_claims_fails(void)
{
    ac_dag_t dag;
    ac_claim_store_t cs;
    ac_subnet_store_t ss;
    ac_block_t genesis, blk_subnet, blk_claim, blk_del;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    int rc;
    TEST("delete subnet with active claims fails");

    ac_dag_init(&dag);
    ac_claims_init(&cs, 1000, 0, &dag);
    ac_subnet_init(&ss, 0, 0, &dag);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    /* Create subnet "net-a" (10.0.0.0/24) */
    make_subnet_create_block(&blk_subnet, &genesis, pub, priv,
                             "net-a", 10, 0, 0, 0, 24, 1, 0, 1);
    ASSERT_OK(ac_subnet_validate_block(&ss, &blk_subnet), "subnet create validate");
    ASSERT_OK(ac_subnet_apply_block(&ss, &blk_subnet), "subnet create apply");

    /* Claim 10.0.0.1 in subnet "net-a" */
    make_claim_block_with_subnet(&blk_claim, &blk_subnet, pub, priv,
                                 AC_TX_CLAIM, 1, "net-a", 0, 2);
    ASSERT_OK(ac_claims_validate_block(&cs, &blk_claim), "claim validate");
    ASSERT_OK(ac_claims_apply_block(&cs, &blk_claim), "claim apply");

    /* Try to delete subnet — should fail because claim depends on it */
    make_subnet_delete_block(&blk_del, &blk_claim, pub, priv, "net-a", 3);
    rc = ac_subnet_validate_block(&ss, &blk_del);
    ASSERT_EQ(rc, AC_ERR_EXIST, "delete should fail with AC_ERR_EXIST");

    ac_claims_destroy(&cs);
    ac_subnet_destroy(&ss);
    ac_dag_destroy(&dag);
    PASS();
}

/*
 * 2. delete_subnet_after_release_succeeds
 *    Create subnet, CLAIM, RELEASE the claim, then DELETE subnet.
 *    Should succeed since no claims remain.
 */
static void test_delete_subnet_after_release_succeeds(void)
{
    ac_dag_t dag;
    ac_claim_store_t cs;
    ac_subnet_store_t ss;
    ac_block_t genesis, blk_subnet, blk_claim, blk_release, blk_del;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    TEST("delete subnet after release succeeds");

    ac_dag_init(&dag);
    ac_claims_init(&cs, 1000, 0, &dag);
    ac_subnet_init(&ss, 0, 0, &dag);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    /* Create subnet */
    make_subnet_create_block(&blk_subnet, &genesis, pub, priv,
                             "net-b", 10, 1, 0, 0, 24, 1, 0, 1);
    ASSERT_OK(ac_subnet_validate_block(&ss, &blk_subnet), "subnet create validate");
    ASSERT_OK(ac_subnet_apply_block(&ss, &blk_subnet), "subnet create apply");

    /* Claim 10.1.0.1 */
    make_claim_block_with_subnet(&blk_claim, &blk_subnet, pub, priv,
                                 AC_TX_CLAIM, 1, "net-b", 0, 2);
    ASSERT_OK(ac_claims_validate_block(&cs, &blk_claim), "claim validate");
    ASSERT_OK(ac_claims_apply_block(&cs, &blk_claim), "claim apply");
    ASSERT_EQ(ac_claims_count(&cs), 1, "should have 1 claim");

    /* Release the claim */
    make_claim_block_with_subnet(&blk_release, &blk_claim, pub, priv,
                                 AC_TX_RELEASE, 1, "net-b", 0, 3);
    ASSERT_OK(ac_claims_validate_block(&cs, &blk_release), "release validate");
    ASSERT_OK(ac_claims_apply_block(&cs, &blk_release), "release apply");
    ASSERT_EQ(ac_claims_count(&cs), 0, "should have 0 claims");

    /* Delete subnet — should succeed now */
    make_subnet_delete_block(&blk_del, &blk_release, pub, priv, "net-b", 4);
    ASSERT_OK(ac_subnet_validate_block(&ss, &blk_del), "delete validate should pass");
    ASSERT_OK(ac_subnet_apply_block(&ss, &blk_del), "delete apply should pass");
    ASSERT_EQ(ac_subnet_count(&ss), 0, "subnet count should be 0");

    ac_claims_destroy(&cs);
    ac_subnet_destroy(&ss);
    ac_dag_destroy(&dag);
    PASS();
}

/*
 * 3. delete_subnet_after_lease_expiry_succeeds
 *    Create subnet, CLAIM with short lease (5 blocks), apply block at
 *    index=100 (triggers expiry), then DELETE subnet. Should succeed.
 */
static void test_delete_subnet_after_lease_expiry_succeeds(void)
{
    ac_dag_t dag;
    ac_claim_store_t cs;
    ac_subnet_store_t ss;
    ac_block_t genesis, blk_subnet, blk_claim, blk_expire, blk_del;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    TEST("delete subnet after lease expiry succeeds");

    ac_dag_init(&dag);
    ac_claims_init(&cs, 1000, 0, &dag);
    ac_subnet_init(&ss, 0, 0, &dag);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    /* Create subnet */
    make_subnet_create_block(&blk_subnet, &genesis, pub, priv,
                             "net-c", 10, 2, 0, 0, 24, 1, 0, 1);
    ASSERT_OK(ac_subnet_validate_block(&ss, &blk_subnet), "subnet create validate");
    ASSERT_OK(ac_subnet_apply_block(&ss, &blk_subnet), "subnet create apply");

    /* Claim with short lease of 5 blocks */
    make_claim_block_with_subnet(&blk_claim, &blk_subnet, pub, priv,
                                 AC_TX_CLAIM, 1, "net-c", 5, 2);
    ASSERT_OK(ac_claims_validate_block(&cs, &blk_claim), "claim validate");
    ASSERT_OK(ac_claims_apply_block(&cs, &blk_claim), "claim apply");
    ASSERT_EQ(ac_claims_count(&cs), 1, "should have 1 claim");

    /* Advance to block 100 — well past lease expiry of block ~2 + 5 = ~7 */
    make_block_at_index(&blk_expire, &blk_claim, 100);
    ASSERT_OK(ac_claims_apply_block(&cs, &blk_expire), "apply empty block for expiry");
    ASSERT_EQ(ac_claims_count(&cs), 0, "claim should have expired");

    /* Delete subnet — should succeed since claim expired */
    make_subnet_delete_block(&blk_del, &blk_expire, pub, priv, "net-c", 3);
    ASSERT_OK(ac_subnet_validate_block(&ss, &blk_del), "delete validate should pass");
    ASSERT_OK(ac_subnet_apply_block(&ss, &blk_del), "delete apply should pass");
    ASSERT_EQ(ac_subnet_count(&ss), 0, "subnet count should be 0");

    ac_claims_destroy(&cs);
    ac_subnet_destroy(&ss);
    ac_dag_destroy(&dag);
    PASS();
}

/*
 * 4. cascade_validation
 *    Create partition → add subnet to partition → claim in subnet.
 *    Try delete subnet (fail, has claims).
 *    Try delete partition (the partition apply marks it inactive but the DAG
 *    node persists because ac_dag_remove_node refuses when children exist).
 *    Release claim → delete subnet succeeds → then delete partition
 *    succeeds because the subnet DAG node is gone.
 */
static void test_cascade_validation(void)
{
    ac_dag_t dag;
    ac_claim_store_t cs;
    ac_subnet_store_t ss;
    ac_partition_store_t ps;
    ac_block_t genesis, blk1, blk2, blk3, blk4, blk5, blk6, blk7;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    uint8_t dag_part_id[AC_MAX_ADDR_LEN];
    uint8_t dag_sub_id[AC_MAX_ADDR_LEN];
    int rc;
    TEST("cascade validation");

    ac_dag_init(&dag);
    ac_claims_init(&cs, 1000, 0, &dag);
    ac_subnet_init(&ss, 0, 0, &dag);
    ac_partition_init(&ps, 0, 0, &dag);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    /* Step 1: Create partition "prod" */
    make_partition_block(&blk1, &genesis, pub, priv, "prod",
                         AC_PART_CREATE, NULL, NULL, 100, 1);
    ASSERT_OK(ac_partition_validate_block(&ps, &blk1), "partition create validate");
    ASSERT_OK(ac_partition_apply_block(&ps, &blk1), "partition create apply");

    /* Step 2: Create subnet "cas-net" */
    make_subnet_create_block(&blk2, &blk1, pub, priv,
                             "cas-net", 10, 3, 0, 0, 24, 1, 0, 2);
    ASSERT_OK(ac_subnet_validate_block(&ss, &blk2), "subnet create validate");
    ASSERT_OK(ac_subnet_apply_block(&ss, &blk2), "subnet create apply");

    /* Step 3: Add subnet to partition (creates partition→subnet DAG edge) */
    make_partition_block(&blk3, &blk2, pub, priv, "prod",
                         AC_PART_ADD_SUBNET, "cas-net", NULL, 100, 3);
    ASSERT_OK(ac_partition_validate_block(&ps, &blk3), "add subnet validate");
    ASSERT_OK(ac_partition_apply_block(&ps, &blk3), "add subnet apply");

    /* Step 4: Claim 10.3.0.1 in subnet */
    make_claim_block_with_subnet(&blk4, &blk3, pub, priv,
                                 AC_TX_CLAIM, 1, "cas-net", 0, 4);
    ASSERT_OK(ac_claims_validate_block(&cs, &blk4), "claim validate");
    ASSERT_OK(ac_claims_apply_block(&cs, &blk4), "claim apply");

    /* Step 5: Try delete subnet — should fail (has claims) */
    {
        ac_block_t try_del;
        make_subnet_delete_block(&try_del, &blk4, pub, priv, "cas-net", 5);
        rc = ac_subnet_validate_block(&ss, &try_del);
        ASSERT_EQ(rc, AC_ERR_EXIST, "subnet delete should fail (has claims)");
    }

    /* Step 6: Verify partition DAG node has dependents (the subnet) */
    pad_dag_id(dag_part_id, "prod", AC_PARTITION_ID_LEN);
    ASSERT_EQ(ac_dag_has_dependents(&dag, AC_RES_PARTITION, dag_part_id), 1,
              "partition should have dependents");

    /* Step 7: Release claim */
    make_claim_block_with_subnet(&blk5, &blk4, pub, priv,
                                 AC_TX_RELEASE, 1, "cas-net", 0, 5);
    ASSERT_OK(ac_claims_validate_block(&cs, &blk5), "release validate");
    ASSERT_OK(ac_claims_apply_block(&cs, &blk5), "release apply");

    /* Step 8: Delete subnet — should succeed now */
    make_subnet_delete_block(&blk6, &blk5, pub, priv, "cas-net", 6);
    ASSERT_OK(ac_subnet_validate_block(&ss, &blk6), "subnet delete validate");
    ASSERT_OK(ac_subnet_apply_block(&ss, &blk6), "subnet delete apply");

    /* Step 9: Partition no longer has dependents */
    pad_dag_id(dag_sub_id, "cas-net", AC_SUBNET_ID_LEN);
    ASSERT_EQ(ac_dag_has_dependents(&dag, AC_RES_PARTITION, dag_part_id), 0,
              "partition should have no dependents after subnet removal");

    /* Step 10: Delete partition — should succeed */
    make_partition_block(&blk7, &blk6, pub, priv, "prod",
                         AC_PART_DELETE, NULL, NULL, 100, 7);
    ASSERT_OK(ac_partition_validate_block(&ps, &blk7), "partition delete validate");
    ASSERT_OK(ac_partition_apply_block(&ps, &blk7), "partition delete apply");

    ac_claims_destroy(&cs);
    ac_subnet_destroy(&ss);
    ac_partition_destroy(&ps);
    ac_dag_destroy(&dag);
    PASS();
}

/* ── Node Tracking Tests ─────────────────────────────────────────────── */

/*
 * 5. dag_tracks_claim_nodes
 *    Create subnet + claim. Check DAG has claim node. Release claim.
 *    Check DAG no longer has claim node.
 */
static void test_dag_tracks_claim_nodes(void)
{
    ac_dag_t dag;
    ac_claim_store_t cs;
    ac_subnet_store_t ss;
    ac_block_t genesis, blk_subnet, blk_claim, blk_release;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    uint8_t claim_addr[AC_MAX_ADDR_LEN];
    int rc;
    TEST("DAG tracks claim nodes");

    ac_dag_init(&dag);
    ac_claims_init(&cs, 1000, 0, &dag);
    ac_subnet_init(&ss, 0, 0, &dag);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    /* Create subnet */
    make_subnet_create_block(&blk_subnet, &genesis, pub, priv,
                             "trk-net", 10, 4, 0, 0, 24, 1, 0, 1);
    ASSERT_OK(ac_subnet_validate_block(&ss, &blk_subnet), "subnet validate");
    ASSERT_OK(ac_subnet_apply_block(&ss, &blk_subnet), "subnet apply");

    /* Claim 10.4.0.1 */
    make_claim_block_with_subnet(&blk_claim, &blk_subnet, pub, priv,
                                 AC_TX_CLAIM, 1, "trk-net", 0, 2);
    ASSERT_OK(ac_claims_validate_block(&cs, &blk_claim), "claim validate");
    ASSERT_OK(ac_claims_apply_block(&cs, &blk_claim), "claim apply");

    /* Verify claim node exists: adding duplicate should fail.
       make_ipv4_addr produces address 10.0.0.1 regardless of subnet prefix. */
    memset(claim_addr, 0, AC_MAX_ADDR_LEN);
    claim_addr[0] = 10; claim_addr[1] = 0; claim_addr[2] = 0; claim_addr[3] = 1;
    rc = ac_dag_add_node(&dag, AC_RES_CLAIM, claim_addr);
    ASSERT_EQ(rc, AC_ERR_EXIST, "claim node should exist in DAG");

    /* Release claim */
    make_claim_block_with_subnet(&blk_release, &blk_claim, pub, priv,
                                 AC_TX_RELEASE, 1, "trk-net", 0, 3);
    ASSERT_OK(ac_claims_validate_block(&cs, &blk_release), "release validate");
    ASSERT_OK(ac_claims_apply_block(&cs, &blk_release), "release apply");

    /* Verify claim node is gone: adding it should succeed now */
    rc = ac_dag_add_node(&dag, AC_RES_CLAIM, claim_addr);
    ASSERT_OK(rc, "claim node should no longer exist in DAG");
    /* Clean up the node we just added */
    ac_dag_remove_node(&dag, AC_RES_CLAIM, claim_addr);

    ac_claims_destroy(&cs);
    ac_subnet_destroy(&ss);
    ac_dag_destroy(&dag);
    PASS();
}

/*
 * 6. dag_tracks_subnet_nodes
 *    Create subnet. Check DAG has subnet node. Delete subnet. Check DAG
 *    no longer has it.
 */
static void test_dag_tracks_subnet_nodes(void)
{
    ac_dag_t dag;
    ac_subnet_store_t ss;
    ac_block_t genesis, blk_create, blk_del;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    uint8_t dag_id[AC_MAX_ADDR_LEN];
    int rc;
    TEST("DAG tracks subnet nodes");

    ac_dag_init(&dag);
    ac_subnet_init(&ss, 0, 0, &dag);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    /* Create subnet */
    make_subnet_create_block(&blk_create, &genesis, pub, priv,
                             "sub-trk", 10, 5, 0, 0, 24, 1, 0, 1);
    ASSERT_OK(ac_subnet_validate_block(&ss, &blk_create), "subnet validate");
    ASSERT_OK(ac_subnet_apply_block(&ss, &blk_create), "subnet apply");

    /* Check DAG has subnet node: adding duplicate should fail */
    pad_dag_id(dag_id, "sub-trk", AC_SUBNET_ID_LEN);
    rc = ac_dag_add_node(&dag, AC_RES_SUBNET, dag_id);
    ASSERT_EQ(rc, AC_ERR_EXIST, "subnet node should exist in DAG");

    /* Delete subnet */
    make_subnet_delete_block(&blk_del, &blk_create, pub, priv, "sub-trk", 2);
    ASSERT_OK(ac_subnet_validate_block(&ss, &blk_del), "delete validate");
    ASSERT_OK(ac_subnet_apply_block(&ss, &blk_del), "delete apply");

    /* Check DAG no longer has subnet node */
    rc = ac_dag_add_node(&dag, AC_RES_SUBNET, dag_id);
    ASSERT_OK(rc, "subnet node should be gone from DAG");
    ac_dag_remove_node(&dag, AC_RES_SUBNET, dag_id);

    ac_subnet_destroy(&ss);
    ac_dag_destroy(&dag);
    PASS();
}

/* ── Edge Tests ──────────────────────────────────────────────────────── */

/*
 * 7. claim_to_subnet_edge
 *    Create subnet, CLAIM in subnet. Check ac_dag_has_dependents on the
 *    subnet returns true (the claim depends on it). ac_dag_dependent_count
 *    returns 1.
 */
static void test_claim_to_subnet_edge(void)
{
    ac_dag_t dag;
    ac_claim_store_t cs;
    ac_subnet_store_t ss;
    ac_block_t genesis, blk_subnet, blk_claim;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    uint8_t dag_id[AC_MAX_ADDR_LEN];
    TEST("claim to subnet edge");

    ac_dag_init(&dag);
    ac_claims_init(&cs, 1000, 0, &dag);
    ac_subnet_init(&ss, 0, 0, &dag);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    /* Create subnet */
    make_subnet_create_block(&blk_subnet, &genesis, pub, priv,
                             "edge-net", 10, 6, 0, 0, 24, 1, 0, 1);
    ASSERT_OK(ac_subnet_validate_block(&ss, &blk_subnet), "subnet validate");
    ASSERT_OK(ac_subnet_apply_block(&ss, &blk_subnet), "subnet apply");

    /* Subnet exists but no dependents yet */
    pad_dag_id(dag_id, "edge-net", AC_SUBNET_ID_LEN);
    ASSERT_EQ(ac_dag_has_dependents(&dag, AC_RES_SUBNET, dag_id), 0,
              "no dependents initially");
    ASSERT_EQ(ac_dag_dependent_count(&dag, AC_RES_SUBNET, dag_id), 0,
              "dependent count should be 0");

    /* Claim 10.6.0.1 */
    make_claim_block_with_subnet(&blk_claim, &blk_subnet, pub, priv,
                                 AC_TX_CLAIM, 1, "edge-net", 0, 2);
    ASSERT_OK(ac_claims_validate_block(&cs, &blk_claim), "claim validate");
    ASSERT_OK(ac_claims_apply_block(&cs, &blk_claim), "claim apply");

    /* Subnet should now have 1 dependent (the claim) */
    ASSERT_EQ(ac_dag_has_dependents(&dag, AC_RES_SUBNET, dag_id), 1,
              "subnet should have dependents");
    ASSERT_EQ(ac_dag_dependent_count(&dag, AC_RES_SUBNET, dag_id), 1,
              "dependent count should be 1");

    ac_claims_destroy(&cs);
    ac_subnet_destroy(&ss);
    ac_dag_destroy(&dag);
    PASS();
}

/*
 * 8. multiple_claims_in_subnet
 *    Create subnet, CLAIM 3 addresses. Dependent count = 3. Release one.
 *    Count = 2.
 */
static void test_multiple_claims_in_subnet(void)
{
    ac_dag_t dag;
    ac_claim_store_t cs;
    ac_subnet_store_t ss;
    ac_block_t genesis, blk_subnet, blk_c1, blk_c2, blk_c3, blk_rel;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    uint8_t dag_id[AC_MAX_ADDR_LEN];
    TEST("multiple claims in subnet");

    ac_dag_init(&dag);
    ac_claims_init(&cs, 1000, 0, &dag);
    ac_subnet_init(&ss, 0, 0, &dag);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    /* Create subnet */
    make_subnet_create_block(&blk_subnet, &genesis, pub, priv,
                             "multi-net", 10, 7, 0, 0, 24, 1, 0, 1);
    ASSERT_OK(ac_subnet_validate_block(&ss, &blk_subnet), "subnet validate");
    ASSERT_OK(ac_subnet_apply_block(&ss, &blk_subnet), "subnet apply");

    /* Claim 3 addresses: 10.7.0.1, 10.7.0.2, 10.7.0.3 */
    make_claim_block_with_subnet(&blk_c1, &blk_subnet, pub, priv,
                                 AC_TX_CLAIM, 1, "multi-net", 0, 2);
    ASSERT_OK(ac_claims_validate_block(&cs, &blk_c1), "claim 1 validate");
    ASSERT_OK(ac_claims_apply_block(&cs, &blk_c1), "claim 1 apply");

    make_claim_block_with_subnet(&blk_c2, &blk_c1, pub, priv,
                                 AC_TX_CLAIM, 2, "multi-net", 0, 3);
    ASSERT_OK(ac_claims_validate_block(&cs, &blk_c2), "claim 2 validate");
    ASSERT_OK(ac_claims_apply_block(&cs, &blk_c2), "claim 2 apply");

    make_claim_block_with_subnet(&blk_c3, &blk_c2, pub, priv,
                                 AC_TX_CLAIM, 3, "multi-net", 0, 4);
    ASSERT_OK(ac_claims_validate_block(&cs, &blk_c3), "claim 3 validate");
    ASSERT_OK(ac_claims_apply_block(&cs, &blk_c3), "claim 3 apply");

    /* Dependent count should be 3 */
    pad_dag_id(dag_id, "multi-net", AC_SUBNET_ID_LEN);
    ASSERT_EQ(ac_dag_dependent_count(&dag, AC_RES_SUBNET, dag_id), 3,
              "dependent count should be 3");

    /* Release claim for 10.7.0.2 */
    make_claim_block_with_subnet(&blk_rel, &blk_c3, pub, priv,
                                 AC_TX_RELEASE, 2, "multi-net", 0, 5);
    ASSERT_OK(ac_claims_validate_block(&cs, &blk_rel), "release validate");
    ASSERT_OK(ac_claims_apply_block(&cs, &blk_rel), "release apply");

    /* Dependent count should now be 2 */
    ASSERT_EQ(ac_dag_dependent_count(&dag, AC_RES_SUBNET, dag_id), 2,
              "dependent count should be 2");

    ac_claims_destroy(&cs);
    ac_subnet_destroy(&ss);
    ac_dag_destroy(&dag);
    PASS();
}

/* ── main ────────────────────────────────────────────────────────────── */

int main(void)
{
    printf("ac_dag_integration_test\n");

    /* Dependency chain tests */
    test_delete_subnet_with_active_claims_fails();
    test_delete_subnet_after_release_succeeds();
    test_delete_subnet_after_lease_expiry_succeeds();
    test_cascade_validation();

    /* Node tracking tests */
    test_dag_tracks_claim_nodes();
    test_dag_tracks_subnet_nodes();

    /* Edge tests */
    test_claim_to_subnet_edge();
    test_multiple_claims_in_subnet();

    printf("\n  %d/%d passed", pass_count, test_count);
    if (fail_count)
        printf(", %d FAILED", fail_count);
    printf("\n");

    return fail_count ? 1 : 0;
}
