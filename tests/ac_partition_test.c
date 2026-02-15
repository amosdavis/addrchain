/*
 * ac_partition_test.c — Unit tests for ac_partition.c
 *
 * Tests: init/destroy, create/delete partitions, add/remove subnets,
 *        allow/deny cross-partition traffic, VLAN uniqueness, rebuild.
 *
 * Mitigates: N16,N22,N23
 */

#include "ac_partition.h"
#include "ac_chain.h"
#include "ac_crypto.h"

#include <stdio.h>
#include <string.h>

static int test_count = 0;
static int pass_count = 0;
static int fail_count = 0;

#define TEST(name) do { \
    test_count++; \
    printf("  [%02d] %-55s ", test_count, name); \
} while (0)

#define PASS() do { pass_count++; printf("PASS\n"); } while (0)
#define FAIL(msg) do { fail_count++; printf("FAIL: %s\n", msg); } while (0)

#define ASSERT_EQ(a, b, msg) do { \
    if ((a) != (b)) { FAIL(msg); return; } \
} while (0)

#define ASSERT_NE(a, b, msg) do { \
    if ((a) == (b)) { FAIL(msg); return; } \
} while (0)

#define ASSERT_OK(rc, msg) ASSERT_EQ(rc, AC_OK, msg)

/* ================================================================== */
/*  Helpers                                                            */
/* ================================================================== */

static void make_keypair(uint8_t pub[AC_PUBKEY_LEN], uint8_t priv[64])
{
    uint8_t seed[32];
    ac_crypto_random(seed, sizeof(seed));
    ac_crypto_ed25519_keypair(seed, pub, priv);
}

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

/* ================================================================== */
/*  Tests                                                              */
/* ================================================================== */

static void test_partition_init_destroy(void)
{
    ac_partition_store_t ps;
    TEST("partition store init and destroy");

    ASSERT_OK(ac_partition_init(&ps), "init should succeed");
    ASSERT_EQ(ac_partition_count(&ps), 0, "should start empty");

    ac_partition_destroy(&ps);
    PASS();
}

static void test_partition_create(void)
{
    ac_partition_store_t ps;
    ac_block_t genesis, blk;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    const ac_partition_record_t *rec;
    TEST("create a partition");

    ac_partition_init(&ps);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    make_partition_block(&blk, &genesis, pub, priv,
                         "prod", AC_PART_CREATE, NULL, NULL, 100, 1);

    ASSERT_OK(ac_partition_validate_block(&ps, &blk), "validate");
    ASSERT_OK(ac_partition_apply_block(&ps, &blk), "apply");
    ASSERT_EQ(ac_partition_count(&ps), 1, "1 partition");

    rec = ac_partition_find(&ps, (const uint8_t *)"prod\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
    ASSERT_NE((uintptr_t)rec, (uintptr_t)NULL, "should find partition");
    ASSERT_EQ(rec->vlan_id, 100, "VLAN should be 100");

    ac_partition_destroy(&ps);
    PASS();
}

static void test_partition_duplicate_rejected(void)
{
    ac_partition_store_t ps;
    ac_block_t genesis, blk1, blk2;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    int rc;
    TEST("duplicate partition_id rejected");

    ac_partition_init(&ps);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    make_partition_block(&blk1, &genesis, pub, priv,
                         "dup", AC_PART_CREATE, NULL, NULL, 0, 1);
    ac_partition_apply_block(&ps, &blk1);

    make_partition_block(&blk2, &blk1, pub, priv,
                         "dup", AC_PART_CREATE, NULL, NULL, 0, 2);
    rc = ac_partition_validate_block(&ps, &blk2);
    ASSERT_EQ(rc, AC_ERR_EXIST, "duplicate should fail");

    ac_partition_destroy(&ps);
    PASS();
}

static void test_partition_vlan_uniqueness(void)
{
    ac_partition_store_t ps;
    ac_block_t genesis, blk1, blk2;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    int rc;
    TEST("VLAN ID uniqueness enforced (N16)");

    ac_partition_init(&ps);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    make_partition_block(&blk1, &genesis, pub, priv,
                         "part-a", AC_PART_CREATE, NULL, NULL, 200, 1);
    ac_partition_apply_block(&ps, &blk1);

    make_partition_block(&blk2, &blk1, pub, priv,
                         "part-b", AC_PART_CREATE, NULL, NULL, 200, 2);
    rc = ac_partition_validate_block(&ps, &blk2);
    ASSERT_EQ(rc, AC_ERR_CONFLICT, "duplicate VLAN should fail");

    ac_partition_destroy(&ps);
    PASS();
}

static void test_partition_add_remove_subnet(void)
{
    ac_partition_store_t ps;
    ac_block_t genesis, blk1, blk2, blk3;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    const ac_partition_record_t *rec;
    TEST("add and remove subnets from partition");

    ac_partition_init(&ps);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    make_partition_block(&blk1, &genesis, pub, priv,
                         "net-part", AC_PART_CREATE, NULL, NULL, 0, 1);
    ac_partition_apply_block(&ps, &blk1);

    /* Add subnet */
    make_partition_block(&blk2, &blk1, pub, priv,
                         "net-part", AC_PART_ADD_SUBNET, "lab-net", NULL, 0, 2);
    ASSERT_OK(ac_partition_validate_block(&ps, &blk2), "add subnet");
    ac_partition_apply_block(&ps, &blk2);

    rec = ac_partition_find(&ps, (const uint8_t *)"net-part\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
    ASSERT_EQ(rec->subnet_count, 1, "should have 1 subnet");

    /* Check for_subnet lookup */
    {
        const ac_partition_record_t *found;
        found = ac_partition_for_subnet(&ps,
                    (const uint8_t *)"lab-net\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
        ASSERT_NE((uintptr_t)found, (uintptr_t)NULL, "for_subnet should find");
    }

    /* Remove subnet */
    make_partition_block(&blk3, &blk2, pub, priv,
                         "net-part", AC_PART_REMOVE_SUBNET, "lab-net", NULL, 0, 3);
    ASSERT_OK(ac_partition_validate_block(&ps, &blk3), "remove subnet");
    ac_partition_apply_block(&ps, &blk3);

    rec = ac_partition_find(&ps, (const uint8_t *)"net-part\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
    ASSERT_EQ(rec->subnet_count, 0, "should have 0 subnets");

    ac_partition_destroy(&ps);
    PASS();
}

static void test_partition_cross_traffic_default_deny(void)
{
    ac_partition_store_t ps;
    ac_block_t genesis, blk1, blk2;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    TEST("cross-partition traffic denied by default (N22)");

    ac_partition_init(&ps);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    make_partition_block(&blk1, &genesis, pub, priv,
                         "zone-a", AC_PART_CREATE, NULL, NULL, 0, 1);
    ac_partition_apply_block(&ps, &blk1);

    make_partition_block(&blk2, &blk1, pub, priv,
                         "zone-b", AC_PART_CREATE, NULL, NULL, 0, 2);
    ac_partition_apply_block(&ps, &blk2);

    ASSERT_EQ(ac_partition_allowed(&ps,
        (const uint8_t *)"zone-a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        (const uint8_t *)"zone-b\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"),
        0, "should be denied by default");

    /* Same partition is allowed */
    ASSERT_EQ(ac_partition_allowed(&ps,
        (const uint8_t *)"zone-a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        (const uint8_t *)"zone-a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"),
        1, "same partition should be allowed");

    ac_partition_destroy(&ps);
    PASS();
}

static void test_partition_allow_cross(void)
{
    ac_partition_store_t ps;
    ac_block_t genesis, blk1, blk2, blk3, blk4;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    TEST("ALLOW_CROSS / DENY_CROSS lifecycle");

    ac_partition_init(&ps);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    make_partition_block(&blk1, &genesis, pub, priv,
                         "x-a", AC_PART_CREATE, NULL, NULL, 0, 1);
    ac_partition_apply_block(&ps, &blk1);

    make_partition_block(&blk2, &blk1, pub, priv,
                         "x-b", AC_PART_CREATE, NULL, NULL, 0, 2);
    ac_partition_apply_block(&ps, &blk2);

    /* Allow */
    make_partition_block(&blk3, &blk2, pub, priv,
                         "x-a", AC_PART_ALLOW_CROSS, NULL, "x-b", 0, 3);
    ASSERT_OK(ac_partition_validate_block(&ps, &blk3), "allow validate");
    ac_partition_apply_block(&ps, &blk3);

    ASSERT_EQ(ac_partition_allowed(&ps,
        (const uint8_t *)"x-a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        (const uint8_t *)"x-b\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"),
        1, "should be allowed after ALLOW_CROSS");

    /* Deny */
    make_partition_block(&blk4, &blk3, pub, priv,
                         "x-a", AC_PART_DENY_CROSS, NULL, "x-b", 0, 4);
    ASSERT_OK(ac_partition_validate_block(&ps, &blk4), "deny validate");
    ac_partition_apply_block(&ps, &blk4);

    ASSERT_EQ(ac_partition_allowed(&ps,
        (const uint8_t *)"x-a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        (const uint8_t *)"x-b\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"),
        0, "should be denied after DENY_CROSS");

    ac_partition_destroy(&ps);
    PASS();
}

static void test_partition_delete(void)
{
    ac_partition_store_t ps;
    ac_block_t genesis, blk1, blk2;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    TEST("delete partition");

    ac_partition_init(&ps);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    make_partition_block(&blk1, &genesis, pub, priv,
                         "temp", AC_PART_CREATE, NULL, NULL, 0, 1);
    ac_partition_apply_block(&ps, &blk1);
    ASSERT_EQ(ac_partition_count(&ps), 1, "1 partition");

    make_partition_block(&blk2, &blk1, pub, priv,
                         "temp", AC_PART_DELETE, NULL, NULL, 0, 2);
    ASSERT_OK(ac_partition_validate_block(&ps, &blk2), "delete validate");
    ac_partition_apply_block(&ps, &blk2);

    ASSERT_EQ((uintptr_t)ac_partition_find(&ps,
        (const uint8_t *)"temp\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"),
        (uintptr_t)NULL, "deleted partition not found");

    ac_partition_destroy(&ps);
    PASS();
}

static void test_partition_rebuild(void)
{
    ac_partition_store_t ps;
    ac_block_t blocks[4];
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    TEST("rebuild from chain");

    ac_partition_init(&ps);
    make_keypair(pub, priv);

    ac_genesis_block(&blocks[0]);
    make_partition_block(&blocks[1], &blocks[0], pub, priv,
                         "rb-a", AC_PART_CREATE, NULL, NULL, 10, 1);
    make_partition_block(&blocks[2], &blocks[1], pub, priv,
                         "rb-b", AC_PART_CREATE, NULL, NULL, 20, 2);
    make_partition_block(&blocks[3], &blocks[2], pub, priv,
                         "rb-a", AC_PART_ADD_SUBNET, "sub1", NULL, 0, 3);

    ASSERT_OK(ac_partition_rebuild(&ps, blocks, 4), "rebuild");
    ASSERT_EQ(ac_partition_count(&ps), 2, "2 partitions");

    ac_partition_destroy(&ps);
    PASS();
}

static void test_partition_null_safety(void)
{
    TEST("NULL parameter safety (K01)");

    ASSERT_NE(ac_partition_init(NULL), AC_OK, "init(NULL)");
    ASSERT_EQ(ac_partition_count(NULL), 0, "count(NULL)");
    ASSERT_EQ((uintptr_t)ac_partition_find(NULL, NULL), (uintptr_t)NULL, "find(NULL)");
    ASSERT_EQ(ac_partition_allowed(NULL, NULL, NULL), 0, "allowed(NULL) = denied");

    PASS();
}

/* ================================================================== */
/*  Main                                                               */
/* ================================================================== */

int main(void)
{
    printf("=== ac_partition unit tests ===\n\n");

    test_partition_init_destroy();
    test_partition_create();
    test_partition_duplicate_rejected();
    test_partition_vlan_uniqueness();
    test_partition_add_remove_subnet();
    test_partition_cross_traffic_default_deny();
    test_partition_allow_cross();
    test_partition_delete();
    test_partition_rebuild();
    test_partition_null_safety();

    printf("\n=== Results: %d passed, %d failed, %d total ===\n",
           pass_count, fail_count, test_count);

    return fail_count > 0 ? 1 : 0;
}
