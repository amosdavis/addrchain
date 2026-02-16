/*
 * ac_snapshot_test.c — Unit tests for ac_snapshot.c and ac_chain_prune
 *
 * Tests:
 *   1. Create snapshot, verify hash
 *   2. Create snapshot, load back, verify
 *   3. Create snapshot, restore, verify state matches
 *   4. Corrupted snapshot detection (flip a byte, verify fails)
 *   5. Unknown version rejection
 *   6. Prune + restore roundtrip
 *
 * Mitigates: S06,S07,S08,S22,S24,K01,K03
 */

#include "ac_snapshot.h"
#include "ac_crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_count = 0;
static int pass_count = 0;
static int fail_count = 0;

#define TEST(name) do { \
    test_count++; \
    printf("  [%02d] %-50s ", test_count, name); \
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

#define ASSERT_MEM_EQ(a, b, n, msg) do { \
    if (memcmp((a), (b), (n)) != 0) { FAIL(msg); return; } \
} while (0)

/* ================================================================== */
/*  Helpers                                                            */
/* ================================================================== */

static void make_keypair(uint8_t pubkey[AC_PUBKEY_LEN],
                         uint8_t privkey[64])
{
    uint8_t seed[32];
    ac_crypto_random(seed, sizeof(seed));
    ac_crypto_ed25519_keypair(seed, pubkey, privkey);
}

static void make_claim_tx(ac_transaction_t *tx,
                          const uint8_t pubkey[AC_PUBKEY_LEN],
                          const uint8_t privkey[64],
                          uint8_t ip_byte, uint32_t nonce)
{
    memset(tx, 0, sizeof(*tx));
    tx->type = AC_TX_CLAIM;
    memcpy(tx->node_pubkey, pubkey, AC_PUBKEY_LEN);
    tx->timestamp = ac_time_unix_sec();
    tx->nonce = nonce;

    tx->payload.claim.address.family = AC_AF_IPV4;
    tx->payload.claim.address.addr[0] = 10;
    tx->payload.claim.address.addr[1] = 0;
    tx->payload.claim.address.addr[2] = 0;
    tx->payload.claim.address.addr[3] = ip_byte;
    tx->payload.claim.address.prefix_len = 24;

    ac_tx_sign(tx, privkey);
}

/* Initialize all stores for testing */
static void init_all(ac_chain_t *chain, ac_claim_store_t *cs,
                     ac_subnet_store_t *ss, ac_vpn_store_t *vs,
                     ac_partition_store_t *ps, ac_dag_t *dag)
{
    int rc;

    rc = ac_dag_init(dag);
    (void)rc;
    rc = ac_chain_init(chain);
    (void)rc;
    rc = ac_claims_init(cs, 0, 0, dag);
    (void)rc;
    rc = ac_subnet_init(ss, 0, 0, dag);
    (void)rc;
    rc = ac_vpn_init(vs, 0, dag);
    (void)rc;
    rc = ac_partition_init(ps, 0, 0, dag);
    (void)rc;
}

static void destroy_all(ac_chain_t *chain, ac_claim_store_t *cs,
                        ac_subnet_store_t *ss, ac_vpn_store_t *vs,
                        ac_partition_store_t *ps, ac_dag_t *dag)
{
    ac_partition_destroy(ps);
    ac_vpn_destroy(vs);
    ac_subnet_destroy(ss);
    ac_claims_destroy(cs);
    ac_chain_destroy(chain);
    ac_dag_destroy(dag);
}

/* Add a block with one CLAIM transaction to the chain and apply to stores */
static int add_claim_block(ac_chain_t *chain, ac_claim_store_t *cs,
                           const uint8_t pubkey[AC_PUBKEY_LEN],
                           const uint8_t privkey[64],
                           uint8_t ip_byte, uint32_t nonce)
{
    ac_block_t prev, blk;
    ac_transaction_t tx;
    int rc;

    make_claim_tx(&tx, pubkey, privkey, ip_byte, nonce);

    rc = ac_chain_last_block(chain, &prev);
    if (rc != AC_OK) return rc;

    rc = ac_block_create(&prev, &tx, 1, &blk);
    if (rc != AC_OK) return rc;

    rc = ac_chain_add_block(chain, &blk);
    if (rc != AC_OK) return rc;

    rc = ac_claims_apply_block(cs, &blk);
    return rc;
}

/* ================================================================== */
/*  Test 1: Create snapshot, verify hash                               */
/* ================================================================== */

static void test_create_and_verify(void)
{
    ac_chain_t chain;
    ac_claim_store_t cs;
    ac_subnet_store_t ss;
    ac_vpn_store_t vs;
    ac_partition_store_t ps;
    ac_dag_t dag;
    ac_snapshot_t snap;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    int rc;

    TEST("create snapshot and verify hash");

    init_all(&chain, &cs, &ss, &vs, &ps, &dag);
    make_keypair(pub, priv);

    /* Add a claim to have some state */
    rc = add_claim_block(&chain, &cs, pub, priv, 10, 1);
    ASSERT_OK(rc, "add_claim_block");

    rc = ac_snapshot_create(&snap, 1, &chain, &cs, &ss, &vs, &ps, &dag);
    ASSERT_OK(rc, "snapshot_create");

    ASSERT_NE(snap.data, NULL, "snap.data should be non-NULL");
    ASSERT_NE(snap.size, 0, "snap.size should be > 0");
    ASSERT_EQ(snap.block_index, 1, "block_index should be 1");

    rc = ac_snapshot_verify(&snap);
    ASSERT_OK(rc, "snapshot_verify should succeed");

    PASS();
    ac_snapshot_free(&snap);
    destroy_all(&chain, &cs, &ss, &vs, &ps, &dag);
}

/* ================================================================== */
/*  Test 2: Create snapshot, load back, verify                         */
/* ================================================================== */

static void test_create_load_verify(void)
{
    ac_chain_t chain;
    ac_claim_store_t cs;
    ac_subnet_store_t ss;
    ac_vpn_store_t vs;
    ac_partition_store_t ps;
    ac_dag_t dag;
    ac_snapshot_t snap, snap2;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    int rc;

    TEST("create snapshot, load from buffer, verify");

    init_all(&chain, &cs, &ss, &vs, &ps, &dag);
    make_keypair(pub, priv);

    rc = add_claim_block(&chain, &cs, pub, priv, 20, 1);
    ASSERT_OK(rc, "add_claim_block");

    rc = ac_snapshot_create(&snap, 1, &chain, &cs, &ss, &vs, &ps, &dag);
    ASSERT_OK(rc, "snapshot_create");

    /* Load from raw buffer */
    rc = ac_snapshot_load(&snap2, snap.data, snap.size);
    ASSERT_OK(rc, "snapshot_load");

    ASSERT_EQ(snap2.size, snap.size, "loaded size should match");
    ASSERT_EQ(snap2.block_index, snap.block_index, "block_index should match");
    ASSERT_MEM_EQ(snap2.hash, snap.hash, AC_HASH_LEN, "hash should match");

    rc = ac_snapshot_verify(&snap2);
    ASSERT_OK(rc, "verify loaded snapshot");

    PASS();
    ac_snapshot_free(&snap);
    ac_snapshot_free(&snap2);
    destroy_all(&chain, &cs, &ss, &vs, &ps, &dag);
}

/* ================================================================== */
/*  Test 3: Create snapshot, restore, verify state matches             */
/* ================================================================== */

static void test_create_restore_roundtrip(void)
{
    ac_chain_t chain, chain2;
    ac_claim_store_t cs, cs2;
    ac_subnet_store_t ss, ss2;
    ac_vpn_store_t vs, vs2;
    ac_partition_store_t ps, ps2;
    ac_dag_t dag, dag2;
    ac_snapshot_t snap;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    uint8_t owner[AC_PUBKEY_LEN];
    ac_address_t addr;
    int rc;

    TEST("create snapshot, restore, state matches");

    init_all(&chain, &cs, &ss, &vs, &ps, &dag);
    make_keypair(pub, priv);

    /* Add 3 claims */
    rc = add_claim_block(&chain, &cs, pub, priv, 30, 1);
    ASSERT_OK(rc, "claim 1");
    rc = add_claim_block(&chain, &cs, pub, priv, 31, 2);
    ASSERT_OK(rc, "claim 2");
    rc = add_claim_block(&chain, &cs, pub, priv, 32, 3);
    ASSERT_OK(rc, "claim 3");

    ASSERT_EQ(ac_claims_count(&cs), 3, "should have 3 claims");

    /* Snapshot */
    rc = ac_snapshot_create(&snap, 3, &chain, &cs, &ss, &vs, &ps, &dag);
    ASSERT_OK(rc, "snapshot_create");

    /* Restore into fresh stores */
    init_all(&chain2, &cs2, &ss2, &vs2, &ps2, &dag2);

    rc = ac_snapshot_restore(&snap, &chain2, &cs2, &ss2, &vs2, &ps2, &dag2);
    ASSERT_OK(rc, "snapshot_restore");

    /* Verify claim count matches */
    ASSERT_EQ(ac_claims_count(&cs2), 3, "restored should have 3 claims");

    /* Verify a specific claim is accessible */
    memset(&addr, 0, sizeof(addr));
    addr.family = AC_AF_IPV4;
    addr.addr[0] = 10;
    addr.addr[1] = 0;
    addr.addr[2] = 0;
    addr.addr[3] = 31;

    rc = ac_claims_get_owner(&cs2, &addr, owner);
    ASSERT_OK(rc, "get_owner for 10.0.0.31");
    ASSERT_MEM_EQ(owner, pub, AC_PUBKEY_LEN, "owner pubkey should match");

    PASS();
    ac_snapshot_free(&snap);
    destroy_all(&chain, &cs, &ss, &vs, &ps, &dag);
    destroy_all(&chain2, &cs2, &ss2, &vs2, &ps2, &dag2);
}

/* ================================================================== */
/*  Test 4: Corrupted snapshot detection                               */
/* ================================================================== */

static void test_corrupted_snapshot(void)
{
    ac_chain_t chain;
    ac_claim_store_t cs;
    ac_subnet_store_t ss;
    ac_vpn_store_t vs;
    ac_partition_store_t ps;
    ac_dag_t dag;
    ac_snapshot_t snap;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    int rc;

    TEST("corrupted snapshot detected by verify");

    init_all(&chain, &cs, &ss, &vs, &ps, &dag);
    make_keypair(pub, priv);

    rc = add_claim_block(&chain, &cs, pub, priv, 40, 1);
    ASSERT_OK(rc, "add_claim_block");

    rc = ac_snapshot_create(&snap, 1, &chain, &cs, &ss, &vs, &ps, &dag);
    ASSERT_OK(rc, "snapshot_create");

    /* Verify passes before corruption */
    rc = ac_snapshot_verify(&snap);
    ASSERT_OK(rc, "verify before corruption");

    /* Flip a byte in the payload (after header) */
    snap.data[sizeof(ac_snapshot_header_t) + 5] ^= 0xFF;

    /* Verify should now fail */
    rc = ac_snapshot_verify(&snap);
    ASSERT_EQ(rc, AC_ERR_CRYPTO, "verify should fail after corruption");

    PASS();
    ac_snapshot_free(&snap);
    destroy_all(&chain, &cs, &ss, &vs, &ps, &dag);
}

/* ================================================================== */
/*  Test 5: Unknown version rejection                                  */
/* ================================================================== */

static void test_unknown_version(void)
{
    ac_chain_t chain;
    ac_claim_store_t cs;
    ac_subnet_store_t ss;
    ac_vpn_store_t vs;
    ac_partition_store_t ps;
    ac_dag_t dag;
    ac_snapshot_t snap, snap2;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    int rc;

    TEST("unknown format version rejected");

    init_all(&chain, &cs, &ss, &vs, &ps, &dag);
    make_keypair(pub, priv);

    rc = ac_snapshot_create(&snap, 0, &chain, &cs, &ss, &vs, &ps, &dag);
    ASSERT_OK(rc, "snapshot_create");

    /* Tamper with format_version in header (offset 4) */
    {
        uint32_t bad_version = ac_cpu_to_le32(99);
        memcpy(snap.data + 4, &bad_version, 4);
    }

    /* Load should reject */
    rc = ac_snapshot_load(&snap2, snap.data, snap.size);
    ASSERT_EQ(rc, AC_ERR_INVAL, "load should reject unknown version");

    PASS();
    ac_snapshot_free(&snap);
    destroy_all(&chain, &cs, &ss, &vs, &ps, &dag);
}

/* ================================================================== */
/*  Test 6: Prune + restore roundtrip                                  */
/* ================================================================== */

static void test_prune_restore_roundtrip(void)
{
    ac_chain_t chain, chain2;
    ac_claim_store_t cs, cs2;
    ac_subnet_store_t ss, ss2;
    ac_vpn_store_t vs, vs2;
    ac_partition_store_t ps, ps2;
    ac_dag_t dag, dag2;
    ac_snapshot_t snap;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    int rc, pruned;
    uint32_t i;
    uint8_t owner[AC_PUBKEY_LEN];
    ac_address_t addr;

    TEST("prune + restore roundtrip");

    init_all(&chain, &cs, &ss, &vs, &ps, &dag);
    make_keypair(pub, priv);

    /* Add 5 blocks with claims */
    for (i = 0; i < 5; i++) {
        rc = add_claim_block(&chain, &cs, pub, priv,
                             (uint8_t)(50 + i), i + 1);
        ASSERT_OK(rc, "add_claim_block in loop");
    }

    ASSERT_EQ(ac_chain_len(&chain), 6, "chain should have 6 blocks");
    ASSERT_EQ(ac_claims_count(&cs), 5, "should have 5 claims");

    /* Take snapshot at block 3 (after 3 claim blocks) */
    rc = ac_snapshot_create(&snap, 3, &chain, &cs, &ss, &vs, &ps, &dag);
    ASSERT_OK(rc, "snapshot_create at block 3");

    /* Prune first 3 blocks */
    pruned = ac_chain_prune(&chain, 3);
    ASSERT_EQ(pruned, 3, "should have pruned 3 blocks");
    ASSERT_EQ(ac_chain_len(&chain), 3, "chain should have 3 blocks left");

    /* Restore into fresh stores, then replay remaining blocks */
    init_all(&chain2, &cs2, &ss2, &vs2, &ps2, &dag2);

    rc = ac_snapshot_restore(&snap, &chain2, &cs2, &ss2, &vs2, &ps2, &dag2);
    ASSERT_OK(rc, "snapshot_restore");

    /* Verify all 5 original claims exist in restored state */
    ASSERT_EQ(ac_claims_count(&cs2), 5, "restored should have 5 claims");

    /* Verify a claim from before the prune point */
    memset(&addr, 0, sizeof(addr));
    addr.family = AC_AF_IPV4;
    addr.addr[0] = 10;
    addr.addr[3] = 50;
    rc = ac_claims_get_owner(&cs2, &addr, owner);
    ASSERT_OK(rc, "get_owner for 10.0.0.50");
    ASSERT_MEM_EQ(owner, pub, AC_PUBKEY_LEN, "owner should match");

    /* Verify a claim from after the snapshot point */
    addr.addr[3] = 54;
    rc = ac_claims_get_owner(&cs2, &addr, owner);
    ASSERT_OK(rc, "get_owner for 10.0.0.54");

    PASS();
    ac_snapshot_free(&snap);
    destroy_all(&chain, &cs, &ss, &vs, &ps, &dag);
    destroy_all(&chain2, &cs2, &ss2, &vs2, &ps2, &dag2);
}

/* ================================================================== */
/*  Test 7: Empty snapshot (no state)                                  */
/* ================================================================== */

static void test_empty_snapshot(void)
{
    ac_chain_t chain;
    ac_claim_store_t cs;
    ac_subnet_store_t ss;
    ac_vpn_store_t vs;
    ac_partition_store_t ps;
    ac_dag_t dag;
    ac_snapshot_t snap;
    int rc;

    TEST("empty snapshot (no claims/subnets/etc)");

    init_all(&chain, &cs, &ss, &vs, &ps, &dag);

    rc = ac_snapshot_create(&snap, 0, &chain, &cs, &ss, &vs, &ps, &dag);
    ASSERT_OK(rc, "create empty snapshot");

    rc = ac_snapshot_verify(&snap);
    ASSERT_OK(rc, "verify empty snapshot");

    /* Header size(48) + 8 section counts (4 each) = 48 + 32 = 80 */
    ASSERT_EQ(snap.size, 80, "empty snapshot should be 80 bytes");

    PASS();
    ac_snapshot_free(&snap);
    destroy_all(&chain, &cs, &ss, &vs, &ps, &dag);
}

/* ================================================================== */
/*  Test 8: Prune edge cases                                           */
/* ================================================================== */

static void test_prune_edge_cases(void)
{
    ac_chain_t chain;
    ac_claim_store_t cs;
    ac_subnet_store_t ss;
    ac_vpn_store_t vs;
    ac_partition_store_t ps;
    ac_dag_t dag;
    int pruned;

    TEST("prune edge cases (0, beyond count)");

    init_all(&chain, &cs, &ss, &vs, &ps, &dag);

    /* Prune 0 should do nothing */
    pruned = ac_chain_prune(&chain, 0);
    ASSERT_EQ(pruned, 0, "prune(0) should remove 0");
    ASSERT_EQ(ac_chain_len(&chain), 1, "chain still has genesis");

    /* Prune beyond count should do nothing */
    pruned = ac_chain_prune(&chain, 100);
    ASSERT_EQ(pruned, 0, "prune(100) should remove 0");
    ASSERT_EQ(ac_chain_len(&chain), 1, "chain still has genesis");

    PASS();
    destroy_all(&chain, &cs, &ss, &vs, &ps, &dag);
}

/* ================================================================== */
/*  Test 9: NULL parameter handling                                    */
/* ================================================================== */

static void test_null_params(void)
{
    ac_snapshot_t snap;
    int rc;

    TEST("NULL parameter rejection");

    rc = ac_snapshot_create(NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL);
    ASSERT_EQ(rc, AC_ERR_INVAL, "create(NULL) should fail");

    rc = ac_snapshot_verify(NULL);
    ASSERT_EQ(rc, AC_ERR_INVAL, "verify(NULL) should fail");

    rc = ac_snapshot_load(NULL, NULL, 0);
    ASSERT_EQ(rc, AC_ERR_INVAL, "load(NULL) should fail");

    memset(&snap, 0, sizeof(snap));
    rc = ac_snapshot_verify(&snap);
    ASSERT_EQ(rc, AC_ERR_INVAL, "verify(empty) should fail");

    /* Free on NULL should be safe */
    ac_snapshot_free(NULL);

    PASS();
}

/* ================================================================== */
/*  Test 10: Snapshot load rejects truncated data                      */
/* ================================================================== */

static void test_truncated_load(void)
{
    ac_snapshot_t snap;
    uint8_t small[10] = {0};
    int rc;

    TEST("snapshot load rejects truncated data");

    rc = ac_snapshot_load(&snap, small, 10);
    ASSERT_EQ(rc, AC_ERR_INVAL, "too-small buffer should fail");

    PASS();
}

/* ================================================================== */
/*  Main                                                               */
/* ================================================================== */

int main(void)
{
    printf("\n=== ac_snapshot_test ===\n\n");

    test_create_and_verify();
    test_create_load_verify();
    test_create_restore_roundtrip();
    test_corrupted_snapshot();
    test_unknown_version();
    test_prune_restore_roundtrip();
    test_empty_snapshot();
    test_prune_edge_cases();
    test_null_params();
    test_truncated_load();

    printf("\n  Results: %d/%d passed", pass_count, test_count);
    if (fail_count > 0)
        printf(", %d FAILED", fail_count);
    printf("\n\n");

    return fail_count > 0 ? 1 : 0;
}
