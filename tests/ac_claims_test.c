/*
 * ac_claims_test.c — Unit tests for ac_claims.c
 *
 * Tests: init/destroy, claim/release/renew, conflict detection,
 *        lease expiry, key revocation, rollback detection, validation.
 *
 * Mitigates: K01,K02,K03,K04,K05,K07,K08,K13,K18,K21,K46
 */

#include "ac_claims.h"
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

static void make_ipv4_addr(ac_address_t *addr, uint8_t a, uint8_t b,
                           uint8_t c, uint8_t d)
{
    memset(addr, 0, sizeof(*addr));
    addr->family = AC_AF_IPV4;
    addr->addr[0] = a;
    addr->addr[1] = b;
    addr->addr[2] = c;
    addr->addr[3] = d;
    addr->prefix_len = 24;
}

static void make_claim_block(ac_block_t *blk, const ac_block_t *prev,
                             const uint8_t pub[AC_PUBKEY_LEN],
                             const uint8_t priv[64],
                             uint8_t tx_type,
                             uint8_t ip_last_byte, uint32_t nonce)
{
    ac_transaction_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.type = tx_type;
    memcpy(tx.node_pubkey, pub, AC_PUBKEY_LEN);
    tx.timestamp = ac_time_unix_sec();
    tx.nonce = nonce;
    make_ipv4_addr(&tx.payload.claim.address, 10, 0, 0, ip_last_byte);
    ac_tx_sign(&tx, priv);
    ac_block_create(prev, &tx, 1, blk);
}

/* ================================================================== */
/*  Tests                                                              */
/* ================================================================== */

static void test_claims_init_destroy(void)
{
    ac_claim_store_t cs;
    int rc;
    TEST("claim store init and destroy");

    rc = ac_claims_init(&cs, 0, 0, NULL);
    ASSERT_OK(rc, "init should succeed");
    ASSERT_EQ(ac_claims_count(&cs), 0, "should start empty");

    ac_claims_destroy(&cs);
    PASS();
}

static void test_claims_apply_claim(void)
{
    ac_claim_store_t cs;
    ac_block_t genesis, blk;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    uint8_t owner[AC_PUBKEY_LEN];
    int rc;
    TEST("apply CLAIM tx creates ownership");

    ac_claims_init(&cs, 1000, 0, NULL);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    make_claim_block(&blk, &genesis, pub, priv, AC_TX_CLAIM, 1, 1);
    rc = ac_claims_apply_block(&cs, &blk);
    ASSERT_OK(rc, "apply should succeed");
    ASSERT_EQ(ac_claims_count(&cs), 1, "should have 1 claim");

    {
        ac_address_t addr;
        make_ipv4_addr(&addr, 10, 0, 0, 1);
        rc = ac_claims_get_owner(&cs, &addr, owner);
        ASSERT_OK(rc, "get_owner should succeed");
        if (memcmp(owner, pub, AC_PUBKEY_LEN) != 0) {
            FAIL("owner should match claimant");
            ac_claims_destroy(&cs);
            return;
        }
    }

    ac_claims_destroy(&cs);
    PASS();
}

static void test_claims_conflict_detection(void)
{
    ac_claim_store_t cs;
    ac_block_t genesis, blk1, blk2;
    uint8_t pub1[AC_PUBKEY_LEN], priv1[64];
    uint8_t pub2[AC_PUBKEY_LEN], priv2[64];
    int rc;
    TEST("conflict: second CLAIM for same address rejected");

    ac_claims_init(&cs, 1000, 0, NULL);
    make_keypair(pub1, priv1);
    make_keypair(pub2, priv2);
    ac_genesis_block(&genesis);

    /* First claim */
    make_claim_block(&blk1, &genesis, pub1, priv1, AC_TX_CLAIM, 1, 1);
    ac_claims_apply_block(&cs, &blk1);

    /* Second claim for same IP by different node */
    make_claim_block(&blk2, &blk1, pub2, priv2, AC_TX_CLAIM, 1, 1);
    rc = ac_claims_validate_block(&cs, &blk2);
    ASSERT_NE(rc, AC_OK, "duplicate claim should be rejected");

    ac_claims_destroy(&cs);
    PASS();
}

static void test_claims_release(void)
{
    ac_claim_store_t cs;
    ac_block_t genesis, blk1, blk2;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    ac_address_t addr;
    uint8_t owner[AC_PUBKEY_LEN];
    int rc;
    TEST("RELEASE frees an address");

    ac_claims_init(&cs, 1000, 0, NULL);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    make_claim_block(&blk1, &genesis, pub, priv, AC_TX_CLAIM, 1, 1);
    ac_claims_apply_block(&cs, &blk1);
    ASSERT_EQ(ac_claims_count(&cs), 1, "should have 1 claim");

    make_claim_block(&blk2, &blk1, pub, priv, AC_TX_RELEASE, 1, 2);
    ac_claims_apply_block(&cs, &blk2);
    ASSERT_EQ(ac_claims_count(&cs), 0, "should have 0 claims");

    make_ipv4_addr(&addr, 10, 0, 0, 1);
    rc = ac_claims_get_owner(&cs, &addr, owner);
    ASSERT_EQ(rc, AC_ERR_NOENT, "address should be unclaimed");

    ac_claims_destroy(&cs);
    PASS();
}

static void test_claims_renew(void)
{
    ac_claim_store_t cs;
    ac_block_t genesis, blk1, blk2;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    TEST("RENEW extends lease");

    ac_claims_init(&cs, 1000, 0, NULL);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    make_claim_block(&blk1, &genesis, pub, priv, AC_TX_CLAIM, 1, 1);
    ac_claims_apply_block(&cs, &blk1);

    make_claim_block(&blk2, &blk1, pub, priv, AC_TX_RENEW, 1, 2);
    ac_claims_apply_block(&cs, &blk2);
    ASSERT_EQ(ac_claims_count(&cs), 1, "should still have 1 claim");

    ac_claims_destroy(&cs);
    PASS();
}

static void test_claims_lease_expiry(void)
{
    ac_claim_store_t cs;
    ac_block_t genesis, blk1, blk_far;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    TEST("lease expiry removes claim");

    ac_claims_init(&cs, 5, 0, NULL); /* 5-block lease for fast expiry */
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    make_claim_block(&blk1, &genesis, pub, priv, AC_TX_CLAIM, 1, 1);
    ac_claims_apply_block(&cs, &blk1);
    ASSERT_EQ(ac_claims_count(&cs), 1, "should have 1 claim");

    /* Apply a block far in the future (index 100) to trigger expiry */
    memset(&blk_far, 0, sizeof(blk_far));
    blk_far.index = 100;
    blk_far.tx_count = 0;
    ac_claims_apply_block(&cs, &blk_far);
    ASSERT_EQ(ac_claims_count(&cs), 0, "claim should have expired");

    ac_claims_destroy(&cs);
    PASS();
}

static void test_claims_release_non_owner(void)
{
    ac_claim_store_t cs;
    ac_block_t genesis, blk1, blk2;
    uint8_t pub1[AC_PUBKEY_LEN], priv1[64];
    uint8_t pub2[AC_PUBKEY_LEN], priv2[64];
    int rc;
    TEST("RELEASE by non-owner rejected in validation");

    ac_claims_init(&cs, 1000, 0, NULL);
    make_keypair(pub1, priv1);
    make_keypair(pub2, priv2);
    ac_genesis_block(&genesis);

    /* Node1 claims */
    make_claim_block(&blk1, &genesis, pub1, priv1, AC_TX_CLAIM, 1, 1);
    ac_claims_apply_block(&cs, &blk1);

    /* Node2 tries to release */
    make_claim_block(&blk2, &blk1, pub2, priv2, AC_TX_RELEASE, 1, 1);
    rc = ac_claims_validate_block(&cs, &blk2);
    ASSERT_NE(rc, AC_OK, "non-owner release should be rejected");

    ac_claims_destroy(&cs);
    PASS();
}

static void test_claims_multiple_addresses(void)
{
    ac_claim_store_t cs;
    ac_block_t genesis, blk;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    ac_address_t addrs[10];
    uint32_t count;
    TEST("multiple addresses per node");

    ac_claims_init(&cs, 1000, 0, NULL);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    /* Claim 3 addresses */
    {
        ac_block_t prev = genesis;
        uint8_t i;
        for (i = 1; i <= 3; i++) {
            make_claim_block(&blk, &prev, pub, priv, AC_TX_CLAIM, i, i);
            ac_claims_apply_block(&cs, &blk);
            prev = blk;
        }
    }

    ASSERT_EQ(ac_claims_count(&cs), 3, "should have 3 claims");

    count = ac_claims_by_node(&cs, pub, addrs, 10);
    ASSERT_EQ(count, 3, "should find 3 addresses for node");

    ac_claims_destroy(&cs);
    PASS();
}

static void test_claims_rebuild(void)
{
    ac_claim_store_t cs;
    ac_block_t blocks[4];
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    ac_address_t lost[10];
    uint32_t lost_count = 0;
    int rc;
    TEST("rebuild from chain");

    ac_claims_init(&cs, 1000, 0, NULL);
    make_keypair(pub, priv);

    /* Build a small chain */
    ac_genesis_block(&blocks[0]);
    make_claim_block(&blocks[1], &blocks[0], pub, priv, AC_TX_CLAIM, 1, 1);
    make_claim_block(&blocks[2], &blocks[1], pub, priv, AC_TX_CLAIM, 2, 2);
    make_claim_block(&blocks[3], &blocks[2], pub, priv, AC_TX_CLAIM, 3, 3);

    rc = ac_claims_rebuild(&cs, blocks, 4, pub, lost, 10, &lost_count);
    ASSERT_OK(rc, "rebuild should succeed");
    ASSERT_EQ(ac_claims_count(&cs), 3, "should have 3 claims after rebuild");
    ASSERT_EQ(lost_count, 0, "no losses on first build");

    ac_claims_destroy(&cs);
    PASS();
}

static void test_claims_rollback_detection(void)
{
    ac_claim_store_t cs;
    ac_block_t blocks1[3], blocks2[2];
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    ac_address_t lost[10];
    uint32_t lost_count = 0;
    int rc;
    TEST("rollback detection: lost claims identified");

    ac_claims_init(&cs, 1000, 0, NULL);
    make_keypair(pub, priv);

    /* Build chain with 2 claims */
    ac_genesis_block(&blocks1[0]);
    make_claim_block(&blocks1[1], &blocks1[0], pub, priv, AC_TX_CLAIM, 1, 1);
    make_claim_block(&blocks1[2], &blocks1[1], pub, priv, AC_TX_CLAIM, 2, 2);

    ac_claims_rebuild(&cs, blocks1, 3, pub, lost, 10, &lost_count);
    ASSERT_EQ(ac_claims_count(&cs), 2, "should have 2 claims");

    /* Rebuild with shorter chain (fork: only 1 claim) */
    ac_genesis_block(&blocks2[0]);
    make_claim_block(&blocks2[1], &blocks2[0], pub, priv, AC_TX_CLAIM, 1, 1);

    rc = ac_claims_rebuild(&cs, blocks2, 2, pub, lost, 10, &lost_count);
    ASSERT_OK(rc, "rebuild should succeed");
    ASSERT_EQ(ac_claims_count(&cs), 1, "should have 1 claim");
    ASSERT_EQ(lost_count, 1, "should detect 1 lost claim");

    ac_claims_destroy(&cs);
    PASS();
}

static void test_claims_null_safety(void)
{
    int rc;
    TEST("NULL parameter safety (K01)");

    rc = ac_claims_init(NULL, 0, 0, NULL);
    ASSERT_NE(rc, AC_OK, "init(NULL) should fail");

    rc = ac_claims_get_owner(NULL, NULL, NULL);
    ASSERT_NE(rc, AC_OK, "get_owner(NULL) should fail");

    rc = ac_claims_validate_block(NULL, NULL);
    ASSERT_NE(rc, AC_OK, "validate(NULL) should fail");

    PASS();
}

/* ================================================================== */
/*  Main                                                               */
/* ================================================================== */

int main(void)
{
    printf("=== ac_claims unit tests ===\n\n");

    test_claims_init_destroy();
    test_claims_apply_claim();
    test_claims_conflict_detection();
    test_claims_release();
    test_claims_renew();
    test_claims_lease_expiry();
    test_claims_release_non_owner();
    test_claims_multiple_addresses();
    test_claims_rebuild();
    test_claims_rollback_detection();
    test_claims_null_safety();

    printf("\n=== Results: %d passed, %d failed, %d total ===\n",
           pass_count, fail_count, test_count);

    return fail_count > 0 ? 1 : 0;
}
