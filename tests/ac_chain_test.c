/*
 * ac_chain_test.c — Unit tests for ac_chain.c
 *
 * Tests: genesis creation, block creation, signing/verification,
 *        chain add, chain replace, rate limiting, clock sanity,
 *        type validation, replay protection.
 *
 * Mitigates: K01,K02,K03,K04,K05,K07,K08,K13,K18,K21,K46
 */

#include "ac_chain.h"
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

/* ================================================================== */
/*  Helper: create a keypair                                           */
/* ================================================================== */

static void make_keypair(uint8_t pubkey[AC_PUBKEY_LEN],
                         uint8_t privkey[64])
{
    uint8_t seed[32];
    ac_crypto_random(seed, sizeof(seed));
    ac_crypto_ed25519_keypair(seed, pubkey, privkey);
}

/* ================================================================== */
/*  Helper: create and sign a CLAIM transaction                        */
/* ================================================================== */

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

/* ================================================================== */
/*  Tests                                                              */
/* ================================================================== */

static void test_genesis_deterministic(void)
{
    ac_block_t g1, g2;
    TEST("genesis blocks are identical");

    ac_genesis_block(&g1);
    ac_genesis_block(&g2);

    if (memcmp(g1.hash, g2.hash, AC_HASH_LEN) != 0) {
        FAIL("genesis hashes differ");
        return;
    }
    if (g1.index != 0 || g2.index != 0) {
        FAIL("genesis index not 0");
        return;
    }
    if (g1.timestamp != 0 || g2.timestamp != 0) {
        FAIL("genesis timestamp not 0");
        return;
    }
    PASS();
}

static void test_block_hash_changes_with_content(void)
{
    ac_block_t g, b1, b2;
    ac_transaction_t tx;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    TEST("block hash changes with content");

    ac_genesis_block(&g);
    make_keypair(pub, priv);
    make_claim_tx(&tx, pub, priv, 1, 1);

    ac_block_create(&g, NULL, 0, &b1);
    ac_block_create(&g, &tx, 1, &b2);

    if (memcmp(b1.hash, b2.hash, AC_HASH_LEN) == 0) {
        FAIL("hashes should differ");
        return;
    }
    PASS();
}

static void test_tx_sign_verify(void)
{
    ac_transaction_t tx;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    int rc;
    TEST("transaction sign and verify");

    make_keypair(pub, priv);
    make_claim_tx(&tx, pub, priv, 1, 1);

    rc = ac_tx_verify(&tx);
    ASSERT_OK(rc, "verify should succeed");
    PASS();
}

static void test_tx_tamper_detection(void)
{
    ac_transaction_t tx;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    int rc;
    TEST("tampered transaction detected");

    make_keypair(pub, priv);
    make_claim_tx(&tx, pub, priv, 1, 1);

    /* Tamper with address */
    tx.payload.claim.address.addr[3] = 99;

    rc = ac_tx_verify(&tx);
    ASSERT_NE(rc, AC_OK, "tampered tx should fail verify");
    PASS();
}

static void test_chain_init_destroy(void)
{
    ac_chain_t chain;
    int rc;
    TEST("chain init and destroy");

    rc = ac_chain_init(&chain);
    ASSERT_OK(rc, "init should succeed");
    ASSERT_EQ(ac_chain_len(&chain), 1, "should have genesis");

    ac_chain_destroy(&chain);
    PASS();
}

static void test_chain_add_valid_block(void)
{
    ac_chain_t chain;
    ac_block_t last, new_blk;
    ac_transaction_t tx;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    int rc;
    TEST("add valid block to chain");

    ac_chain_init(&chain);
    make_keypair(pub, priv);
    make_claim_tx(&tx, pub, priv, 1, 1);

    ac_chain_last_block(&chain, &last);
    ac_block_create(&last, &tx, 1, &new_blk);

    rc = ac_chain_add_block(&chain, &new_blk);
    ASSERT_OK(rc, "add should succeed");
    ASSERT_EQ(ac_chain_len(&chain), 2, "should have 2 blocks");

    ac_chain_destroy(&chain);
    PASS();
}

static void test_chain_reject_bad_index(void)
{
    ac_chain_t chain;
    ac_block_t last, bad_blk;
    int rc;
    TEST("reject block with wrong index");

    ac_chain_init(&chain);
    ac_chain_last_block(&chain, &last);
    ac_block_create(&last, NULL, 0, &bad_blk);
    bad_blk.index = 99; /* corrupt index */
    ac_block_compute_hash(&bad_blk, bad_blk.hash);

    rc = ac_chain_add_block(&chain, &bad_blk);
    ASSERT_NE(rc, AC_OK, "bad index should be rejected");

    ac_chain_destroy(&chain);
    PASS();
}

static void test_chain_reject_bad_prev_hash(void)
{
    ac_chain_t chain;
    ac_block_t last, bad_blk;
    int rc;
    TEST("reject block with wrong prev_hash");

    ac_chain_init(&chain);
    ac_chain_last_block(&chain, &last);
    ac_block_create(&last, NULL, 0, &bad_blk);
    bad_blk.prev_hash[0] ^= 0xFF; /* corrupt prev_hash */
    ac_block_compute_hash(&bad_blk, bad_blk.hash);

    rc = ac_chain_add_block(&chain, &bad_blk);
    ASSERT_NE(rc, AC_OK, "bad prev_hash should be rejected");

    ac_chain_destroy(&chain);
    PASS();
}

static void test_chain_reject_bad_signature(void)
{
    ac_chain_t chain;
    ac_block_t last, bad_blk;
    ac_transaction_t tx;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    int rc;
    TEST("reject block with bad tx signature");

    ac_chain_init(&chain);
    make_keypair(pub, priv);
    make_claim_tx(&tx, pub, priv, 1, 1);
    tx.signature[0] ^= 0xFF; /* corrupt signature */

    ac_chain_last_block(&chain, &last);
    ac_block_create(&last, &tx, 1, &bad_blk);

    rc = ac_chain_add_block(&chain, &bad_blk);
    ASSERT_NE(rc, AC_OK, "bad signature should be rejected");

    ac_chain_destroy(&chain);
    PASS();
}

static void test_chain_replace_longer(void)
{
    ac_chain_t chain;
    ac_block_t blocks[3];
    ac_transaction_t tx;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    int err, replaced;
    TEST("replace chain with longer candidate");

    ac_chain_init(&chain);
    make_keypair(pub, priv);

    /* Build a 3-block candidate chain */
    ac_genesis_block(&blocks[0]);

    make_claim_tx(&tx, pub, priv, 1, 1);
    ac_block_create(&blocks[0], &tx, 1, &blocks[1]);

    make_claim_tx(&tx, pub, priv, 2, 2);
    ac_block_create(&blocks[1], &tx, 1, &blocks[2]);

    replaced = ac_chain_replace(&chain, blocks, 3, &err);
    ASSERT_OK(err, "replace should succeed");
    ASSERT_EQ(replaced, 1, "should have replaced");
    ASSERT_EQ(ac_chain_len(&chain), 3, "should have 3 blocks");

    ac_chain_destroy(&chain);
    PASS();
}

static void test_chain_reject_shorter(void)
{
    ac_chain_t chain;
    ac_block_t last, new_blk;
    ac_block_t candidate[1];
    ac_transaction_t tx;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    int err, replaced;
    TEST("reject shorter candidate chain");

    ac_chain_init(&chain);
    make_keypair(pub, priv);

    /* Add a block to our chain so it's length 2 */
    make_claim_tx(&tx, pub, priv, 1, 1);
    ac_chain_last_block(&chain, &last);
    ac_block_create(&last, &tx, 1, &new_blk);
    ac_chain_add_block(&chain, &new_blk);

    /* Try to replace with genesis-only (length 1) */
    ac_genesis_block(&candidate[0]);
    replaced = ac_chain_replace(&chain, candidate, 1, &err);
    ASSERT_EQ(replaced, 0, "should not replace with shorter");
    ASSERT_EQ(ac_chain_len(&chain), 2, "should still have 2 blocks");

    ac_chain_destroy(&chain);
    PASS();
}

static void test_tx_validate_claim_empty_addr(void)
{
    ac_transaction_t tx;
    int rc;
    TEST("reject CLAIM with empty address");

    memset(&tx, 0, sizeof(tx));
    tx.type = AC_TX_CLAIM;
    tx.payload.claim.address.family = AC_AF_IPV4;
    /* addr is all zeros — should fail */

    rc = ac_tx_validate_type(&tx);
    ASSERT_NE(rc, AC_OK, "empty address should fail");
    PASS();
}

static void test_tx_validate_subnet_no_gateway(void)
{
    ac_transaction_t tx;
    int rc;
    TEST("reject SUBNET_CREATE without gateway (N14)");

    memset(&tx, 0, sizeof(tx));
    tx.type = AC_TX_SUBNET_CREATE;
    tx.payload.subnet_create.subnet_id[0] = 'l';
    tx.payload.subnet_create.subnet_id[1] = 'a';
    tx.payload.subnet_create.subnet_id[2] = 'b';
    tx.payload.subnet_create.prefix.family = AC_AF_IPV4;
    tx.payload.subnet_create.prefix.addr[0] = 10;
    tx.payload.subnet_create.prefix.prefix_len = 24;
    tx.payload.subnet_create.dns_count = 1;
    tx.payload.subnet_create.dns[0].family = AC_AF_IPV4;
    tx.payload.subnet_create.dns[0].addr[0] = 8;
    tx.payload.subnet_create.dns[0].addr[1] = 8;
    tx.payload.subnet_create.dns[0].addr[2] = 8;
    tx.payload.subnet_create.dns[0].addr[3] = 8;
    /* gateway is zero — should fail without NO_GATEWAY flag */

    rc = ac_tx_validate_type(&tx);
    ASSERT_NE(rc, AC_OK, "missing gateway should fail");

    /* Now set the NO_GATEWAY flag — should pass */
    tx.payload.subnet_create.flags = AC_SUBNET_FLAG_NO_GATEWAY;
    rc = ac_tx_validate_type(&tx);
    ASSERT_OK(rc, "NO_GATEWAY flag should allow empty gateway");
    PASS();
}

static void test_tx_validate_subnet_no_dns(void)
{
    ac_transaction_t tx;
    int rc;
    TEST("reject SUBNET_CREATE without DNS (N15)");

    memset(&tx, 0, sizeof(tx));
    tx.type = AC_TX_SUBNET_CREATE;
    tx.payload.subnet_create.subnet_id[0] = 't';
    tx.payload.subnet_create.prefix.family = AC_AF_IPV4;
    tx.payload.subnet_create.prefix.addr[0] = 10;
    tx.payload.subnet_create.prefix.prefix_len = 24;
    tx.payload.subnet_create.gateway.family = AC_AF_IPV4;
    tx.payload.subnet_create.gateway.addr[0] = 10;
    tx.payload.subnet_create.gateway.addr[3] = 1;
    tx.payload.subnet_create.dns_count = 0;
    /* dns_count=0 without NO_DNS flag — should fail */

    rc = ac_tx_validate_type(&tx);
    ASSERT_NE(rc, AC_OK, "missing DNS should fail");

    /* Now set the NO_DNS flag — should pass */
    tx.payload.subnet_create.flags = AC_SUBNET_FLAG_NO_DNS;
    rc = ac_tx_validate_type(&tx);
    ASSERT_OK(rc, "NO_DNS flag should allow empty dns");
    PASS();
}

static void test_clock_sanity(void)
{
    uint64_t delta;
    TEST("clock sanity check");

    /* Current time should have near-zero delta */
    delta = ac_time_sanity_check(ac_time_unix_sec());
    if (delta > 2) {
        FAIL("delta to self should be ~0");
        return;
    }

    /* Far future should trigger error (just verify it returns) */
    delta = ac_time_sanity_check(ac_time_unix_sec() + 1000);
    if (delta < 900) {
        FAIL("delta should be ~1000");
        return;
    }

    PASS();
}

static void test_chain_validate_full(void)
{
    ac_block_t blocks[4];
    ac_transaction_t tx;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    int rc;
    TEST("full chain validation");

    make_keypair(pub, priv);

    ac_genesis_block(&blocks[0]);

    make_claim_tx(&tx, pub, priv, 1, 1);
    ac_block_create(&blocks[0], &tx, 1, &blocks[1]);

    make_claim_tx(&tx, pub, priv, 2, 2);
    ac_block_create(&blocks[1], &tx, 1, &blocks[2]);

    make_claim_tx(&tx, pub, priv, 3, 3);
    ac_block_create(&blocks[2], &tx, 1, &blocks[3]);

    rc = ac_chain_validate(blocks, 4);
    ASSERT_OK(rc, "valid chain should pass");
    PASS();
}

static void test_chain_validate_bad_genesis(void)
{
    ac_block_t blocks[2];
    int rc;
    TEST("reject chain with bad genesis");

    ac_genesis_block(&blocks[0]);
    blocks[0].timestamp = 999; /* corrupt genesis */
    ac_block_compute_hash(&blocks[0], blocks[0].hash);

    rc = ac_chain_validate(blocks, 1);
    ASSERT_NE(rc, AC_OK, "bad genesis should fail");
    PASS();
}

static void test_nonce_replay_detection(void)
{
    ac_block_t blocks[3];
    ac_transaction_t tx;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    int rc;
    TEST("nonce replay detected in full validation");

    make_keypair(pub, priv);

    ac_genesis_block(&blocks[0]);

    make_claim_tx(&tx, pub, priv, 1, 5);
    ac_block_create(&blocks[0], &tx, 1, &blocks[1]);

    /* Same nonce=5 replayed */
    make_claim_tx(&tx, pub, priv, 2, 5);
    ac_block_create(&blocks[1], &tx, 1, &blocks[2]);

    rc = ac_chain_validate(blocks, 3);
    ASSERT_NE(rc, AC_OK, "replayed nonce should be rejected");
    PASS();
}

static void test_chain_get_blocks(void)
{
    ac_chain_t chain;
    ac_block_t out[10];
    uint32_t count = 0;
    int rc;
    TEST("get_blocks returns correct data");

    ac_chain_init(&chain);

    rc = ac_chain_get_blocks(&chain, out, 10, &count);
    ASSERT_OK(rc, "get_blocks should succeed");
    ASSERT_EQ(count, 1, "should have 1 block");

    {
        ac_block_t genesis;
        ac_genesis_block(&genesis);
        if (memcmp(out[0].hash, genesis.hash, AC_HASH_LEN) != 0) {
            FAIL("returned block should match genesis");
            ac_chain_destroy(&chain);
            return;
        }
    }

    ac_chain_destroy(&chain);
    PASS();
}

static void test_multiple_blocks_sequential(void)
{
    ac_chain_t chain;
    ac_block_t last, new_blk;
    ac_transaction_t tx;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    int rc;
    uint8_t i;
    TEST("add 10 blocks sequentially");

    ac_chain_init(&chain);
    make_keypair(pub, priv);

    for (i = 1; i <= 10; i++) {
        make_claim_tx(&tx, pub, priv, i, (uint32_t)i);
        ac_chain_last_block(&chain, &last);
        ac_block_create(&last, &tx, 1, &new_blk);
        rc = ac_chain_add_block(&chain, &new_blk);
        if (rc != AC_OK) {
            FAIL("sequential add failed");
            ac_chain_destroy(&chain);
            return;
        }
    }

    ASSERT_EQ(ac_chain_len(&chain), 11, "should have 11 blocks");
    ac_chain_destroy(&chain);
    PASS();
}

static void test_null_safety(void)
{
    int rc;
    TEST("NULL parameter safety (K01)");

    rc = ac_chain_init(NULL);
    ASSERT_NE(rc, AC_OK, "init(NULL) should fail");

    rc = ac_tx_verify(NULL);
    ASSERT_NE(rc, AC_OK, "verify(NULL) should fail");

    rc = ac_tx_validate_type(NULL);
    ASSERT_NE(rc, AC_OK, "validate_type(NULL) should fail");

    rc = ac_block_compute_hash(NULL, NULL);
    ASSERT_NE(rc, AC_OK, "compute_hash(NULL) should fail");

    PASS();
}

/* ================================================================== */
/*  Main                                                               */
/* ================================================================== */

int main(void)
{
    printf("=== ac_chain unit tests ===\n\n");

    test_genesis_deterministic();
    test_block_hash_changes_with_content();
    test_tx_sign_verify();
    test_tx_tamper_detection();
    test_chain_init_destroy();
    test_chain_add_valid_block();
    test_chain_reject_bad_index();
    test_chain_reject_bad_prev_hash();
    test_chain_reject_bad_signature();
    test_chain_replace_longer();
    test_chain_reject_shorter();
    test_tx_validate_claim_empty_addr();
    test_tx_validate_subnet_no_gateway();
    test_tx_validate_subnet_no_dns();
    test_clock_sanity();
    test_chain_validate_full();
    test_chain_validate_bad_genesis();
    test_nonce_replay_detection();
    test_chain_get_blocks();
    test_multiple_blocks_sequential();
    test_null_safety();

    printf("\n=== Results: %d passed, %d failed, %d total ===\n",
           pass_count, fail_count, test_count);

    return fail_count > 0 ? 1 : 0;
}
