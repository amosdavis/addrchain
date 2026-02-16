/*
 * ac_subnet_test.c — Unit tests for ac_subnet.c
 *
 * Tests: init/destroy, SUBNET_CREATE validation, overlap detection,
 *        prefix containment, gateway/DNS requirements, SUBNET_ASSIGN,
 *        capacity limits, rebuild.
 *
 * Mitigates: N02,N05,N11,N12,N13,N14,N15,N20,N29,N31
 */

#include "ac_subnet.h"
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

    /* Fill subnet create payload */
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

        if (!(flags & AC_SUBNET_FLAG_NO_GATEWAY)) {
            set_ipv4_addr(&sc->gateway, net_a, net_b, net_c, gw_last_byte, prefix_len);
        }
        if (!(flags & AC_SUBNET_FLAG_NO_DNS)) {
            set_ipv4_addr(&sc->dns[0], 8, 8, 8, 8, 32);
            sc->dns_count = 1;
        }
    }

    ac_tx_sign(&tx, priv);
    ac_block_create(prev, &tx, 1, blk);
}

static void make_subnet_assign_block(ac_block_t *blk,
                                     const ac_block_t *prev,
                                     const uint8_t signer_pub[AC_PUBKEY_LEN],
                                     const uint8_t signer_priv[64],
                                     const char *subnet_id,
                                     const uint8_t node_pub[AC_PUBKEY_LEN],
                                     uint32_t nonce)
{
    ac_transaction_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.type = AC_TX_SUBNET_ASSIGN;
    memcpy(tx.node_pubkey, signer_pub, AC_PUBKEY_LEN);
    tx.timestamp = ac_time_unix_sec();
    tx.nonce = nonce;

    {
        ac_tx_subnet_assign_t *sa = &tx.payload.subnet_assign;
        size_t len = strlen(subnet_id);
        if (len >= AC_SUBNET_ID_LEN)
            len = AC_SUBNET_ID_LEN - 1;
        memcpy(sa->subnet_id, subnet_id, len);
        memcpy(sa->node_pubkey, node_pub, AC_PUBKEY_LEN);
    }

    ac_tx_sign(&tx, signer_priv);
    ac_block_create(prev, &tx, 1, blk);
}

/* ================================================================== */
/*  Tests                                                              */
/* ================================================================== */

static void test_subnet_init_destroy(void)
{
    ac_subnet_store_t ss;
    int rc;
    TEST("subnet store init and destroy");

    rc = ac_subnet_init(&ss, 0, 0);
    ASSERT_OK(rc, "init should succeed");
    ASSERT_EQ(ac_subnet_count(&ss), 0, "should start empty");

    ac_subnet_destroy(&ss);
    PASS();
}

static void test_subnet_create_basic(void)
{
    ac_subnet_store_t ss;
    ac_block_t genesis, blk;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    const ac_subnet_record_t *rec;
    TEST("create a subnet");

    ac_subnet_init(&ss, 0, 0);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    make_subnet_create_block(&blk, &genesis, pub, priv,
                             "lab-net", 10, 0, 0, 0, 24, 1, 0, 1);

    ASSERT_OK(ac_subnet_validate_block(&ss, &blk), "validate should pass");
    ASSERT_OK(ac_subnet_apply_block(&ss, &blk), "apply should succeed");
    ASSERT_EQ(ac_subnet_count(&ss), 1, "should have 1 subnet");

    rec = ac_subnet_find(&ss, (const uint8_t *)"lab-net\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
    ASSERT_NE((uintptr_t)rec, (uintptr_t)NULL, "should find subnet");

    ac_subnet_destroy(&ss);
    PASS();
}

static void test_subnet_duplicate_id_rejected(void)
{
    ac_subnet_store_t ss;
    ac_block_t genesis, blk1, blk2;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    int rc;
    TEST("duplicate subnet_id rejected (N11)");

    ac_subnet_init(&ss, 0, 0);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    make_subnet_create_block(&blk1, &genesis, pub, priv,
                             "dup-net", 10, 0, 0, 0, 24, 1, 0, 1);
    ac_subnet_apply_block(&ss, &blk1);

    make_subnet_create_block(&blk2, &blk1, pub, priv,
                             "dup-net", 10, 1, 0, 0, 24, 1, 0, 2);
    rc = ac_subnet_validate_block(&ss, &blk2);
    ASSERT_EQ(rc, AC_ERR_EXIST, "duplicate ID should be rejected");

    ac_subnet_destroy(&ss);
    PASS();
}

static void test_subnet_overlap_rejected(void)
{
    ac_subnet_store_t ss;
    ac_block_t genesis, blk1, blk2;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    int rc;
    TEST("overlapping prefix rejected (N11)");

    ac_subnet_init(&ss, 0, 0);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    /* Create 10.0.0.0/24 */
    make_subnet_create_block(&blk1, &genesis, pub, priv,
                             "net-a", 10, 0, 0, 0, 24, 1, 0, 1);
    ac_subnet_apply_block(&ss, &blk1);

    /* Try to create 10.0.0.0/16 — overlaps */
    make_subnet_create_block(&blk2, &blk1, pub, priv,
                             "net-b", 10, 0, 0, 0, 16, 1, 0, 2);
    rc = ac_subnet_validate_block(&ss, &blk2);
    ASSERT_EQ(rc, AC_ERR_OVERLAP, "overlapping prefix should be rejected");

    ac_subnet_destroy(&ss);
    PASS();
}

static void test_subnet_no_overlap_different_ranges(void)
{
    ac_subnet_store_t ss;
    ac_block_t genesis, blk1, blk2;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    TEST("non-overlapping prefixes allowed");

    ac_subnet_init(&ss, 0, 0);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    make_subnet_create_block(&blk1, &genesis, pub, priv,
                             "net-a", 10, 0, 0, 0, 24, 1, 0, 1);
    ac_subnet_apply_block(&ss, &blk1);

    /* 10.0.1.0/24 does not overlap 10.0.0.0/24 */
    make_subnet_create_block(&blk2, &blk1, pub, priv,
                             "net-b", 10, 0, 1, 0, 24, 1, 0, 2);
    ASSERT_OK(ac_subnet_validate_block(&ss, &blk2), "non-overlap should pass");
    ac_subnet_apply_block(&ss, &blk2);
    ASSERT_EQ(ac_subnet_count(&ss), 2, "should have 2 subnets");

    ac_subnet_destroy(&ss);
    PASS();
}

static void test_subnet_gateway_required(void)
{
    ac_subnet_store_t ss;
    ac_block_t genesis, blk;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    int rc;
    TEST("gateway REQUIRED without --no-gateway (N14)");

    ac_subnet_init(&ss, 0, 0);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    /* Create with no gateway and no NO_GATEWAY flag */
    {
        ac_transaction_t tx;
        memset(&tx, 0, sizeof(tx));
        tx.type = AC_TX_SUBNET_CREATE;
        memcpy(tx.node_pubkey, pub, AC_PUBKEY_LEN);
        tx.timestamp = ac_time_unix_sec();
        tx.nonce = 1;
        memcpy(tx.payload.subnet_create.subnet_id, "no-gw", 5);
        set_ipv4_addr(&tx.payload.subnet_create.prefix, 10, 0, 0, 0, 24);
        /* gateway left as zero */
        tx.payload.subnet_create.flags = 0; /* no NO_GATEWAY flag */
        set_ipv4_addr(&tx.payload.subnet_create.dns[0], 8, 8, 8, 8, 32);
        tx.payload.subnet_create.dns_count = 1;
        ac_tx_sign(&tx, priv);
        ac_block_create(&genesis, &tx, 1, &blk);
    }

    rc = ac_subnet_validate_block(&ss, &blk);
    ASSERT_NE(rc, AC_OK, "missing gateway should be rejected");

    ac_subnet_destroy(&ss);
    PASS();
}

static void test_subnet_no_gateway_flag(void)
{
    ac_subnet_store_t ss;
    ac_block_t genesis, blk;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    TEST("--no-gateway flag allows no gateway (N14)");

    ac_subnet_init(&ss, 0, 0);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    make_subnet_create_block(&blk, &genesis, pub, priv,
                             "isolated", 10, 0, 0, 0, 24, 1,
                             AC_SUBNET_FLAG_NO_GATEWAY | AC_SUBNET_FLAG_NO_DNS,
                             1);

    ASSERT_OK(ac_subnet_validate_block(&ss, &blk), "NO_GATEWAY should pass");

    ac_subnet_destroy(&ss);
    PASS();
}

static void test_subnet_dns_required(void)
{
    ac_subnet_store_t ss;
    ac_block_t genesis, blk;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    int rc;
    TEST("DNS REQUIRED without --no-dns (N15)");

    ac_subnet_init(&ss, 0, 0);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    {
        ac_transaction_t tx;
        memset(&tx, 0, sizeof(tx));
        tx.type = AC_TX_SUBNET_CREATE;
        memcpy(tx.node_pubkey, pub, AC_PUBKEY_LEN);
        tx.timestamp = ac_time_unix_sec();
        tx.nonce = 1;
        memcpy(tx.payload.subnet_create.subnet_id, "no-dns", 6);
        set_ipv4_addr(&tx.payload.subnet_create.prefix, 10, 0, 0, 0, 24);
        set_ipv4_addr(&tx.payload.subnet_create.gateway, 10, 0, 0, 1, 24);
        tx.payload.subnet_create.flags = 0; /* no NO_DNS flag */
        tx.payload.subnet_create.dns_count = 0; /* no DNS */
        ac_tx_sign(&tx, priv);
        ac_block_create(&genesis, &tx, 1, &blk);
    }

    rc = ac_subnet_validate_block(&ss, &blk);
    ASSERT_NE(rc, AC_OK, "missing DNS should be rejected");

    ac_subnet_destroy(&ss);
    PASS();
}

static void test_subnet_contains(void)
{
    ac_subnet_store_t ss;
    ac_block_t genesis, blk;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    const ac_subnet_record_t *rec;
    ac_address_t inside, outside;
    TEST("prefix containment check (N12)");

    ac_subnet_init(&ss, 0, 0);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    make_subnet_create_block(&blk, &genesis, pub, priv,
                             "test-net", 10, 0, 0, 0, 24, 1, 0, 1);
    ac_subnet_apply_block(&ss, &blk);

    rec = ac_subnet_find(&ss, (const uint8_t *)"test-net\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");

    set_ipv4_addr(&inside, 10, 0, 0, 42, 24);
    set_ipv4_addr(&outside, 10, 0, 1, 42, 24);

    ASSERT_EQ(ac_subnet_contains(rec, &inside), 1, "10.0.0.42 in 10.0.0.0/24");
    ASSERT_EQ(ac_subnet_contains(rec, &outside), 0, "10.0.1.42 not in 10.0.0.0/24");

    ac_subnet_destroy(&ss);
    PASS();
}

static void test_subnet_assign(void)
{
    ac_subnet_store_t ss;
    ac_block_t genesis, blk1, blk2;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    uint8_t node_pub[AC_PUBKEY_LEN], node_priv[64];
    TEST("SUBNET_ASSIGN tracks membership");

    ac_subnet_init(&ss, 0, 0);
    make_keypair(pub, priv);
    make_keypair(node_pub, node_priv);
    ac_genesis_block(&genesis);

    make_subnet_create_block(&blk1, &genesis, pub, priv,
                             "assign-net", 10, 0, 0, 0, 24, 1, 0, 1);
    ac_subnet_apply_block(&ss, &blk1);

    make_subnet_assign_block(&blk2, &blk1, pub, priv,
                             "assign-net", node_pub, 2);
    ASSERT_OK(ac_subnet_validate_block(&ss, &blk2), "assign should validate");
    ac_subnet_apply_block(&ss, &blk2);

    ASSERT_EQ(ac_subnet_is_member(&ss, node_pub,
              (const uint8_t *)"assign-net\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"),
              1, "node should be member");
    ASSERT_EQ(ac_subnet_member_count(&ss), 1, "1 member");

    ac_subnet_destroy(&ss);
    PASS();
}

static void test_subnet_assign_nonexistent(void)
{
    ac_subnet_store_t ss;
    ac_block_t genesis, blk;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    uint8_t node_pub[AC_PUBKEY_LEN], node_priv[64];
    int rc;
    TEST("ASSIGN to nonexistent subnet rejected");

    ac_subnet_init(&ss, 0, 0);
    make_keypair(pub, priv);
    make_keypair(node_pub, node_priv);
    ac_genesis_block(&genesis);

    make_subnet_assign_block(&blk, &genesis, pub, priv,
                             "ghost-net", node_pub, 1);
    rc = ac_subnet_validate_block(&ss, &blk);
    ASSERT_EQ(rc, AC_ERR_NOENT, "assign to nonexistent should fail");

    ac_subnet_destroy(&ss);
    PASS();
}

static void test_subnet_assign_duplicate(void)
{
    ac_subnet_store_t ss;
    ac_block_t genesis, blk1, blk2, blk3;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    uint8_t node_pub[AC_PUBKEY_LEN], node_priv[64];
    int rc;
    TEST("duplicate ASSIGN rejected");

    ac_subnet_init(&ss, 0, 0);
    make_keypair(pub, priv);
    make_keypair(node_pub, node_priv);
    ac_genesis_block(&genesis);

    make_subnet_create_block(&blk1, &genesis, pub, priv,
                             "dup-assign", 10, 0, 0, 0, 24, 1, 0, 1);
    ac_subnet_apply_block(&ss, &blk1);

    make_subnet_assign_block(&blk2, &blk1, pub, priv,
                             "dup-assign", node_pub, 2);
    ac_subnet_apply_block(&ss, &blk2);

    make_subnet_assign_block(&blk3, &blk2, pub, priv,
                             "dup-assign", node_pub, 3);
    rc = ac_subnet_validate_block(&ss, &blk3);
    ASSERT_EQ(rc, AC_ERR_EXIST, "duplicate assign should be rejected");

    ac_subnet_destroy(&ss);
    PASS();
}

static void test_subnet_rebuild(void)
{
    ac_subnet_store_t ss;
    ac_block_t blocks[4];
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    uint8_t node_pub[AC_PUBKEY_LEN], node_priv[64];
    TEST("rebuild from chain");

    ac_subnet_init(&ss, 0, 0);
    make_keypair(pub, priv);
    make_keypair(node_pub, node_priv);

    ac_genesis_block(&blocks[0]);
    make_subnet_create_block(&blocks[1], &blocks[0], pub, priv,
                             "rebuild-a", 10, 0, 0, 0, 24, 1, 0, 1);
    make_subnet_create_block(&blocks[2], &blocks[1], pub, priv,
                             "rebuild-b", 10, 0, 1, 0, 24, 1, 0, 2);
    make_subnet_assign_block(&blocks[3], &blocks[2], pub, priv,
                             "rebuild-a", node_pub, 3);

    ASSERT_OK(ac_subnet_rebuild(&ss, blocks, 4), "rebuild should succeed");
    ASSERT_EQ(ac_subnet_count(&ss), 2, "should have 2 subnets");
    ASSERT_EQ(ac_subnet_member_count(&ss), 1, "should have 1 member");

    ac_subnet_destroy(&ss);
    PASS();
}

static void test_subnet_null_safety(void)
{
    int rc;
    TEST("NULL parameter safety (K01)");

    rc = ac_subnet_init(NULL, 0, 0);
    ASSERT_NE(rc, AC_OK, "init(NULL) should fail");
    ASSERT_EQ(ac_subnet_count(NULL), 0, "count(NULL) should be 0");
    ASSERT_EQ((uintptr_t)ac_subnet_find(NULL, NULL), (uintptr_t)NULL, "find(NULL) should be NULL");

    PASS();
}

static void test_subnet_gateway_outside_prefix(void)
{
    ac_subnet_store_t ss;
    ac_block_t genesis, blk;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    int rc;
    TEST("gateway outside prefix rejected");

    ac_subnet_init(&ss, 0, 0);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    /* Create subnet 10.0.0.0/24 with gateway 10.0.1.1 (outside!) */
    {
        ac_transaction_t tx;
        memset(&tx, 0, sizeof(tx));
        tx.type = AC_TX_SUBNET_CREATE;
        memcpy(tx.node_pubkey, pub, AC_PUBKEY_LEN);
        tx.timestamp = ac_time_unix_sec();
        tx.nonce = 1;
        memcpy(tx.payload.subnet_create.subnet_id, "bad-gw", 6);
        set_ipv4_addr(&tx.payload.subnet_create.prefix, 10, 0, 0, 0, 24);
        set_ipv4_addr(&tx.payload.subnet_create.gateway, 10, 0, 1, 1, 24);
        set_ipv4_addr(&tx.payload.subnet_create.dns[0], 8, 8, 8, 8, 32);
        tx.payload.subnet_create.dns_count = 1;
        tx.payload.subnet_create.flags = 0;
        ac_tx_sign(&tx, priv);
        ac_block_create(&genesis, &tx, 1, &blk);
    }

    rc = ac_subnet_validate_block(&ss, &blk);
    ASSERT_NE(rc, AC_OK, "gateway outside prefix should be rejected");

    ac_subnet_destroy(&ss);
    PASS();
}

static void test_subnet_overlaps_utility(void)
{
    ac_address_t a, b, c;
    TEST("ac_subnet_overlaps utility function");

    set_ipv4_addr(&a, 10, 0, 0, 0, 24);    /* 10.0.0.0/24 */
    set_ipv4_addr(&b, 10, 0, 0, 0, 16);    /* 10.0.0.0/16 — overlaps */
    set_ipv4_addr(&c, 192, 168, 0, 0, 24); /* 192.168.0.0/24 — no overlap */

    ASSERT_EQ(ac_subnet_overlaps(&a, &b), 1, "10.0.0.0/24 overlaps 10.0.0.0/16");
    ASSERT_EQ(ac_subnet_overlaps(&a, &c), 0, "10.0.0.0/24 doesn't overlap 192.168.0.0/24");
    ASSERT_EQ(ac_subnet_overlaps(&b, &c), 0, "10.0.0.0/16 doesn't overlap 192.168.0.0/24");

    PASS();
}

static void test_subnet_empty_id_rejected(void)
{
    ac_subnet_store_t ss;
    ac_block_t genesis, blk;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    int rc;
    TEST("empty subnet_id rejected");

    ac_subnet_init(&ss, 0, 0);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    make_subnet_create_block(&blk, &genesis, pub, priv,
                             "", 10, 0, 0, 0, 24, 1, 0, 1);
    rc = ac_subnet_validate_block(&ss, &blk);
    ASSERT_NE(rc, AC_OK, "empty subnet_id should be rejected");

    ac_subnet_destroy(&ss);
    PASS();
}

/* ================================================================== */
/*  Main                                                               */
/* ================================================================== */

int main(void)
{
    printf("=== ac_subnet unit tests ===\n\n");

    test_subnet_init_destroy();
    test_subnet_create_basic();
    test_subnet_duplicate_id_rejected();
    test_subnet_overlap_rejected();
    test_subnet_no_overlap_different_ranges();
    test_subnet_gateway_required();
    test_subnet_no_gateway_flag();
    test_subnet_dns_required();
    test_subnet_contains();
    test_subnet_assign();
    test_subnet_assign_nonexistent();
    test_subnet_assign_duplicate();
    test_subnet_rebuild();
    test_subnet_null_safety();
    test_subnet_gateway_outside_prefix();
    test_subnet_overlaps_utility();
    test_subnet_empty_id_rejected();

    printf("\n=== Results: %d passed, %d failed, %d total ===\n",
           pass_count, fail_count, test_count);

    return fail_count > 0 ? 1 : 0;
}
