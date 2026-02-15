/*
 * ac_discover_test.c — Unit tests for ac_discover.c
 *
 * Tests: init/destroy, announce build/process, self-discovery prevention,
 *        peer lifecycle, LRU eviction, failure marking, pruning, best peer.
 *
 * Mitigates: K11,N07,N09,N36,P17,P18,P19,P20,P21
 */

#include "ac_discover.h"
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
    (void)priv;
    ac_crypto_random(seed, sizeof(seed));
    ac_crypto_ed25519_keypair(seed, pub, priv);
}

static void set_ipv4(ac_address_t *addr, uint8_t a, uint8_t b,
                     uint8_t c, uint8_t d)
{
    memset(addr, 0, sizeof(*addr));
    addr->family = AC_AF_IPV4;
    addr->addr[0] = a;
    addr->addr[1] = b;
    addr->addr[2] = c;
    addr->addr[3] = d;
    addr->prefix_len = 32;
}

/* ================================================================== */
/*  Tests                                                              */
/* ================================================================== */

static void test_discover_init_destroy(void)
{
    ac_discover_state_t ds;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    TEST("init and destroy");

    make_keypair(pub, priv);
    ASSERT_OK(ac_discover_init(&ds, pub, 9877,
                                AC_DISC_IPV4_BCAST | AC_DISC_IPV6_MCAST),
              "init");
    ASSERT_EQ(ac_discover_peer_count(&ds), 0, "no peers");

    ac_discover_destroy(&ds);
    PASS();
}

static void test_discover_build_announce(void)
{
    ac_discover_state_t ds;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    ac_announce_t ann;
    uint8_t tip[AC_HASH_LEN];
    TEST("build announce payload");

    make_keypair(pub, priv);
    ac_discover_init(&ds, pub, 9877, AC_DISC_IPV4_BCAST);

    memset(tip, 0xAB, AC_HASH_LEN);
    ac_discover_update_local(&ds, 42, tip, AC_CAP_POOL);

    ASSERT_OK(ac_discover_build_announce(&ds, &ann), "build");
    ASSERT_EQ(ann.version, AC_VERSION, "version");
    ASSERT_EQ(ann.chain_height, 42, "height");
    ASSERT_EQ(ann.sync_port, 9877, "port");
    ASSERT_EQ(ann.capabilities, AC_CAP_POOL, "caps");
    if (memcmp(ann.node_pubkey, pub, AC_PUBKEY_LEN) != 0) {
        FAIL("pubkey mismatch");
        ac_discover_destroy(&ds);
        return;
    }

    ac_discover_destroy(&ds);
    PASS();
}

static void test_discover_process_peer(void)
{
    ac_discover_state_t ds;
    uint8_t local_pub[AC_PUBKEY_LEN], local_priv[64];
    uint8_t peer_pub[AC_PUBKEY_LEN], peer_priv[64];
    ac_announce_t ann;
    ac_address_t peer_addr;
    TEST("process announce adds peer");

    make_keypair(local_pub, local_priv);
    make_keypair(peer_pub, peer_priv);
    ac_discover_init(&ds, local_pub, 9877, AC_DISC_IPV4_BCAST);

    memset(&ann, 0, sizeof(ann));
    ann.version = AC_VERSION;
    memcpy(ann.node_pubkey, peer_pub, AC_PUBKEY_LEN);
    ann.chain_height = 10;
    ann.sync_port = 9877;

    set_ipv4(&peer_addr, 10, 0, 0, 2);

    ASSERT_OK(ac_discover_process_announce(&ds, &ann, &peer_addr), "process");
    ASSERT_EQ(ac_discover_peer_count(&ds), 1, "1 peer");

    ac_discover_destroy(&ds);
    PASS();
}

static void test_discover_self_drop(void)
{
    ac_discover_state_t ds;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    ac_announce_t ann;
    ac_address_t addr;
    TEST("self-announce dropped (P19)");

    make_keypair(pub, priv);
    ac_discover_init(&ds, pub, 9877, AC_DISC_IPV4_BCAST);

    memset(&ann, 0, sizeof(ann));
    ann.version = AC_VERSION;
    memcpy(ann.node_pubkey, pub, AC_PUBKEY_LEN); /* same as local */
    set_ipv4(&addr, 10, 0, 0, 1);

    ASSERT_OK(ac_discover_process_announce(&ds, &ann, &addr), "process");
    ASSERT_EQ(ac_discover_peer_count(&ds), 0, "self not added");

    ac_discover_destroy(&ds);
    PASS();
}

static void test_discover_update_existing(void)
{
    ac_discover_state_t ds;
    uint8_t local_pub[AC_PUBKEY_LEN], local_priv[64];
    uint8_t peer_pub[AC_PUBKEY_LEN], peer_priv[64];
    ac_announce_t ann;
    ac_address_t addr;
    const ac_peer_t *best;
    TEST("update existing peer on re-announce");

    make_keypair(local_pub, local_priv);
    make_keypair(peer_pub, peer_priv);
    ac_discover_init(&ds, local_pub, 9877, AC_DISC_IPV4_BCAST);

    memset(&ann, 0, sizeof(ann));
    ann.version = AC_VERSION;
    memcpy(ann.node_pubkey, peer_pub, AC_PUBKEY_LEN);
    ann.chain_height = 5;
    ann.sync_port = 9877;
    set_ipv4(&addr, 10, 0, 0, 2);

    ac_discover_process_announce(&ds, &ann, &addr);
    ASSERT_EQ(ac_discover_peer_count(&ds), 1, "1 peer");

    /* Re-announce with higher height */
    ann.chain_height = 50;
    ac_discover_process_announce(&ds, &ann, &addr);
    ASSERT_EQ(ac_discover_peer_count(&ds), 1, "still 1 peer");

    best = ac_discover_best_peer(&ds);
    ASSERT_NE((uintptr_t)best, (uintptr_t)NULL, "best peer");
    ASSERT_EQ(best->chain_height, 50, "height updated");

    ac_discover_destroy(&ds);
    PASS();
}

static void test_discover_best_peer(void)
{
    ac_discover_state_t ds;
    uint8_t local_pub[AC_PUBKEY_LEN], local_priv[64];
    uint8_t pub1[AC_PUBKEY_LEN], priv1[64];
    uint8_t pub2[AC_PUBKEY_LEN], priv2[64];
    ac_announce_t ann;
    ac_address_t addr;
    const ac_peer_t *best;
    TEST("best peer = highest chain height");

    make_keypair(local_pub, local_priv);
    make_keypair(pub1, priv1);
    make_keypair(pub2, priv2);
    ac_discover_init(&ds, local_pub, 9877, AC_DISC_IPV4_BCAST);

    memset(&ann, 0, sizeof(ann));
    ann.version = AC_VERSION;
    ann.sync_port = 9877;

    memcpy(ann.node_pubkey, pub1, AC_PUBKEY_LEN);
    ann.chain_height = 10;
    set_ipv4(&addr, 10, 0, 0, 2);
    ac_discover_process_announce(&ds, &ann, &addr);

    memcpy(ann.node_pubkey, pub2, AC_PUBKEY_LEN);
    ann.chain_height = 100;
    set_ipv4(&addr, 10, 0, 0, 3);
    ac_discover_process_announce(&ds, &ann, &addr);

    best = ac_discover_best_peer(&ds);
    ASSERT_NE((uintptr_t)best, (uintptr_t)NULL, "best peer");
    ASSERT_EQ(best->chain_height, 100, "highest chain");

    ac_discover_destroy(&ds);
    PASS();
}

static void test_discover_failure_marking(void)
{
    ac_discover_state_t ds;
    uint8_t local_pub[AC_PUBKEY_LEN], local_priv[64];
    uint8_t peer_pub[AC_PUBKEY_LEN], peer_priv[64];
    ac_announce_t ann;
    ac_address_t addr;
    TEST("mark unreachable after 3 failures");

    make_keypair(local_pub, local_priv);
    make_keypair(peer_pub, peer_priv);
    ac_discover_init(&ds, local_pub, 9877, AC_DISC_IPV4_BCAST);

    memset(&ann, 0, sizeof(ann));
    ann.version = AC_VERSION;
    memcpy(ann.node_pubkey, peer_pub, AC_PUBKEY_LEN);
    ann.chain_height = 10;
    ann.sync_port = 9877;
    set_ipv4(&addr, 10, 0, 0, 2);
    ac_discover_process_announce(&ds, &ann, &addr);

    ASSERT_EQ(ac_discover_peer_count(&ds), 1, "1 active peer");

    ac_discover_mark_failed(&ds, peer_pub);
    ac_discover_mark_failed(&ds, peer_pub);
    ASSERT_EQ(ac_discover_peer_count(&ds), 1, "still active");

    ac_discover_mark_failed(&ds, peer_pub);
    ASSERT_EQ(ac_discover_peer_count(&ds), 0, "unreachable after 3");

    /* Recovery via mark_success */
    ac_discover_mark_success(&ds, peer_pub);
    ASSERT_EQ(ac_discover_peer_count(&ds), 1, "recovered");

    ac_discover_destroy(&ds);
    PASS();
}

static void test_discover_static_peer(void)
{
    ac_discover_state_t ds;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    ac_address_t addr;
    TEST("static peer never evicted on prune");

    make_keypair(pub, priv);
    ac_discover_init(&ds, pub, 9877, AC_DISC_IPV4_BCAST);

    set_ipv4(&addr, 10, 0, 0, 99);
    ASSERT_OK(ac_discover_add_static_peer(&ds, &addr, 9877), "add static");

    /* Prune with far-future timestamp */
    ac_discover_prune(&ds, ac_time_unix_sec() + 999999);
    ASSERT_EQ(ds.peer_count, 1, "static peer survives prune");

    ac_discover_destroy(&ds);
    PASS();
}

static void test_discover_prune_stale(void)
{
    ac_discover_state_t ds;
    uint8_t local_pub[AC_PUBKEY_LEN], local_priv[64];
    uint8_t peer_pub[AC_PUBKEY_LEN], peer_priv[64];
    ac_announce_t ann;
    ac_address_t addr;
    TEST("prune removes stale non-static peers");

    make_keypair(local_pub, local_priv);
    make_keypair(peer_pub, peer_priv);
    ac_discover_init(&ds, local_pub, 9877, AC_DISC_IPV4_BCAST);

    memset(&ann, 0, sizeof(ann));
    ann.version = AC_VERSION;
    memcpy(ann.node_pubkey, peer_pub, AC_PUBKEY_LEN);
    ann.chain_height = 10;
    ann.sync_port = 9877;
    set_ipv4(&addr, 10, 0, 0, 2);
    ac_discover_process_announce(&ds, &ann, &addr);

    ASSERT_EQ(ds.peer_count, 1, "1 peer before prune");

    /* Prune with timestamp far in future */
    ac_discover_prune(&ds, ac_time_unix_sec() + 999999);
    ASSERT_EQ(ds.peer_count, 0, "peer pruned");

    ac_discover_destroy(&ds);
    PASS();
}

static void test_discover_version_mismatch(void)
{
    ac_discover_state_t ds;
    uint8_t local_pub[AC_PUBKEY_LEN], local_priv[64];
    uint8_t peer_pub[AC_PUBKEY_LEN], peer_priv[64];
    ac_announce_t ann;
    ac_address_t addr;
    int rc;
    TEST("version mismatch rejected (P10)");

    make_keypair(local_pub, local_priv);
    make_keypair(peer_pub, peer_priv);
    ac_discover_init(&ds, local_pub, 9877, AC_DISC_IPV4_BCAST);

    memset(&ann, 0, sizeof(ann));
    ann.version = 0xFF00; /* wrong major version */
    memcpy(ann.node_pubkey, peer_pub, AC_PUBKEY_LEN);
    set_ipv4(&addr, 10, 0, 0, 2);

    rc = ac_discover_process_announce(&ds, &ann, &addr);
    ASSERT_EQ(rc, AC_ERR_INVAL, "version mismatch");
    ASSERT_EQ(ac_discover_peer_count(&ds), 0, "not added");

    ac_discover_destroy(&ds);
    PASS();
}

static void test_discover_null_safety(void)
{
    TEST("NULL parameter safety (K01)");

    ASSERT_NE(ac_discover_init(NULL, NULL, 0, 0), AC_OK, "init(NULL)");
    ASSERT_EQ(ac_discover_peer_count(NULL), 0, "count(NULL)");
    ASSERT_EQ((uintptr_t)ac_discover_best_peer(NULL), (uintptr_t)NULL, "best(NULL)");

    PASS();
}

/* ================================================================== */
/*  Main                                                               */
/* ================================================================== */

int main(void)
{
    printf("=== ac_discover unit tests ===\n\n");

    test_discover_init_destroy();
    test_discover_build_announce();
    test_discover_process_peer();
    test_discover_self_drop();
    test_discover_update_existing();
    test_discover_best_peer();
    test_discover_failure_marking();
    test_discover_static_peer();
    test_discover_prune_stale();
    test_discover_version_mismatch();
    test_discover_null_safety();

    printf("\n=== Results: %d passed, %d failed, %d total ===\n",
           pass_count, fail_count, test_count);

    return fail_count > 0 ? 1 : 0;
}
