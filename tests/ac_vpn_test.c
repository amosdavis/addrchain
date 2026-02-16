/*
 * ac_vpn_test.c — Unit tests for ac_vpn.c
 *
 * Tests: init/destroy, VPN_KEY/VPN_TUNNEL validation, state machine
 *        transitions, handshake marking, traffic counters, pruning,
 *        rekey lifecycle, rebuild.
 *
 * Mitigates: K42,K43,K44,K45,N25,N26,N27,N28
 */

#include "ac_vpn.h"
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

static void set_ipv4(ac_address_t *addr, uint8_t a, uint8_t b,
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

static void make_vpn_key_block(ac_block_t *blk,
                               const ac_block_t *prev,
                               const uint8_t pub[AC_PUBKEY_LEN],
                               const uint8_t priv[64],
                               uint8_t proto,
                               uint32_t nonce)
{
    ac_transaction_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.type = AC_TX_VPN_KEY;
    memcpy(tx.node_pubkey, pub, AC_PUBKEY_LEN);
    tx.timestamp = ac_time_unix_sec();
    tx.nonce = nonce;

    tx.payload.vpn_key.vpn_proto = proto;
    /* Generate a random VPN pubkey */
    ac_crypto_random(tx.payload.vpn_key.vpn_pubkey, AC_PUBKEY_LEN);

    ac_tx_sign(&tx, priv);
    ac_block_create(prev, &tx, 1, blk);
}

static void make_vpn_tunnel_block(ac_block_t *blk,
                                  const ac_block_t *prev,
                                  const uint8_t pub[AC_PUBKEY_LEN],
                                  const uint8_t priv[64],
                                  uint8_t proto,
                                  uint16_t port,
                                  uint32_t nonce)
{
    ac_transaction_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.type = AC_TX_VPN_TUNNEL;
    memcpy(tx.node_pubkey, pub, AC_PUBKEY_LEN);
    tx.timestamp = ac_time_unix_sec();
    tx.nonce = nonce;

    tx.payload.vpn_tunnel.vpn_proto = proto;
    set_ipv4(&tx.payload.vpn_tunnel.endpoint, 203, 0, 113, 1, 32);
    tx.payload.vpn_tunnel.listen_port = port;
    tx.payload.vpn_tunnel.mtu = 1420;
    tx.payload.vpn_tunnel.persistent_keepalive = 25;

    /* One allowed IP */
    set_ipv4(&tx.payload.vpn_tunnel.allowed_ips[0], 10, 0, 0, 0, 24);
    tx.payload.vpn_tunnel.allowed_ip_count = 1;

    ac_tx_sign(&tx, priv);
    ac_block_create(prev, &tx, 1, blk);
}

/* ================================================================== */
/*  Tests                                                              */
/* ================================================================== */

static void test_vpn_init_destroy(void)
{
    ac_vpn_store_t vs;
    TEST("vpn store init and destroy");

    ASSERT_OK(ac_vpn_init(&vs, 0), "init");
    ASSERT_EQ(ac_vpn_count(&vs), 0, "empty");

    ac_vpn_destroy(&vs);
    PASS();
}

static void test_vpn_key_creates_tunnel(void)
{
    ac_vpn_store_t vs;
    ac_block_t genesis, blk;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    const ac_vpn_tunnel_t *tun;
    TEST("VPN_KEY creates KEYED tunnel");

    ac_vpn_init(&vs, 0);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    make_vpn_key_block(&blk, &genesis, pub, priv, AC_VPN_WIREGUARD, 1);
    ASSERT_OK(ac_vpn_validate_block(&vs, &blk), "validate");
    ASSERT_OK(ac_vpn_apply_block(&vs, &blk), "apply");
    ASSERT_EQ(ac_vpn_count(&vs), 1, "1 tunnel");

    tun = ac_vpn_find(&vs, pub);
    ASSERT_NE((uintptr_t)tun, (uintptr_t)NULL, "should find tunnel");
    ASSERT_EQ(tun->state, AC_VPN_STATE_KEYED, "state should be KEYED");
    ASSERT_EQ(tun->vpn_proto, AC_VPN_WIREGUARD, "proto should be WG");

    ac_vpn_destroy(&vs);
    PASS();
}

static void test_vpn_tunnel_config(void)
{
    ac_vpn_store_t vs;
    ac_block_t genesis, blk1, blk2;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    const ac_vpn_tunnel_t *tun;
    TEST("VPN_TUNNEL sets endpoint config");

    ac_vpn_init(&vs, 0);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    make_vpn_key_block(&blk1, &genesis, pub, priv, AC_VPN_WIREGUARD, 1);
    ac_vpn_apply_block(&vs, &blk1);

    make_vpn_tunnel_block(&blk2, &blk1, pub, priv, AC_VPN_WIREGUARD, 51820, 2);
    ASSERT_OK(ac_vpn_validate_block(&vs, &blk2), "validate");
    ac_vpn_apply_block(&vs, &blk2);

    tun = ac_vpn_find(&vs, pub);
    ASSERT_EQ(tun->listen_port, 51820, "port");
    ASSERT_EQ(tun->mtu, 1420, "MTU");
    ASSERT_EQ(tun->allowed_ip_count, 1, "allowed IPs");

    ac_vpn_destroy(&vs);
    PASS();
}

static void test_vpn_state_transitions(void)
{
    ac_vpn_store_t vs;
    ac_block_t genesis, blk;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    TEST("state machine transitions");

    ac_vpn_init(&vs, 0);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    make_vpn_key_block(&blk, &genesis, pub, priv, AC_VPN_WIREGUARD, 1);
    ac_vpn_apply_block(&vs, &blk);

    /* KEYED → ACTIVE */
    ASSERT_OK(ac_vpn_transition(&vs, pub, AC_VPN_STATE_ACTIVE), "KEYED→ACTIVE");

    /* ACTIVE → REKEYING */
    ASSERT_OK(ac_vpn_transition(&vs, pub, AC_VPN_STATE_REKEYING), "ACTIVE→REKEYING");

    /* REKEYING → ACTIVE */
    ASSERT_OK(ac_vpn_transition(&vs, pub, AC_VPN_STATE_ACTIVE), "REKEYING→ACTIVE");

    /* ACTIVE → CLOSED */
    ASSERT_OK(ac_vpn_transition(&vs, pub, AC_VPN_STATE_CLOSED), "ACTIVE→CLOSED");

    ac_vpn_destroy(&vs);
    PASS();
}

static void test_vpn_invalid_transition(void)
{
    ac_vpn_store_t vs;
    ac_block_t genesis, blk;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    int rc;
    TEST("invalid state transition rejected");

    ac_vpn_init(&vs, 0);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    make_vpn_key_block(&blk, &genesis, pub, priv, AC_VPN_WIREGUARD, 1);
    ac_vpn_apply_block(&vs, &blk);

    /* KEYED → REKEYING is invalid */
    rc = ac_vpn_transition(&vs, pub, AC_VPN_STATE_REKEYING);
    ASSERT_EQ(rc, AC_ERR_INVAL, "KEYED→REKEYING should fail");

    ac_vpn_destroy(&vs);
    PASS();
}

static void test_vpn_handshake_marking(void)
{
    ac_vpn_store_t vs;
    ac_block_t genesis, blk;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    const ac_vpn_tunnel_t *tun;
    uint64_t now;
    TEST("handshake marking advances to ACTIVE");

    ac_vpn_init(&vs, 0);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    make_vpn_key_block(&blk, &genesis, pub, priv, AC_VPN_IPSEC, 1);
    ac_vpn_apply_block(&vs, &blk);

    now = ac_time_unix_sec();
    ac_vpn_mark_handshake(&vs, pub, now);

    tun = ac_vpn_find(&vs, pub);
    ASSERT_EQ(tun->state, AC_VPN_STATE_ACTIVE, "should be ACTIVE");
    ASSERT_EQ(tun->last_handshake, now, "handshake time set");

    ac_vpn_destroy(&vs);
    PASS();
}

static void test_vpn_traffic_counters(void)
{
    ac_vpn_store_t vs;
    ac_block_t genesis, blk;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    const ac_vpn_tunnel_t *tun;
    TEST("traffic counter updates");

    ac_vpn_init(&vs, 0);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    make_vpn_key_block(&blk, &genesis, pub, priv, AC_VPN_POOL, 1);
    ac_vpn_apply_block(&vs, &blk);

    ac_vpn_update_traffic(&vs, pub, 1000, 2000);
    ac_vpn_update_traffic(&vs, pub, 500, 300);

    tun = ac_vpn_find(&vs, pub);
    ASSERT_EQ(tun->bytes_tx, 1500, "tx bytes");
    ASSERT_EQ(tun->bytes_rx, 2300, "rx bytes");

    ac_vpn_destroy(&vs);
    PASS();
}

static void test_vpn_prune_stale(void)
{
    ac_vpn_store_t vs;
    ac_block_t genesis, blk;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    TEST("prune stale KEYED tunnels after timeout");

    ac_vpn_init(&vs, 0);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    make_vpn_key_block(&blk, &genesis, pub, priv, AC_VPN_WIREGUARD, 1);
    ac_vpn_apply_block(&vs, &blk);
    ASSERT_EQ(ac_vpn_count(&vs), 1, "1 tunnel");

    /* Prune with future time beyond handshake timeout */
    ac_vpn_prune_stale(&vs, ac_time_unix_sec() + AC_VPN_HANDSHAKE_TIMEOUT_SEC + 10);
    ASSERT_EQ(ac_vpn_count(&vs), 0, "pruned after timeout");

    ac_vpn_destroy(&vs);
    PASS();
}

static void test_vpn_invalid_protocol(void)
{
    ac_vpn_store_t vs;
    ac_block_t genesis, blk;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    ac_transaction_t tx;
    int rc;
    TEST("invalid VPN protocol rejected");

    ac_vpn_init(&vs, 0);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    memset(&tx, 0, sizeof(tx));
    tx.type = AC_TX_VPN_KEY;
    memcpy(tx.node_pubkey, pub, AC_PUBKEY_LEN);
    tx.timestamp = ac_time_unix_sec();
    tx.nonce = 1;
    tx.payload.vpn_key.vpn_proto = 0xFF; /* invalid */
    ac_crypto_random(tx.payload.vpn_key.vpn_pubkey, AC_PUBKEY_LEN);
    ac_tx_sign(&tx, priv);
    ac_block_create(&genesis, &tx, 1, &blk);

    rc = ac_vpn_validate_block(&vs, &blk);
    ASSERT_EQ(rc, AC_ERR_INVAL, "invalid proto should fail");

    ac_vpn_destroy(&vs);
    PASS();
}

static void test_vpn_zero_port_rejected(void)
{
    ac_vpn_store_t vs;
    ac_block_t genesis, blk;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    ac_transaction_t tx;
    int rc;
    TEST("zero listen_port rejected");

    ac_vpn_init(&vs, 0);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    memset(&tx, 0, sizeof(tx));
    tx.type = AC_TX_VPN_TUNNEL;
    memcpy(tx.node_pubkey, pub, AC_PUBKEY_LEN);
    tx.timestamp = ac_time_unix_sec();
    tx.nonce = 1;
    tx.payload.vpn_tunnel.vpn_proto = AC_VPN_WIREGUARD;
    set_ipv4(&tx.payload.vpn_tunnel.endpoint, 10, 0, 0, 1, 32);
    tx.payload.vpn_tunnel.listen_port = 0; /* invalid */
    ac_tx_sign(&tx, priv);
    ac_block_create(&genesis, &tx, 1, &blk);

    rc = ac_vpn_validate_block(&vs, &blk);
    ASSERT_EQ(rc, AC_ERR_INVAL, "zero port should fail");

    ac_vpn_destroy(&vs);
    PASS();
}

static void test_vpn_mtu_too_low(void)
{
    ac_vpn_store_t vs;
    ac_block_t genesis, blk;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    ac_transaction_t tx;
    int rc;
    TEST("MTU below 576 rejected (N25)");

    ac_vpn_init(&vs, 0);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    memset(&tx, 0, sizeof(tx));
    tx.type = AC_TX_VPN_TUNNEL;
    memcpy(tx.node_pubkey, pub, AC_PUBKEY_LEN);
    tx.timestamp = ac_time_unix_sec();
    tx.nonce = 1;
    tx.payload.vpn_tunnel.vpn_proto = AC_VPN_WIREGUARD;
    set_ipv4(&tx.payload.vpn_tunnel.endpoint, 10, 0, 0, 1, 32);
    tx.payload.vpn_tunnel.listen_port = 51820;
    tx.payload.vpn_tunnel.mtu = 100; /* too low */
    ac_tx_sign(&tx, priv);
    ac_block_create(&genesis, &tx, 1, &blk);

    rc = ac_vpn_validate_block(&vs, &blk);
    ASSERT_EQ(rc, AC_ERR_INVAL, "MTU < 576 should fail");

    ac_vpn_destroy(&vs);
    PASS();
}

static void test_vpn_rebuild(void)
{
    ac_vpn_store_t vs;
    ac_block_t blocks[3];
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    TEST("rebuild from chain");

    ac_vpn_init(&vs, 0);
    make_keypair(pub, priv);

    ac_genesis_block(&blocks[0]);
    make_vpn_key_block(&blocks[1], &blocks[0], pub, priv, AC_VPN_WIREGUARD, 1);
    make_vpn_tunnel_block(&blocks[2], &blocks[1], pub, priv, AC_VPN_WIREGUARD, 51820, 2);

    ASSERT_OK(ac_vpn_rebuild(&vs, blocks, 3), "rebuild");
    ASSERT_EQ(ac_vpn_count(&vs), 1, "1 tunnel");

    ac_vpn_destroy(&vs);
    PASS();
}

static void test_vpn_null_safety(void)
{
    TEST("NULL parameter safety (K01)");

    ASSERT_NE(ac_vpn_init(NULL, 0), AC_OK, "init(NULL)");
    ASSERT_EQ(ac_vpn_count(NULL), 0, "count(NULL)");
    ASSERT_EQ((uintptr_t)ac_vpn_find(NULL, NULL), (uintptr_t)NULL, "find(NULL)");

    PASS();
}

static void test_vpn_multiple_protocols(void)
{
    ac_vpn_store_t vs;
    ac_block_t genesis, blk1, blk2;
    uint8_t pub[AC_PUBKEY_LEN], priv[64];
    const ac_vpn_tunnel_t *tun;
    TEST("same node, different VPN protocols");

    ac_vpn_init(&vs, 0);
    make_keypair(pub, priv);
    ac_genesis_block(&genesis);

    /* WireGuard */
    make_vpn_key_block(&blk1, &genesis, pub, priv, AC_VPN_WIREGUARD, 1);
    ac_vpn_apply_block(&vs, &blk1);

    /* IPsec */
    make_vpn_key_block(&blk2, &blk1, pub, priv, AC_VPN_IPSEC, 2);
    ac_vpn_apply_block(&vs, &blk2);

    ASSERT_EQ(ac_vpn_count(&vs), 2, "2 tunnels");

    tun = ac_vpn_find_by_proto(&vs, pub, AC_VPN_WIREGUARD);
    ASSERT_NE((uintptr_t)tun, (uintptr_t)NULL, "WG tunnel found");
    ASSERT_EQ(tun->vpn_proto, AC_VPN_WIREGUARD, "WG proto");

    tun = ac_vpn_find_by_proto(&vs, pub, AC_VPN_IPSEC);
    ASSERT_NE((uintptr_t)tun, (uintptr_t)NULL, "IPsec tunnel found");
    ASSERT_EQ(tun->vpn_proto, AC_VPN_IPSEC, "IPsec proto");

    ac_vpn_destroy(&vs);
    PASS();
}

/* ================================================================== */
/*  Main                                                               */
/* ================================================================== */

int main(void)
{
    printf("=== ac_vpn unit tests ===\n\n");

    test_vpn_init_destroy();
    test_vpn_key_creates_tunnel();
    test_vpn_tunnel_config();
    test_vpn_state_transitions();
    test_vpn_invalid_transition();
    test_vpn_handshake_marking();
    test_vpn_traffic_counters();
    test_vpn_prune_stale();
    test_vpn_invalid_protocol();
    test_vpn_zero_port_rejected();
    test_vpn_mtu_too_low();
    test_vpn_rebuild();
    test_vpn_null_safety();
    test_vpn_multiple_protocols();

    printf("\n=== Results: %d passed, %d failed, %d total ===\n",
           pass_count, fail_count, test_count);

    return fail_count > 0 ? 1 : 0;
}
