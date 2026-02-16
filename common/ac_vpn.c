/*
 * ac_vpn.c — VPN state machine implementation
 *
 * Protocol-agnostic VPN tunnel lifecycle. Validates VPN_KEY and VPN_TUNNEL
 * transactions, manages tunnel records, enforces state machine transitions.
 *
 * State machine:
 *   IDLE → KEYED (on VPN_KEY tx)
 *   KEYED → ACTIVE (on handshake success)
 *   ACTIVE → REKEYING (on rekey trigger)
 *   REKEYING → ACTIVE (on rekey success)
 *   REKEYING → ERROR (after AC_VPN_MAX_REKEY_ATTEMPTS failures)
 *   * → CLOSED (explicit teardown)
 *
 * Mitigates: K42,K43,K44,K45,N25,N26,N27,N28,P28,P29,P30,P31,P32,P33,P34
 */

#include "ac_vpn.h"
#include "ac_crypto.h"
#include "ac_dag.h"

#include <string.h>

/* Composite key: remote_pubkey[AC_PUBKEY_LEN] || vpn_proto[1] */
#define AC_VPN_KEY_LEN  (AC_PUBKEY_LEN + 1)

/* ================================================================== */
/*  Internal helpers                                                   */
/* ================================================================== */

static void make_tunnel_key(uint8_t key[AC_VPN_KEY_LEN],
                            const uint8_t remote[AC_PUBKEY_LEN],
                            uint8_t proto)
{
    memcpy(key, remote, AC_PUBKEY_LEN);
    key[AC_PUBKEY_LEN] = proto;
}

static ac_vpn_tunnel_t *find_by_remote(ac_vpn_store_t *vs,
                                       const uint8_t remote[AC_PUBKEY_LEN])
{
    ac_hashmap_iter_t it;
    const void *k;
    uint32_t kl;
    void *v;

    ac_hashmap_iter_init(&it, &vs->tunnel_map);
    while (ac_hashmap_iter_next(&it, &k, &kl, &v)) {
        ac_vpn_tunnel_t *tun = (ac_vpn_tunnel_t *)v;
        if (memcmp(tun->remote_pubkey, remote, AC_PUBKEY_LEN) == 0)
            return tun;
    }
    return NULL;
}

static ac_vpn_tunnel_t *find_by_remote_proto(ac_vpn_store_t *vs,
                                             const uint8_t remote[AC_PUBKEY_LEN],
                                             uint8_t proto)
{
    uint8_t key[AC_VPN_KEY_LEN];
    make_tunnel_key(key, remote, proto);
    return (ac_vpn_tunnel_t *)ac_hashmap_get(&vs->tunnel_map, key, AC_VPN_KEY_LEN);
}

/* Validate state transition */
static int valid_transition(ac_vpn_state_t from, ac_vpn_state_t to)
{
    switch (from) {
    case AC_VPN_STATE_IDLE:
        return to == AC_VPN_STATE_KEYED || to == AC_VPN_STATE_CLOSED;
    case AC_VPN_STATE_KEYED:
        return to == AC_VPN_STATE_ACTIVE || to == AC_VPN_STATE_CLOSED;
    case AC_VPN_STATE_ACTIVE:
        return to == AC_VPN_STATE_REKEYING || to == AC_VPN_STATE_CLOSED;
    case AC_VPN_STATE_REKEYING:
        return to == AC_VPN_STATE_ACTIVE || to == AC_VPN_STATE_ERROR ||
               to == AC_VPN_STATE_CLOSED;
    case AC_VPN_STATE_ERROR:
        return to == AC_VPN_STATE_CLOSED;
    case AC_VPN_STATE_CLOSED:
        return 0; /* terminal state */
    default:
        return 0;
    }
}

/* ================================================================== */
/*  Validation                                                         */
/* ================================================================== */

static int validate_vpn_key(const ac_vpn_store_t *vs,
                            const ac_tx_vpn_key_t *vk,
                            const uint8_t node_pubkey[AC_PUBKEY_LEN])
{
    (void)node_pubkey;

    /* Protocol must be valid */
    if (vk->vpn_proto != AC_VPN_WIREGUARD &&
        vk->vpn_proto != AC_VPN_IPSEC &&
        vk->vpn_proto != AC_VPN_POOL) {
        ac_log(AC_LOG_WARN, "vpn: invalid protocol %u", vk->vpn_proto);
        return AC_ERR_INVAL;
    }

    /* VPN pubkey must not be all zeros */
    {
        uint8_t zero[AC_PUBKEY_LEN];
        memset(zero, 0, sizeof(zero));
        if (memcmp(vk->vpn_pubkey, zero, AC_PUBKEY_LEN) == 0) {
            ac_log(AC_LOG_WARN, "vpn: zero VPN pubkey");
            return AC_ERR_INVAL;
        }
    }

    /* Check capacity */
    if (vs->max_tunnels > 0 &&
        ac_hashmap_count(&vs->tunnel_map) >= vs->max_tunnels) {
        ac_log(AC_LOG_WARN, "vpn: tunnel table full");
        return AC_ERR_NOMEM;
    }

    return AC_OK;
}

static int validate_vpn_tunnel(const ac_vpn_store_t *vs,
                               const ac_tx_vpn_tunnel_t *vt)
{
    (void)vs;

    /* Protocol must be valid */
    if (vt->vpn_proto != AC_VPN_WIREGUARD &&
        vt->vpn_proto != AC_VPN_IPSEC &&
        vt->vpn_proto != AC_VPN_POOL) {
        ac_log(AC_LOG_WARN, "vpn: invalid tunnel protocol %u", vt->vpn_proto);
        return AC_ERR_INVAL;
    }

    /* Endpoint must have a valid family */
    if (vt->endpoint.family != AC_AF_IPV4 &&
        vt->endpoint.family != AC_AF_IPV6 &&
        vt->endpoint.family != AC_AF_POOL) {
        ac_log(AC_LOG_WARN, "vpn: invalid endpoint family");
        return AC_ERR_INVAL;
    }

    /* Port must be nonzero */
    if (vt->listen_port == 0) {
        ac_log(AC_LOG_WARN, "vpn: listen_port must be nonzero");
        return AC_ERR_INVAL;
    }

    /* Allowed IP count must be within limits */
    if (vt->allowed_ip_count > AC_MAX_VPN_ALLOWED_IPS) {
        ac_log(AC_LOG_WARN, "vpn: too many allowed_ips (%u)",
               vt->allowed_ip_count);
        return AC_ERR_INVAL;
    }

    /* MTU sanity: 0 = auto is fine, but if set must be >= 576 (IPv4 min) */
    if (vt->mtu != 0 && vt->mtu < 576) {
        ac_log(AC_LOG_WARN, "vpn: MTU %u below minimum (576)", vt->mtu);
        return AC_ERR_INVAL;
    }

    return AC_OK;
}

/* ================================================================== */
/*  Apply                                                              */
/* ================================================================== */

static void apply_vpn_key(ac_vpn_store_t *vs,
                          const ac_tx_vpn_key_t *vk,
                          const uint8_t node_pubkey[AC_PUBKEY_LEN],
                          uint32_t block_index)
{
    ac_vpn_tunnel_t *tun;

    /* Check if tunnel for this node+proto already exists */
    tun = find_by_remote_proto(vs, node_pubkey, vk->vpn_proto);
    if (tun) {
        /* Update VPN pubkey (rekey) */
        memcpy(tun->vpn_pubkey, vk->vpn_pubkey, AC_PUBKEY_LEN);
        if (tun->state == AC_VPN_STATE_ACTIVE)
            tun->state = AC_VPN_STATE_REKEYING;
        ac_log(AC_LOG_INFO, "vpn: key updated for existing tunnel (proto=%u)",
               vk->vpn_proto);
        return;
    }

    /* Create new tunnel record */
    tun = (ac_vpn_tunnel_t *)ac_zalloc(sizeof(*tun), AC_MEM_NORMAL);
    if (!tun) {
        ac_log(AC_LOG_WARN, "vpn: no memory for new tunnel");
        return;
    }

    memcpy(tun->remote_pubkey, node_pubkey, AC_PUBKEY_LEN);
    tun->vpn_proto = vk->vpn_proto;
    memcpy(tun->vpn_pubkey, vk->vpn_pubkey, AC_PUBKEY_LEN);
    tun->state = AC_VPN_STATE_KEYED;
    tun->created_at = ac_time_unix_sec();
    tun->block_registered = block_index;
    tun->active = 1;

    {
        uint8_t key[AC_VPN_KEY_LEN];
        make_tunnel_key(key, node_pubkey, vk->vpn_proto);
        if (ac_hashmap_put(&vs->tunnel_map, key, AC_VPN_KEY_LEN,
                           tun, NULL) != AC_OK) {
            ac_free(tun);
            ac_log(AC_LOG_WARN, "vpn: hashmap put failed");
            return;
        }
    }

    /* DAG: register tunnel node */
    if (vs->dag)
        ac_dag_add_node(vs->dag, AC_RES_VPN_TUNNEL, node_pubkey);

    ac_log(AC_LOG_INFO, "vpn: new tunnel registered (proto=%u, state=KEYED)",
           vk->vpn_proto);
}

static void apply_vpn_tunnel(ac_vpn_store_t *vs,
                             const ac_tx_vpn_tunnel_t *vt,
                             const uint8_t node_pubkey[AC_PUBKEY_LEN],
                             uint32_t block_index)
{
    ac_vpn_tunnel_t *tun;

    tun = find_by_remote_proto(vs, node_pubkey, vt->vpn_proto);
    if (!tun) {
        /* Create new record if no VPN_KEY was seen first */
        tun = (ac_vpn_tunnel_t *)ac_zalloc(sizeof(*tun), AC_MEM_NORMAL);
        if (!tun) {
            ac_log(AC_LOG_WARN, "vpn: no memory for tunnel");
            return;
        }

        memcpy(tun->remote_pubkey, node_pubkey, AC_PUBKEY_LEN);
        tun->created_at = ac_time_unix_sec();
        tun->block_registered = block_index;
        tun->active = 1;

        {
            uint8_t key[AC_VPN_KEY_LEN];
            make_tunnel_key(key, node_pubkey, vt->vpn_proto);
            if (ac_hashmap_put(&vs->tunnel_map, key, AC_VPN_KEY_LEN,
                               tun, NULL) != AC_OK) {
                ac_free(tun);
                ac_log(AC_LOG_WARN, "vpn: hashmap put failed");
                return;
            }
        }
    }

    tun->vpn_proto = vt->vpn_proto;
    tun->endpoint = vt->endpoint;
    tun->listen_port = vt->listen_port;
    tun->allowed_ip_count = vt->allowed_ip_count;
    if (vt->allowed_ip_count > 0) {
        memcpy(tun->allowed_ips, vt->allowed_ips,
               vt->allowed_ip_count * sizeof(ac_address_t));
    }
    tun->mtu = vt->mtu;
    tun->persistent_keepalive = vt->persistent_keepalive;
    tun->nat_hint = vt->nat_hint;

    if (tun->state == AC_VPN_STATE_IDLE)
        tun->state = AC_VPN_STATE_KEYED;

    ac_log(AC_LOG_INFO, "vpn: tunnel config applied (proto=%u, port=%u)",
           vt->vpn_proto, vt->listen_port);
}

/* ================================================================== */
/*  Public API                                                         */
/* ================================================================== */

int ac_vpn_init(ac_vpn_store_t *vs, uint32_t max_tunnels, ac_dag_t *dag)
{
    int rc;

    if (!vs)
        return AC_ERR_INVAL;

    memset(vs, 0, sizeof(*vs));
    vs->max_tunnels = max_tunnels;
    vs->dag = dag;

    rc = ac_mutex_init(&vs->lock);
    if (rc != AC_OK)
        return rc;

    rc = ac_hashmap_init(&vs->tunnel_map, 64, max_tunnels);
    if (rc != AC_OK) {
        ac_mutex_destroy(&vs->lock);
        return rc;
    }

    ac_log(AC_LOG_INFO, "vpn store initialized");
    return AC_OK;
}

void ac_vpn_destroy(ac_vpn_store_t *vs)
{
    ac_hashmap_iter_t it;
    const void *k;
    uint32_t kl;
    void *v;

    if (!vs)
        return;

    /* Zeroize VPN keys and free records (K20) */
    ac_hashmap_iter_init(&it, &vs->tunnel_map);
    while (ac_hashmap_iter_next(&it, &k, &kl, &v)) {
        ac_vpn_tunnel_t *tun = (ac_vpn_tunnel_t *)v;
        ac_crypto_zeroize(tun->vpn_pubkey, AC_PUBKEY_LEN);
        ac_free(tun);
    }
    ac_hashmap_destroy(&vs->tunnel_map);

    ac_mutex_destroy(&vs->lock);
    memset(vs, 0, sizeof(*vs));
    ac_log(AC_LOG_INFO, "vpn store destroyed");
}

int ac_vpn_validate_block(ac_vpn_store_t *vs, const ac_block_t *blk)
{
    uint16_t i;
    int rc;

    if (!vs || !blk)
        return AC_ERR_INVAL;

    ac_mutex_lock(&vs->lock);

    for (i = 0; i < blk->tx_count; i++) {
        const ac_transaction_t *tx = &blk->txs[i];

        switch (tx->type) {
        case AC_TX_VPN_KEY:
            rc = validate_vpn_key(vs, &tx->payload.vpn_key, tx->node_pubkey);
            if (rc != AC_OK) {
                ac_mutex_unlock(&vs->lock);
                return rc;
            }
            break;

        case AC_TX_VPN_TUNNEL:
            rc = validate_vpn_tunnel(vs, &tx->payload.vpn_tunnel);
            if (rc != AC_OK) {
                ac_mutex_unlock(&vs->lock);
                return rc;
            }
            break;

        default:
            break;
        }
    }

    ac_mutex_unlock(&vs->lock);
    return AC_OK;
}

int ac_vpn_apply_block(ac_vpn_store_t *vs, const ac_block_t *blk)
{
    uint16_t i;

    if (!vs || !blk)
        return AC_ERR_INVAL;

    ac_mutex_lock(&vs->lock);

    for (i = 0; i < blk->tx_count; i++) {
        const ac_transaction_t *tx = &blk->txs[i];

        switch (tx->type) {
        case AC_TX_VPN_KEY:
            apply_vpn_key(vs, &tx->payload.vpn_key,
                          tx->node_pubkey, blk->index);
            break;

        case AC_TX_VPN_TUNNEL:
            apply_vpn_tunnel(vs, &tx->payload.vpn_tunnel,
                             tx->node_pubkey, blk->index);
            break;

        default:
            break;
        }
    }

    ac_mutex_unlock(&vs->lock);
    return AC_OK;
}

const ac_vpn_tunnel_t *ac_vpn_find(const ac_vpn_store_t *vs,
                                    const uint8_t remote_pubkey[AC_PUBKEY_LEN])
{
    ac_hashmap_iter_t it;
    const void *k;
    uint32_t kl;
    void *v;

    if (!vs || !remote_pubkey)
        return NULL;

    ac_hashmap_iter_init(&it, (ac_hashmap_t *)&vs->tunnel_map);
    while (ac_hashmap_iter_next(&it, &k, &kl, &v)) {
        ac_vpn_tunnel_t *tun = (ac_vpn_tunnel_t *)v;
        if (memcmp(tun->remote_pubkey, remote_pubkey, AC_PUBKEY_LEN) == 0)
            return tun;
    }
    return NULL;
}

const ac_vpn_tunnel_t *ac_vpn_find_by_proto(
    const ac_vpn_store_t *vs,
    const uint8_t remote_pubkey[AC_PUBKEY_LEN],
    uint8_t vpn_proto)
{
    uint8_t key[AC_VPN_KEY_LEN];

    if (!vs || !remote_pubkey)
        return NULL;

    make_tunnel_key(key, remote_pubkey, vpn_proto);
    return (const ac_vpn_tunnel_t *)ac_hashmap_get(
        &vs->tunnel_map, key, AC_VPN_KEY_LEN);
}

int ac_vpn_transition(ac_vpn_store_t *vs,
                      const uint8_t remote_pubkey[AC_PUBKEY_LEN],
                      ac_vpn_state_t new_state)
{
    ac_vpn_tunnel_t *tun;

    if (!vs || !remote_pubkey)
        return AC_ERR_INVAL;

    ac_mutex_lock(&vs->lock);

    tun = find_by_remote(vs, remote_pubkey);
    if (!tun) {
        ac_mutex_unlock(&vs->lock);
        return AC_ERR_NOENT;
    }

    if (!valid_transition(tun->state, new_state)) {
        ac_log(AC_LOG_WARN, "vpn: invalid transition %u → %u",
               tun->state, new_state);
        ac_mutex_unlock(&vs->lock);
        return AC_ERR_INVAL;
    }

    tun->state = new_state;
    if (new_state == AC_VPN_STATE_CLOSED) {
        uint8_t key[AC_VPN_KEY_LEN];
        /* DAG: remove tunnel node */
        if (vs->dag)
            ac_dag_remove_node(vs->dag, AC_RES_VPN_TUNNEL, tun->remote_pubkey);
        tun->active = 0;
        make_tunnel_key(key, tun->remote_pubkey, tun->vpn_proto);
        ac_hashmap_remove(&vs->tunnel_map, key, AC_VPN_KEY_LEN);
        ac_free(tun);
    }

    ac_mutex_unlock(&vs->lock);
    return AC_OK;
}

void ac_vpn_mark_handshake(ac_vpn_store_t *vs,
                           const uint8_t remote_pubkey[AC_PUBKEY_LEN],
                           uint64_t now)
{
    ac_vpn_tunnel_t *tun;

    if (!vs || !remote_pubkey)
        return;

    ac_mutex_lock(&vs->lock);
    tun = find_by_remote(vs, remote_pubkey);
    if (tun) {
        tun->last_handshake = now;
        tun->rekey_attempts = 0;
        if (tun->state == AC_VPN_STATE_KEYED ||
            tun->state == AC_VPN_STATE_REKEYING)
            tun->state = AC_VPN_STATE_ACTIVE;
    }
    ac_mutex_unlock(&vs->lock);
}

void ac_vpn_update_traffic(ac_vpn_store_t *vs,
                           const uint8_t remote_pubkey[AC_PUBKEY_LEN],
                           uint64_t tx_bytes, uint64_t rx_bytes)
{
    ac_vpn_tunnel_t *tun;

    if (!vs || !remote_pubkey)
        return;

    ac_mutex_lock(&vs->lock);
    tun = find_by_remote(vs, remote_pubkey);
    if (tun) {
        tun->bytes_tx += tx_bytes;
        tun->bytes_rx += rx_bytes;
    }
    ac_mutex_unlock(&vs->lock);
}

void ac_vpn_prune_stale(ac_vpn_store_t *vs, uint64_t now)
{
    ac_hashmap_iter_t it;
    const void *k;
    uint32_t kl;
    void *v;

    if (!vs)
        return;

    ac_mutex_lock(&vs->lock);

    ac_hashmap_iter_init(&it, &vs->tunnel_map);
    while (ac_hashmap_iter_next(&it, &k, &kl, &v)) {
        ac_vpn_tunnel_t *tun = (ac_vpn_tunnel_t *)v;

        if (tun->state == AC_VPN_STATE_CLOSED)
            continue;

        /* Check handshake timeout for KEYED tunnels */
        if (tun->state == AC_VPN_STATE_KEYED &&
            tun->last_handshake == 0 &&
            now > tun->created_at &&
            (now - tun->created_at) > AC_VPN_HANDSHAKE_TIMEOUT_SEC) {
            ac_log(AC_LOG_WARN, "vpn: tunnel handshake timeout, closing");
            /* DAG: remove tunnel node */
            if (vs->dag)
                ac_dag_remove_node(vs->dag, AC_RES_VPN_TUNNEL, tun->remote_pubkey);
            tun->state = AC_VPN_STATE_CLOSED;
            tun->active = 0;
            ac_hashmap_iter_remove(&it);
            ac_free(tun);
            continue;
        }

        /* Check rekey failure limit */
        if (tun->state == AC_VPN_STATE_REKEYING &&
            tun->rekey_attempts >= AC_VPN_MAX_REKEY_ATTEMPTS) {
            ac_log(AC_LOG_WARN, "vpn: rekey failed %u times, error state",
                   tun->rekey_attempts);
            tun->state = AC_VPN_STATE_ERROR;
        }
    }

    ac_mutex_unlock(&vs->lock);
}

uint32_t ac_vpn_count(const ac_vpn_store_t *vs)
{
    if (!vs)
        return 0;

    return ac_hashmap_count(&vs->tunnel_map);
}

int ac_vpn_rebuild(ac_vpn_store_t *vs,
                   const ac_block_t *blocks,
                   uint32_t block_count)
{
    uint32_t i;
    ac_hashmap_iter_t it;
    const void *k;
    uint32_t kl;
    void *v;

    if (!vs || (!blocks && block_count > 0))
        return AC_ERR_INVAL;

    ac_mutex_lock(&vs->lock);

    /* Zeroize existing keys and free records */
    ac_hashmap_iter_init(&it, &vs->tunnel_map);
    while (ac_hashmap_iter_next(&it, &k, &kl, &v)) {
        ac_vpn_tunnel_t *tun = (ac_vpn_tunnel_t *)v;
        ac_crypto_zeroize(tun->vpn_pubkey, AC_PUBKEY_LEN);
        ac_free(tun);
        ac_hashmap_iter_remove(&it);
    }

    for (i = 0; i < block_count; i++) {
        uint16_t j;
        const ac_block_t *blk = &blocks[i];

        for (j = 0; j < blk->tx_count; j++) {
            const ac_transaction_t *tx = &blk->txs[j];

            switch (tx->type) {
            case AC_TX_VPN_KEY:
                apply_vpn_key(vs, &tx->payload.vpn_key,
                              tx->node_pubkey, blk->index);
                break;
            case AC_TX_VPN_TUNNEL:
                apply_vpn_tunnel(vs, &tx->payload.vpn_tunnel,
                                 tx->node_pubkey, blk->index);
                break;
            default:
                break;
            }
        }
    }

    ac_mutex_unlock(&vs->lock);
    ac_log(AC_LOG_INFO, "vpn store rebuilt: %u tunnels",
           ac_hashmap_count(&vs->tunnel_map));
    return AC_OK;
}
