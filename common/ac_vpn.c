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

#include <string.h>

/* ================================================================== */
/*  Internal helpers                                                   */
/* ================================================================== */

static int find_by_remote(const ac_vpn_store_t *vs,
                          const uint8_t remote[AC_PUBKEY_LEN])
{
    uint32_t i;
    for (i = 0; i < vs->tunnel_count; i++) {
        if (vs->tunnels[i].active &&
            memcmp(vs->tunnels[i].remote_pubkey, remote, AC_PUBKEY_LEN) == 0)
            return (int)i;
    }
    return -1;
}

static int find_by_remote_proto(const ac_vpn_store_t *vs,
                                const uint8_t remote[AC_PUBKEY_LEN],
                                uint8_t proto)
{
    uint32_t i;
    for (i = 0; i < vs->tunnel_count; i++) {
        if (vs->tunnels[i].active &&
            vs->tunnels[i].vpn_proto == proto &&
            memcmp(vs->tunnels[i].remote_pubkey, remote, AC_PUBKEY_LEN) == 0)
            return (int)i;
    }
    return -1;
}

/* Find a free slot or evict a CLOSED tunnel */
static int alloc_slot(ac_vpn_store_t *vs)
{
    uint32_t i;

    /* Reuse inactive slot */
    for (i = 0; i < vs->tunnel_count; i++) {
        if (!vs->tunnels[i].active)
            return (int)i;
    }

    /* Reuse a CLOSED slot */
    for (i = 0; i < vs->tunnel_count; i++) {
        if (vs->tunnels[i].state == AC_VPN_STATE_CLOSED) {
            memset(&vs->tunnels[i], 0, sizeof(vs->tunnels[i]));
            return (int)i;
        }
    }

    /* Append */
    if (vs->tunnel_count < AC_MAX_VPN_TUNNELS)
        return (int)vs->tunnel_count++;

    return -1;
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
    {
        uint32_t active = 0, i;
        for (i = 0; i < vs->tunnel_count; i++) {
            if (vs->tunnels[i].active)
                active++;
        }
        if (active >= AC_MAX_VPN_TUNNELS) {
            ac_log(AC_LOG_WARN, "vpn: tunnel table full");
            return AC_ERR_NOMEM;
        }
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
    int idx;
    ac_vpn_tunnel_t *tun;

    /* Check if tunnel for this node+proto already exists */
    idx = find_by_remote_proto(vs, node_pubkey, vk->vpn_proto);
    if (idx >= 0) {
        /* Update VPN pubkey (rekey) */
        tun = &vs->tunnels[idx];
        memcpy(tun->vpn_pubkey, vk->vpn_pubkey, AC_PUBKEY_LEN);
        if (tun->state == AC_VPN_STATE_ACTIVE)
            tun->state = AC_VPN_STATE_REKEYING;
        ac_log(AC_LOG_INFO, "vpn: key updated for existing tunnel (proto=%u)",
               vk->vpn_proto);
        return;
    }

    /* Create new tunnel record */
    idx = alloc_slot(vs);
    if (idx < 0) {
        ac_log(AC_LOG_WARN, "vpn: no slot for new tunnel");
        return;
    }

    tun = &vs->tunnels[idx];
    memset(tun, 0, sizeof(*tun));
    memcpy(tun->remote_pubkey, node_pubkey, AC_PUBKEY_LEN);
    tun->vpn_proto = vk->vpn_proto;
    memcpy(tun->vpn_pubkey, vk->vpn_pubkey, AC_PUBKEY_LEN);
    tun->state = AC_VPN_STATE_KEYED;
    tun->created_at = ac_time_unix_sec();
    tun->block_registered = block_index;
    tun->active = 1;

    ac_log(AC_LOG_INFO, "vpn: new tunnel registered (proto=%u, state=KEYED)",
           vk->vpn_proto);
}

static void apply_vpn_tunnel(ac_vpn_store_t *vs,
                             const ac_tx_vpn_tunnel_t *vt,
                             const uint8_t node_pubkey[AC_PUBKEY_LEN],
                             uint32_t block_index)
{
    int idx;
    ac_vpn_tunnel_t *tun;

    idx = find_by_remote_proto(vs, node_pubkey, vt->vpn_proto);
    if (idx >= 0) {
        /* Update existing tunnel parameters */
        tun = &vs->tunnels[idx];
    } else {
        /* Create new record if no VPN_KEY was seen first */
        idx = alloc_slot(vs);
        if (idx < 0) {
            ac_log(AC_LOG_WARN, "vpn: no slot for tunnel");
            return;
        }
        tun = &vs->tunnels[idx];
        memset(tun, 0, sizeof(*tun));
        memcpy(tun->remote_pubkey, node_pubkey, AC_PUBKEY_LEN);
        tun->created_at = ac_time_unix_sec();
        tun->block_registered = block_index;
        tun->active = 1;
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

int ac_vpn_init(ac_vpn_store_t *vs)
{
    if (!vs)
        return AC_ERR_INVAL;

    memset(vs, 0, sizeof(*vs));
    ac_mutex_init(&vs->lock);
    ac_log(AC_LOG_INFO, "vpn store initialized");
    return AC_OK;
}

void ac_vpn_destroy(ac_vpn_store_t *vs)
{
    if (!vs)
        return;

    /* Zeroize VPN keys (K20) */
    {
        uint32_t i;
        for (i = 0; i < vs->tunnel_count; i++) {
            ac_crypto_zeroize(vs->tunnels[i].vpn_pubkey, AC_PUBKEY_LEN);
        }
    }

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
    int idx;
    if (!vs || !remote_pubkey)
        return NULL;
    idx = find_by_remote(vs, remote_pubkey);
    return idx >= 0 ? &vs->tunnels[idx] : NULL;
}

const ac_vpn_tunnel_t *ac_vpn_find_by_proto(
    const ac_vpn_store_t *vs,
    const uint8_t remote_pubkey[AC_PUBKEY_LEN],
    uint8_t vpn_proto)
{
    int idx;
    if (!vs || !remote_pubkey)
        return NULL;
    idx = find_by_remote_proto(vs, remote_pubkey, vpn_proto);
    return idx >= 0 ? &vs->tunnels[idx] : NULL;
}

int ac_vpn_transition(ac_vpn_store_t *vs,
                      const uint8_t remote_pubkey[AC_PUBKEY_LEN],
                      ac_vpn_state_t new_state)
{
    int idx;

    if (!vs || !remote_pubkey)
        return AC_ERR_INVAL;

    ac_mutex_lock(&vs->lock);

    idx = find_by_remote(vs, remote_pubkey);
    if (idx < 0) {
        ac_mutex_unlock(&vs->lock);
        return AC_ERR_NOENT;
    }

    if (!valid_transition(vs->tunnels[idx].state, new_state)) {
        ac_log(AC_LOG_WARN, "vpn: invalid transition %u → %u",
               vs->tunnels[idx].state, new_state);
        ac_mutex_unlock(&vs->lock);
        return AC_ERR_INVAL;
    }

    vs->tunnels[idx].state = new_state;
    if (new_state == AC_VPN_STATE_CLOSED)
        vs->tunnels[idx].active = 0;

    ac_mutex_unlock(&vs->lock);
    return AC_OK;
}

void ac_vpn_mark_handshake(ac_vpn_store_t *vs,
                           const uint8_t remote_pubkey[AC_PUBKEY_LEN],
                           uint64_t now)
{
    int idx;

    if (!vs || !remote_pubkey)
        return;

    ac_mutex_lock(&vs->lock);
    idx = find_by_remote(vs, remote_pubkey);
    if (idx >= 0) {
        vs->tunnels[idx].last_handshake = now;
        vs->tunnels[idx].rekey_attempts = 0;
        if (vs->tunnels[idx].state == AC_VPN_STATE_KEYED ||
            vs->tunnels[idx].state == AC_VPN_STATE_REKEYING)
            vs->tunnels[idx].state = AC_VPN_STATE_ACTIVE;
    }
    ac_mutex_unlock(&vs->lock);
}

void ac_vpn_update_traffic(ac_vpn_store_t *vs,
                           const uint8_t remote_pubkey[AC_PUBKEY_LEN],
                           uint64_t tx_bytes, uint64_t rx_bytes)
{
    int idx;

    if (!vs || !remote_pubkey)
        return;

    ac_mutex_lock(&vs->lock);
    idx = find_by_remote(vs, remote_pubkey);
    if (idx >= 0) {
        vs->tunnels[idx].bytes_tx += tx_bytes;
        vs->tunnels[idx].bytes_rx += rx_bytes;
    }
    ac_mutex_unlock(&vs->lock);
}

void ac_vpn_prune_stale(ac_vpn_store_t *vs, uint64_t now)
{
    uint32_t i;

    if (!vs)
        return;

    ac_mutex_lock(&vs->lock);

    for (i = 0; i < vs->tunnel_count; i++) {
        ac_vpn_tunnel_t *tun = &vs->tunnels[i];
        if (!tun->active)
            continue;
        if (tun->state == AC_VPN_STATE_CLOSED)
            continue;

        /* Check handshake timeout for KEYED tunnels */
        if (tun->state == AC_VPN_STATE_KEYED &&
            tun->last_handshake == 0 &&
            now > tun->created_at &&
            (now - tun->created_at) > AC_VPN_HANDSHAKE_TIMEOUT_SEC) {
            ac_log(AC_LOG_WARN, "vpn: tunnel handshake timeout, closing");
            tun->state = AC_VPN_STATE_CLOSED;
            tun->active = 0;
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
    uint32_t i, count = 0;

    if (!vs)
        return 0;

    for (i = 0; i < vs->tunnel_count; i++) {
        if (vs->tunnels[i].active &&
            vs->tunnels[i].state != AC_VPN_STATE_CLOSED)
            count++;
    }
    return count;
}

int ac_vpn_rebuild(ac_vpn_store_t *vs,
                   const ac_block_t *blocks,
                   uint32_t block_count)
{
    uint32_t i;

    if (!vs || (!blocks && block_count > 0))
        return AC_ERR_INVAL;

    ac_mutex_lock(&vs->lock);

    /* Zeroize existing keys */
    {
        uint32_t j;
        for (j = 0; j < vs->tunnel_count; j++)
            ac_crypto_zeroize(vs->tunnels[j].vpn_pubkey, AC_PUBKEY_LEN);
    }

    vs->tunnel_count = 0;
    memset(vs->tunnels, 0, sizeof(vs->tunnels));

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
    ac_log(AC_LOG_INFO, "vpn store rebuilt: %u tunnels", vs->tunnel_count);
    return AC_OK;
}
