/*
 * ac_discover.c — Autodiscovery protocol implementation
 *
 * Manages peer table with blockchain-aware priority. Handles announce
 * building/processing, peer lifecycle, self-discovery prevention,
 * and LRU eviction.
 *
 * Mitigates: K11,N07,N09,N36,P17,P18,P19,P20,P21
 */

#include "ac_discover.h"
#include "ac_crypto.h"

#include <string.h>

/* ================================================================== */
/*  Internal helpers                                                   */
/* ================================================================== */

/* Find peer by pubkey, returns index or -1 */
static int find_peer_by_pubkey(const ac_discover_state_t *ds,
                               const uint8_t pubkey[AC_PUBKEY_LEN])
{
    uint32_t i;
    for (i = 0; i < ds->peer_count; i++) {
        if (memcmp(ds->peers[i].pubkey, pubkey, AC_PUBKEY_LEN) == 0)
            return (int)i;
    }
    return -1;
}

/* Find peer by address, returns index or -1 */
static int find_peer_by_addr(const ac_discover_state_t *ds,
                             const ac_address_t *addr)
{
    uint32_t i;
    for (i = 0; i < ds->peer_count; i++) {
        if (ds->peers[i].addr.family == addr->family &&
            memcmp(ds->peers[i].addr.addr, addr->addr, AC_MAX_ADDR_LEN) == 0)
            return (int)i;
    }
    return -1;
}

/*
 * evict_lru — Find the LRU non-static peer and evict it.
 * Returns the index of the freed slot, or -1 if no evictable peer.
 */
static int evict_lru(ac_discover_state_t *ds)
{
    uint32_t i;
    int oldest_idx = -1;
    uint64_t oldest_time = UINT64_MAX;

    for (i = 0; i < ds->peer_count; i++) {
        if (ds->peers[i].flags & AC_PEER_STATIC)
            continue; /* never evict static peers */
        if (ds->peers[i].last_seen < oldest_time) {
            oldest_time = ds->peers[i].last_seen;
            oldest_idx = (int)i;
        }
    }

    if (oldest_idx >= 0) {
        /* Shift remaining peers */
        if ((uint32_t)oldest_idx < ds->peer_count - 1) {
            memmove(&ds->peers[oldest_idx],
                    &ds->peers[oldest_idx + 1],
                    (ds->peer_count - 1 - (uint32_t)oldest_idx) * sizeof(ac_peer_t));
        }
        ds->peer_count--;
        ac_log(AC_LOG_INFO, "evicted LRU peer (slot %d)", oldest_idx);
    }

    return oldest_idx >= 0 ? (int)ds->peer_count : -1;
}

/* ================================================================== */
/*  Public API                                                         */
/* ================================================================== */

int ac_discover_init(ac_discover_state_t *ds,
                     const uint8_t local_pubkey[AC_PUBKEY_LEN],
                     uint16_t sync_port,
                     uint8_t methods)
{
    if (!ds || !local_pubkey)
        return AC_ERR_INVAL;

    memset(ds, 0, sizeof(*ds));
    memcpy(ds->local_pubkey, local_pubkey, AC_PUBKEY_LEN);
    ds->local_sync_port = sync_port;
    ds->methods_enabled = methods;
    ac_mutex_init(&ds->lock);

    ac_log(AC_LOG_INFO, "discovery initialized (methods=0x%02x, port=%u)",
           methods, sync_port);
    return AC_OK;
}

void ac_discover_destroy(ac_discover_state_t *ds)
{
    if (!ds)
        return;
    ac_mutex_destroy(&ds->lock);
    memset(ds, 0, sizeof(*ds));
    ac_log(AC_LOG_INFO, "discovery destroyed");
}

void ac_discover_update_local(ac_discover_state_t *ds,
                              uint32_t chain_height,
                              const uint8_t tip_hash[AC_HASH_LEN],
                              uint8_t capabilities)
{
    if (!ds)
        return;

    ac_mutex_lock(&ds->lock);
    ds->local_chain_height = chain_height;
    if (tip_hash)
        memcpy(ds->local_tip_hash, tip_hash, AC_HASH_LEN);
    ds->local_capabilities = capabilities;
    ac_mutex_unlock(&ds->lock);
}

int ac_discover_build_announce(const ac_discover_state_t *ds,
                               ac_announce_t *announce)
{
    if (!ds || !announce)
        return AC_ERR_INVAL;

    memset(announce, 0, sizeof(*announce));
    announce->version = AC_VERSION;
    memcpy(announce->node_pubkey, ds->local_pubkey, AC_PUBKEY_LEN);
    announce->chain_height = ds->local_chain_height;
    memcpy(announce->tip_hash, ds->local_tip_hash, AC_HASH_LEN);
    announce->sync_port = ds->local_sync_port;
    announce->capabilities = ds->local_capabilities;

    return AC_OK;
}

int ac_discover_process_announce(ac_discover_state_t *ds,
                                 const ac_announce_t *announce,
                                 const ac_address_t *peer_addr)
{
    int idx;
    ac_peer_t *peer;
    uint64_t now;

    if (!ds || !announce || !peer_addr)
        return AC_ERR_INVAL;

    /* P19: Self-discovery prevention */
    if (memcmp(announce->node_pubkey, ds->local_pubkey, AC_PUBKEY_LEN) == 0) {
        return AC_OK; /* silently drop self-announces */
    }

    /* P10: Version check */
    if ((announce->version >> 8) != AC_VERSION_MAJOR) {
        ac_log(AC_LOG_WARN, "discover: version mismatch (got %u, want %u)",
               announce->version >> 8, AC_VERSION_MAJOR);
        return AC_ERR_INVAL;
    }

    now = ac_time_unix_sec();

    ac_mutex_lock(&ds->lock);

    idx = find_peer_by_pubkey(ds, announce->node_pubkey);

    if (idx >= 0) {
        /* Update existing peer */
        peer = &ds->peers[idx];
        peer->addr = *peer_addr;
        peer->sync_port = announce->sync_port;
        peer->chain_height = announce->chain_height;
        memcpy(peer->tip_hash, announce->tip_hash, AC_HASH_LEN);
        peer->capabilities = announce->capabilities;
        peer->last_seen = now;
        peer->flags |= AC_PEER_ACTIVE;
        peer->flags &= (uint8_t)~AC_PEER_UNREACHABLE;
    } else {
        /* Add new peer */
        if (ds->peer_count >= AC_MAX_PEERS) {
            /* P17: LRU eviction */
            if (evict_lru(ds) < 0) {
                ac_mutex_unlock(&ds->lock);
                ac_log(AC_LOG_WARN, "discover: peer table full, all static");
                return AC_ERR_NOMEM;
            }
        }

        peer = &ds->peers[ds->peer_count];
        memset(peer, 0, sizeof(*peer));
        memcpy(peer->pubkey, announce->node_pubkey, AC_PUBKEY_LEN);
        peer->addr = *peer_addr;
        peer->sync_port = announce->sync_port;
        peer->chain_height = announce->chain_height;
        memcpy(peer->tip_hash, announce->tip_hash, AC_HASH_LEN);
        peer->capabilities = announce->capabilities;
        peer->flags = AC_PEER_ACTIVE;
        peer->last_seen = now;
        peer->fail_count = 0;
        ds->peer_count++;

        ac_log(AC_LOG_INFO, "discover: new peer (height=%u, port=%u)",
               announce->chain_height, announce->sync_port);
    }

    ac_mutex_unlock(&ds->lock);
    return AC_OK;
}

int ac_discover_add_static_peer(ac_discover_state_t *ds,
                                const ac_address_t *addr,
                                uint16_t sync_port)
{
    ac_peer_t *peer;
    int idx;

    if (!ds || !addr)
        return AC_ERR_INVAL;

    ac_mutex_lock(&ds->lock);

    /* Check if already known by address */
    idx = find_peer_by_addr(ds, addr);
    if (idx >= 0) {
        ds->peers[idx].flags |= AC_PEER_STATIC;
        ds->peers[idx].sync_port = sync_port;
        ac_mutex_unlock(&ds->lock);
        return AC_OK;
    }

    if (ds->peer_count >= AC_MAX_PEERS) {
        ac_mutex_unlock(&ds->lock);
        return AC_ERR_NOMEM;
    }

    peer = &ds->peers[ds->peer_count];
    memset(peer, 0, sizeof(*peer));
    peer->addr = *addr;
    peer->sync_port = sync_port;
    peer->flags = AC_PEER_STATIC | AC_PEER_ACTIVE;
    peer->last_seen = ac_time_unix_sec();
    ds->peer_count++;

    ac_mutex_unlock(&ds->lock);
    ac_log(AC_LOG_INFO, "static peer added (port=%u)", sync_port);
    return AC_OK;
}

void ac_discover_prune(ac_discover_state_t *ds, uint64_t now)
{
    uint32_t i;

    if (!ds)
        return;

    ac_mutex_lock(&ds->lock);

    i = 0;
    while (i < ds->peer_count) {
        ac_peer_t *p = &ds->peers[i];

        /* Don't prune static peers */
        if (p->flags & AC_PEER_STATIC) {
            i++;
            continue;
        }

        /* Check timeout (convert ms to sec) */
        if (now > p->last_seen &&
            (now - p->last_seen) > (AC_PEER_TIMEOUT_MS / 1000)) {
            /* Remove by shifting */
            if (i < ds->peer_count - 1) {
                memmove(&ds->peers[i], &ds->peers[i + 1],
                        (ds->peer_count - 1 - i) * sizeof(ac_peer_t));
            }
            ds->peer_count--;
            ac_log(AC_LOG_INFO, "pruned stale peer");
            /* Don't increment i — check new element at same index */
        } else {
            i++;
        }
    }

    ac_mutex_unlock(&ds->lock);
}

const ac_peer_t *ac_discover_best_peer(const ac_discover_state_t *ds)
{
    uint32_t i;
    const ac_peer_t *best = NULL;

    if (!ds)
        return NULL;

    for (i = 0; i < ds->peer_count; i++) {
        const ac_peer_t *p = &ds->peers[i];
        if (p->flags & AC_PEER_UNREACHABLE)
            continue;
        if (!best || p->chain_height > best->chain_height)
            best = p;
    }

    return best;
}

void ac_discover_mark_failed(ac_discover_state_t *ds,
                             const uint8_t pubkey[AC_PUBKEY_LEN])
{
    int idx;

    if (!ds || !pubkey)
        return;

    ac_mutex_lock(&ds->lock);
    idx = find_peer_by_pubkey(ds, pubkey);
    if (idx >= 0) {
        ds->peers[idx].fail_count++;
        if (ds->peers[idx].fail_count >= 3) {
            ds->peers[idx].flags |= AC_PEER_UNREACHABLE;
            ds->peers[idx].flags &= (uint8_t)~AC_PEER_ACTIVE;
            ac_log(AC_LOG_WARN, "peer marked unreachable after 3 failures");
        }
    }
    ac_mutex_unlock(&ds->lock);
}

void ac_discover_mark_success(ac_discover_state_t *ds,
                              const uint8_t pubkey[AC_PUBKEY_LEN])
{
    int idx;

    if (!ds || !pubkey)
        return;

    ac_mutex_lock(&ds->lock);
    idx = find_peer_by_pubkey(ds, pubkey);
    if (idx >= 0) {
        ds->peers[idx].fail_count = 0;
        ds->peers[idx].flags |= AC_PEER_ACTIVE;
        ds->peers[idx].flags &= (uint8_t)~AC_PEER_UNREACHABLE;
    }
    ac_mutex_unlock(&ds->lock);
}

uint32_t ac_discover_peer_count(const ac_discover_state_t *ds)
{
    uint32_t i, count = 0;

    if (!ds)
        return 0;

    for (i = 0; i < ds->peer_count; i++) {
        if (!(ds->peers[i].flags & AC_PEER_UNREACHABLE))
            count++;
    }
    return count;
}
