/*
 * ac_discover.c — Autodiscovery protocol implementation
 *
 * Manages peer table with blockchain-aware priority. Handles announce
 * building/processing, peer lifecycle, self-discovery prevention,
 * and LRU eviction. Peers are stored in a hashmap keyed by pubkey.
 *
 * Mitigates: K11,N07,N09,N36,P17,P18,P19,P20,P21
 */

#include "ac_discover.h"
#include "ac_crypto.h"

#include <string.h>

/* Default peer limit when max_peers is 0 */
#define AC_DEFAULT_MAX_PEERS 256

/* ================================================================== */
/*  Internal helpers                                                   */
/* ================================================================== */

/*
 * Generate a synthetic pubkey for a static peer from its address.
 * Uses SHA-256 of address bytes, truncated to AC_PUBKEY_LEN.
 */
static void synthetic_key_from_addr(const ac_address_t *addr,
                                    uint8_t out[AC_PUBKEY_LEN])
{
    uint8_t hash[AC_HASH_LEN];
    ac_crypto_sha256((const uint8_t *)addr, sizeof(*addr), hash);
    memcpy(out, hash, AC_PUBKEY_LEN);
}

/*
 * Find a peer by address via iteration. Returns the peer pointer or NULL.
 * Optionally writes the key used for the match into found_key.
 */
static ac_peer_t *find_peer_by_addr(ac_discover_state_t *ds,
                                    const ac_address_t *addr,
                                    uint8_t found_key[AC_PUBKEY_LEN])
{
    ac_hashmap_iter_t it;
    const void *key;
    uint32_t key_len;
    void *value;

    ac_hashmap_iter_init(&it, &ds->peer_map);
    while (ac_hashmap_iter_next(&it, &key, &key_len, &value)) {
        ac_peer_t *p = (ac_peer_t *)value;
        if (p->addr.family == addr->family &&
            memcmp(p->addr.addr, addr->addr, AC_MAX_ADDR_LEN) == 0) {
            if (found_key)
                memcpy(found_key, key, AC_PUBKEY_LEN);
            return p;
        }
    }
    return NULL;
}

/*
 * evict_lru — Find the LRU non-static peer and evict it.
 * Returns 0 on success, -1 if no evictable peer.
 */
static int evict_lru(ac_discover_state_t *ds)
{
    ac_hashmap_iter_t it;
    const void *key;
    uint32_t key_len;
    void *value;
    uint64_t oldest_time = UINT64_MAX;
    uint8_t oldest_key[AC_PUBKEY_LEN];
    int found = 0;

    ac_hashmap_iter_init(&it, &ds->peer_map);
    while (ac_hashmap_iter_next(&it, &key, &key_len, &value)) {
        ac_peer_t *p = (ac_peer_t *)value;
        if (p->flags & AC_PEER_STATIC)
            continue;
        if (p->last_seen < oldest_time) {
            oldest_time = p->last_seen;
            memcpy(oldest_key, key, AC_PUBKEY_LEN);
            found = 1;
        }
    }

    if (found) {
        ac_peer_t *removed = (ac_peer_t *)ac_hashmap_remove(
            &ds->peer_map, oldest_key, AC_PUBKEY_LEN);
        if (removed) {
            ac_free(removed);
            ds->peer_count--;
            ac_log(AC_LOG_INFO, "evicted LRU peer");
        }
        return 0;
    }

    return -1;
}

/* ================================================================== */
/*  Public API                                                         */
/* ================================================================== */

int ac_discover_init(ac_discover_state_t *ds,
                     const uint8_t local_pubkey[AC_PUBKEY_LEN],
                     uint16_t sync_port,
                     uint8_t methods,
                     uint32_t max_peers)
{
    int rc;

    if (!ds || !local_pubkey)
        return AC_ERR_INVAL;

    memset(ds, 0, sizeof(*ds));
    memcpy(ds->local_pubkey, local_pubkey, AC_PUBKEY_LEN);
    ds->local_sync_port = sync_port;
    ds->methods_enabled = methods;
    ds->max_peers = (max_peers == 0) ? AC_DEFAULT_MAX_PEERS : max_peers;

    rc = ac_hashmap_init(&ds->peer_map, 0, 0);
    if (rc != AC_OK)
        return rc;

    ac_mutex_init(&ds->lock);

    ac_log(AC_LOG_INFO, "discovery initialized (methods=0x%02x, port=%u)",
           methods, sync_port);
    return AC_OK;
}

void ac_discover_destroy(ac_discover_state_t *ds)
{
    ac_hashmap_iter_t it;
    const void *key;
    uint32_t key_len;
    void *value;

    if (!ds)
        return;

    /* Free all heap-allocated peer records */
    ac_hashmap_iter_init(&it, &ds->peer_map);
    while (ac_hashmap_iter_next(&it, &key, &key_len, &value)) {
        ac_free((ac_peer_t *)value);
    }
    ac_hashmap_destroy(&ds->peer_map);

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
    ac_peer_t *peer;
    uint64_t now;

    if (!ds || !announce || !peer_addr)
        return AC_ERR_INVAL;

    /* P19: Self-discovery prevention */
    if (memcmp(announce->node_pubkey, ds->local_pubkey, AC_PUBKEY_LEN) == 0) {
        return AC_OK;
    }

    /* P10: Version check */
    if ((announce->version >> 8) != AC_VERSION_MAJOR) {
        ac_log(AC_LOG_WARN, "discover: version mismatch (got %u, want %u)",
               announce->version >> 8, AC_VERSION_MAJOR);
        return AC_ERR_INVAL;
    }

    now = ac_time_unix_sec();

    ac_mutex_lock(&ds->lock);

    /* Look up by pubkey first */
    peer = (ac_peer_t *)ac_hashmap_get(&ds->peer_map,
                                        announce->node_pubkey, AC_PUBKEY_LEN);

    if (peer) {
        /* Update existing peer */
        peer->addr = *peer_addr;
        peer->sync_port = announce->sync_port;
        peer->chain_height = announce->chain_height;
        memcpy(peer->tip_hash, announce->tip_hash, AC_HASH_LEN);
        peer->capabilities = announce->capabilities;
        peer->last_seen = now;
        peer->flags |= AC_PEER_ACTIVE;
        peer->flags &= (uint8_t)~AC_PEER_UNREACHABLE;
    } else {
        uint8_t synth_key[AC_PUBKEY_LEN];
        ac_peer_t *existing_static;

        /*
         * Check if a static peer with matching address exists
         * under a synthetic key. If so, remove and re-insert
         * under the real pubkey.
         */
        existing_static = find_peer_by_addr(ds, peer_addr, synth_key);
        if (existing_static && (existing_static->flags & AC_PEER_STATIC)) {
            /* Remove from old synthetic key */
            ac_peer_t *old = (ac_peer_t *)ac_hashmap_remove(
                &ds->peer_map, synth_key, AC_PUBKEY_LEN);
            if (old) {
                /* Update fields and re-insert under real pubkey */
                memcpy(old->pubkey, announce->node_pubkey, AC_PUBKEY_LEN);
                old->addr = *peer_addr;
                old->sync_port = announce->sync_port;
                old->chain_height = announce->chain_height;
                memcpy(old->tip_hash, announce->tip_hash, AC_HASH_LEN);
                old->capabilities = announce->capabilities;
                old->last_seen = now;
                old->flags |= AC_PEER_ACTIVE;
                old->flags &= (uint8_t)~AC_PEER_UNREACHABLE;

                if (ac_hashmap_put(&ds->peer_map, announce->node_pubkey,
                                   AC_PUBKEY_LEN, old, NULL) != AC_OK) {
                    ac_free(old);
                    ds->peer_count--;
                    ac_mutex_unlock(&ds->lock);
                    return AC_ERR_NOMEM;
                }
                /* peer_count stays the same — moved, not added */
                ac_mutex_unlock(&ds->lock);
                return AC_OK;
            }
        }

        /* Add new peer */
        if (ds->peer_count >= ds->max_peers) {
            if (evict_lru(ds) < 0) {
                ac_mutex_unlock(&ds->lock);
                ac_log(AC_LOG_WARN, "discover: peer table full, all static");
                return AC_ERR_NOMEM;
            }
        }

        peer = (ac_peer_t *)ac_zalloc(sizeof(*peer), AC_MEM_NORMAL);
        if (!peer) {
            ac_mutex_unlock(&ds->lock);
            return AC_ERR_NOMEM;
        }

        memcpy(peer->pubkey, announce->node_pubkey, AC_PUBKEY_LEN);
        peer->addr = *peer_addr;
        peer->sync_port = announce->sync_port;
        peer->chain_height = announce->chain_height;
        memcpy(peer->tip_hash, announce->tip_hash, AC_HASH_LEN);
        peer->capabilities = announce->capabilities;
        peer->flags = AC_PEER_ACTIVE;
        peer->last_seen = now;
        peer->fail_count = 0;

        if (ac_hashmap_put(&ds->peer_map, announce->node_pubkey,
                           AC_PUBKEY_LEN, peer, NULL) != AC_OK) {
            ac_free(peer);
            ac_mutex_unlock(&ds->lock);
            return AC_ERR_NOMEM;
        }
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
    ac_peer_t *existing;
    uint8_t synth_key[AC_PUBKEY_LEN];
    uint8_t found_key[AC_PUBKEY_LEN];

    if (!ds || !addr)
        return AC_ERR_INVAL;

    ac_mutex_lock(&ds->lock);

    /* Check if already known by address */
    existing = find_peer_by_addr(ds, addr, found_key);
    if (existing) {
        existing->flags |= AC_PEER_STATIC;
        existing->sync_port = sync_port;
        ac_mutex_unlock(&ds->lock);
        return AC_OK;
    }

    if (ds->peer_count >= ds->max_peers) {
        ac_mutex_unlock(&ds->lock);
        return AC_ERR_NOMEM;
    }

    /* Use synthetic key derived from address */
    synthetic_key_from_addr(addr, synth_key);

    peer = (ac_peer_t *)ac_zalloc(sizeof(*peer), AC_MEM_NORMAL);
    if (!peer) {
        ac_mutex_unlock(&ds->lock);
        return AC_ERR_NOMEM;
    }

    memcpy(peer->pubkey, synth_key, AC_PUBKEY_LEN);
    peer->addr = *addr;
    peer->sync_port = sync_port;
    peer->flags = AC_PEER_STATIC | AC_PEER_ACTIVE;
    peer->last_seen = ac_time_unix_sec();

    if (ac_hashmap_put(&ds->peer_map, synth_key, AC_PUBKEY_LEN,
                       peer, NULL) != AC_OK) {
        ac_free(peer);
        ac_mutex_unlock(&ds->lock);
        return AC_ERR_NOMEM;
    }
    ds->peer_count++;

    ac_mutex_unlock(&ds->lock);
    ac_log(AC_LOG_INFO, "static peer added (port=%u)", sync_port);
    return AC_OK;
}

void ac_discover_prune(ac_discover_state_t *ds, uint64_t now)
{
    ac_hashmap_iter_t it;
    const void *key;
    uint32_t key_len;
    void *value;

    if (!ds)
        return;

    ac_mutex_lock(&ds->lock);

    ac_hashmap_iter_init(&it, &ds->peer_map);
    while (ac_hashmap_iter_next(&it, &key, &key_len, &value)) {
        ac_peer_t *p = (ac_peer_t *)value;

        if (p->flags & AC_PEER_STATIC)
            continue;

        if (now > p->last_seen &&
            (now - p->last_seen) > (AC_PEER_TIMEOUT_MS / 1000)) {
            ac_hashmap_iter_remove(&it);
            ac_free(p);
            ds->peer_count--;
            ac_log(AC_LOG_INFO, "pruned stale peer");
        }
    }

    ac_mutex_unlock(&ds->lock);
}

const ac_peer_t *ac_discover_best_peer(const ac_discover_state_t *ds)
{
    ac_hashmap_iter_t it;
    const void *key;
    uint32_t key_len;
    void *value;
    const ac_peer_t *best = NULL;

    if (!ds)
        return NULL;

    ac_hashmap_iter_init(&it, (ac_hashmap_t *)&ds->peer_map);
    while (ac_hashmap_iter_next(&it, &key, &key_len, &value)) {
        const ac_peer_t *p = (const ac_peer_t *)value;
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
    ac_peer_t *peer;

    if (!ds || !pubkey)
        return;

    ac_mutex_lock(&ds->lock);
    peer = (ac_peer_t *)ac_hashmap_get(&ds->peer_map, pubkey, AC_PUBKEY_LEN);
    if (peer) {
        peer->fail_count++;
        if (peer->fail_count >= 3) {
            peer->flags |= AC_PEER_UNREACHABLE;
            peer->flags &= (uint8_t)~AC_PEER_ACTIVE;
            ac_log(AC_LOG_WARN, "peer marked unreachable after 3 failures");
        }
    }
    ac_mutex_unlock(&ds->lock);
}

void ac_discover_mark_success(ac_discover_state_t *ds,
                              const uint8_t pubkey[AC_PUBKEY_LEN])
{
    ac_peer_t *peer;

    if (!ds || !pubkey)
        return;

    ac_mutex_lock(&ds->lock);
    peer = (ac_peer_t *)ac_hashmap_get(&ds->peer_map, pubkey, AC_PUBKEY_LEN);
    if (peer) {
        peer->fail_count = 0;
        peer->flags |= AC_PEER_ACTIVE;
        peer->flags &= (uint8_t)~AC_PEER_UNREACHABLE;
    }
    ac_mutex_unlock(&ds->lock);
}

uint32_t ac_discover_peer_count(const ac_discover_state_t *ds)
{
    ac_hashmap_iter_t it;
    const void *key;
    uint32_t key_len;
    void *value;
    uint32_t count = 0;

    if (!ds)
        return 0;

    ac_hashmap_iter_init(&it, (ac_hashmap_t *)&ds->peer_map);
    while (ac_hashmap_iter_next(&it, &key, &key_len, &value)) {
        const ac_peer_t *p = (const ac_peer_t *)value;
        if (!(p->flags & AC_PEER_UNREACHABLE))
            count++;
    }
    return count;
}
