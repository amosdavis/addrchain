/*
 * ac_claims.c — Claim store for addrchain (dynamic hashmap-backed)
 *
 * C port of Go claims.go with v2 extensions: lease TTL in blocks,
 * key revocation chain, rollback detection, address prefix validation.
 * Backed by ac_hashmap_t for unlimited scaling (S01, S15).
 *
 * Thread-safe: all public functions acquire cs->lock.
 *
 * Mitigates: K01,K02,K07,K37,K41,N01,N02,N03,N04,N06,N10,N12,
 *            N28,N34,N38,N39,S01,S13,S15
 */

#include "ac_claims.h"
#include "ac_crypto.h"
#include "ac_dag.h"

/* ================================================================== */
/*  Internal helpers (caller holds lock)                               */
/* ================================================================== */

/* Address key for hashmap: family + addr bytes = 33 bytes */
#define AC_CLAIM_KEY_LEN (1 + AC_MAX_ADDR_LEN)

static void make_claim_key(uint8_t out[AC_CLAIM_KEY_LEN],
                           const ac_address_t *addr)
{
    out[0] = addr->family;
    memcpy(out + 1, addr->addr, AC_MAX_ADDR_LEN);
}

/* Find claim by address. Returns pointer or NULL. */
static ac_claim_record_t *find_claim(ac_claim_store_t *cs,
                                      const ac_address_t *addr)
{
    uint8_t key[AC_CLAIM_KEY_LEN];
    make_claim_key(key, addr);
    return (ac_claim_record_t *)ac_hashmap_get(&cs->claims_map,
                                                key, AC_CLAIM_KEY_LEN);
}

/* Resolve pubkey through revocation chain (no locking). */
static void resolve_pubkey_internal(const ac_claim_store_t *cs,
                                     const uint8_t pubkey[AC_PUBKEY_LEN],
                                     uint8_t out[AC_PUBKEY_LEN])
{
    uint8_t current[AC_PUBKEY_LEN];
    uint32_t depth = 0;
    ac_revocation_t *rev;

    memcpy(current, pubkey, AC_PUBKEY_LEN);

    while (depth < cs->revoke_count + 1) {
        rev = (ac_revocation_t *)ac_hashmap_get(&cs->revoke_map,
                                                 current, AC_PUBKEY_LEN);
        if (!rev || !rev->active)
            break;
        memcpy(current, rev->new_pubkey, AC_PUBKEY_LEN);
        depth++;
    }

    memcpy(out, current, AC_PUBKEY_LEN);
}

/* Get effective lease TTL for a claim. */
static uint32_t effective_lease(const ac_claim_store_t *cs,
                                 const ac_claim_record_t *rec)
{
    if (rec->lease_blocks != 0)
        return rec->lease_blocks;
    return cs->lease_ttl;
}

/* Expire stale leases at given block index (S13: safe iter+remove). */
static void expire_leases(ac_claim_store_t *cs, uint32_t tip_index)
{
    ac_hashmap_iter_t it;
    const void *k;
    uint32_t kl;
    void *v;

    ac_hashmap_iter_init(&it, &cs->claims_map);
    while (ac_hashmap_iter_next(&it, &k, &kl, &v)) {
        ac_claim_record_t *rec = (ac_claim_record_t *)v;
        uint32_t ttl = effective_lease(cs, rec);
        if (tip_index > rec->last_renewed_block + ttl) {
            ac_log_info("claim expired: block %u + ttl %u < tip %u",
                        rec->last_renewed_block, ttl, tip_index);
            /* DAG: remove expired claim node */
            if (cs->dag)
                ac_dag_remove_node(cs->dag, AC_RES_CLAIM, rec->address.addr);
            ac_hashmap_iter_remove(&it);
            ac_free(rec);
            cs->claim_count--;
        }
    }
}

/* Apply a single CLAIM/RELEASE/RENEW/REVOKE transaction. */
static int apply_tx(ac_claim_store_t *cs,
                     const ac_transaction_t *tx,
                     uint32_t block_index)
{
    uint8_t resolved[AC_PUBKEY_LEN];
    uint8_t key[AC_CLAIM_KEY_LEN];
    ac_claim_record_t *rec;

    switch (tx->type) {
    case AC_TX_CLAIM: {
        const ac_tx_claim_t *cl = &tx->payload.claim;

        rec = find_claim(cs, &cl->address);
        if (rec != NULL)
            return AC_OK;

        if (cs->max_claims > 0 && cs->claim_count >= cs->max_claims) {
            ac_log_warn("claim store full (%u/%u)", cs->claim_count, cs->max_claims);
            return AC_ERR_FULL;
        }

        resolve_pubkey_internal(cs, tx->node_pubkey, resolved);

        rec = (ac_claim_record_t *)ac_zalloc(sizeof(*rec), AC_MEM_NORMAL);
        if (!rec)
            return AC_ERR_NOMEM;

        rec->active = 1;
        rec->address = cl->address;
        memcpy(rec->owner_pubkey, resolved, AC_PUBKEY_LEN);
        rec->last_renewed_block = block_index;
        rec->lease_blocks = ac_le32_to_cpu(cl->lease_blocks);
        rec->original_nonce = tx->nonce;

        make_claim_key(key, &cl->address);
        if (ac_hashmap_put(&cs->claims_map, key, AC_CLAIM_KEY_LEN,
                           rec, NULL) != AC_OK) {
            ac_free(rec);
            return AC_ERR_NOMEM;
        }
        cs->claim_count++;

        /* DAG: register claim node and claim→subnet dependency edge */
        if (cs->dag) {
            ac_dag_add_node(cs->dag, AC_RES_CLAIM, cl->address.addr);
            {
                uint8_t zero_id[AC_SUBNET_ID_LEN];
                memset(zero_id, 0, sizeof(zero_id));
                if (memcmp(cl->subnet_id, zero_id, AC_SUBNET_ID_LEN) != 0) {
                    uint8_t subnet_dag_id[AC_MAX_ADDR_LEN];
                    memset(subnet_dag_id, 0, AC_MAX_ADDR_LEN);
                    memcpy(subnet_dag_id, cl->subnet_id, AC_SUBNET_ID_LEN);
                    ac_dag_add_edge(cs->dag, AC_RES_SUBNET, subnet_dag_id,
                                    AC_RES_CLAIM, cl->address.addr);
                }
            }
        }
        break;
    }

    case AC_TX_RELEASE: {
        const ac_tx_claim_t *cl = &tx->payload.claim;

        rec = find_claim(cs, &cl->address);
        if (!rec)
            return AC_OK;

        resolve_pubkey_internal(cs, tx->node_pubkey, resolved);

        if (memcmp(rec->owner_pubkey, resolved, AC_PUBKEY_LEN) != 0)
            return AC_OK;

        make_claim_key(key, &cl->address);
        rec = (ac_claim_record_t *)ac_hashmap_remove(&cs->claims_map,
                                                      key, AC_CLAIM_KEY_LEN);
        if (rec) {
            /* DAG: remove claim node (edges pruned automatically) */
            if (cs->dag)
                ac_dag_remove_node(cs->dag, AC_RES_CLAIM, cl->address.addr);
            ac_free(rec);
            cs->claim_count--;
        }
        break;
    }

    case AC_TX_RENEW: {
        const ac_tx_claim_t *cl = &tx->payload.claim;

        rec = find_claim(cs, &cl->address);
        if (!rec)
            return AC_OK;

        resolve_pubkey_internal(cs, tx->node_pubkey, resolved);

        if (memcmp(rec->owner_pubkey, resolved, AC_PUBKEY_LEN) != 0)
            return AC_OK;

        rec->last_renewed_block = block_index;
        if (ac_le32_to_cpu(cl->lease_blocks) != 0)
            rec->lease_blocks = ac_le32_to_cpu(cl->lease_blocks);
        break;
    }

    case AC_TX_REVOKE: {
        const ac_tx_revoke_t *rv = &tx->payload.revoke;
        ac_revocation_t *revoc;
        ac_hashmap_iter_t it;
        const void *ik;
        uint32_t ikl;
        void *iv;

        revoc = (ac_revocation_t *)ac_zalloc(sizeof(*revoc), AC_MEM_NORMAL);
        if (!revoc)
            return AC_ERR_NOMEM;
        memcpy(revoc->old_pubkey, rv->old_pubkey, AC_PUBKEY_LEN);
        memcpy(revoc->new_pubkey, rv->new_pubkey, AC_PUBKEY_LEN);
        revoc->active = 1;

        {
            void *old_rev = NULL;
            if (ac_hashmap_put(&cs->revoke_map, rv->old_pubkey, AC_PUBKEY_LEN,
                               revoc, &old_rev) != AC_OK) {
                ac_free(revoc);
                return AC_ERR_NOMEM;
            }
            if (old_rev)
                ac_free(old_rev);
            else
                cs->revoke_count++;
        }

        ac_hashmap_iter_init(&it, &cs->claims_map);
        while (ac_hashmap_iter_next(&it, &ik, &ikl, &iv)) {
            ac_claim_record_t *cr = (ac_claim_record_t *)iv;
            if (cr->active &&
                memcmp(cr->owner_pubkey, rv->old_pubkey, AC_PUBKEY_LEN) == 0) {
                memcpy(cr->owner_pubkey, rv->new_pubkey, AC_PUBKEY_LEN);
            }
        }
        break;
    }

    default:
        break;
    }

    return AC_OK;
}

/* ================================================================== */
/*  Lifecycle                                                          */
/* ================================================================== */

int ac_claims_init(ac_claim_store_t *cs, uint32_t lease_ttl, uint32_t max_claims,
                   ac_dag_t *dag)
{
    int rc;

    if (!cs)
        return AC_ERR_INVAL;

    memset(cs, 0, sizeof(*cs));
    cs->dag = dag;

    rc = ac_mutex_init(&cs->lock);
    if (rc != AC_OK)
        return rc;

    cs->max_claims = max_claims;

    if (max_claims > 0) {
        size_t entry_overhead = sizeof(ac_claim_record_t) + AC_CLAIM_KEY_LEN + 64;
        if ((uint64_t)max_claims * entry_overhead > (uint64_t)1 << 31) {
            ac_log_error("max_claims %u would exceed vmalloc limit", max_claims);
            ac_mutex_destroy(&cs->lock);
            return AC_ERR_NOMEM;
        }
    }

    rc = ac_hashmap_init(&cs->claims_map, 64, max_claims);
    if (rc != AC_OK) {
        ac_mutex_destroy(&cs->lock);
        return rc;
    }

    rc = ac_hashmap_init(&cs->revoke_map, 16, 0);
    if (rc != AC_OK) {
        ac_hashmap_destroy(&cs->claims_map);
        ac_mutex_destroy(&cs->lock);
        return rc;
    }

    cs->lease_ttl = (lease_ttl > 0) ? lease_ttl : AC_DEFAULT_LEASE_BLOCKS;
    ac_log_info("claim store initialized (lease_ttl=%u blocks, max=%u)",
                cs->lease_ttl, max_claims);
    return AC_OK;
}

void ac_claims_destroy(ac_claim_store_t *cs)
{
    ac_hashmap_iter_t it;
    const void *k;
    uint32_t kl;
    void *v;

    if (!cs)
        return;

    ac_mutex_lock(&cs->lock);

    ac_hashmap_iter_init(&it, &cs->claims_map);
    while (ac_hashmap_iter_next(&it, &k, &kl, &v)) {
        ac_crypto_zeroize(v, sizeof(ac_claim_record_t));
        ac_free(v);
    }
    ac_hashmap_destroy(&cs->claims_map);

    ac_hashmap_iter_init(&it, &cs->revoke_map);
    while (ac_hashmap_iter_next(&it, &k, &kl, &v))
        ac_free(v);
    ac_hashmap_destroy(&cs->revoke_map);

    cs->claim_count = 0;
    cs->revoke_count = 0;
    ac_mutex_unlock(&cs->lock);

    ac_mutex_destroy(&cs->lock);
    ac_log_info("claim store destroyed");
}

/* ================================================================== */
/*  Claim operations (thread-safe)                                     */
/* ================================================================== */

int ac_claims_get_owner(ac_claim_store_t *cs,
                         const ac_address_t *addr,
                         uint8_t out_owner[AC_PUBKEY_LEN])
{
    ac_claim_record_t *rec;

    if (!cs || !addr || !out_owner)
        return AC_ERR_INVAL;

    ac_mutex_lock(&cs->lock);
    rec = find_claim(cs, addr);
    if (!rec) {
        ac_mutex_unlock(&cs->lock);
        return AC_ERR_NOENT;
    }
    memcpy(out_owner, rec->owner_pubkey, AC_PUBKEY_LEN);
    ac_mutex_unlock(&cs->lock);
    return AC_OK;
}

uint32_t ac_claims_count(ac_claim_store_t *cs)
{
    uint32_t count;
    if (!cs)
        return 0;
    ac_mutex_lock(&cs->lock);
    count = cs->claim_count;
    ac_mutex_unlock(&cs->lock);
    return count;
}

uint32_t ac_claims_by_node(ac_claim_store_t *cs,
                            const uint8_t pubkey[AC_PUBKEY_LEN],
                            ac_address_t *out, uint32_t max_out)
{
    uint32_t found = 0;
    uint8_t resolved[AC_PUBKEY_LEN];
    ac_hashmap_iter_t it;
    const void *k;
    uint32_t kl;
    void *v;

    if (!cs || !pubkey)
        return 0;

    ac_mutex_lock(&cs->lock);
    resolve_pubkey_internal(cs, pubkey, resolved);

    ac_hashmap_iter_init(&it, &cs->claims_map);
    while (ac_hashmap_iter_next(&it, &k, &kl, &v) && found < max_out) {
        ac_claim_record_t *rec = (ac_claim_record_t *)v;
        if (rec->active &&
            memcmp(rec->owner_pubkey, resolved, AC_PUBKEY_LEN) == 0) {
            if (out)
                out[found] = rec->address;
            found++;
        }
    }
    ac_mutex_unlock(&cs->lock);
    return found;
}

/* ================================================================== */
/*  Block validation                                                   */
/* ================================================================== */

int ac_claims_validate_block(ac_claim_store_t *cs,
                              const ac_block_t *blk)
{
    ac_address_t pending_claims[AC_MAX_TX_PER_BLOCK];
    uint8_t pending_owners[AC_MAX_TX_PER_BLOCK][AC_PUBKEY_LEN];
    uint16_t pending_count = 0;
    ac_address_t pending_releases[AC_MAX_TX_PER_BLOCK];
    uint16_t release_count = 0;
    uint16_t i, j;
    ac_claim_record_t *rec;
    uint8_t resolved[AC_PUBKEY_LEN];

    if (!cs || !blk)
        return AC_ERR_INVAL;

    if (blk->tx_count > AC_MAX_TX_PER_BLOCK)
        return AC_ERR_INVAL;

    ac_mutex_lock(&cs->lock);

    for (i = 0; i < blk->tx_count; i++) {
        const ac_transaction_t *tx = &blk->txs[i];

        resolve_pubkey_internal(cs, tx->node_pubkey, resolved);

        switch (tx->type) {
        case AC_TX_CLAIM: {
            const ac_tx_claim_t *cl = &tx->payload.claim;

            rec = find_claim(cs, &cl->address);
            if (rec) {
                int was_released = 0;
                for (j = 0; j < release_count; j++) {
                    if (ac_addr_cmp(&pending_releases[j], &cl->address) == 0) {
                        was_released = 1;
                        break;
                    }
                }
                if (!was_released) {
                    ac_log_warn("validate: tx %u address already claimed", i);
                    ac_mutex_unlock(&cs->lock);
                    return AC_ERR_EXIST;
                }
            }

            for (j = 0; j < pending_count; j++) {
                if (ac_addr_cmp(&pending_claims[j], &cl->address) == 0) {
                    ac_log_warn("validate: tx %u intra-block duplicate claim", i);
                    ac_mutex_unlock(&cs->lock);
                    return AC_ERR_EXIST;
                }
            }

            pending_claims[pending_count] = cl->address;
            memcpy(pending_owners[pending_count], resolved, AC_PUBKEY_LEN);
            pending_count++;
            break;
        }

        case AC_TX_RELEASE: {
            const ac_tx_claim_t *cl = &tx->payload.claim;

            rec = find_claim(cs, &cl->address);
            if (!rec) {
                int found = 0;
                for (j = 0; j < pending_count; j++) {
                    if (ac_addr_cmp(&pending_claims[j], &cl->address) == 0 &&
                        memcmp(pending_owners[j], resolved, AC_PUBKEY_LEN) == 0) {
                        found = 1;
                        break;
                    }
                }
                if (!found) {
                    ac_log_warn("validate: tx %u release unclaimed address", i);
                    ac_mutex_unlock(&cs->lock);
                    return AC_ERR_NOENT;
                }
            } else {
                if (memcmp(rec->owner_pubkey, resolved, AC_PUBKEY_LEN) != 0) {
                    ac_log_warn("validate: tx %u release by non-owner", i);
                    ac_mutex_unlock(&cs->lock);
                    return AC_ERR_PERM;
                }
            }

            pending_releases[release_count++] = cl->address;
            break;
        }

        case AC_TX_RENEW: {
            const ac_tx_claim_t *cl = &tx->payload.claim;

            rec = find_claim(cs, &cl->address);
            if (!rec) {
                int found = 0;
                for (j = 0; j < pending_count; j++) {
                    if (ac_addr_cmp(&pending_claims[j], &cl->address) == 0)
                        found = 1;
                }
                if (!found) {
                    ac_log_warn("validate: tx %u renew unclaimed address", i);
                    ac_mutex_unlock(&cs->lock);
                    return AC_ERR_NOENT;
                }
            } else {
                if (memcmp(rec->owner_pubkey, resolved, AC_PUBKEY_LEN) != 0) {
                    ac_log_warn("validate: tx %u renew by non-owner", i);
                    ac_mutex_unlock(&cs->lock);
                    return AC_ERR_PERM;
                }
            }
            break;
        }

        case AC_TX_REVOKE:
            break;

        default:
            break;
        }
    }

    ac_mutex_unlock(&cs->lock);
    return AC_OK;
}

/* ================================================================== */
/*  Block application                                                  */
/* ================================================================== */

int ac_claims_apply_block(ac_claim_store_t *cs,
                           const ac_block_t *blk)
{
    uint16_t i;
    int rc;

    if (!cs || !blk)
        return AC_ERR_INVAL;

    ac_mutex_lock(&cs->lock);

    for (i = 0; i < blk->tx_count && i < AC_MAX_TX_PER_BLOCK; i++) {
        rc = apply_tx(cs, &blk->txs[i], blk->index);
        if (rc != AC_OK) {
            ac_log_warn("apply_block: tx %u failed: %d", i, rc);
            ac_mutex_unlock(&cs->lock);
            return rc;
        }
    }

    expire_leases(cs, blk->index);
    ac_mutex_unlock(&cs->lock);
    return AC_OK;
}

/* ================================================================== */
/*  Chain rebuild (N10, N28) — iterates hashmap                        */
/* ================================================================== */

int ac_claims_rebuild(ac_claim_store_t *cs,
                       const ac_block_t *blocks, uint32_t block_count,
                       const uint8_t local_pubkey[AC_PUBKEY_LEN],
                       ac_address_t *lost_addrs, uint32_t lost_max,
                       uint32_t *lost_count)
{
    ac_hashmap_t old_map;
    ac_hashmap_iter_t it;
    const void *k;
    uint32_t kl;
    void *v;
    uint32_t i, j;
    uint32_t tip_index;
    int rc;

    if (!cs || !blocks || block_count == 0)
        return AC_ERR_INVAL;

    if (lost_count)
        *lost_count = 0;

    ac_mutex_lock(&cs->lock);

    /* Move current claims map to old_map for rollback detection */
    old_map = cs->claims_map;

    rc = ac_hashmap_init(&cs->claims_map, 64, cs->max_claims);
    if (rc != AC_OK) {
        cs->claims_map = old_map;
        ac_mutex_unlock(&cs->lock);
        return rc;
    }
    cs->claim_count = 0;

    /* Clear revocations */
    ac_hashmap_iter_init(&it, &cs->revoke_map);
    while (ac_hashmap_iter_next(&it, &k, &kl, &v)) {
        ac_free(v);
        ac_hashmap_iter_remove(&it);
    }
    cs->revoke_count = 0;

    tip_index = blocks[block_count - 1].index;

    for (i = 0; i < block_count; i++) {
        for (j = 0; j < blocks[i].tx_count && j < AC_MAX_TX_PER_BLOCK; j++) {
            apply_tx(cs, &blocks[i].txs[j], blocks[i].index);
        }
    }

    expire_leases(cs, tip_index);

    /* Detect lost claims (rollback detection) */
    if (local_pubkey && lost_addrs && lost_count) {
        uint32_t losses = 0;
        uint8_t resolved_local[AC_PUBKEY_LEN];
        resolve_pubkey_internal(cs, local_pubkey, resolved_local);

        ac_hashmap_iter_init(&it, &old_map);
        while (ac_hashmap_iter_next(&it, &k, &kl, &v) && losses < lost_max) {
            ac_claim_record_t *old_rec = (ac_claim_record_t *)v;
            if (!old_rec->active)
                continue;
            if (memcmp(old_rec->owner_pubkey, resolved_local, AC_PUBKEY_LEN) != 0)
                continue;

            ac_claim_record_t *new_rec = find_claim(cs, &old_rec->address);
            int still_owned = (new_rec != NULL &&
                               memcmp(new_rec->owner_pubkey, resolved_local,
                                      AC_PUBKEY_LEN) == 0);

            if (!still_owned) {
                lost_addrs[losses++] = old_rec->address;
            }
        }
        *lost_count = losses;

        if (losses > 0) {
            ac_log_warn("rebuild: %u local claims lost (rollback)", losses);
        }
    }

    ac_mutex_unlock(&cs->lock);

    /* Free old map entries */
    ac_hashmap_iter_init(&it, &old_map);
    while (ac_hashmap_iter_next(&it, &k, &kl, &v)) {
        ac_crypto_zeroize(v, sizeof(ac_claim_record_t));
        ac_free(v);
    }
    ac_hashmap_destroy(&old_map);

    ac_log_info("claim store rebuilt from %u blocks, %u active claims",
                block_count, cs->claim_count);
    return AC_OK;
}

/* ================================================================== */
/*  Revocation resolution (thread-safe)                                */
/* ================================================================== */

void ac_claims_resolve_pubkey(ac_claim_store_t *cs,
                               const uint8_t pubkey[AC_PUBKEY_LEN],
                               uint8_t out[AC_PUBKEY_LEN])
{
    if (!cs || !pubkey || !out) {
        if (out && pubkey)
            memcpy(out, pubkey, AC_PUBKEY_LEN);
        return;
    }

    ac_mutex_lock(&cs->lock);
    resolve_pubkey_internal(cs, pubkey, out);
    ac_mutex_unlock(&cs->lock);
}
