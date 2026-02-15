/*
 * ac_claims.c — Claim store for addrchain
 *
 * C port of Go claims.go with v2 extensions: lease TTL in blocks,
 * key revocation chain, rollback detection, address prefix validation.
 *
 * Thread-safe: all public functions acquire cs->lock.
 *
 * Mitigates: K01,K02,K07,K37,K41,N01,N02,N03,N04,N06,N10,N12,
 *            N28,N34,N38,N39
 */

#include "ac_claims.h"
#include "ac_crypto.h"

/* ================================================================== */
/*  Internal helpers (caller holds lock)                               */
/* ================================================================== */

/* Find claim slot by address. Returns index or -1 if not found. */
static int find_claim(const ac_claim_store_t *cs, const ac_address_t *addr)
{
    uint32_t i;
    for (i = 0; i < AC_MAX_CLAIMS; i++) {
        if (cs->claims[i].active &&
            ac_addr_cmp(&cs->claims[i].address, addr) == 0)
            return (int)i;
    }
    return -1;
}

/* Find a free claim slot. Returns index or -1 if full. */
static int find_free_claim(const ac_claim_store_t *cs)
{
    uint32_t i;
    for (i = 0; i < AC_MAX_CLAIMS; i++) {
        if (!cs->claims[i].active)
            return (int)i;
    }
    return -1;
}

/* Find revocation entry for old_pubkey. Returns index or -1. */
static int find_revocation(const ac_claim_store_t *cs,
                           const uint8_t pubkey[AC_PUBKEY_LEN])
{
    uint32_t i;
    for (i = 0; i < AC_MAX_REVOCATIONS; i++) {
        if (cs->revoked[i].active &&
            memcmp(cs->revoked[i].old_pubkey, pubkey, AC_PUBKEY_LEN) == 0)
            return (int)i;
    }
    return -1;
}

/* Resolve pubkey through revocation chain (no locking). */
static void resolve_pubkey_internal(const ac_claim_store_t *cs,
                                    const uint8_t pubkey[AC_PUBKEY_LEN],
                                    uint8_t out[AC_PUBKEY_LEN])
{
    uint8_t current[AC_PUBKEY_LEN];
    uint32_t depth = 0;
    int idx;

    memcpy(current, pubkey, AC_PUBKEY_LEN);

    /* Follow revocation chain with cycle detection (max depth) */
    while (depth < AC_MAX_REVOCATIONS) {
        idx = find_revocation(cs, current);
        if (idx < 0)
            break;
        memcpy(current, cs->revoked[idx].new_pubkey, AC_PUBKEY_LEN);
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

/* Expire stale leases at given block index. */
static void expire_leases(ac_claim_store_t *cs, uint32_t tip_index)
{
    uint32_t i;
    for (i = 0; i < AC_MAX_CLAIMS; i++) {
        if (!cs->claims[i].active)
            continue;
        uint32_t ttl = effective_lease(cs, &cs->claims[i]);
        if (tip_index > cs->claims[i].last_renewed_block + ttl) {
            ac_log_info("claim expired: block %u + ttl %u < tip %u",
                        cs->claims[i].last_renewed_block, ttl, tip_index);
            cs->claims[i].active = 0;
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
    int idx;

    switch (tx->type) {
    case AC_TX_CLAIM: {
        const ac_tx_claim_t *cl = &tx->payload.claim;

        /* N01: reject if already claimed (FCFS) */
        idx = find_claim(cs, &cl->address);
        if (idx >= 0)
            return AC_OK; /* silently skip — block validation catches this */

        /* K37: check capacity */
        idx = find_free_claim(cs);
        if (idx < 0) {
            ac_log_warn("claim store full (%u/%u)", cs->claim_count, AC_MAX_CLAIMS);
            return AC_ERR_FULL;
        }

        resolve_pubkey_internal(cs, tx->node_pubkey, resolved);

        cs->claims[idx].active = 1;
        cs->claims[idx].address = cl->address;
        memcpy(cs->claims[idx].owner_pubkey, resolved, AC_PUBKEY_LEN);
        cs->claims[idx].last_renewed_block = block_index;
        cs->claims[idx].lease_blocks = ac_le32_to_cpu(cl->lease_blocks);
        cs->claims[idx].original_nonce = tx->nonce;
        cs->claim_count++;
        break;
    }

    case AC_TX_RELEASE: {
        const ac_tx_claim_t *cl = &tx->payload.claim;

        idx = find_claim(cs, &cl->address);
        if (idx < 0)
            return AC_OK; /* already released */

        resolve_pubkey_internal(cs, tx->node_pubkey, resolved);

        /* Only owner can release */
        if (memcmp(cs->claims[idx].owner_pubkey, resolved, AC_PUBKEY_LEN) != 0)
            return AC_OK; /* not owner — skip */

        cs->claims[idx].active = 0;
        cs->claim_count--;
        break;
    }

    case AC_TX_RENEW: {
        const ac_tx_claim_t *cl = &tx->payload.claim;

        idx = find_claim(cs, &cl->address);
        if (idx < 0)
            return AC_OK; /* can't renew unclaimed */

        resolve_pubkey_internal(cs, tx->node_pubkey, resolved);

        if (memcmp(cs->claims[idx].owner_pubkey, resolved, AC_PUBKEY_LEN) != 0)
            return AC_OK; /* not owner */

        cs->claims[idx].last_renewed_block = block_index;
        /* Update lease if specified */
        if (ac_le32_to_cpu(cl->lease_blocks) != 0)
            cs->claims[idx].lease_blocks = ac_le32_to_cpu(cl->lease_blocks);
        break;
    }

    case AC_TX_REVOKE: {
        const ac_tx_revoke_t *rv = &tx->payload.revoke;
        uint32_t i;

        /* Record revocation */
        if (cs->revoke_count < AC_MAX_REVOCATIONS) {
            uint32_t ri = cs->revoke_count;
            memcpy(cs->revoked[ri].old_pubkey, rv->old_pubkey, AC_PUBKEY_LEN);
            memcpy(cs->revoked[ri].new_pubkey, rv->new_pubkey, AC_PUBKEY_LEN);
            cs->revoked[ri].active = 1;
            cs->revoke_count++;
        }

        /* Migrate claims from old identity to new */
        for (i = 0; i < AC_MAX_CLAIMS; i++) {
            if (cs->claims[i].active &&
                memcmp(cs->claims[i].owner_pubkey, rv->old_pubkey,
                       AC_PUBKEY_LEN) == 0) {
                memcpy(cs->claims[i].owner_pubkey, rv->new_pubkey,
                       AC_PUBKEY_LEN);
            }
        }
        break;
    }

    default:
        /* Non-claim transaction types (SUBNET_*, VPN_*, PARTITION) —
         * handled by other subsystems, ignore here. */
        break;
    }

    return AC_OK;
}

/* ================================================================== */
/*  Lifecycle                                                          */
/* ================================================================== */

int ac_claims_init(ac_claim_store_t *cs, uint32_t lease_ttl)
{
    int rc;

    if (!cs)
        return AC_ERR_INVAL;

    memset(cs, 0, sizeof(*cs));

    rc = ac_mutex_init(&cs->lock);
    if (rc != AC_OK)
        return rc;

    cs->lease_ttl = (lease_ttl > 0) ? lease_ttl : AC_DEFAULT_LEASE_BLOCKS;
    ac_log_info("claim store initialized (lease_ttl=%u blocks)", cs->lease_ttl);
    return AC_OK;
}

void ac_claims_destroy(ac_claim_store_t *cs)
{
    if (!cs)
        return;

    ac_mutex_lock(&cs->lock);
    /* K04: zeroize claim data (may contain sensitive pubkeys) */
    ac_crypto_zeroize(cs->claims, sizeof(cs->claims));
    ac_crypto_zeroize(cs->revoked, sizeof(cs->revoked));
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
    int idx;

    if (!cs || !addr || !out_owner)
        return AC_ERR_INVAL;

    ac_mutex_lock(&cs->lock);
    idx = find_claim(cs, addr);
    if (idx < 0) {
        ac_mutex_unlock(&cs->lock);
        return AC_ERR_NOENT;
    }
    memcpy(out_owner, cs->claims[idx].owner_pubkey, AC_PUBKEY_LEN);
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
    uint32_t i, found = 0;
    uint8_t resolved[AC_PUBKEY_LEN];

    if (!cs || !pubkey)
        return 0;

    ac_mutex_lock(&cs->lock);
    resolve_pubkey_internal(cs, pubkey, resolved);

    for (i = 0; i < AC_MAX_CLAIMS && found < max_out; i++) {
        if (cs->claims[i].active &&
            memcmp(cs->claims[i].owner_pubkey, resolved, AC_PUBKEY_LEN) == 0) {
            if (out)
                out[found] = cs->claims[i].address;
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
    /*
     * Validate block transactions against current claim state.
     * Uses a temporary overlay: we track "pending claims" for this
     * block without modifying the actual store.
     *
     * Temporary overlay uses small arrays since blocks have
     * at most AC_MAX_TX_PER_BLOCK transactions.
     */
    ac_address_t pending_claims[AC_MAX_TX_PER_BLOCK];
    uint8_t pending_owners[AC_MAX_TX_PER_BLOCK][AC_PUBKEY_LEN];
    uint16_t pending_count = 0;
    ac_address_t pending_releases[AC_MAX_TX_PER_BLOCK];
    uint16_t release_count = 0;
    uint16_t i, j;
    int idx;
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

            /* Check existing claims */
            idx = find_claim(cs, &cl->address);
            if (idx >= 0) {
                /* Check if it was released in this block */
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

            /* Check pending claims in this block (intra-block conflict) */
            for (j = 0; j < pending_count; j++) {
                if (ac_addr_cmp(&pending_claims[j], &cl->address) == 0) {
                    ac_log_warn("validate: tx %u intra-block duplicate claim", i);
                    ac_mutex_unlock(&cs->lock);
                    return AC_ERR_EXIST;
                }
            }

            /* Record pending claim */
            pending_claims[pending_count] = cl->address;
            memcpy(pending_owners[pending_count], resolved, AC_PUBKEY_LEN);
            pending_count++;
            break;
        }

        case AC_TX_RELEASE: {
            const ac_tx_claim_t *cl = &tx->payload.claim;

            idx = find_claim(cs, &cl->address);
            if (idx < 0) {
                /* Check if it's a pending claim being released */
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
                /* Verify ownership */
                if (memcmp(cs->claims[idx].owner_pubkey, resolved,
                           AC_PUBKEY_LEN) != 0) {
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

            idx = find_claim(cs, &cl->address);
            if (idx < 0) {
                /* Check pending claims */
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
                if (memcmp(cs->claims[idx].owner_pubkey, resolved,
                           AC_PUBKEY_LEN) != 0) {
                    ac_log_warn("validate: tx %u renew by non-owner", i);
                    ac_mutex_unlock(&cs->lock);
                    return AC_ERR_PERM;
                }
            }
            break;
        }

        case AC_TX_REVOKE:
            /* Revocation validated at chain level (signature check) */
            break;

        default:
            /* Non-claim types validated elsewhere */
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
/*  Chain rebuild (N10, N28)                                           */
/* ================================================================== */

int ac_claims_rebuild(ac_claim_store_t *cs,
                      const ac_block_t *blocks, uint32_t block_count,
                      const uint8_t local_pubkey[AC_PUBKEY_LEN],
                      ac_address_t *lost_addrs, uint32_t lost_max,
                      uint32_t *lost_count)
{
    /* Save old claims to detect rollback losses */
    ac_claim_record_t *old_claims = NULL;
    uint32_t i, j;
    uint32_t tip_index;

    if (!cs || !blocks || block_count == 0)
        return AC_ERR_INVAL;

    if (lost_count)
        *lost_count = 0;

    old_claims = (ac_claim_record_t *)ac_alloc(
        sizeof(ac_claim_record_t) * AC_MAX_CLAIMS, AC_MEM_NORMAL);
    if (!old_claims)
        return AC_ERR_NOMEM;

    ac_mutex_lock(&cs->lock);

    /* Save old state */
    memcpy(old_claims, cs->claims, sizeof(cs->claims));

    /* Clear all state */
    memset(cs->claims, 0, sizeof(cs->claims));
    memset(cs->revoked, 0, sizeof(cs->revoked));
    cs->claim_count = 0;
    cs->revoke_count = 0;

    tip_index = blocks[block_count - 1].index;

    /* Replay all blocks */
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

        for (i = 0; i < AC_MAX_CLAIMS && losses < lost_max; i++) {
            if (!old_claims[i].active)
                continue;
            if (memcmp(old_claims[i].owner_pubkey, resolved_local,
                       AC_PUBKEY_LEN) != 0)
                continue;

            /* Check if we still own this address */
            int still_owned = 0;
            for (j = 0; j < AC_MAX_CLAIMS; j++) {
                if (cs->claims[j].active &&
                    ac_addr_cmp(&cs->claims[j].address,
                                &old_claims[i].address) == 0 &&
                    memcmp(cs->claims[j].owner_pubkey, resolved_local,
                           AC_PUBKEY_LEN) == 0) {
                    still_owned = 1;
                    break;
                }
            }

            if (!still_owned) {
                lost_addrs[losses++] = old_claims[i].address;
            }
        }
        *lost_count = losses;

        if (losses > 0) {
            ac_log_warn("rebuild: %u local claims lost (rollback)", losses);
        }
    }

    ac_mutex_unlock(&cs->lock);

    ac_crypto_zeroize(old_claims, sizeof(ac_claim_record_t) * AC_MAX_CLAIMS);
    ac_free(old_claims);

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
