/*
 * ac_chain.c — Blockchain chain engine for addrchain
 *
 * C port of Go chain.go with v2 extensions: 9 transaction types,
 * binary hashing, nonce replay protection, rate limiting, clock
 * sanity check, fork resolution with deterministic tiebreaker.
 *
 * Thread-safe: all public ac_chain_* functions acquire chain->lock.
 *
 * Mitigates: K01,K02,K03,K04,K06,K07,K14,K25,K35,K36,K37,K38,
 *            N06,N07,N08,N10,N30
 */

#include "ac_chain.h"
#include "ac_crypto.h"
#include "ac_hashmap.h"

/* Initial allocation for blocks array */
#define AC_CHAIN_INITIAL_CAP    64

/* ================================================================== */
/*  Internal helpers (no locking — caller holds lock or is static)     */
/* ================================================================== */

/* K01: NULL-safe memcmp wrapper */
static int safe_memcmp(const void *a, const void *b, size_t n)
{
    if (!a || !b)
        return (a == b) ? 0 : -1;
    return memcmp(a, b, n);
}

/* Constant-time comparison for hashes (P03: timing side-channel) */
static int hash_equal(const uint8_t a[AC_HASH_LEN],
                      const uint8_t b[AC_HASH_LEN])
{
    uint32_t diff = 0;
    size_t i;
    for (i = 0; i < AC_HASH_LEN; i++)
        diff |= (uint32_t)(a[i] ^ b[i]);
    return diff == 0;
}

/* ================================================================== */
/*  Transaction signing payload                                        */
/* ================================================================== */

/*
 * Canonical signing payload: binary concatenation of all fields
 * EXCEPT the signature itself.  This is what gets hashed and signed.
 *
 * Format: type(1) | node_pubkey(32) | timestamp(8) | nonce(4) | payload(var)
 */
int ac_tx_signing_payload(const ac_transaction_t *tx,
                          uint8_t *out, size_t out_len)
{
    size_t offset = 0;
    size_t payload_size;

    if (!tx || !out)
        return -1;

    /* Header: type(1) + pubkey(32) + timestamp(8) + nonce(4) = 45 bytes */
    if (out_len < 45)
        return -1;

    out[offset++] = tx->type;
    memcpy(out + offset, tx->node_pubkey, AC_PUBKEY_LEN);
    offset += AC_PUBKEY_LEN;

    /* Timestamp in little-endian */
    {
        uint64_t ts = ac_cpu_to_le64(tx->timestamp);
        memcpy(out + offset, &ts, 8);
        offset += 8;
    }

    /* Nonce in little-endian */
    {
        uint32_t n = ac_cpu_to_le32(tx->nonce);
        memcpy(out + offset, &n, 4);
        offset += 4;
    }

    /* Payload depends on type */
    switch (tx->type) {
    case AC_TX_CLAIM:
    case AC_TX_RELEASE:
    case AC_TX_RENEW:
        payload_size = sizeof(ac_tx_claim_t);
        break;
    case AC_TX_REVOKE:
        payload_size = sizeof(ac_tx_revoke_t);
        break;
    case AC_TX_SUBNET_CREATE:
        payload_size = sizeof(ac_tx_subnet_create_t);
        break;
    case AC_TX_SUBNET_ASSIGN:
        payload_size = sizeof(ac_tx_subnet_assign_t);
        break;
    case AC_TX_VPN_TUNNEL:
        payload_size = sizeof(ac_tx_vpn_tunnel_t);
        break;
    case AC_TX_VPN_KEY:
        payload_size = sizeof(ac_tx_vpn_key_t);
        break;
    case AC_TX_PARTITION:
        payload_size = sizeof(ac_tx_partition_t);
        break;
    default:
        return -1;
    }

    if (offset + payload_size > out_len)
        return -1;

    memcpy(out + offset, &tx->payload, payload_size);
    offset += payload_size;

    return (int)offset;
}

/* ================================================================== */
/*  Transaction sign / verify                                          */
/* ================================================================== */

/* Max signing payload buffer: header(45) + largest payload union */
#define AC_MAX_SIGNING_BUF  (45 + sizeof(((ac_transaction_t *)0)->payload))

int ac_tx_sign(ac_transaction_t *tx, const uint8_t privkey[64])
{
    uint8_t buf[AC_MAX_SIGNING_BUF];
    int payload_len;

    if (!tx || !privkey)
        return AC_ERR_INVAL;

    payload_len = ac_tx_signing_payload(tx, buf, sizeof(buf));
    if (payload_len < 0)
        return AC_ERR_INVAL;

    return ac_crypto_ed25519_sign(privkey, buf, (size_t)payload_len,
                                 tx->signature);
}

int ac_tx_verify(const ac_transaction_t *tx)
{
    uint8_t buf[AC_MAX_SIGNING_BUF];
    int payload_len;

    if (!tx)
        return AC_ERR_INVAL;

    payload_len = ac_tx_signing_payload(tx, buf, sizeof(buf));
    if (payload_len < 0)
        return AC_ERR_CRYPTO;

    return ac_crypto_ed25519_verify(tx->node_pubkey, buf,
                                   (size_t)payload_len, tx->signature);
}

/* ================================================================== */
/*  Transaction type validation                                        */
/* ================================================================== */

int ac_tx_validate_type(const ac_transaction_t *tx)
{
    if (!tx)
        return AC_ERR_INVAL;

    switch (tx->type) {
    case AC_TX_CLAIM:
    case AC_TX_RELEASE:
    case AC_TX_RENEW:
        /* Address must not be zero */
        if (ac_addr_is_zero(&tx->payload.claim.address))
            return AC_ERR_INVAL;
        /* Address family must be valid */
        if (tx->payload.claim.address.family != AC_AF_IPV4 &&
            tx->payload.claim.address.family != AC_AF_IPV6 &&
            tx->payload.claim.address.family != AC_AF_POOL)
            return AC_ERR_INVAL;
        /* Lease bounds check (0 means default) */
        if (tx->payload.claim.lease_blocks != 0) {
            uint32_t lb = ac_le32_to_cpu(tx->payload.claim.lease_blocks);
            if (lb < AC_MIN_LEASE_BLOCKS || lb > AC_MAX_LEASE_BLOCKS)
                return AC_ERR_INVAL;
        }
        break;

    case AC_TX_REVOKE:
        /* Old and new pubkeys must differ */
        if (safe_memcmp(tx->payload.revoke.old_pubkey,
                        tx->payload.revoke.new_pubkey,
                        AC_PUBKEY_LEN) == 0)
            return AC_ERR_INVAL;
        break;

    case AC_TX_SUBNET_CREATE: {
        const ac_tx_subnet_create_t *sc = &tx->payload.subnet_create;
        /* Subnet ID must not be empty */
        if (sc->subnet_id[0] == '\0')
            return AC_ERR_INVAL;
        /* Prefix address must not be zero */
        if (ac_addr_is_zero(&sc->prefix))
            return AC_ERR_INVAL;
        /* Prefix must have a valid prefix length */
        if (sc->prefix.prefix_len == 0)
            return AC_ERR_INVAL;
        /* Gateway REQUIRED unless NO_GATEWAY flag (hardened N14) */
        if (!(sc->flags & AC_SUBNET_FLAG_NO_GATEWAY) &&
            ac_addr_is_zero(&sc->gateway))
            return AC_ERR_INVAL;
        /* DNS REQUIRED unless NO_DNS flag (hardened N15) */
        if (!(sc->flags & AC_SUBNET_FLAG_NO_DNS) && sc->dns_count == 0)
            return AC_ERR_INVAL;
        /* DNS count bounds */
        if (sc->dns_count > AC_MAX_DNS_ADDRS)
            return AC_ERR_INVAL;
        break;
    }

    case AC_TX_SUBNET_ASSIGN:
        /* Subnet ID must not be empty */
        if (tx->payload.subnet_assign.subnet_id[0] == '\0')
            return AC_ERR_INVAL;
        break;

    case AC_TX_VPN_TUNNEL: {
        const ac_tx_vpn_tunnel_t *vt = &tx->payload.vpn_tunnel;
        /* VPN protocol must be valid */
        if (vt->vpn_proto != AC_VPN_WIREGUARD &&
            vt->vpn_proto != AC_VPN_IPSEC &&
            vt->vpn_proto != AC_VPN_POOL)
            return AC_ERR_INVAL;
        /* Endpoint must not be zero */
        if (ac_addr_is_zero(&vt->endpoint))
            return AC_ERR_INVAL;
        /* AllowedIPs count bounds */
        if (vt->allowed_ip_count > AC_MAX_VPN_ALLOWED_IPS)
            return AC_ERR_INVAL;
        break;
    }

    case AC_TX_VPN_KEY:
        /* VPN protocol must be valid */
        if (tx->payload.vpn_key.vpn_proto != AC_VPN_WIREGUARD &&
            tx->payload.vpn_key.vpn_proto != AC_VPN_IPSEC &&
            tx->payload.vpn_key.vpn_proto != AC_VPN_POOL)
            return AC_ERR_INVAL;
        break;

    case AC_TX_PARTITION: {
        const ac_tx_partition_t *pt = &tx->payload.partition;
        /* Partition ID must not be empty */
        if (pt->partition_id[0] == '\0')
            return AC_ERR_INVAL;
        /* Action must be valid */
        if (pt->action < AC_PART_CREATE || pt->action > AC_PART_DENY_CROSS)
            return AC_ERR_INVAL;
        /* ADD/REMOVE require target_subnet_id */
        if ((pt->action == AC_PART_ADD_SUBNET ||
             pt->action == AC_PART_REMOVE_SUBNET) &&
            pt->target_subnet_id[0] == '\0')
            return AC_ERR_INVAL;
        /* ALLOW/DENY require target_partition_id */
        if ((pt->action == AC_PART_ALLOW_CROSS ||
             pt->action == AC_PART_DENY_CROSS) &&
            pt->target_partition_id[0] == '\0')
            return AC_ERR_INVAL;
        break;
    }

    default:
        return AC_ERR_INVAL;
    }

    return AC_OK;
}

/* ================================================================== */
/*  Block hashing                                                      */
/* ================================================================== */

/*
 * Hash content: index(4) + timestamp(8) + prev_hash(32) +
 *               tx_count(2) + all transactions (excluding tx signatures
 *               from the block-level hash — tx sigs are verified
 *               independently).
 *
 * For simplicity and determinism, we hash the raw binary
 * representation of the block fields. The hash covers ALL fields
 * of each transaction INCLUDING signatures, so a tampered signature
 * also changes the block hash.
 */
int ac_block_compute_hash(const ac_block_t *blk, uint8_t out[AC_HASH_LEN])
{
    /*
     * K06: avoid large stack buffer. Hash incrementally using
     * SHA-256 update calls. We hash fields sequentially.
     *
     * We hash: index(LE32) | timestamp(LE64) | prev_hash(32) |
     *          tx_count(LE16) | txs[0..tx_count-1]
     */
    uint8_t header_buf[4 + 8 + AC_HASH_LEN + 2]; /* 46 bytes */
    uint32_t idx_le;
    uint64_t ts_le;
    uint16_t txc_le;
    size_t offset = 0;

    /* We need to do incremental SHA-256. Use a two-pass approach:
     * 1. Hash header fields
     * 2. Hash each transaction
     *
     * Since ac_crypto_sha256 takes a single buffer, we need to
     * build a hash of the concatenated data. Use the internal
     * SHA-256 context directly would be better, but we keep the
     * API clean by hashing header+txs as a single logical unit.
     *
     * For now, hash header bytes, then chain with tx data by
     * re-hashing the concatenation. This is acceptable because
     * block sizes are bounded (AC_MAX_TX_PER_BLOCK).
     *
     * Alternative approach: hash a buffer of [header || tx_bytes].
     * Since max block is bounded, this fits in a reasonable alloc.
     */

    if (!blk || !out)
        return AC_ERR_INVAL;

    /* K03: bounds check */
    if (blk->tx_count > AC_MAX_TX_PER_BLOCK)
        return AC_ERR_INVAL;

    /* Build header bytes */
    idx_le = ac_cpu_to_le32(blk->index);
    memcpy(header_buf + offset, &idx_le, 4);
    offset += 4;

    ts_le = ac_cpu_to_le64(blk->timestamp);
    memcpy(header_buf + offset, &ts_le, 8);
    offset += 8;

    memcpy(header_buf + offset, blk->prev_hash, AC_HASH_LEN);
    offset += AC_HASH_LEN;

    txc_le = ac_cpu_to_le16(blk->tx_count);
    memcpy(header_buf + offset, &txc_le, 2);
    offset += 2;

    if (blk->tx_count == 0) {
        /* No transactions — hash header only */
        return ac_crypto_sha256(header_buf, offset, out);
    }

    /*
     * With transactions: allocate buffer = header + tx_count * sizeof(ac_transaction_t).
     * K37: bounded by AC_MAX_TX_PER_BLOCK (64), so max ~200KB — acceptable
     * for both kernel and userspace.
     */
    {
        size_t tx_data_len = (size_t)blk->tx_count * sizeof(ac_transaction_t);
        size_t total_len = offset + tx_data_len;
        uint8_t *buf = (uint8_t *)ac_alloc(total_len, AC_MEM_NORMAL);
        int rc;

        if (!buf)
            return AC_ERR_NOMEM;

        memcpy(buf, header_buf, offset);
        memcpy(buf + offset, blk->txs, tx_data_len);

        rc = ac_crypto_sha256(buf, total_len, out);
        ac_free(buf);
        return rc;
    }
}

/* ================================================================== */
/*  Genesis block                                                      */
/* ================================================================== */

void ac_genesis_block(ac_block_t *out)
{
    if (!out)
        return;

    memset(out, 0, sizeof(*out));
    out->index     = 0;
    out->timestamp = 0;     /* deterministic: epoch zero */
    /* prev_hash = all zeros (already from memset) */
    out->tx_count  = 0;

    ac_block_compute_hash(out, out->hash);
}

/* ================================================================== */
/*  Block creation                                                     */
/* ================================================================== */

int ac_block_create(const ac_block_t *prev,
                    const ac_transaction_t *txs, uint16_t tx_count,
                    ac_block_t *out)
{
    if (!prev || !out)
        return AC_ERR_INVAL;
    if (tx_count > AC_MAX_TX_PER_BLOCK)
        return AC_ERR_INVAL;
    if (tx_count > 0 && !txs)
        return AC_ERR_INVAL;

    memset(out, 0, sizeof(*out));
    out->index     = prev->index + 1;
    out->timestamp = ac_time_unix_sec();
    memcpy(out->prev_hash, prev->hash, AC_HASH_LEN);
    out->tx_count  = tx_count;

    if (tx_count > 0)
        memcpy(out->txs, txs, (size_t)tx_count * sizeof(ac_transaction_t));

    return ac_block_compute_hash(out, out->hash);
}

/* ================================================================== */
/*  Rate limiting                                                      */
/* ================================================================== */

/*
 * Count transactions per node in the last AC_RATE_WINDOW_BLOCKS blocks
 * plus the candidate block. No node may exceed AC_RATE_MAX_TX.
 *
 * Uses a simple linear scan — bounded by window size * max tx/block.
 * K06: no recursion. Stack usage: rate_counts array on heap.
 */
static int enforce_rate_limit(const ac_block_t *candidate,
                              const ac_block_t *chain, uint32_t chain_len)
{
    ac_rate_entry_t *rates = NULL;
    uint32_t rate_count = 0;
    uint32_t rate_cap = 64;
    uint32_t window_start;
    uint32_t i;
    uint16_t j;
    int rc = AC_OK;

    rates = (ac_rate_entry_t *)ac_zalloc(
        rate_cap * sizeof(ac_rate_entry_t), AC_MEM_NORMAL);
    if (!rates)
        return AC_ERR_NOMEM;

    /* Helper: find or insert a pubkey in rates table */
    #define RATE_INC(pubkey_ptr) do {                                    \
        uint32_t _ri;                                                    \
        int _found = 0;                                                  \
        for (_ri = 0; _ri < rate_count; _ri++) {                         \
            if (memcmp(rates[_ri].pubkey, (pubkey_ptr),                  \
                       AC_PUBKEY_LEN) == 0) {                            \
                rates[_ri].count++;                                      \
                _found = 1;                                              \
                break;                                                   \
            }                                                            \
        }                                                                \
        if (!_found) {                                                   \
            if (rate_count >= rate_cap) {                                 \
                uint32_t new_cap = rate_cap * 2;                         \
                ac_rate_entry_t *nr = (ac_rate_entry_t *)ac_zalloc(      \
                    new_cap * sizeof(ac_rate_entry_t), AC_MEM_NORMAL);   \
                if (!nr) { rc = AC_ERR_NOMEM; goto out; }                \
                memcpy(nr, rates, rate_count * sizeof(ac_rate_entry_t)); \
                ac_free(rates);                                          \
                rates = nr;                                              \
                rate_cap = new_cap;                                      \
            }                                                            \
            memcpy(rates[rate_count].pubkey, (pubkey_ptr),               \
                   AC_PUBKEY_LEN);                                       \
            rates[rate_count].count = 1;                                 \
            rate_count++;                                                \
        }                                                                \
    } while (0)

    /* Count in candidate block */
    if (candidate) {
        for (j = 0; j < candidate->tx_count && j < AC_MAX_TX_PER_BLOCK; j++)
            RATE_INC(candidate->txs[j].node_pubkey);
    }

    /* Count in preceding window */
    window_start = 0;
    if (chain_len > AC_RATE_WINDOW_BLOCKS)
        window_start = chain_len - AC_RATE_WINDOW_BLOCKS;

    for (i = window_start; i < chain_len; i++) {
        const ac_block_t *b = &chain[i];
        for (j = 0; j < b->tx_count && j < AC_MAX_TX_PER_BLOCK; j++)
            RATE_INC(b->txs[j].node_pubkey);
    }

    #undef RATE_INC

    /* Check limits */
    for (i = 0; i < rate_count; i++) {
        if (rates[i].count > AC_RATE_MAX_TX) {
            ac_log_warn("rate limit exceeded for node (first 4 bytes: "
                        "%02x%02x%02x%02x): %u txs in window (max %u)",
                        rates[i].pubkey[0], rates[i].pubkey[1],
                        rates[i].pubkey[2], rates[i].pubkey[3],
                        rates[i].count, AC_RATE_MAX_TX);
            rc = AC_ERR_RATELIM;
            goto out;
        }
    }

out:
    ac_free(rates);
    return rc;
}

/* ================================================================== */
/*  Single-block validation                                            */
/* ================================================================== */

int ac_block_validate(const ac_block_t *blk, const ac_block_t *prev,
                      const ac_block_t *chain, uint32_t chain_len)
{
    uint8_t computed_hash[AC_HASH_LEN];
    uint16_t i;
    int rc;

    if (!blk || !prev)
        return AC_ERR_INVAL;

    /* Index continuity */
    if (blk->index != prev->index + 1) {
        ac_log_warn("block %u: expected index %u, got %u",
                    blk->index, prev->index + 1, blk->index);
        return AC_ERR_INVAL;
    }

    /* Previous hash linkage */
    if (!hash_equal(blk->prev_hash, prev->hash)) {
        ac_log_warn("block %u: previous hash mismatch", blk->index);
        return AC_ERR_INVAL;
    }

    /* K03: tx_count bounds */
    if (blk->tx_count > AC_MAX_TX_PER_BLOCK) {
        ac_log_warn("block %u: tx_count %u exceeds max %u",
                    blk->index, blk->tx_count, AC_MAX_TX_PER_BLOCK);
        return AC_ERR_INVAL;
    }

    /* Block hash verification */
    rc = ac_block_compute_hash(blk, computed_hash);
    if (rc != AC_OK)
        return rc;
    if (!hash_equal(blk->hash, computed_hash)) {
        ac_log_warn("block %u: hash mismatch", blk->index);
        return AC_ERR_INVAL;
    }

    /* Validate each transaction */
    for (i = 0; i < blk->tx_count; i++) {
        const ac_transaction_t *tx = &blk->txs[i];

        /* Ed25519 signature verification (K40: mandatory) */
        rc = ac_tx_verify(tx);
        if (rc != AC_OK) {
            ac_log_warn("block %u tx %u: invalid signature", blk->index, i);
            return rc;
        }

        /* Type-specific field validation */
        rc = ac_tx_validate_type(tx);
        if (rc != AC_OK) {
            ac_log_warn("block %u tx %u: type validation failed (type=%s)",
                        blk->index, i, ac_tx_type_name(tx->type));
            return rc;
        }
    }

    /* Rate limiting */
    rc = enforce_rate_limit(blk, chain, chain_len);
    if (rc != AC_OK) {
        ac_log_warn("block %u: rate limit violation", blk->index);
        return rc;
    }

    /* Clock sanity check (N30) — informational only */
    if (blk->timestamp != 0) {
        ac_time_sanity_check(blk->timestamp);
    }

    return AC_OK;
}

/* ================================================================== */
/*  Full-chain validation                                              */
/* ================================================================== */

int ac_chain_validate(const ac_block_t *blocks, uint32_t count)
{
    ac_block_t genesis;
    uint32_t i;
    uint16_t j;
    int rc;

    /* Nonce replay tracker — hashmap (pubkey -> ac_seq_entry_t*) */
    ac_hashmap_t seq_map;
    int map_inited = 0;

    if (!blocks || count == 0)
        return AC_ERR_INVAL;

    /* Check genesis */
    ac_genesis_block(&genesis);
    if (!hash_equal(blocks[0].hash, genesis.hash) ||
        !hash_equal(blocks[0].prev_hash, genesis.prev_hash) ||
        blocks[0].index != 0) {
        ac_log_warn("genesis block mismatch");
        return AC_ERR_INVAL;
    }

    if (count == 1)
        return AC_OK;

    rc = ac_hashmap_init(&seq_map, 0, 0);
    if (rc != AC_OK)
        return AC_ERR_NOMEM;
    map_inited = 1;

    for (i = 1; i < count; i++) {
        /* Validate block against predecessor + chain context */
        rc = ac_block_validate(&blocks[i], &blocks[i - 1], blocks, i);
        if (rc != AC_OK) {
            ac_log_warn("chain validation failed at block %u", i);
            goto cleanup;
        }

        /* Nonce replay check (per-node monotonicity) */
        for (j = 0; j < blocks[i].tx_count && j < AC_MAX_TX_PER_BLOCK; j++) {
            const ac_transaction_t *tx = &blocks[i].txs[j];
            ac_seq_entry_t *entry;

            entry = (ac_seq_entry_t *)ac_hashmap_get(
                &seq_map, tx->node_pubkey, AC_PUBKEY_LEN);

            if (entry) {
                /* P05: nonce must be strictly increasing */
                if (tx->nonce <= entry->last_nonce &&
                    tx->nonce != 0) {
                    ac_log_warn("block %u tx %u: replayed nonce %u "
                                "(last seen %u)",
                                i, j, tx->nonce,
                                entry->last_nonce);
                    rc = AC_ERR_INVAL;
                    goto cleanup;
                }
                if (tx->nonce > entry->last_nonce)
                    entry->last_nonce = tx->nonce;
            } else {
                entry = (ac_seq_entry_t *)ac_zalloc(
                    sizeof(*entry), AC_MEM_NORMAL);
                if (!entry) {
                    rc = AC_ERR_NOMEM;
                    goto cleanup;
                }
                memcpy(entry->pubkey, tx->node_pubkey, AC_PUBKEY_LEN);
                entry->last_nonce = tx->nonce;

                rc = ac_hashmap_put(&seq_map, tx->node_pubkey,
                                    AC_PUBKEY_LEN, entry, NULL);
                if (rc != AC_OK) {
                    ac_free(entry);
                    goto cleanup;
                }
            }
        }
    }

    rc = AC_OK;

cleanup:
    if (map_inited) {
        ac_hashmap_iter_t it;
        const void *key;
        uint32_t key_len;
        void *value;

        ac_hashmap_iter_init(&it, &seq_map);
        while (ac_hashmap_iter_next(&it, &key, &key_len, &value)) {
            ac_free((ac_seq_entry_t *)value);
        }
        ac_hashmap_destroy(&seq_map);
    }
    return rc;
}

/* ================================================================== */
/*  Clock sanity check (N30 hardened)                                  */
/* ================================================================== */

uint64_t ac_time_sanity_check(uint64_t peer_timestamp)
{
    uint64_t local = ac_time_unix_sec();
    uint64_t delta;

    if (peer_timestamp > local)
        delta = peer_timestamp - local;
    else
        delta = local - peer_timestamp;

    if (delta > AC_CLOCK_ERROR_DELTA) {
        ac_log_error("clock sanity: peer delta %llu seconds (>%us ERROR)",
                     (unsigned long long)delta, AC_CLOCK_ERROR_DELTA);
    } else if (delta > AC_CLOCK_WARN_DELTA) {
        ac_log_warn("clock sanity: peer delta %llu seconds (>%us WARNING)",
                    (unsigned long long)delta, AC_CLOCK_WARN_DELTA);
    }

    return delta;
}

/* ================================================================== */
/*  Chain lifecycle                                                    */
/* ================================================================== */

int ac_chain_init(ac_chain_t *chain)
{
    int rc;

    if (!chain)
        return AC_ERR_INVAL;

    memset(chain, 0, sizeof(*chain));

    rc = ac_mutex_init(&chain->lock);
    if (rc != AC_OK)
        return rc;

    rc = ac_hashmap_init(&chain->seq_map, 0, 0);
    if (rc != AC_OK) {
        ac_mutex_destroy(&chain->lock);
        return rc;
    }

    chain->blocks = (ac_block_t *)ac_zalloc(
        AC_CHAIN_INITIAL_CAP * sizeof(ac_block_t), AC_MEM_NORMAL);
    if (!chain->blocks) {
        ac_hashmap_destroy(&chain->seq_map);
        ac_mutex_destroy(&chain->lock);
        return AC_ERR_NOMEM;
    }
    chain->capacity = AC_CHAIN_INITIAL_CAP;

    /* Create genesis block */
    ac_genesis_block(&chain->blocks[0]);
    chain->count = 1;
    chain->audit_count = 1;

    ac_log_info("chain initialized with genesis block");
    return AC_OK;
}

void ac_chain_destroy(ac_chain_t *chain)
{
    ac_hashmap_iter_t it;
    const void *key;
    uint32_t key_len;
    void *value;

    if (!chain)
        return;

    ac_mutex_lock(&chain->lock);
    if (chain->blocks) {
        /* K04: zeroize chain data before freeing (P04: key material) */
        ac_crypto_zeroize(chain->blocks,
                          (size_t)chain->capacity * sizeof(ac_block_t));
        ac_free(chain->blocks);
        chain->blocks = NULL;  /* K02: clear pointer after free */
    }

    /* Free all seq entries */
    ac_hashmap_iter_init(&it, &chain->seq_map);
    while (ac_hashmap_iter_next(&it, &key, &key_len, &value)) {
        ac_free((ac_seq_entry_t *)value);
    }
    ac_hashmap_destroy(&chain->seq_map);

    chain->count = 0;
    chain->capacity = 0;
    ac_mutex_unlock(&chain->lock);

    ac_mutex_destroy(&chain->lock);
    ac_log_info("chain destroyed");
}

/* ================================================================== */
/*  Chain operations (thread-safe)                                     */
/* ================================================================== */

uint32_t ac_chain_len(ac_chain_t *chain)
{
    uint32_t len;
    if (!chain)
        return 0;
    ac_mutex_lock(&chain->lock);
    len = chain->count;
    ac_mutex_unlock(&chain->lock);
    return len;
}

int ac_chain_last_block(ac_chain_t *chain, ac_block_t *out)
{
    if (!chain || !out)
        return AC_ERR_INVAL;

    ac_mutex_lock(&chain->lock);
    if (chain->count == 0) {
        ac_mutex_unlock(&chain->lock);
        return AC_ERR_INVAL;
    }
    memcpy(out, &chain->blocks[chain->count - 1], sizeof(ac_block_t));
    ac_mutex_unlock(&chain->lock);
    return AC_OK;
}

/* Grow blocks array if needed. Caller must hold lock. */
static int chain_ensure_capacity(ac_chain_t *chain, uint32_t needed)
{
    uint32_t new_cap;
    ac_block_t *new_blocks;

    if (needed <= chain->capacity)
        return AC_OK;

    /* S25: enforce configurable max (0 = unlimited) */
    if (chain->max_blocks > 0 && needed > chain->max_blocks) {
        ac_log_error("chain would exceed max blocks (%u > %u)",
                     needed, chain->max_blocks);
        return AC_ERR_FULL;
    }

    new_cap = chain->capacity * 2;
    if (new_cap < needed)
        new_cap = needed;
    if (chain->max_blocks > 0 && new_cap > chain->max_blocks)
        new_cap = chain->max_blocks;

    new_blocks = (ac_block_t *)ac_zalloc(
        new_cap * sizeof(ac_block_t), AC_MEM_NORMAL);
    if (!new_blocks)
        return AC_ERR_NOMEM;

    memcpy(new_blocks, chain->blocks,
           (size_t)chain->count * sizeof(ac_block_t));

    /* K02: zeroize old data before free */
    ac_crypto_zeroize(chain->blocks,
                      (size_t)chain->capacity * sizeof(ac_block_t));
    ac_free(chain->blocks);

    chain->blocks = new_blocks;
    chain->capacity = new_cap;
    return AC_OK;
}

int ac_chain_add_block(ac_chain_t *chain, const ac_block_t *blk)
{
    int rc;

    if (!chain || !blk)
        return AC_ERR_INVAL;

    ac_mutex_lock(&chain->lock);

    if (chain->count == 0) {
        ac_mutex_unlock(&chain->lock);
        return AC_ERR_INVAL;
    }

    /* Validate against current chain */
    rc = ac_block_validate(blk, &chain->blocks[chain->count - 1],
                           chain->blocks, chain->count);
    if (rc != AC_OK) {
        ac_mutex_unlock(&chain->lock);
        return rc;
    }

    /* Ensure capacity */
    rc = chain_ensure_capacity(chain, chain->count + 1);
    if (rc != AC_OK) {
        ac_mutex_unlock(&chain->lock);
        return rc;
    }

    memcpy(&chain->blocks[chain->count], blk, sizeof(ac_block_t));
    chain->count++;
    chain->audit_count++;

    ac_log_info("block %u added to chain (tx_count=%u)",
                blk->index, blk->tx_count);
    ac_mutex_unlock(&chain->lock);
    return AC_OK;
}

/* ================================================================== */
/*  Chain replacement (fork resolution)                                */
/*                                                                     */
/*  K25: atomic replacement — old chain freed only after new is set.   */
/*  K38: RCU-style pointer swap for minimal disruption.                */
/*  N10: longest-chain-wins resolves partition reconnect.              */
/* ================================================================== */

int ac_chain_replace(ac_chain_t *chain,
                     const ac_block_t *candidate, uint32_t candidate_len,
                     int *err)
{
    ac_block_t *new_blocks = NULL;
    int replaced = 0;
    int rc;

    if (!chain || !candidate || candidate_len == 0 || !err) {
        if (err) *err = AC_ERR_INVAL;
        return 0;
    }

    /* Validate candidate chain before acquiring lock */
    rc = ac_chain_validate(candidate, candidate_len);
    if (rc != AC_OK) {
        ac_log_warn("candidate chain validation failed: %d", rc);
        *err = rc;
        return 0;
    }

    /* S25: enforce configurable max (0 = unlimited) */
    if (chain->max_blocks > 0 && candidate_len > chain->max_blocks) {
        *err = AC_ERR_FULL;
        return 0;
    }

    /* Allocate new blocks before locking (minimize lock hold time) */
    new_blocks = (ac_block_t *)ac_zalloc(
        candidate_len * sizeof(ac_block_t), AC_MEM_NORMAL);
    if (!new_blocks) {
        *err = AC_ERR_NOMEM;
        return 0;
    }
    memcpy(new_blocks, candidate, candidate_len * sizeof(ac_block_t));

    ac_mutex_lock(&chain->lock);

    /* N06: longest chain wins with deterministic tiebreaker */
    if (candidate_len < chain->count) {
        /* Candidate is shorter — reject */
        replaced = 0;
    } else if (candidate_len == chain->count) {
        /* Same length: lowest tip hash wins (deterministic tiebreaker) */
        const uint8_t *cand_hash = candidate[candidate_len - 1].hash;
        const uint8_t *our_hash  = chain->blocks[chain->count - 1].hash;
        if (memcmp(cand_hash, our_hash, AC_HASH_LEN) < 0) {
            replaced = 1;
        }
    } else {
        /* Candidate is longer — accept */
        replaced = 1;
    }

    if (replaced) {
        ac_block_t *old = chain->blocks;
        uint32_t old_cap = chain->capacity;

        /* K25/K38: atomic pointer swap */
        chain->blocks   = new_blocks;
        chain->count    = candidate_len;
        chain->capacity = candidate_len;
        chain->audit_count++;
        new_blocks = NULL;  /* prevent double-free below */

        /* Free old chain after swap */
        if (old) {
            ac_crypto_zeroize(old, (size_t)old_cap * sizeof(ac_block_t));
            ac_free(old);
        }

        ac_log_info("chain replaced: new length %u", candidate_len);
    }

    ac_mutex_unlock(&chain->lock);

    /* Free unused allocation */
    if (new_blocks) {
        ac_crypto_zeroize(new_blocks,
                          candidate_len * sizeof(ac_block_t));
        ac_free(new_blocks);
    }

    *err = AC_OK;
    return replaced;
}

int ac_chain_get_blocks(ac_chain_t *chain,
                        ac_block_t *out, uint32_t out_capacity,
                        uint32_t *out_count)
{
    if (!chain || !out || !out_count)
        return AC_ERR_INVAL;

    ac_mutex_lock(&chain->lock);

    if (out_capacity < chain->count) {
        ac_mutex_unlock(&chain->lock);
        *out_count = chain->count;
        return AC_ERR_INVAL;
    }

    memcpy(out, chain->blocks, (size_t)chain->count * sizeof(ac_block_t));
    *out_count = chain->count;

    ac_mutex_unlock(&chain->lock);
    return AC_OK;
}

/* ================================================================== */
/*  Chain pruning (S24: daemon-only)                                   */
/* ================================================================== */

int ac_chain_prune(ac_chain_t *chain, uint32_t keep_from)
{
    uint32_t removed;

    if (!chain)
        return 0;

    ac_mutex_lock(&chain->lock);

    if (keep_from == 0 || keep_from >= chain->count) {
        ac_mutex_unlock(&chain->lock);
        return 0;
    }

    removed = keep_from;

    /* Shift remaining blocks to the front */
    memmove(chain->blocks,
            chain->blocks + keep_from,
            (size_t)(chain->count - keep_from) * sizeof(ac_block_t));

    /* Zeroize freed tail slots (K04: clear sensitive data) */
    ac_crypto_zeroize(chain->blocks + (chain->count - keep_from),
                      (size_t)keep_from * sizeof(ac_block_t));

    chain->count -= keep_from;

    ac_mutex_unlock(&chain->lock);

    ac_log_info("chain pruned: removed %u blocks, %u remaining",
                removed, chain->count);
    return (int)removed;
}
