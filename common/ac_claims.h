/*
 * ac_claims.h — Claim store interface for addrchain
 *
 * Manages address→owner mappings derived from the blockchain.
 * Thread-safe: all public functions acquire cs->lock (lock order:
 * chain_lock → claim_lock per ac_platform.h K08).
 *
 * Mitigates:
 *   K01  — NULL checks on all pointer parameters
 *   K02  — Clear pointers after free
 *   K07  — Mutex protects all shared claim state
 *   K37  — Bounded claim table (AC_MAX_CLAIMS)
 *   K41  — DAD conflict detection via chain lookup
 *   N01  — FCFS claim + Ed25519 ownership proof
 *   N02  — Full visibility of available addresses
 *   N03  — Auto-renew via RENEW tx at 50% TTL
 *   N04  — Pre-check chain before CLAIM
 *   N06  — Deterministic conflict resolution
 *   N10  — RebuildFromChain on partition reconnect
 *   N12  — CLAIM validated against subnet prefix
 *   N28  — State rebuild on interface up
 *   N34  — POOL address validation (type, CRC32, node_id)
 *   N38  — DAD failure → RELEASE + auto-retry
 *   N39  — MAC update via RENEW
 */

#ifndef AC_CLAIMS_H
#define AC_CLAIMS_H

#include "ac_proto.h"
#include "ac_platform.h"
#include "ac_chain.h"
#include "ac_hashmap.h"
#include "ac_dag.h"

/* ------------------------------------------------------------------ */
/*  Limits (legacy constants kept for reference; no longer enforced)    */
/* ------------------------------------------------------------------ */

/* Removed: AC_MAX_CLAIMS, AC_MAX_REVOCATIONS — now dynamic via hashmap */

/* ------------------------------------------------------------------ */
/*  Claim record                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    ac_address_t    address;
    uint8_t         owner_pubkey[AC_PUBKEY_LEN];
    uint32_t        last_renewed_block; /* block index of last CLAIM/RENEW */
    uint32_t        lease_blocks;       /* 0 = default (AC_DEFAULT_LEASE_BLOCKS) */
    uint32_t        original_nonce;
    int             active;             /* 1 = slot in use */
} ac_claim_record_t;

/* ------------------------------------------------------------------ */
/*  Revocation record                                                  */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t     old_pubkey[AC_PUBKEY_LEN];
    uint8_t     new_pubkey[AC_PUBKEY_LEN];
    int         active;
} ac_revocation_t;

/* ------------------------------------------------------------------ */
/*  Claim store                                                        */
/* ------------------------------------------------------------------ */

typedef struct {
    ac_hashmap_t        claims_map;     /* key: ac_address_t bytes → ac_claim_record_t* */
    uint32_t            claim_count;
    ac_hashmap_t        revoke_map;     /* key: old_pubkey bytes → ac_revocation_t* */
    uint32_t            revoke_count;
    uint32_t            lease_ttl;      /* default lease in blocks */
    uint32_t            max_claims;     /* 0 = unlimited (userspace) */
    ac_mutex_t          lock;           /* K07: claim_lock (order 2) */
    ac_dag_t           *dag;            /* optional DAG for dependency tracking */
} ac_claim_store_t;

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                          */
/* ------------------------------------------------------------------ */

/* Initialize claim store with default or custom lease TTL.
 * If lease_ttl == 0, uses AC_DEFAULT_LEASE_BLOCKS.
 * max_claims: 0 = unlimited (userspace). In kernel, set from module param. */
int ac_claims_init(ac_claim_store_t *cs, uint32_t lease_ttl, uint32_t max_claims,
                   ac_dag_t *dag);

/* Free claim store resources. */
void ac_claims_destroy(ac_claim_store_t *cs);

/* ------------------------------------------------------------------ */
/*  Claim operations (thread-safe)                                     */
/* ------------------------------------------------------------------ */

/* Look up the owner of an address. Returns AC_OK and copies pubkey to
 * `out_owner` if claimed, or AC_ERR_NOENT if unclaimed. */
int ac_claims_get_owner(ac_claim_store_t *cs,
                        const ac_address_t *addr,
                        uint8_t out_owner[AC_PUBKEY_LEN]);

/* Count total active claims. */
uint32_t ac_claims_count(ac_claim_store_t *cs);

/* Get all claims for a specific node. Writes up to `max_out` addresses
 * to `out`, returns actual count. */
uint32_t ac_claims_by_node(ac_claim_store_t *cs,
                           const uint8_t pubkey[AC_PUBKEY_LEN],
                           ac_address_t *out, uint32_t max_out);

/* ------------------------------------------------------------------ */
/*  Block processing                                                   */
/* ------------------------------------------------------------------ */

/* Validate a block's transactions against current claim state.
 * Does NOT modify state — read-only check.
 * Returns AC_OK if all transactions are valid, error code otherwise. */
int ac_claims_validate_block(ac_claim_store_t *cs,
                             const ac_block_t *blk);

/* Apply a validated block's transactions to the claim state.
 * Expires stale leases based on block index. */
int ac_claims_apply_block(ac_claim_store_t *cs,
                          const ac_block_t *blk);

/* Rebuild claim state from scratch by replaying the entire chain.
 * Returns number of local claims that were lost (rollback detection)
 * in `*lost_count`. `local_pubkey` identifies the local node.
 * Lost addresses are written to `lost_addrs` (up to `lost_max`). */
int ac_claims_rebuild(ac_claim_store_t *cs,
                      const ac_block_t *blocks, uint32_t block_count,
                      const uint8_t local_pubkey[AC_PUBKEY_LEN],
                      ac_address_t *lost_addrs, uint32_t lost_max,
                      uint32_t *lost_count);

/* ------------------------------------------------------------------ */
/*  Revocation                                                         */
/* ------------------------------------------------------------------ */

/* Resolve a pubkey through the revocation chain to find the
 * current identity. Writes result to `out`. */
void ac_claims_resolve_pubkey(ac_claim_store_t *cs,
                              const uint8_t pubkey[AC_PUBKEY_LEN],
                              uint8_t out[AC_PUBKEY_LEN]);

#endif /* AC_CLAIMS_H */
