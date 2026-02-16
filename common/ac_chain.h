/*
 * ac_chain.h — Blockchain chain engine interface for addrchain
 *
 * Provides block creation, validation, chain management, and fork
 * resolution.  Thread-safe via platform mutex abstraction.
 *
 * Mitigates:
 *   K01  — NULL checks on all pointer parameters
 *   K02  — Clear pointers after free, refcount-safe teardown
 *   K03  — Bounds checks on all buffer accesses
 *   K06  — No recursion, no large stack variables
 *   K07  — Mutex protects all shared chain state
 *   K25  — Atomic chain replacement via pointer swap
 *   K35  — Independent validation of every block
 *   K36  — Per-block validation, not full-chain rescan
 *   K37  — Pruning via configurable max_blocks
 *   K38  — Fork resolution via longest-chain-wins + hash tiebreaker
 *   N06  — Deterministic FCFS conflict resolution
 *   N08  — Ed25519 signature verification on every transaction
 *   N10  — Longest-chain-wins on partition reconnect
 *   N30  — ac_time_sanity_check() for clock delta logging
 */

#ifndef AC_CHAIN_H
#define AC_CHAIN_H

#include "ac_proto.h"
#include "ac_platform.h"
#include "ac_hashmap.h"

/* ------------------------------------------------------------------ */
/*  Sequence tracker: replay protection per node (K07, N08)            */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t     pubkey[AC_PUBKEY_LEN];
    uint32_t    last_nonce;
} ac_seq_entry_t;

/* ------------------------------------------------------------------ */
/*  Rate limiter: per-node transaction counting (AC_ERR_RATELIM)       */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t     pubkey[AC_PUBKEY_LEN];
    uint32_t    count;
} ac_rate_entry_t;

/* ------------------------------------------------------------------ */
/*  Chain: thread-safe blockchain container                            */
/* ------------------------------------------------------------------ */

typedef struct {
    ac_block_t     *blocks;             /* dynamically allocated array  */
    uint32_t        count;              /* number of blocks             */
    uint32_t        capacity;           /* allocated slots              */
    ac_mutex_t      lock;               /* K07: protects all fields     */

    /* Nonce replay tracker */
    ac_hashmap_t    seq_map;            /* pubkey -> ac_seq_entry_t*    */

    /* S25: configurable max (0 = unlimited userspace, >0 = kernel cap) */
    uint32_t        max_blocks;

    /* Audit ring buffer (P49: change journaling tenet) */
    uint32_t        audit_count;        /* total state changes logged   */
} ac_chain_t;

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                          */
/* ------------------------------------------------------------------ */

/* Initialize a new chain with the genesis block.
 * Returns AC_OK on success, AC_ERR_NOMEM on allocation failure. */
int ac_chain_init(ac_chain_t *chain);

/* Free all chain resources. Sets count/capacity to zero.
 * Safe to call on an already-destroyed chain (idempotent). */
void ac_chain_destroy(ac_chain_t *chain);

/* ------------------------------------------------------------------ */
/*  Genesis block                                                      */
/* ------------------------------------------------------------------ */

/* Create the deterministic genesis block. All nodes produce the same
 * genesis to form a compatible chain. Writes into `out`. */
void ac_genesis_block(ac_block_t *out);

/* ------------------------------------------------------------------ */
/*  Block creation                                                     */
/* ------------------------------------------------------------------ */

/* Create a new block with `tx_count` transactions, linked to `prev`.
 * Populates `out` with the new block including computed hash.
 * Returns AC_OK or AC_ERR_INVAL if tx_count exceeds limit. */
int ac_block_create(const ac_block_t *prev,
                    const ac_transaction_t *txs, uint16_t tx_count,
                    ac_block_t *out);

/* ------------------------------------------------------------------ */
/*  Block hashing                                                      */
/* ------------------------------------------------------------------ */

/* Compute the SHA-256 hash of a block (index + timestamp + prev_hash +
 * all transactions).  Writes AC_HASH_LEN bytes to `out`. */
int ac_block_compute_hash(const ac_block_t *blk, uint8_t out[AC_HASH_LEN]);

/* ------------------------------------------------------------------ */
/*  Transaction signing and verification                               */
/* ------------------------------------------------------------------ */

/* Compute the canonical signing payload for a transaction.
 * Writes to `out`, up to `out_len` bytes. Returns actual payload length
 * or -1 on error. */
int ac_tx_signing_payload(const ac_transaction_t *tx,
                          uint8_t *out, size_t out_len);

/* Sign a transaction with the given private key.
 * Fills tx->signature. Returns AC_OK or AC_ERR_CRYPTO. */
int ac_tx_sign(ac_transaction_t *tx, const uint8_t privkey[64]);

/* Verify a transaction's Ed25519 signature.
 * Returns AC_OK if valid, AC_ERR_CRYPTO if invalid. */
int ac_tx_verify(const ac_transaction_t *tx);

/* ------------------------------------------------------------------ */
/*  Single-block validation                                            */
/* ------------------------------------------------------------------ */

/* Validate a block against the previous block and the chain context.
 * Checks: index continuity, prev_hash linkage, block hash, all tx
 * signatures, tx type validity, rate limiting.
 * Returns AC_OK or an error code. */
int ac_block_validate(const ac_block_t *blk, const ac_block_t *prev,
                      const ac_block_t *chain, uint32_t chain_len);

/* ------------------------------------------------------------------ */
/*  Full-chain validation                                              */
/* ------------------------------------------------------------------ */

/* Validate an entire chain from genesis to tip.
 * Checks genesis match, all block linkage, all signatures, sequence
 * replay, rate limiting.
 * Returns AC_OK or an error code. */
int ac_chain_validate(const ac_block_t *blocks, uint32_t count);

/* ------------------------------------------------------------------ */
/*  Chain operations (thread-safe)                                     */
/* ------------------------------------------------------------------ */

/* Get the number of blocks in the chain. */
uint32_t ac_chain_len(ac_chain_t *chain);

/* Copy the last block into `out`. Returns AC_OK or AC_ERR_INVAL. */
int ac_chain_last_block(ac_chain_t *chain, ac_block_t *out);

/* Validate and append a block. Returns AC_OK or validation error. */
int ac_chain_add_block(ac_chain_t *chain, const ac_block_t *blk);

/* Replace the chain with `candidate` if it is valid and longer
 * (or same length with lower tip hash — deterministic tiebreak).
 * Returns 1 if replaced, 0 if not replaced.
 * Sets `*err` to AC_OK or error code. */
int ac_chain_replace(ac_chain_t *chain,
                     const ac_block_t *candidate, uint32_t candidate_len,
                     int *err);

/* Copy all blocks into caller-provided buffer. `*out_count` is set
 * to actual block count. Caller must provide enough space.
 * Returns AC_OK or AC_ERR_INVAL. */
int ac_chain_get_blocks(ac_chain_t *chain,
                        ac_block_t *out, uint32_t out_capacity,
                        uint32_t *out_count);

/* Prune blocks before keep_from. Returns number of blocks removed.
 * Shifts remaining blocks and adjusts count. Daemon-only. */
int ac_chain_prune(ac_chain_t *chain, uint32_t keep_from);

/* ------------------------------------------------------------------ */
/*  Clock sanity check (N30 hardened)                                  */
/* ------------------------------------------------------------------ */

/* Compare local clock to a peer's reported timestamp.
 * Logs WARNING if delta > AC_CLOCK_WARN_DELTA,
 * ERROR if delta > AC_CLOCK_ERROR_DELTA.
 * Returns absolute delta in seconds. */
uint64_t ac_time_sanity_check(uint64_t peer_timestamp);

/* ------------------------------------------------------------------ */
/*  Transaction type validation                                        */
/* ------------------------------------------------------------------ */

/* Validate that a transaction's type-specific fields are consistent.
 * Returns AC_OK or AC_ERR_INVAL. */
int ac_tx_validate_type(const ac_transaction_t *tx);

#endif /* AC_CHAIN_H */
