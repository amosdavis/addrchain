/*
 * ac_snapshot.h — State snapshot serialization and verification
 *
 * Serializes all module state (claims, subnets, VPN tunnels, partitions,
 * DAG edges, nonce table) into a contiguous binary buffer with SHA-256
 * hash verification.  Supports chain pruning via snapshot + replay.
 *
 * Mitigates: S06 (deterministic binary format), S07 (hash verification),
 *            S08 (snapshot interval), S22 (local self-consistency),
 *            S24 (prune to confirmed SNAPSHOT tx)
 */

#ifndef AC_SNAPSHOT_H
#define AC_SNAPSHOT_H

#include "ac_proto.h"
#include "ac_platform.h"
#include "ac_claims.h"
#include "ac_subnet.h"
#include "ac_vpn.h"
#include "ac_partition.h"
#include "ac_discover.h"
#include "ac_dag.h"
#include "ac_chain.h"

/* Snapshot header (binary, little-endian) */
#pragma pack(push, 1)
typedef struct {
    uint32_t    magic;              /* AC_SNAPSHOT_MAGIC ("ACSS") */
    uint32_t    format_version;     /* AC_SNAPSHOT_VERSION */
    uint32_t    snapshot_block;     /* block index at snapshot */
    uint8_t     state_hash[AC_HASH_LEN]; /* SHA-256 of serialized state */
    uint32_t    total_size;         /* total bytes including header */
} ac_snapshot_header_t;
#pragma pack(pop)

/* Snapshot buffer — owns the serialized data */
typedef struct {
    uint8_t    *data;               /* allocated buffer */
    uint32_t    size;               /* total size */
    uint32_t    block_index;        /* which block this snapshot was taken at */
    uint8_t     hash[AC_HASH_LEN];  /* computed hash */
} ac_snapshot_t;

/* Create a snapshot of all module state.
 * Serializes claims, subnets, VPN tunnels, partitions, DAG edges, and nonce table
 * into a contiguous buffer. Computes SHA-256 hash.
 * Returns AC_OK on success. Caller must free with ac_snapshot_free(). */
int ac_snapshot_create(ac_snapshot_t *snap,
                       uint32_t block_index,
                       ac_chain_t *chain,
                       ac_claim_store_t *cs,
                       ac_subnet_store_t *ss,
                       ac_vpn_store_t *vs,
                       ac_partition_store_t *ps,
                       ac_dag_t *dag);

/* Restore module state from a snapshot buffer.
 * Clears existing state and loads from serialized data.
 * Returns AC_OK on success, AC_ERR_INVAL on format error. */
int ac_snapshot_restore(const ac_snapshot_t *snap,
                        ac_chain_t *chain,
                        ac_claim_store_t *cs,
                        ac_subnet_store_t *ss,
                        ac_vpn_store_t *vs,
                        ac_partition_store_t *ps,
                        ac_dag_t *dag);

/* Verify snapshot hash. Returns AC_OK if hash matches, AC_ERR_CRYPTO if not. */
int ac_snapshot_verify(const ac_snapshot_t *snap);

/* Free snapshot buffer. */
void ac_snapshot_free(ac_snapshot_t *snap);

/* Load snapshot from raw buffer (e.g., file data). Validates header.
 * Returns AC_OK on success. snap->data points to a copy of the input. */
int ac_snapshot_load(ac_snapshot_t *snap, const uint8_t *data, uint32_t size);

#endif /* AC_SNAPSHOT_H */
