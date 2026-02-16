# Chain Pruning & State Snapshots

## Overview

addrchain supports state snapshots and chain pruning to bound memory usage
while preserving auditability. Snapshots capture the full state of all modules
at a given block index. Blocks before the snapshot point can be safely pruned
without losing current state.

## Snapshot Format

### Header (44 bytes, little-endian)

| Offset | Size | Field            | Description                          |
|--------|------|------------------|--------------------------------------|
| 0      | 4    | `magic`          | `0x41435353` ("ACSS" LE)             |
| 4      | 4    | `format_version` | Currently `1`                        |
| 8      | 4    | `snapshot_block` | Block index at snapshot               |
| 12     | 32   | `state_hash`     | SHA-256 of all serialized sections    |
| 44     | 4    | `total_size`     | Total buffer size including header    |

### Sections (v1 format)

Sections appear in fixed order after the header. Each section begins with a
`uint32_t` count of records.

| Order | Section       | Record Type           | Notes                        |
|-------|---------------|-----------------------|------------------------------|
| 1     | Claims        | `ac_claim_record_t`   | Flat copy per record         |
| 2     | Subnets       | `ac_subnet_record_t`  | Flat copy per record         |
| 3     | Members       | `ac_subnet_member_t`  | Flat copy per record         |
| 4     | VPN Tunnels   | `ac_vpn_tunnel_t`     | Flat copy per record         |
| 5     | Partitions    | Variable              | id + vlan + active + subnets |
| 6     | Cross Rules   | `ac_cross_rule_t`     | Flat copy per record         |
| 7     | Seq Table     | `ac_seq_entry_t`      | Flat copy per record         |
| 8     | DAG Edges     | 33+33 bytes           | parent_key + child_key       |

### Partition Record Layout

Each partition record:
- `partition_id[32]` (bytes)
- `vlan_id` (uint16_t)
- `active` (uint8_t)
- `subnet_count` (uint32_t)
- `subnet_ids[subnet_count][32]` (bytes)

### DAG Edge Layout

Each DAG edge: 33-byte parent key + 33-byte child key.
Key format: `type(1 byte) + id(32 bytes)`.

## Hash Computation

The `state_hash` is the SHA-256 digest of all bytes after the header
(offset 48 through end of buffer). This covers all serialized sections.

## On-Chain Recording

When a snapshot is created, a `SNAPSHOT` transaction (type `0x40`) is
committed to the chain containing:

- `snapshot_block`: the block index captured
- `state_hash[32]`: the computed hash

This provides cryptographic proof of state at the prune point. Even after
pruning, the hash on-chain allows verification that a snapshot file is
authentic.

## Pruning Rules

1. **Only prune to a confirmed snapshot.** The latest `AC_TX_SNAPSHOT`
   transaction on the longest chain determines the safe prune point.

2. **Keep at least the snapshot block.** `ac_chain_prune(chain, N)` removes
   blocks `0..N-1`, keeping block `N` onward.

3. **Daemon-only.** The kernel module does NOT prune. Kernel chain capacity
   is bounded by the `max_chain_blocks` module parameter (default 65536).

4. **Atomic file replacement.** Snapshot files are written via
   write-then-rename to prevent corruption (S08). The previous snapshot is
   kept as backup until the new one is verified.

5. **Snapshot interval.** Configurable via `AC_SNAPSHOT_INTERVAL` (default
   1000 blocks). The daemon creates snapshots automatically.

## Rebuild from Snapshot

After restoring a snapshot, rebuild is:

1. `ac_snapshot_restore()` — loads all module state from snapshot
2. Replay blocks from `snapshot_block + 1` to chain tip
3. State is identical to replaying from genesis

This reduces rebuild from O(total_blocks × txs) to
O(remaining_blocks × txs).

## Sync Protocol

When a peer requests blocks that have been pruned:

1. Respond with `SNAPSHOT_OFFER` containing snapshot hash + block index
2. Peer downloads snapshot file out-of-band
3. Peer verifies hash against on-chain `SNAPSHOT` tx
4. Peer restores snapshot, then syncs remaining blocks normally

## Version Migration

If `format_version` in the header is not recognized, `ac_snapshot_load()`
returns `AC_ERR_INVAL` with an error log indicating the expected vs actual
version. Future versions will include migration logic or parallel loaders.

## Storage

- Default path: `/etc/addrchain/snapshots/`
- Filename: `snapshot-<block_index>.bin`
- Previous snapshot kept until new one verified
- Daemon manages lifecycle; operator can also trigger via `addrctl snapshot`

## Security Considerations

- **S06**: Snapshot hash provides tamper detection
- **S07**: Hash on-chain preserves audit trail after pruning
- **S08**: Atomic writes prevent partial corruption
- **S09**: Snapshot created under chain lock for consistency
- **S22**: Snapshots are node-local; hash allows cross-node verification
- **S24**: Only prune to on-chain confirmed snapshot
