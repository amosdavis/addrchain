# AddrChain Protocol Specification

**Version:** 2.0  
**Status:** Normative  
**Last Updated:** 2025-07-15

---

## 1. Overview

AddrChain is a blockchain-based network address management protocol replacing
DHCP with a decentralized ledger. All wire formats use **little-endian** byte
order and **packed structs** (`#pragma pack(1)`) for deterministic hashing.

## 2. Cryptographic Primitives

| Primitive   | Algorithm          | Size     |
|-------------|--------------------|----------|
| Hash        | SHA-256            | 32 bytes |
| Signature   | Ed25519            | 64 bytes |
| Public key  | Ed25519            | 32 bytes |
| AEAD (POOL) | ChaCha20-Poly1305  | —        |

Signing payload: `type(1) | node_pubkey(32) | timestamp(8) | nonce(4) | payload(variable)`.

## 3. Address Wire Format

`ac_address_t` (34 bytes packed): `family(1) | addr(32) | prefix_len(1)`.
Families: IPv4 (`0x01`, 4B + 28B zero), IPv6 (`0x02`, 16B + 16B zero), POOL (`0x03`, 32B).

## 4. Transaction Envelope

```
ac_transaction_t (packed)
┌──────────┬──────────────┬─────────────┬─────────┬───────────┬───────────┐
│ type     │ node_pubkey  │ timestamp   │ nonce   │ payload   │ signature │
│ 1 byte   │ 32 bytes     │ 8 bytes LE  │ 4 bytes │ variable  │ 64 bytes  │
└──────────┴──────────────┴─────────────┴─────────┴───────────┴───────────┘
```

- **type**: One of the 9 transaction type codes (§4.1).
- **node_pubkey**: Ed25519 public key of the submitting node.
- **timestamp**: Unix seconds (informational; not used for ordering).
- **nonce**: Monotonically increasing per-node; prevents replay (§6.2).
- **payload**: Type-dependent union (§4.1).
- **signature**: Ed25519 over the signing payload (everything except signature).

### 4.1 Transaction Types

| Code   | Name           | Payload Struct             | Purpose                        |
|--------|----------------|----------------------------|--------------------------------|
| `0x01` | CLAIM          | `ac_tx_claim_t`            | Claim a network address        |
| `0x02` | RELEASE        | `ac_tx_claim_t`            | Release a claimed address      |
| `0x03` | RENEW          | `ac_tx_claim_t`            | Extend an existing lease       |
| `0x04` | REVOKE         | `ac_tx_revoke_t`           | Rotate key, migrate claims     |
| `0x10` | SUBNET_CREATE  | `ac_tx_subnet_create_t`    | Define a network subnet        |
| `0x11` | SUBNET_ASSIGN  | `ac_tx_subnet_assign_t`    | Assign a node to a subnet      |
| `0x20` | VPN_TUNNEL     | `ac_tx_vpn_tunnel_t`       | Register VPN tunnel endpoint   |
| `0x21` | VPN_KEY        | `ac_tx_vpn_key_t`          | Publish VPN public key         |
| `0x30` | PARTITION      | `ac_tx_partition_t`        | Create/modify partitions       |
| `0x40` | SNAPSHOT       | `ac_tx_snapshot_t`         | Record state snapshot hash     |

## 5. Block Structure

```
ac_block_t (packed)
┌─────────┬─────────────┬───────────┬──────────┬──────────┬─────────────────┐
│ index   │ timestamp   │ prev_hash │ hash     │ tx_count │ txs[64]         │
│ 4B LE   │ 8B LE       │ 32B       │ 32B      │ 2B LE    │ up to 64 tx     │
└─────────┴─────────────┴───────────┴──────────┴──────────┴─────────────────┘
```

- **index**: Zero-based block height (uint32).
- **timestamp**: Unix seconds at block creation (uint64).
- **prev_hash**: SHA-256 of the preceding block (all zeroes for genesis).
- **hash**: SHA-256 of this block (§5.1).
- **tx_count**: Number of transactions in this block (0–64).
- **txs**: Array of `ac_transaction_t`, length `tx_count`.

### 5.1 Block Hash Computation

The block hash is computed as:

```
SHA-256( index_LE32 | timestamp_LE64 | prev_hash | tx_count_LE16 | tx[0] | tx[1] | … )
```

All fields are serialized in their packed wire format. The hash covers the
complete binary representation of every transaction in the block.

### 5.2 Genesis Block

The genesis block is deterministic: `index=0`, `timestamp=0`,
`prev_hash=0x00…00`, `tx_count=0`.

## 6. Validation Rules

### 6.1 Block Validation

A block MUST satisfy all of the following:

1. **Index continuity**: `block.index == predecessor.index + 1`.
2. **Hash linkage**: `block.prev_hash == predecessor.hash` (constant-time compare).
3. **Hash integrity**: Recomputed hash matches `block.hash`.
4. **Transaction count**: `0 ≤ tx_count ≤ 64`.
5. **Signature validity**: Every transaction has a valid Ed25519 signature.
6. **Type-specific rules**: Each transaction passes type-specific validation.
7. **Rate limit**: No node exceeds the per-node rate limit (§6.3).
8. **In-block conflict**: No two transactions in the same block claim the same address.

### 6.2 Nonce Replay Protection

Each node maintains a monotonically increasing nonce. The sequence table tracks
up to 256 nodes (`AC_MAX_SEQ_ENTRIES`). A transaction is rejected if its nonce
is not strictly greater than the last seen nonce for that `node_pubkey`.

### 6.3 Rate Limiting

| Parameter              | Value |
|------------------------|-------|
| Window                 | 10 blocks (`AC_RATE_WINDOW_BLOCKS`) |
| Max transactions/node  | 20 (`AC_RATE_MAX_TX`)               |

The rate limiter counts all transactions attributed to a given `node_pubkey`
within the sliding window of the most recent 10 blocks plus the candidate block.
Violation returns `AC_ERR_RATELIM`.

### 6.4 Clock Sanity

| Threshold | Delta   | Severity |
|-----------|---------|----------|
| Warning   | > 60 s  | WARN     |
| Error     | > 300 s | ERROR    |

Clock sanity is **informational only**. A block is never rejected solely due to
timestamp drift. The check is applied after signature and hash validation.

## 7. Fork Resolution

AddrChain uses **longest-chain-wins** with a deterministic tiebreaker:

```
if candidate.height > local.height:
    replace local chain with candidate
elif candidate.height == local.height:
    if candidate.tip_hash < local.tip_hash:   # lexicographic compare
        replace local chain with candidate
```

### 7.1 Chain Replacement

1. Validate entire candidate chain. 2. Allocate memory. 3. Acquire mutex.
4. Atomic pointer swap (RCU-style). 5. Release old blocks. 6. Release mutex.
Validation occurs **before** locking to minimize contention.

## 8. Sync Protocol

| Parameter        | Value                        |
|------------------|------------------------------|
| Transport        | TCP                          |
| Port             | 9877 (`AC_SYNC_PORT`)        |
| Framing          | 4-byte LE length prefix + payload |
| Max message size | 1,048,576 bytes (1 MiB)      |
| Timeout          | 10 seconds                   |

### 8.1 Sync Handshake

```
  Node A                          Node B
    │                                │
    │──── chain_height (4B LE) ─────►│
    │◄─── chain_height (4B LE) ──────│
    │                                │
    │  (if B is taller)              │
    │──── REQUEST_CHAIN ────────────►│
    │◄─── blocks[n..tip] ───────────│
    │                                │
```

Each received block is validated via `ac_block_validate()` before application.
POOL sessions use ChaCha20-Poly1305; plain TCP requires `--insecure`.

## 9. Discovery Protocol

| Parameter           | Value                          |
|---------------------|--------------------------------|
| Transport           | UDP                            |
| Port                | 9876 (`AC_DISCOVERY_PORT`)     |
| Announce interval   | 5,000 ms                       |
| Peer timeout        | 30,000 ms                      |
| Rate limit interval | 100 ms                         |
| Max peers           | 256                            |

### 9.1 Announce Payload

```
ac_announce_t (91 bytes, packed)
┌──────────┬──────────────┬──────────────┬──────────┬───────────┬──────────────┐
│ version  │ node_pubkey  │ chain_height │ tip_hash │ sync_port │ capabilities │
│ 2B LE    │ 32B          │ 4B LE        │ 32B      │ 2B LE     │ 1B           │
└──────────┴──────────────┴──────────────┴──────────┴───────────┴──────────────┘
```

### 9.2 Discovery Methods

| Method        | Code   | Address / Mechanism              |
|---------------|--------|----------------------------------|
| POOL multicast| `0x01` | `239.253.0.1:9253`               |
| IPv6 multicast| `0x02` | `ff02::addc:1` UDP 9876          |
| IPv4 broadcast| `0x04` | Subnet broadcast UDP 9876        |
| mDNS          | `0x08` | `_addrchain._udp.local`          |
| Static peers  | `0x10` | `--peer` CLI flag                |

### 9.3 Capabilities

| Bit  | Name      | Meaning                |
|------|-----------|------------------------|
| 0x01 | AC_CAP_POOL | POOL transport available |
| 0x02 | AC_CAP_VPN  | VPN tunneling available  |

### 9.4 Peer Lifecycle

Announces with local `node_pubkey` are dropped (self-discovery prevention).
`fail_count` increments on connection failure; `UNREACHABLE` after 3 failures.
Stale non-static peers pruned after 30 s. Best peer selected by highest `chain_height`.

## 10. Limits Summary

| Resource              | Limit     | Constant / Config             |
|-----------------------|-----------|-------------------------------|
| Transactions/block    | 64        | `AC_MAX_TX_PER_BLOCK`         |
| Chain blocks          | dynamic   | module param `max_chain_blocks` (kernel default 65536) |
| VPN allowed IPs       | 16        | `AC_MAX_VPN_ALLOWED_IPS`      |
| DNS addresses         | 4         | `AC_MAX_DNS_ADDRS`            |
| All other stores      | dynamic   | hashmap-backed, no compile-time limit |

## 11. Error Codes

| Code | Name           | Code | Name             |
|------|----------------|------|------------------|
| 0    | AC_OK          | -7   | AC_ERR_FULL      |
| -1   | AC_ERR         | -8   | AC_ERR_EXPIRED   |
| -2   | AC_ERR_NOMEM   | -9   | AC_ERR_CONFLICT  |
| -3   | AC_ERR_INVAL   | -10  | AC_ERR_CRYPTO    |
| -4   | AC_ERR_EXIST   | -11  | AC_ERR_OVERLAP   |
| -5   | AC_ERR_NOENT   | -12  | AC_ERR_RATELIM   |
| -6   | AC_ERR_PERM    | -13  | AC_ERR_POOL      |
