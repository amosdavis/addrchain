# AddrChain Addressing Specification

**Version:** 2.0  
**Status:** Normative  
**Last Updated:** 2025-07-15

---

## 1. Overview

AddrChain manages network addresses through a claim-based model secured by
Ed25519 cryptography. Nodes claim addresses by submitting signed transactions
to the blockchain, binding addresses to public keys with finite block-based leases.

## 2. Address Model

| Family | Code   | Wire Length | Prefix Range | Padding        |
|--------|--------|-------------|-------------|----------------|
| IPv4   | `0x01` | 4 bytes     | 0–32        | 28 bytes zero  |
| IPv6   | `0x02` | 16 bytes    | 0–128       | 16 bytes zero  |
| POOL   | `0x03` | 32 bytes    | 0–256       | none           |

All addresses use `ac_address_t` (34 bytes packed): `family(1) | addr(32) | prefix_len(1)`.

### 2.1 POOL Address Structure

POOL addresses use the full 256-bit (32-byte) address space with an internal
structure:

```
Offset   Length   Field
─────────────────────────────────
 0        4B      Type + Version (32 bits)
 4        8B      Organization ID (64 bits)
12        8B      Subnet/Segment ID (64 bits)
20        8B      Node ID — SHA-256(pubkey)[0:8] (64 bits)
28        4B      CRC-32 of bytes [0..27] (32 bits)
```

**Validation rules for POOL addresses:**

1. The Node ID field MUST equal the first 8 bytes of `SHA-256(node_pubkey)`.
2. The CRC-32 field MUST be valid over bytes 0–27.
3. Both checks are enforced during CLAIM validation; failure returns
   `AC_ERR_POOL`.

## 3. Claim Lifecycle

### 3.1 State Diagram

```
                   ┌──────────┐
                   │          │
          CLAIM    │  ACTIVE  │◄──── RENEW (extends lease)
       ──────────►│          │
                   │          │
                   └────┬─────┘
                        │
               ┌────────┼────────┐
               │        │        │
           RELEASE   REVOKE   EXPIRE
               │        │        │
               ▼        ▼        ▼
          ┌────────┐ ┌────────┐ ┌─────────┐
          │RELEASED│ │REVOKED │ │ EXPIRED │
          └────────┘ └────────┘ └─────────┘
```

### 3.2 Transaction Details

#### CLAIM (`0x01`)

Creates a new address binding. Payload: `ac_tx_claim_t`.

| Field         | Type           | Description                          |
|---------------|----------------|--------------------------------------|
| address       | ac_address_t   | Address to claim (34 bytes)          |
| subnet_id     | uint8_t[32]    | Subnet this claim belongs to         |
| lease_blocks  | uint32_t LE    | Lease duration in blocks             |

**Validation:**

1. Address not already claimed by another node (DAD check).
2. If `subnet_id` is non-zero, address MUST fall within that subnet's prefix.
3. `lease_blocks` MUST be in range `[AC_MIN_LEASE_BLOCKS, AC_MAX_LEASE_BLOCKS]`
   (10–100,000). If zero, defaults to `AC_DEFAULT_LEASE_BLOCKS` (1,000).
4. For POOL addresses, Node ID and CRC-32 validation applies (§2.3).
5. Rate limit check passes (§6).

#### RELEASE (`0x02`)

Voluntarily relinquishes a claim. Payload: `ac_tx_claim_t`.

**Validation:**

1. The address MUST be currently claimed.
2. The `node_pubkey` on the transaction MUST match the claim owner (after
   following any revocation chain).
3. On success, the claim record is deactivated.

#### RENEW (`0x03`)

Extends the lease of an existing claim. Payload: `ac_tx_claim_t`.

**Validation:**

1. The address MUST be currently claimed and active.
2. The `node_pubkey` MUST match the claim owner.
3. The claim MUST NOT have already expired.
4. The `lease_blocks` value replaces the remaining lease; it must satisfy
   the same range constraints as CLAIM.
5. `last_renewed_block` is updated to the block index containing this RENEW.

#### REVOKE (`0x04`)

Rotates a node's key. All claims under the old key migrate to the new key.
Payload: `ac_tx_revoke_t`.

| Field        | Type           | Description                   |
|--------------|----------------|-------------------------------|
| old_pubkey   | uint8_t[32]    | Key being retired             |
| new_pubkey   | uint8_t[32]    | Replacement key               |

**Validation:**

1. The transaction MUST be signed by `old_pubkey`.
2. A revocation record is created mapping `old_pubkey → new_pubkey`.
3. All existing claims owned by `old_pubkey` are logically transferred.
4. Maximum revocation chain depth: 256 (`AC_MAX_REVOCATIONS`).
5. Cycle detection: the chain MUST NOT form a cycle.

## 4. Lease Model

### 4.1 Parameters

| Parameter                | Value   | Constant                     |
|--------------------------|---------|------------------------------|
| Default lease            | 1,000   | `AC_DEFAULT_LEASE_BLOCKS`    |
| Minimum lease            | 10      | `AC_MIN_LEASE_BLOCKS`        |
| Maximum lease            | 100,000 | `AC_MAX_LEASE_BLOCKS`        |
| Auto-renew threshold     | 50%     | `AC_RENEW_THRESHOLD_PCT`     |

### 4.2 Lease Expiration

A claim expires when:

```
current_block_index > last_renewed_block + lease_blocks
```

Expired claims are eligible for reclamation by any node. The claim store
tracks `last_renewed_block` and `lease_blocks` per claim record.

### 4.3 Auto-Renewal

Nodes SHOULD submit a RENEW transaction when the remaining lease falls below
50% of the original lease duration:

```
remaining = (last_renewed_block + lease_blocks) - current_block_index
if remaining < (lease_blocks * AC_RENEW_THRESHOLD_PCT / 100):
    submit RENEW
```

Auto-renewal is a client-side behavior; the chain enforces only that
RENEW transactions are valid, not that they are timely.

### 4.4 Claim Record

Maximum concurrent claims: 4,096 (`AC_MAX_CLAIMS`). Each record stores:
address (34B), owner_pubkey (32B), last_renewed_block (4B LE),
lease_blocks (4B LE), orig_nonce (4B LE), active (1B).

## 5. Conflict Resolution (DAD)

### 5.1 Duplicate Address Detection

Before accepting a CLAIM, the chain validates:

1. **No active claim**: The address is not claimed by any other node with an
   unexpired lease.
2. **Same-node re-claim**: If the same `node_pubkey` already holds the address,
   the CLAIM acts as an implicit RENEW.
3. **Expired re-claim**: If a prior claim has expired, the new CLAIM succeeds
   and the old record is replaced.

### 5.2 In-Block Conflicts

When a block contains multiple CLAIM transactions for the same address from
different nodes, only the **first** transaction (lowest index in `txs[]`) is
accepted. Subsequent conflicting claims in the same block are rejected.

Validation uses a temporary pending set to detect in-block conflicts without
modifying the persistent claim store.

### 5.3 Revocation Chain Resolution

To determine the current owner of a claim, the validator follows the
revocation chain:

```
owner = claim.owner_pubkey
while revocation_exists(owner):
    owner = revocation[owner].new_pubkey
    depth++
    if depth > AC_MAX_REVOCATIONS: reject (cycle)
return owner
```

## 6. Rate Limiting

Address operations are subject to the global rate limit:

- **Window**: 10 blocks (`AC_RATE_WINDOW_BLOCKS`)
- **Limit**: 20 transactions per node (`AC_RATE_MAX_TX`)

This applies to all transaction types, not just address operations. See
`spec/PROTOCOL.md §6.3` for details.

## 7. Address Validation by Family

| Family | Occupied Bytes | Padding    | Prefix Range | Host Prefix |
|--------|---------------|------------|-------------|-------------|
| IPv4   | 1–4           | 5–32 zero  | 0–32        | /32         |
| IPv6   | 1–16          | 17–32 zero | 0–128       | /128        |
| POOL   | 1–32          | none       | 0–256       | /256        |

POOL addresses are additionally validated per §2.3 (Node ID + CRC-32).

## 8. Interaction with Subnets

When a CLAIM references a non-zero `subnet_id`, the subnet MUST exist and
be active, and the claimed address MUST fall within the subnet's CIDR prefix.
Subnet prefix validation uses byte-by-byte comparison with bit masking.

## 9. Limits Summary

| Resource                 | Limit    | Constant               |
|--------------------------|----------|------------------------|
| Concurrent claims        | 4,096    | `AC_MAX_CLAIMS`        |
| Revocation chain depth   | 256      | `AC_MAX_REVOCATIONS`   |
| Lease range (blocks)     | 10–100k  | `AC_MIN/MAX_LEASE_BLOCKS` |
| Default lease            | 1,000    | `AC_DEFAULT_LEASE_BLOCKS` |
| Auto-renew threshold     | 50%      | `AC_RENEW_THRESHOLD_PCT`  |
