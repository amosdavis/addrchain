# AddrChain Subnetting Specification

**Version:** 2.0  
**Status:** Normative  
**Last Updated:** 2025-07-15

---

## 1. Overview

AddrChain supports decentralized subnet management through two transaction types:
SUBNET_CREATE and SUBNET_ASSIGN. Subnets define CIDR-bounded address spaces with
gateway and DNS requirements, optional VLAN mapping, and membership tracking. All
subnet definitions are committed to the chain and validated against overlap rules.

## 2. Limits

| Resource                   | Limit  | Constant                  |
|----------------------------|--------|---------------------------|
| Maximum subnets            | 256    | `AC_MAX_SUBNETS`          |
| Maximum members per subnet | 1,024  | `AC_MAX_SUBNET_MEMBERS`   |
| Maximum DNS servers        | 4      | `AC_MAX_DNS_ADDRS`        |

## 3. Subnet Creation

### 3.1 SUBNET_CREATE Transaction (`0x10`)

Payload: `ac_tx_subnet_create_t` (packed).

| Field       | Type              | Size    | Description                        |
|-------------|-------------------|---------|------------------------------------|
| subnet_id   | uint8_t[32]       | 32B     | Unique subnet identifier           |
| prefix      | ac_address_t      | 34B     | Network prefix (family + CIDR)     |
| gateway     | ac_address_t      | 34B     | Default gateway address            |
| dns         | ac_address_t[4]   | 136B    | DNS server addresses (up to 4)     |
| dns_count   | uint8_t           | 1B      | Number of DNS entries (0–4)        |
| vlan_id     | uint16_t LE       | 2B      | VLAN tag (0 = no mapping)          |
| flags       | uint8_t           | 1B      | Subnet flags (§3.3)               |

### 3.2 Validation Rules

A SUBNET_CREATE transaction MUST satisfy:

1. **Uniqueness**: No active subnet with the same `subnet_id` exists.
   Violation: `AC_ERR_EXIST`.

2. **CIDR validity**: The `prefix` field must have a valid `family` code
   and a `prefix_len` within the family's range.

3. **No overlap**: The new prefix MUST NOT overlap with any existing
   subnet prefix (§4). Violation: `AC_ERR_OVERLAP`.

4. **Gateway required**: The `gateway` field MUST contain a valid address
   within the subnet prefix UNLESS `AC_SUBNET_FLAG_NO_GATEWAY` is set.
   This flag corresponds to the `--no-gateway` CLI option. Violation:
   `AC_ERR_INVAL`.

5. **DNS required**: At least one DNS server MUST be specified (`dns_count ≥ 1`)
   UNLESS `AC_SUBNET_FLAG_NO_DNS` is set. This flag corresponds to the
   `--no-dns` CLI option. Violation: `AC_ERR_INVAL`.

6. **DNS validity**: Each DNS address must have a valid family code.

7. **Signature**: Transaction signed by the creating node's Ed25519 key.

8. **Rate limit**: Standard rate limiting applies (20 tx / 10 blocks).

### 3.3 Subnet Flags

| Flag                       | Code   | CLI Option       | Effect                      |
|----------------------------|--------|------------------|-----------------------------|
| `AC_SUBNET_FLAG_NO_GATEWAY`| `0x01` | `--no-gateway`   | Allows zero gateway address |
| `AC_SUBNET_FLAG_NO_DNS`    | `0x02` | `--no-dns`       | Allows zero DNS servers     |

Flags are a bitmask; both may be set simultaneously.

### 3.4 Subnet Record

Upon successful validation, a record is stored:

```
ac_subnet_record_t
┌───────────┬────────┬─────────┬─────┬───────────┬──────┬─────────┬──────────────┬────────┐
│ subnet_id │ prefix │ gateway │ dns │ dns_count │ vlan │ creator │ created_block│ active │
│ 32B       │ 34B    │ 34B     │136B │ 1B        │ 2B   │ 32B     │ 4B           │ 1B     │
└───────────┴────────┴─────────┴─────┴───────────┴──────┴─────────┴──────────────┴────────┘
```

## 4. Overlap Detection

### 4.1 Algorithm

Two CIDR prefixes overlap if either contains the other's network address.
The check is bidirectional:

```
overlap(A, B) = prefix_match(A.network, B) OR prefix_match(B.network, A)
```

Where `prefix_match(addr, prefix)` tests whether `addr` falls within `prefix`:

```
function prefix_match(addr, prefix):
    if addr.family != prefix.family:
        return false

    full_bytes = prefix.prefix_len / 8
    rem_bits   = prefix.prefix_len % 8
    max_bits   = family_max_bits(prefix.family)  // 32, 128, or 256

    // Compare full bytes
    for i in 0..full_bytes:
        if addr.addr[i] != prefix.addr[i]:
            return false

    // Compare partial byte
    if rem_bits > 0 AND full_bytes < (max_bits / 8):
        mask = 0xFF << (8 - rem_bits)
        if (addr.addr[full_bytes] & mask) != (prefix.addr[full_bytes] & mask):
            return false

    return true
```

### 4.2 Overlap Examples

```
Existing subnet: 10.0.0.0/16
─────────────────────────────────────────────
New prefix        Result    Reason
─────────────────────────────────────────────
10.0.1.0/24       OVERLAP   10.0.0.0/16 contains 10.0.1.0
10.0.0.0/8        OVERLAP   10.0.0.0/8 contains 10.0.0.0
192.168.0.0/16    OK        Different network
10.1.0.0/16       OK        Adjacent, no overlap
```

### 4.3 Cross-Family Isolation

Prefixes of different address families NEVER overlap. An IPv4 `10.0.0.0/8`
and an IPv6 `fd00::/48` can coexist without conflict. POOL prefixes are
similarly isolated from IPv4 and IPv6.

## 5. Subnet Assignment

### 5.1 SUBNET_ASSIGN Transaction (`0x11`)

Payload: `ac_tx_subnet_assign_t` (packed).

| Field       | Type         | Size | Description                      |
|-------------|-------------|------|----------------------------------|
| subnet_id   | uint8_t[32] | 32B  | Target subnet                    |
| node_pubkey | uint8_t[32] | 32B  | Node being assigned              |

### 5.2 Validation Rules

1. **Subnet exists**: The referenced `subnet_id` MUST correspond to an
   active subnet. Violation: `AC_ERR_NOENT`.

2. **Not already assigned**: The node MUST NOT already be a member of
   this subnet. Violation: `AC_ERR_EXIST`.

3. **Capacity**: The subnet MUST have fewer than `AC_MAX_SUBNET_MEMBERS`
   (1,024) members. Violation: `AC_ERR_FULL`.

4. **Authorization**: The transaction MUST be signed by either the subnet
   creator or the node being assigned.

### 5.3 Member Record

```
ac_subnet_member_t
┌──────────────┬───────────┬──────────────────┐
│ node_pubkey  │ subnet_id │ assignment_block  │
│ 32B          │ 32B       │ 4B LE            │
└──────────────┴───────────┴──────────────────┘
```

## 6. VLAN Mapping

### 6.1 VLAN Assignment

Each subnet MAY have an associated VLAN ID:

- `vlan_id = 0`: No VLAN mapping (default).
- `vlan_id = 1–4094`: Maps the subnet to the specified 802.1Q VLAN.

### 6.2 VLAN Interaction with Partitions

When a subnet is added to a partition (via PARTITION ADD_SUBNET), the
partition's VLAN ID and the subnet's VLAN ID are independent. The partition
VLAN provides inter-partition isolation; the subnet VLAN provides L2
segmentation within a partition.

### 6.3 Uniqueness

VLAN IDs are not globally unique across subnets. Multiple subnets MAY
share the same VLAN ID. However, partition VLAN IDs MUST be unique
(see `spec/PARTITIONING.md §4`).

## 7. Gateway and DNS Semantics

**Gateway**: Default route for subnet nodes. MUST fall within the subnet prefix.
When `AC_SUBNET_FLAG_NO_GATEWAY` (`0x01` / `--no-gateway`) is set, the gateway
field is zeroed. Use case: point-to-point links, overlay-only networks.

**DNS**: Up to 4 name servers. NOT required to be within the subnet prefix.
When `AC_SUBNET_FLAG_NO_DNS` (`0x02` / `--no-dns`) is set, `dns_count` is 0.
Use case: air-gapped networks, DNS-over-POOL.

## 8. Interaction with Address Claims

### 8.1 Prefix Enforcement

When a CLAIM transaction references a `subnet_id`:

1. The subnet MUST exist and be active.
2. The claimed address MUST pass `prefix_match()` against the subnet's prefix.
3. Violation returns `AC_ERR_INVAL`.

### 8.2 Unaffiliated Claims

A CLAIM with an all-zero `subnet_id` is not bound to any subnet. Such claims
are validated only against the global duplicate detection rules. This supports
standalone address allocation without subnet infrastructure.

## 9. Subnet Lifecycle

Subnets become active in the block containing their SUBNET_CREATE transaction.
No explicit SUBNET_DELETE exists; subnets persist indefinitely. Subnets may be
associated with partitions (see `spec/PARTITIONING.md`).

## 10. Concurrency

Subnet operations acquire `subnet_lock` (priority 3 in lock ordering:
chain > claim > subnet > partition > vpn > discover).

## 11. Error Codes

| Code            | Trigger                                    |
|-----------------|--------------------------------------------|
| `AC_ERR_EXIST`  | Duplicate subnet_id                        |
| `AC_ERR_OVERLAP`| CIDR prefix overlaps existing subnet       |
| `AC_ERR_INVAL`  | Missing gateway/DNS, invalid CIDR          |
| `AC_ERR_NOENT`  | Subnet not found (for ASSIGN)              |
| `AC_ERR_FULL`   | Subnet member table at capacity            |
| `AC_ERR_PERM`   | Unauthorized assignment                    |
| `AC_ERR_RATELIM`| Rate limit exceeded                        |
