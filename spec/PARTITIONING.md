# AddrChain Partitioning Specification

**Version:** 2.0  
**Status:** Normative  
**Last Updated:** 2025-07-15

---

## 1. Overview

AddrChain partitions provide network isolation. A partition groups subnets into
an isolated domain with optional VLAN mapping. Cross-partition traffic is
**denied by default**; explicit ALLOW_CROSS transactions enable it.

## 2. Limits

| Resource                     | Limit | Constant                   |
|------------------------------|-------|----------------------------|
| Maximum partitions           | 64    | `AC_MAX_PARTITIONS`        |
| Maximum subnets per partition| 32    | `AC_MAX_PARTITION_SUBNETS` |
| Maximum cross-partition rules| 128   | `AC_MAX_CROSS_RULES`       |

## 3. PARTITION Transaction (`0x30`)

All partition operations use a single transaction type with an `action` field
that selects the operation.

### 3.1 Payload: `ac_tx_partition_t`

| Field            | Type         | Size | Description                       |
|------------------|-------------|------|-----------------------------------|
| partition_id     | uint8_t[32] | 32B  | Partition being operated on       |
| action           | uint8_t     | 1B   | Partition action code (§3.2)      |
| target_subnet_id | uint8_t[32] | 32B  | Subnet for ADD/REMOVE operations  |
| target_part_id   | uint8_t[32] | 32B  | Partner partition for ALLOW/DENY  |
| vlan_id          | uint16_t LE | 2B   | VLAN tag (CREATE only)            |

### 3.2 Actions

| Code   | Name           | Description                                  |
|--------|----------------|----------------------------------------------|
| `0x01` | CREATE         | Create a new partition                        |
| `0x02` | DELETE         | Delete an existing partition                  |
| `0x03` | ADD_SUBNET     | Associate a subnet with this partition        |
| `0x04` | REMOVE_SUBNET  | Disassociate a subnet from this partition     |
| `0x05` | ALLOW_CROSS    | Allow traffic between two partitions          |
| `0x06` | DENY_CROSS     | Deny traffic between two partitions           |

## 4. Partition Lifecycle

### 4.1 CREATE (`0x01`)

Creates a new partition. Validation: unique `partition_id` (`AC_ERR_EXIST`),
unique non-zero `vlan_id` (`AC_ERR_EXIST`), table not full (`AC_ERR_FULL`),
valid Ed25519 signature. Records creator pubkey and block index.

### 4.2 DELETE (`0x02`)

Removes a partition. Requires active partition (`AC_ERR_NOENT`) and creator
signature (`AC_ERR_PERM`). Clears all subnet associations; cross-partition
rules referencing this partition are implicitly voided.

### 4.3 ADD_SUBNET (`0x03`)

Associates a subnet with the partition. Requires: active partition, active
subnet, subnet not already associated (`AC_ERR_EXIST`), fewer than 32 subnets
(`AC_ERR_FULL`), subnet not in another partition.

### 4.4 REMOVE_SUBNET (`0x04`)

Disassociates a subnet. Requires active partition and subnet membership
(`AC_ERR_NOENT`). Array elements shift to fill the gap.

### 4.5 ALLOW_CROSS (`0x05`)

Permits traffic between two partitions. Both must be active (`AC_ERR_NOENT`)
and distinct (`AC_ERR_INVAL`). Creates or updates a cross-rule with `allowed=1`.
Rule matching is **bidirectional**: `(A,B)` also governs `(B,A)`.

### 4.6 DENY_CROSS (`0x06`)

Revokes cross-partition permission. Same validation as ALLOW_CROSS.
Sets `allowed=0` on existing rule or creates explicit deny record.

## 5. Cross-Partition Traffic Model

### 5.1 Default Deny

Cross-partition traffic is **denied by default**. Nodes in different
partitions cannot communicate unless an explicit ALLOW_CROSS rule exists
between their respective partitions.

```
┌────────────┐                    ┌────────────┐
│ Partition A│                    │ Partition B│
│            │   ╳ DENIED ╳      │            │
│  Subnet 1  │◄──────────────────►│  Subnet 3  │
│  Subnet 2  │                    │  Subnet 4  │
└────────────┘                    └────────────┘

After ALLOW_CROSS(A, B):

┌────────────┐                    ┌────────────┐
│ Partition A│                    │ Partition B│
│            │   ✓ ALLOWED ✓     │            │
│  Subnet 1  │◄══════════════════►│  Subnet 3  │
│  Subnet 2  │                    │  Subnet 4  │
└────────────┘                    └────────────┘
```

### 5.2 Intra-Partition Traffic

Traffic within a single partition (between its subnets) is always permitted.
Partitions do not restrict intra-partition communication.

### 5.3 Unpartitioned Subnets

Subnets not associated with any partition are treated as belonging to an
implicit "default" partition. Traffic between unpartitioned subnets is
unrestricted. Traffic between an unpartitioned subnet and a partitioned
subnet follows default-deny rules.

## 6. VLAN Mapping

### 6.1 Partition VLAN

Each partition MAY have an associated VLAN ID assigned at creation:

- `vlan_id = 0`: No VLAN mapping.
- `vlan_id = 1–4094`: Maps the partition to an 802.1Q VLAN.

### 6.2 VLAN Uniqueness Constraint

Partition VLAN IDs MUST be globally unique among active partitions:

```
for each active partition P where P.vlan_id > 0:
    for each other active partition Q where Q.vlan_id > 0:
        assert P.vlan_id != Q.vlan_id
```

This is enforced during CREATE validation. Violation returns `AC_ERR_EXIST`.

### 6.3 VLAN vs. Subnet VLAN

Partition VLANs and subnet VLANs serve different purposes:

| Scope     | Set By          | Uniqueness | Purpose                    |
|-----------|-----------------|------------|----------------------------|
| Partition | PARTITION CREATE| Global     | Inter-partition isolation  |
| Subnet    | SUBNET_CREATE   | None       | L2 segmentation            |

A subnet within a partition may have its own VLAN ID independent of the
partition's VLAN. The two are orthogonal: the partition VLAN provides the
outer isolation boundary, while the subnet VLAN provides inner segmentation.

## 7. Cross-Partition Rule Record

```
ac_cross_rule_t
┌──────────────┬──────────────┬─────────┐
│ part_a       │ part_b       │ allowed │
│ 32B          │ 32B          │ 1B      │
└──────────────┴──────────────┴─────────┘
```

### 7.1 Bidirectional Lookup

Rule matching checks both orderings:

```
function find_cross_rule(A, B):
    for each rule R in cross_rules:
        if (R.part_a == A AND R.part_b == B) OR
           (R.part_a == B AND R.part_b == A):
            return R
    return NULL  // default deny
```

A `NULL` result is equivalent to `allowed = 0` (deny).

### 7.2 ALLOW/DENY Lifecycle

```
Initial state: No rule → DENY (implicit)
      │
      │ ALLOW_CROSS(A, B)
      ▼
Rule created: allowed = 1 → ALLOW
      │
      │ DENY_CROSS(A, B)
      ▼
Rule updated: allowed = 0 → DENY (explicit)
      │
      │ ALLOW_CROSS(A, B)
      ▼
Rule updated: allowed = 1 → ALLOW
      │
      │ (partition A or B deleted)
      ▼
Rule voided: partition inactive → DENY (implicit)
```

Rules are toggled in-place; they are not deleted. This preserves an audit
trail on the chain of all cross-partition permission changes.

## 8. Partition Record

Each `ac_partition_record_t` stores: partition_id (32B), vlan_id (2B LE),
creator pubkey (32B), created_block (4B LE), subnet_ids array (up to 32 × 32B),
subnet_count (1B), active flag (1B).

## 9. Multi-Partition Topology Example

```
Partition A (VLAN 100)  ◄══ ALLOW ══►  Partition B (VLAN 200)
  • 10.0.0.0/16                          • 10.1.0.0/16
  • 10.0.1.0/24                          • 10.1.1.0/24
       ╳ DENY (default)                      ╳ DENY (default)
Partition C (VLAN 300, isolated from A and B)
  • 192.168.0.0/16

Unpartitioned: 172.16.0.0/12 (unrestricted among unpartitioned, deny to A/B/C)
```

## 10. Interaction with Other Subsystems

- **Claims**: Partitions govern traffic flow, not address allocation.
- **VPN**: Cross-partition deny SHOULD prevent tunnel establishment at the
  application layer; VPN_KEY/VPN_TUNNEL transactions are accepted regardless.
- **Discovery**: Operates independently; all nodes share one discovery domain.

## 11. Concurrency

Partition operations acquire `partition_lock` (priority 4 in lock ordering:
chain > claim > subnet > partition > vpn > discover).

## 12. Error Codes

| Code            | Trigger                                         |
|-----------------|-------------------------------------------------|
| `AC_ERR_EXIST`  | Duplicate partition_id or VLAN; subnet already in partition |
| `AC_ERR_NOENT`  | Partition or subnet not found                   |
| `AC_ERR_FULL`   | Partition table, subnet list, or rule table full|
| `AC_ERR_PERM`   | Non-creator attempting DELETE                   |
| `AC_ERR_INVAL`  | Self-referencing cross-partition rule            |
| `AC_ERR_RATELIM`| Rate limit exceeded                             |
