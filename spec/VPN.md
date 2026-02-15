# AddrChain VPN Specification

**Version:** 2.0  
**Status:** Normative  
**Last Updated:** 2025-07-15

---

## 1. Overview

AddrChain integrates VPN tunnel management into the blockchain, enabling nodes
to establish encrypted tunnels by publishing keys and tunnel parameters as
signed transactions. The chain serves as the key distribution and endpoint
discovery mechanism, replacing out-of-band configuration. Three VPN protocols
are supported: WireGuard, IPsec, and POOL (native overlay).

## 2. VPN Protocols

| Protocol   | Code   | Key Type         | Transport           |
|------------|--------|------------------|---------------------|
| WireGuard  | `0x01` | Curve25519       | UDP (default 51820) |
| IPsec      | `0x02` | IKEv2            | UDP 500/4500        |
| POOL       | `0x03` | Ed25519 → X25519 | ChaCha20-Poly1305   |

AddrChain publishes keys and tunnel parameters on-chain; actual protocol
negotiation (WireGuard handshake, IKE) occurs out-of-band. POOL is the
native overlay using Ed25519-to-X25519 key conversion with ChaCha20-Poly1305.

## 3. Transaction Types

### 3.1 VPN_KEY (`0x21`)

Publishes a VPN public key for a node.

| Field      | Type           | Size | Description                    |
|------------|----------------|------|--------------------------------|
| protocol   | uint8_t        | 1B   | VPN protocol code              |
| vpn_pubkey | uint8_t[32]    | 32B  | Protocol-specific public key   |

**Validation:**

1. `protocol` MUST be one of `0x01`, `0x02`, `0x03`.
2. `vpn_pubkey` MUST NOT be all zeroes.
3. Standard Ed25519 signature verification on the transaction envelope.
4. Rate limiting applies.

**Effect:** Creates a tunnel record in `KEYED` state (§4) associating
the node's Ed25519 identity with its VPN public key.

### 3.2 VPN_TUNNEL (`0x20`)

Registers or updates a VPN tunnel endpoint.

| Field             | Type              | Size  | Description                       |
|-------------------|-------------------|-------|-----------------------------------|
| protocol          | uint8_t           | 1B    | VPN protocol code                 |
| endpoint          | ac_address_t      | 34B   | Tunnel endpoint address           |
| listen_port       | uint16_t LE       | 2B    | Endpoint listen port              |
| allowed_ips       | ac_address_t[16]  | 544B  | Allowed IP prefixes               |
| allowed_ip_count  | uint8_t           | 1B    | Number of allowed IP entries      |
| mtu               | uint16_t LE       | 2B    | Tunnel MTU (0 = auto)             |
| keepalive         | uint8_t           | 1B    | Persistent keepalive (seconds)    |
| nat_hint          | uint8_t           | 1B    | NAT traversal hint flag           |

**Validation:**

1. `protocol` MUST match a previously published VPN_KEY for this node.
2. `endpoint` MUST be a valid address.
3. `allowed_ip_count` MUST be ≤ 16 (`AC_MAX_VPN_ALLOWED_IPS`).
4. If `mtu` is non-zero, it MUST be ≥ 576 (`AC_VPN_MIN_MTU`).
5. Standard signature and rate limit checks.

**Effect:** Updates the tunnel record with endpoint configuration. If the
tunnel is in `KEYED` state, it remains `KEYED` until handshake completes.

## 4. VPN State Machine

### 4.1 States

| State     | Code | Description                              |
|-----------|------|------------------------------------------|
| IDLE      | 0    | No keys exchanged                        |
| KEYED     | 1    | VPN_KEY published, awaiting handshake    |
| ACTIVE    | 2    | Tunnel established, traffic flowing      |
| REKEYING  | 3    | Re-key in progress                       |
| CLOSED    | 4    | Tunnel torn down                         |
| ERROR     | 5    | Unrecoverable error                      |

### 4.2 State Transition Diagram

```
                 VPN_KEY tx
    ┌──────┐  ──────────►  ┌──────┐
    │ IDLE │               │KEYED │
    └──────┘               └──┬───┘
                              │
                    handshake │ success
                              ▼
                          ┌────────┐
                     ┌───►│ ACTIVE │◄───┐
                     │    └───┬────┘    │
                     │        │         │
               rekey │   rekey│trigger  │ handshake
              success│        ▼         │ success
                     │  ┌──────────┐    │
                     └──│ REKEYING │────┘
                        └────┬─────┘
                             │
                    max rekey│attempts
                             ▼
              ┌────────┐  ┌───────┐
              │ CLOSED │  │ ERROR │
              └────────┘  └───────┘
                  ▲
                  │ explicit close / timeout
                  └── from any state
```

### 4.3 Valid Transitions

| From      | To        | Trigger                              |
|-----------|-----------|--------------------------------------|
| IDLE      | KEYED     | VPN_KEY transaction published        |
| KEYED     | ACTIVE    | Handshake completes successfully     |
| KEYED     | CLOSED    | Handshake timeout (30 s)             |
| KEYED     | ERROR     | Unrecoverable failure                |
| ACTIVE    | REKEYING  | Rekey interval reached               |
| ACTIVE    | CLOSED    | Explicit close or peer departure     |
| REKEYING  | ACTIVE    | Rekey handshake succeeds             |
| REKEYING  | ERROR     | Max rekey attempts exceeded (3)      |
| REKEYING  | CLOSED    | Explicit close                       |
| ERROR     | IDLE      | Reset (new VPN_KEY required)         |
| CLOSED    | IDLE      | Reset (new VPN_KEY required)         |

Invalid transitions are rejected by `valid_transition()` and return
`AC_ERR_INVAL`.

## 5. Tunnel Lifecycle

### 5.1 Establishment

```
Node A                          Node B
  │                                │
  │── VPN_KEY(proto, pubkey_A) ───►│  (chain tx)
  │                                │
  │◄── VPN_KEY(proto, pubkey_B) ──│  (chain tx)
  │                                │
  │── VPN_TUNNEL(endpoint_A) ─────►│  (chain tx)
  │                                │
  │◄── VPN_TUNNEL(endpoint_B) ────│  (chain tx)
  │                                │
  │◄═══ protocol handshake ═══════►│  (out-of-band)
  │                                │
  │         ACTIVE ◄──► ACTIVE     │
  │                                │
```

1. Both nodes publish VPN_KEY transactions (state → KEYED).
2. Both nodes publish VPN_TUNNEL transactions with endpoint details.
3. Nodes discover each other's keys and endpoints from the chain.
4. Protocol-specific handshake occurs out-of-band.
5. On success, `ac_vpn_mark_handshake()` transitions both to ACTIVE.

### 5.2 Rekeying

Rekeying is triggered by the protocol's rekey interval. During rekeying:

1. State transitions to REKEYING.
2. New key material is generated.
3. A new VPN_KEY transaction MAY be published (protocol-dependent).
4. Handshake attempt occurs.
5. Success → ACTIVE; failure → increment `rekey_attempts`.
6. After `AC_VPN_MAX_REKEY_ATTEMPTS` (3) failures → ERROR.

### 5.3 Teardown

Tunnels are closed by:

- Explicit RELEASE of the associated address claim.
- Handshake timeout (`AC_VPN_HANDSHAKE_TIMEOUT_SEC` = 30 s) while KEYED.
- Max rekey failures while REKEYING.
- Node departure (peer marked UNREACHABLE in discovery).

On close, key material is zeroized via `ac_crypto_zeroize()`.

## 6. Timeouts and Limits

| Parameter                | Value | Constant                          |
|--------------------------|-------|-----------------------------------|
| Max tunnels              | 128   | `AC_MAX_VPN_TUNNELS`              |
| Handshake timeout        | 30 s  | `AC_VPN_HANDSHAKE_TIMEOUT_SEC`    |
| Keepalive interval       | 25 s  | `AC_VPN_KEEPALIVE_INTERVAL_SEC`   |
| Max rekey attempts       | 3     | `AC_VPN_MAX_REKEY_ATTEMPTS`       |
| Min MTU                  | 576   | `AC_VPN_MIN_MTU`                  |
| Max allowed IPs/tunnel   | 16    | `AC_MAX_VPN_ALLOWED_IPS`          |

### 6.1 Min MTU Rationale

The minimum MTU of 576 bytes follows RFC 791 (IPv4 minimum reassembly buffer).
This ensures that even the smallest conforming IP implementation can process
tunnel packets without fragmentation at the tunnel layer.

## 7. Tunnel Record

`ac_vpn_tunnel_t` stores: local_pubkey (32B), remote_pubkey (32B), protocol (1B),
endpoint (34B), allowed_ips (16×34B), state (1B), listen_port (2B), mtu (2B),
keepalive (1B), nat_hint (1B), tx_bytes (8B), rx_bytes (8B), rekey_count (1B),
created_block (4B), last_hsk (8B, monotonic timestamp).

## 8. Stale Tunnel Pruning

`ac_vpn_prune_stale()` scans all tunnel records:
- **KEYED**: If handshake timeout (30 s) exceeded → CLOSED.
- **REKEYING**: If `rekey_count ≥ 3` → ERROR.
- **CLOSED / ERROR**: Eligible for slot reclamation.

## 9. Key Zeroization

All VPN key material is zeroized on tunnel destruction via `ac_crypto_zeroize()`.
Key material MUST NOT persist after transition to CLOSED or ERROR.

## 10. NAT Traversal

The `nat_hint` flag indicates the node is behind NAT. Peers SHOULD use the
handshake source address as the actual endpoint and enable persistent keepalive.

## 11. Concurrency

VPN operations acquire `vpn_lock` (priority 5 in lock ordering:
chain > claim > subnet > partition > vpn > discover).
Traffic counters MAY use atomic operations without holding the lock.

## 12. Security Considerations

- **Key binding**: VPN keys bound to Ed25519 identities via chain signatures.
- **Forward secrecy**: POOL uses ephemeral X25519; WireGuard/IPsec provide their own.
- **DoS prevention**: Rate limiting (20 tx / 10 blocks) prevents key flooding.
- **Replay protection**: Nonce monotonicity prevents replaying old transactions.
