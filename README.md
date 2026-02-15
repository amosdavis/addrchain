# addrchain

A minimal blockchain for self-assignable network addresses. Replaces DHCP or static addressing on a LAN with a decentralized, tamper-evident ledger.

## How It Works

Nodes on a LAN broadcast their presence via UDP and synchronize a blockchain over TCP. Each node has an Ed25519 keypair (auto-generated, persisted to `~/.addrchain/key`). To claim a network address, a node signs a CLAIM transaction and adds it to the chain. Conflicts are resolved first-come-first-served with longest-chain-wins.

**Transaction types:** CLAIM, RELEASE, RENEW, REVOKE

**Consensus:** None — FCFS with longest-chain-wins tiebreaker (lowest block hash for equal-length chains).

**Lease model:** Claims expire after 100 blocks unless renewed. Nodes auto-renew every 30 seconds.

## Build

```
go build ./cmd/addrchain
```

## Usage

Start a node:
```
addrchain serve
addrchain serve --port 9877 --udp-port 9876
addrchain serve --peer 192.168.1.10:9877 --peer 192.168.1.11:9877
```

Claim an address:
```
addrchain claim 192.168.1.100
addrchain claim fe80::1
addrchain claim aa:bb:cc:dd:ee:ff
```

Release an address:
```
addrchain release 192.168.1.100
```

List all claimed addresses:
```
addrchain list
```

Show node status:
```
addrchain status
```

Revoke a compromised key (migrates all claims to a new identity):
```
addrchain revoke
```

## Protocol

- **UDP port 9876**: Peer discovery (JSON broadcast every 5s)
- **TCP port 9877**: Chain sync and block propagation (JSON over TCP)
- **Message types**: `REQUEST_CHAIN`, `SEND_CHAIN`, `NEW_BLOCK`
- **Max message size**: 1 MB

## Security

- Ed25519 signatures on every transaction (NodeID = public key)
- Replay protection via per-node monotonic sequence numbers
- Rate limiting: max 10 claims per node per 50 blocks
- Key persistence with restricted file permissions (0600)
- Key revocation with claim migration (REVOKE transaction)
- Malformed message resilience (size limits, JSON validation, panic recovery)

## Tests

```
go test -v ./...
```

Includes unit tests and BDD tests (Cucumber/godog) covering:
- Address claiming, releasing, renewal
- Conflict detection (simultaneous claims)
- Chain synchronization (longest-chain-wins, partition recovery)
- Lease expiry and renewal
- Key revocation and claim migration
- Rate limiting enforcement
- Malformed message resilience
- Rollback detection

## Chain Size

- **Minimum chain**: ~400 bytes (genesis + 1 claim)
- **Per additional claim**: ~200 bytes
- **Zero external dependencies** for core (godog for BDD tests only)
