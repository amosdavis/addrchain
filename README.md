# addrchain

A blockchain-based network address management system that replaces DHCP with a
decentralized, tamper-evident ledger. Nodes self-assign IPv4, IPv6, or POOL
256-bit addresses and synchronize claims over a peer-to-peer blockchain.

> **Status:** Linux kernel module and userspace tools are implemented. Windows
> NDIS filter driver (Phase 6) and macOS System Extension (Phase 7) are planned.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        User Space                                │
│                                                                  │
│   ┌──────────┐    ┌──────────────────────────────────────────┐   │
│   │ addrctl  │───▶│  addrd  (userspace daemon)               │   │
│   │  (CLI)   │    │  ├─ chain sync   (TCP :9877)             │   │
│   └──────────┘    │  ├─ VPN negotiation (X25519)             │   │
│                   │  ├─ peer discovery (UDP broadcast)       │   │
│                   │  └─ POOL bridge orchestration            │   │
│                   └──────────────┬───────────────────────────┘   │
│                                  │ netlink / ioctl               │
├──────────────────────────────────┼───────────────────────────────┤
│                        Kernel Space                              │
│                                  │                               │
│   ┌──────────────────────────────▼───────────────────────────┐   │
│   │  addrchain.ko  (Linux kernel module)                     │   │
│   │  ├─ ac_main.c         module lifecycle                   │   │
│   │  ├─ ac_netdev.c       netdevice hooks, ARP guard         │   │
│   │  ├─ ac_netlink.c      user↔kernel messaging              │   │
│   │  ├─ ac_sysinfo.c      /proc & sysfs status               │   │
│   │  ├─ ac_linux_crypto.c Ed25519 + SHA-256 (kernel API)     │   │
│   │  ├─ ac_linux_vpn.c    in-kernel VPN datapath             │   │
│   │  └─ ac_pool_bridge.c  POOL 256-bit address bridge        │   │
│   └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│   ┌──────────────┐  ┌──────────────┐                             │
│   │ addrchain.sys│  │ addrchain    │                             │
│   │ (Win NDIS)   │  │ .kext (macOS)│   ← planned                │
│   └──────────────┘  └──────────────┘                             │
└──────────────────────────────────────────────────────────────────┘
```

## Features

- **Decentralized addressing** — no DHCP server required
- **IPv4, IPv6, and POOL** — 256-bit POOL addresses with optional pool.ko bridge
- **Blockchain consensus** — FCFS with longest-chain-wins; lowest hash tiebreaker
- **Ed25519 identity** — every node has an auto-generated keypair (TweetNaCl)
- **Subnet management** — gateway + DNS required at creation (explicit opt-out only)
- **Partition tolerance** — chain sync recovers automatically after network splits
- **VPN transport** — X25519 key agreement, encrypted peer tunnels
- **ARP guard** — always-on for managed interfaces; prevents spoofing
- **Lease model** — claims expire after 100 blocks unless renewed (auto-renew 30 s)
- **Safe mode** — boot parameter `addrchain.disabled=1` disables the kernel module
- **Failure coverage** — 182 identified failure modes, 100% covered by implementation

## Project Structure

```
addrchain/
├── common/          Platform-independent C: chain engine, claims, subnets,
│                    partitions, VPN, discovery, crypto (Ed25519 + SHA-256)
├── linux/           Linux kernel module (.ko)
│   ├── ac_main.c          Module lifecycle
│   ├── ac_netdev.c        Netdevice hooks, ARP guard
│   ├── ac_netlink.c       Netlink messaging
│   ├── ac_sysinfo.c       /proc and sysfs status
│   ├── ac_linux_crypto.c  Kernel crypto (Ed25519, SHA-256)
│   ├── ac_linux_vpn.c     In-kernel VPN datapath
│   └── ac_pool_bridge.c   POOL 256-bit bridge
├── windows/         Windows NDIS filter driver (Phase 6 — planned)
├── macos/           macOS System Extension (Phase 7 — planned)
├── daemon/          Userspace daemon (addrd)
│   ├── addrd.c            Entry point
│   ├── addrd_sync.c       Chain synchronization
│   └── addrd_vpn.c        VPN orchestration
├── cli/             CLI tool (addrctl)
│   └── addrctl.c
├── tests/           84 C unit tests + BDD Cucumber/godog features
├── spec/            Protocol specifications
│   ├── PROTOCOL.md
│   ├── ADDRESSING.md
│   ├── SUBNETTING.md
│   ├── VPN.md
│   └── PARTITIONING.md
├── go/              Original Go v1 prototype (preserved)
├── Kbuild           Kernel build integration
└── Makefile         Top-level build
```

## Build

### Unit Tests

**Linux:**
```bash
gcc -Wall -Wextra -Werror -std=c11 -O2 \
    -o tests/<test>.exe tests/<test>.c common/*.c -I common
```

**Windows:**
```cmd
gcc -Wall -Wextra -Werror -std=c11 -O2 ^
    -o tests\<test>.exe tests\<test>.c common\*.c -I common -ladvapi32
```

### CLI (`addrctl`)

```bash
gcc -Wall -Wextra -Werror -std=c11 -O2 \
    -o cli/addrctl cli/addrctl.c common/*.c -I common
```

### Daemon (`addrd`)

**Linux:**
```bash
gcc -Wall -Wextra -Werror -std=c11 -O2 \
    -o daemon/addrd daemon/addrd.c daemon/addrd_sync.c daemon/addrd_vpn.c \
    common/*.c -I common -lpthread
```

**Windows:**
```cmd
gcc -Wall -Wextra -Werror -std=c11 -O2 ^
    -o daemon\addrd.exe daemon\addrd.c daemon\addrd_sync.c daemon\addrd_vpn.c ^
    common\*.c -I common -lws2_32
```

### Kernel Module

Requires Linux kernel headers (kernel 5.15+):

```bash
cd addrchain && make
```

### BDD Tests

```bash
cd tests && go test -v -run TestFeatures
```

## Usage

### CLI (`addrctl`)

```bash
# Show node status (chain height, identity, peers, addresses)
addrctl status

# Claim an address
addrctl claim 192.168.1.100
addrctl claim fe80::1
addrctl claim pool://00aabbcc...   # POOL 256-bit

# Release an address
addrctl release 192.168.1.100

# Create a subnet (gateway and DNS are required)
addrctl subnet create 10.0.0.0/24 --gateway 10.0.0.1 --dns 10.0.0.2

# List subnets
addrctl subnet list

# Show discovered peers
addrctl peers

# Show local node identity (Ed25519 public key)
addrctl identity
```

### Daemon (`addrd`)

```bash
# Start with defaults
addrd

# Custom configuration
addrd --config-dir /etc/addrchain \
      --sync-port 9877 \
      --peer 192.168.1.10:9877 \
      --peer 192.168.1.11:9877

# Require POOL bridge (fail-fast if pool.ko is not loaded)
addrd --pool-required

# Disable TLS for testing (NOT for production)
addrd --insecure
```

## Protocol

| Transport | Port | Purpose                              |
|-----------|------|--------------------------------------|
| UDP       | 9876 | Peer discovery (broadcast every 5 s) |
| TCP       | 9877 | Chain sync and block propagation     |

**Transaction types:** `CLAIM`, `RELEASE`, `RENEW`, `REVOKE`

**Consensus:** FCFS with longest-chain-wins. Equal-length chains are resolved by
lowest block hash.

See [spec/PROTOCOL.md](spec/PROTOCOL.md) for the full wire format.

## Security

- **Ed25519** signatures on every transaction (NodeID = public key)
- **X25519** key agreement for VPN and POOL transport encryption
- Replay protection via per-node monotonic sequence numbers
- Rate limiting: max 10 claims per node per 50 blocks
- Key persistence with restricted file permissions (`0600`)
- Key revocation with automatic claim migration (`REVOKE` transaction)
- ARP guard always enabled for managed interfaces
- Malformed message resilience (size limits, validation, panic recovery)

## Design Decisions

1. **C for kernel modules** — direct kernel API access; Go v1 prototype preserved
   in `go/` for reference.
2. **Ed25519 for chain identity, X25519 for POOL transport** — separate signing
   and encryption keys.
3. **pool.ko is optional** for IPv4/IPv6 but **required** if POOL addresses are
   configured (fail-fast).
4. **Gateway + DNS required** for subnet creation — explicit opt-out only to
   prevent misconfigured subnets.
5. **ARP guard always on** for managed interfaces — no configuration to disable.
6. **Boot parameter `addrchain.disabled=1`** — safe mode that prevents the kernel
   module from initializing.

## Failure Analysis

182 identified failure modes across five categories:

| Category              | Count | Examples                                |
|-----------------------|-------|-----------------------------------------|
| Kernel module         |    48 | Module load, netdev hooks, crypto init  |
| Networking config     |    39 | ARP guard, DHCP conflict, MTU mismatch  |
| POOL protocol         |    50 | Bridge init, 256-bit routing, key agree |
| Blockchain            |    26 | Fork resolution, partition recovery     |
| Real-world incidents  |    19 | Power loss, disk full, clock skew       |

All 182 failure modes are covered by the current implementation.

## Tests

- **84 C unit tests** covering chain engine, claims, subnets, partitions, VPN,
  discovery, and crypto.
- **BDD Cucumber/godog features** for integration-level scenarios.

```bash
# Run all C unit tests (example for a single test on Linux)
gcc -Wall -Wextra -Werror -std=c11 -O2 \
    -o tests/test_chain tests/test_chain.c common/*.c -I common && \
    ./tests/test_chain

# Run BDD tests
cd tests && go test -v -run TestFeatures
```

## Specifications

| Document                                     | Description              |
|----------------------------------------------|--------------------------|
| [PROTOCOL.md](spec/PROTOCOL.md)              | Wire protocol format     |
| [ADDRESSING.md](spec/ADDRESSING.md)          | Address types and claims |
| [SUBNETTING.md](spec/SUBNETTING.md)          | Subnet management        |
| [VPN.md](spec/VPN.md)                        | VPN transport            |
| [PARTITIONING.md](spec/PARTITIONING.md)      | Network partitions       |

## License

To be determined.

## Links

- **GitHub:** <https://github.com/amosdavis/addrchain>
