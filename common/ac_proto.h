/*
 * ac_proto.h — addrchain wire format, constants, and transaction types
 *
 * Defines the on-wire binary format for blocks and transactions in the
 * addrchain blockchain.  All multi-byte fields are little-endian.
 * Structs are packed for deterministic hashing and cross-platform
 * compatibility (ISO/IEC 9945 alignment-safe via pragma pack).
 *
 * Mitigates: K03 (buffer overflow — BUILD_BUG_ON for struct sizes)
 */

#ifndef AC_PROTO_H
#define AC_PROTO_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <stddef.h>
#endif

/* ------------------------------------------------------------------ */
/*  Version                                                            */
/* ------------------------------------------------------------------ */

#define AC_VERSION_MAJOR    2
#define AC_VERSION_MINOR    0
#define AC_VERSION          ((AC_VERSION_MAJOR << 8) | AC_VERSION_MINOR)

/* ------------------------------------------------------------------ */
/*  Limits                                                             */
/* ------------------------------------------------------------------ */

#define AC_MAX_ADDR_LEN         32      /* 256-bit POOL address        */
#define AC_IPV4_ADDR_LEN        4
#define AC_IPV6_ADDR_LEN        16
#define AC_POOL_ADDR_LEN        32
#define AC_HASH_LEN             32      /* SHA-256                     */
#define AC_SIG_LEN              64      /* Ed25519 signature           */
#define AC_PUBKEY_LEN           32      /* Ed25519 public key          */
#define AC_SUBNET_ID_LEN        32      /* null-terminated subnet name */
#define AC_PARTITION_ID_LEN     32      /* null-terminated partition   */
#define AC_MAX_TX_PER_BLOCK     64
#define AC_MAX_CHAIN_BLOCKS     4096    /* kernel-side pruning limit   */
#define AC_MAX_DNS_ADDRS        4       /* max DNS servers per subnet  */
#define AC_MAX_VPN_ALLOWED_IPS  16      /* max AllowedIPs entries      */

/* Rate limiting: max transactions per node per N blocks */
#define AC_RATE_WINDOW_BLOCKS   10
#define AC_RATE_MAX_TX          20

/* Lease TTL in block count (not wall time — immune to clock skew) */
#define AC_DEFAULT_LEASE_BLOCKS 1000
#define AC_MIN_LEASE_BLOCKS     10
#define AC_MAX_LEASE_BLOCKS     100000
#define AC_RENEW_THRESHOLD_PCT  50      /* auto-renew at 50% remaining */

/* Clock sanity thresholds (seconds) */
#define AC_CLOCK_WARN_DELTA     60
#define AC_CLOCK_ERROR_DELTA    300

/* Network ports */
#define AC_DISCOVERY_PORT       9876    /* UDP discovery               */
#define AC_SYNC_PORT            9877    /* TCP chain sync              */

/* Virtual NIC limits */
#define AC_MAX_VNICS            64

/* ------------------------------------------------------------------ */
/*  Address family                                                     */
/* ------------------------------------------------------------------ */

typedef enum {
    AC_AF_IPV4      = 0x01,
    AC_AF_IPV6      = 0x02,
    AC_AF_POOL      = 0x03,
} ac_addr_family_t;

/* ------------------------------------------------------------------ */
/*  Transaction types                                                  */
/* ------------------------------------------------------------------ */

typedef enum {
    AC_TX_CLAIM         = 0x01,
    AC_TX_RELEASE       = 0x02,
    AC_TX_RENEW         = 0x03,
    AC_TX_REVOKE        = 0x04,
    AC_TX_SUBNET_CREATE = 0x10,
    AC_TX_SUBNET_ASSIGN = 0x11,
    AC_TX_SUBNET_UPDATE = 0x12,
    AC_TX_SUBNET_DELETE = 0x13,
    AC_TX_VPN_TUNNEL    = 0x20,
    AC_TX_VPN_KEY       = 0x21,
    AC_TX_PARTITION     = 0x30,
} ac_tx_type_t;

/* ------------------------------------------------------------------ */
/*  VPN protocol type                                                  */
/* ------------------------------------------------------------------ */

typedef enum {
    AC_VPN_WIREGUARD    = 0x01,
    AC_VPN_IPSEC        = 0x02,
    AC_VPN_POOL         = 0x03,
} ac_vpn_proto_t;

/* ------------------------------------------------------------------ */
/*  Partition action                                                   */
/* ------------------------------------------------------------------ */

typedef enum {
    AC_PART_CREATE      = 0x01,
    AC_PART_DELETE      = 0x02,
    AC_PART_ADD_SUBNET  = 0x03,
    AC_PART_REMOVE_SUBNET = 0x04,
    AC_PART_ALLOW_CROSS = 0x05,     /* allow cross-partition traffic  */
    AC_PART_DENY_CROSS  = 0x06,     /* deny cross-partition traffic   */
} ac_partition_action_t;

/* ------------------------------------------------------------------ */
/*  Subnet flags                                                       */
/* ------------------------------------------------------------------ */

#define AC_SUBNET_FLAG_NO_GATEWAY   0x01    /* explicit --no-gateway   */
#define AC_SUBNET_FLAG_NO_DNS       0x02    /* explicit --no-dns       */

/* ------------------------------------------------------------------ */
/*  SUBNET_UPDATE field bitmask                                        */
/* ------------------------------------------------------------------ */

#define AC_SUBNET_UPD_GATEWAY   0x01    /* gateway field changed   */
#define AC_SUBNET_UPD_DNS       0x02    /* dns/dns_count changed   */
#define AC_SUBNET_UPD_VLAN      0x04    /* vlan_id changed         */
#define AC_SUBNET_UPD_FLAGS     0x08    /* flags changed           */
#define AC_SUBNET_UPD_PREFIX    0x10    /* prefix changed (risky)  */

/* ------------------------------------------------------------------ */
/*  Packed structs — wire format                                       */
/* ------------------------------------------------------------------ */

#pragma pack(push, 1)

/* Unified address: holds any address family */
typedef struct {
    uint8_t     family;                     /* ac_addr_family_t        */
    uint8_t     addr[AC_MAX_ADDR_LEN];      /* right-padded with 0    */
    uint8_t     prefix_len;                 /* CIDR prefix length      */
} ac_address_t;

/* ---- Transaction payloads ---- */

/* CLAIM / RELEASE / RENEW share the same payload */
typedef struct {
    ac_address_t    address;
    uint8_t         subnet_id[AC_SUBNET_ID_LEN];   /* required if subnets exist */
    uint32_t        lease_blocks;                   /* 0 = use default           */
} ac_tx_claim_t;

/* REVOKE: revoke old key, migrate claims to new key */
typedef struct {
    uint8_t     old_pubkey[AC_PUBKEY_LEN];
    uint8_t     new_pubkey[AC_PUBKEY_LEN];
    uint8_t     old_sig[AC_SIG_LEN];        /* old key signs this tx   */
} ac_tx_revoke_t;

/* SUBNET_CREATE: define a new subnet */
typedef struct {
    uint8_t         subnet_id[AC_SUBNET_ID_LEN];
    ac_address_t    prefix;                 /* network + prefix_len    */
    ac_address_t    gateway;                /* REQUIRED unless NO_GATEWAY flag */
    ac_address_t    dns[AC_MAX_DNS_ADDRS];  /* REQUIRED unless NO_DNS flag */
    uint8_t         dns_count;
    uint16_t        vlan_id;                /* 0 = no VLAN mapping     */
    uint8_t         flags;                  /* AC_SUBNET_FLAG_*        */
} ac_tx_subnet_create_t;

/* SUBNET_ASSIGN: assign a node to a subnet */
typedef struct {
    uint8_t     subnet_id[AC_SUBNET_ID_LEN];
    uint8_t     node_pubkey[AC_PUBKEY_LEN];
} ac_tx_subnet_assign_t;

/* SUBNET_UPDATE: modify an existing subnet (S03, S12, S16) */
typedef struct {
    uint8_t         subnet_id[AC_SUBNET_ID_LEN];
    uint8_t         update_mask;            /* AC_SUBNET_UPD_* bitmask */
    ac_address_t    prefix;                 /* new prefix (if UPD_PREFIX)  */
    ac_address_t    gateway;                /* new gateway (if UPD_GATEWAY)*/
    ac_address_t    dns[AC_MAX_DNS_ADDRS];  /* new DNS (if UPD_DNS)       */
    uint8_t         dns_count;
    uint16_t        vlan_id;                /* new VLAN (if UPD_VLAN)     */
    uint8_t         flags;                  /* new flags (if UPD_FLAGS)   */
} ac_tx_subnet_update_t;

/* SUBNET_DELETE: soft-delete a subnet (S04, S16, S18) */
typedef struct {
    uint8_t         subnet_id[AC_SUBNET_ID_LEN];
} ac_tx_subnet_delete_t;

/* VPN_TUNNEL: register a VPN tunnel endpoint */
typedef struct {
    uint8_t         vpn_proto;              /* ac_vpn_proto_t          */
    ac_address_t    endpoint;               /* public IP of tunnel     */
    uint16_t        listen_port;
    ac_address_t    allowed_ips[AC_MAX_VPN_ALLOWED_IPS];
    uint8_t         allowed_ip_count;
    uint16_t        mtu;                    /* 0 = auto-calculate      */
    uint8_t         persistent_keepalive;   /* seconds, 0 = disabled   */
    uint8_t         nat_hint;               /* 1 = behind NAT          */
} ac_tx_vpn_tunnel_t;

/* VPN_KEY: publish a VPN public key */
typedef struct {
    uint8_t     vpn_proto;                  /* ac_vpn_proto_t          */
    uint8_t     vpn_pubkey[AC_PUBKEY_LEN];  /* WG pubkey or IKE identity */
} ac_tx_vpn_key_t;

/* PARTITION: create/modify network partition */
typedef struct {
    uint8_t     partition_id[AC_PARTITION_ID_LEN];
    uint8_t     action;                     /* ac_partition_action_t   */
    uint8_t     target_subnet_id[AC_SUBNET_ID_LEN];    /* for ADD/REMOVE */
    uint8_t     target_partition_id[AC_PARTITION_ID_LEN]; /* for ALLOW/DENY */
    uint16_t    vlan_id;                    /* for CREATE              */
} ac_tx_partition_t;

/* ---- Transaction envelope ---- */

typedef struct {
    uint8_t     type;                       /* ac_tx_type_t            */
    uint8_t     node_pubkey[AC_PUBKEY_LEN]; /* signer identity         */
    uint64_t    timestamp;                  /* unix seconds (info only)*/
    uint32_t    nonce;                      /* replay protection       */

    /*
     * Payload: variable-length, type-dependent.  In the packed wire
     * format the payload immediately follows this header.  We store
     * a fixed-size union for in-memory representation.
     */
    union {
        ac_tx_claim_t           claim;      /* CLAIM, RELEASE, RENEW   */
        ac_tx_revoke_t          revoke;
        ac_tx_subnet_create_t   subnet_create;
        ac_tx_subnet_assign_t   subnet_assign;
        ac_tx_subnet_update_t   subnet_update;
        ac_tx_subnet_delete_t   subnet_delete;
        ac_tx_vpn_tunnel_t      vpn_tunnel;
        ac_tx_vpn_key_t         vpn_key;
        ac_tx_partition_t       partition;
    } payload;

    uint8_t     signature[AC_SIG_LEN];      /* Ed25519(hash(header+payload)) */
} ac_transaction_t;

/* ---- Block ---- */

typedef struct {
    uint32_t        index;                  /* block height            */
    uint64_t        timestamp;              /* unix seconds            */
    uint8_t         prev_hash[AC_HASH_LEN]; /* SHA-256 of prev block  */
    uint8_t         hash[AC_HASH_LEN];      /* SHA-256 of this block  */
    uint16_t        tx_count;
    ac_transaction_t txs[AC_MAX_TX_PER_BLOCK];
} ac_block_t;

#pragma pack(pop)

/* ------------------------------------------------------------------ */
/*  Compile-time size assertions (K03 mitigation)                      */
/* ------------------------------------------------------------------ */

#ifdef __KERNEL__
#define AC_BUILD_BUG_ON(cond) BUILD_BUG_ON(cond)
#else
#define AC_BUILD_BUG_ON(cond) \
    ((void)sizeof(char[1 - 2 * !!(cond)]))
#endif

/* Call from any init function to verify struct packing */
static inline void ac_proto_verify_sizes(void)
{
    AC_BUILD_BUG_ON(sizeof(ac_address_t) != 34);
    AC_BUILD_BUG_ON(AC_HASH_LEN != 32);
    AC_BUILD_BUG_ON(AC_SIG_LEN != 64);
    AC_BUILD_BUG_ON(AC_PUBKEY_LEN != 32);
    AC_BUILD_BUG_ON(AC_MAX_ADDR_LEN != 32);
}

/* ------------------------------------------------------------------ */
/*  Helper: tx type name for logging                                   */
/* ------------------------------------------------------------------ */

static inline const char *ac_tx_type_name(uint8_t type)
{
    switch (type) {
    case AC_TX_CLAIM:           return "CLAIM";
    case AC_TX_RELEASE:         return "RELEASE";
    case AC_TX_RENEW:           return "RENEW";
    case AC_TX_REVOKE:          return "REVOKE";
    case AC_TX_SUBNET_CREATE:   return "SUBNET_CREATE";
    case AC_TX_SUBNET_ASSIGN:   return "SUBNET_ASSIGN";
    case AC_TX_SUBNET_UPDATE:   return "SUBNET_UPDATE";
    case AC_TX_SUBNET_DELETE:   return "SUBNET_DELETE";
    case AC_TX_VPN_TUNNEL:      return "VPN_TUNNEL";
    case AC_TX_VPN_KEY:         return "VPN_KEY";
    case AC_TX_PARTITION:       return "PARTITION";
    default:                    return "UNKNOWN";
    }
}

/* ------------------------------------------------------------------ */
/*  Helper: address family name                                        */
/* ------------------------------------------------------------------ */

static inline const char *ac_af_name(uint8_t family)
{
    switch (family) {
    case AC_AF_IPV4:    return "IPv4";
    case AC_AF_IPV6:    return "IPv6";
    case AC_AF_POOL:    return "POOL";
    default:            return "UNKNOWN";
    }
}

/* ------------------------------------------------------------------ */
/*  POOL 256-bit address structure (within ac_address_t.addr[32])      */
/*                                                                     */
/*  [0..3]   type+version (32 bits)                                    */
/*  [4..11]  organization ID (64 bits)                                 */
/*  [12..19] subnet/segment ID (64 bits)                               */
/*  [20..27] node ID — hash of Ed25519 pubkey (64 bits)                */
/*  [28..31] CRC-32 of bytes [0..27] (32 bits)                         */
/* ------------------------------------------------------------------ */

#define AC_POOL_TYPE_OFFSET     0
#define AC_POOL_TYPE_LEN        4
#define AC_POOL_ORG_OFFSET      4
#define AC_POOL_ORG_LEN         8
#define AC_POOL_SUBNET_OFFSET   12
#define AC_POOL_SUBNET_LEN      8
#define AC_POOL_NODE_OFFSET     20
#define AC_POOL_NODE_LEN        8
#define AC_POOL_CRC_OFFSET      28
#define AC_POOL_CRC_LEN         4

#endif /* AC_PROTO_H */
