/*
 * ac_discover.h — Autodiscovery protocol interface
 *
 * Layered discovery: POOL multicast, IPv6 link-local multicast,
 * IPv4 subnet broadcast, mDNS. Manages peer table with blockchain-aware
 * priority (highest chain height preferred, LRU eviction).
 *
 * Mitigates: K11,N07,N09,N36,P17,P18,P19,P20,P21
 */

#ifndef AC_DISCOVER_H
#define AC_DISCOVER_H

#include "ac_proto.h"
#include "ac_platform.h"
#include "ac_hashmap.h"

/* ------------------------------------------------------------------ */
/*  Limits                                                             */
/* ------------------------------------------------------------------ */

#define AC_ANNOUNCE_INTERVAL_MS 5000    /* 5 seconds */
#define AC_PEER_TIMEOUT_MS      30000   /* 30 seconds */
#define AC_ANNOUNCE_RATELIMIT_MS 100    /* P18: min interval between sends */

/* Discovery methods (bitmask) */
#define AC_DISC_POOL        0x01    /* POOL multicast 239.253.0.1:9253 */
#define AC_DISC_IPV6_MCAST  0x02    /* ff02::addc:1 UDP 9876 */
#define AC_DISC_IPV4_BCAST  0x04    /* subnet broadcast UDP 9876 */
#define AC_DISC_MDNS        0x08    /* _addrchain._udp.local */
#define AC_DISC_STATIC      0x10    /* --peer CLI flag */

/* ------------------------------------------------------------------ */
/*  Announce payload (sent in discovery messages)                      */
/* ------------------------------------------------------------------ */

#pragma pack(push, 1)

typedef struct {
    uint16_t    version;            /* AC_VERSION */
    uint8_t     node_pubkey[AC_PUBKEY_LEN];
    uint32_t    chain_height;       /* tip block index */
    uint8_t     tip_hash[AC_HASH_LEN]; /* tip block hash */
    uint16_t    sync_port;          /* TCP sync port */
    uint8_t     capabilities;       /* bitmask: POOL, VPN, etc. */
} ac_announce_t;

#pragma pack(pop)

#define AC_CAP_POOL     0x01    /* POOL transport available */
#define AC_CAP_VPN      0x02    /* VPN tunneling available */

/* ------------------------------------------------------------------ */
/*  Peer record                                                        */
/* ------------------------------------------------------------------ */

typedef enum {
    AC_PEER_ACTIVE      = 0x01,
    AC_PEER_UNREACHABLE = 0x02,
    AC_PEER_STATIC      = 0x04,  /* added via --peer, never evicted */
} ac_peer_flags_t;

typedef struct {
    uint8_t     pubkey[AC_PUBKEY_LEN];
    ac_address_t addr;              /* IP address of peer */
    uint16_t    sync_port;
    uint32_t    chain_height;
    uint8_t     tip_hash[AC_HASH_LEN];
    uint8_t     capabilities;
    uint8_t     flags;              /* ac_peer_flags_t bitmask */
    uint64_t    last_seen;          /* timestamp (unix seconds) */
    uint8_t     fail_count;         /* consecutive sync failures */
} ac_peer_t;

/* ------------------------------------------------------------------ */
/*  Discovery state                                                    */
/* ------------------------------------------------------------------ */

typedef struct {
    ac_hashmap_t    peer_map;           /* pubkey -> ac_peer_t* */
    uint32_t        peer_count;
    uint32_t        max_peers;          /* 0 = default (256) */

    uint8_t         local_pubkey[AC_PUBKEY_LEN];
    uint32_t        local_chain_height;
    uint8_t         local_tip_hash[AC_HASH_LEN];
    uint16_t        local_sync_port;
    uint8_t         local_capabilities;

    uint8_t         methods_enabled;    /* bitmask of AC_DISC_* */
    uint64_t        last_announce;      /* timestamp of last send */

    ac_mutex_t      lock;
} ac_discover_state_t;

/* ------------------------------------------------------------------ */
/*  API                                                                */
/* ------------------------------------------------------------------ */

int ac_discover_init(ac_discover_state_t *ds,
                     const uint8_t local_pubkey[AC_PUBKEY_LEN],
                     uint16_t sync_port,
                     uint8_t methods,
                     uint32_t max_peers);

void ac_discover_destroy(ac_discover_state_t *ds);

/*
 * ac_discover_update_local — Update local chain state for announcements.
 */
void ac_discover_update_local(ac_discover_state_t *ds,
                              uint32_t chain_height,
                              const uint8_t tip_hash[AC_HASH_LEN],
                              uint8_t capabilities);

/*
 * ac_discover_build_announce — Build an announce payload to send.
 */
int ac_discover_build_announce(const ac_discover_state_t *ds,
                               ac_announce_t *announce);

/*
 * ac_discover_process_announce — Process a received announce from a peer.
 * Adds or updates the peer in the table.
 * Returns AC_OK if peer was added/updated.
 */
int ac_discover_process_announce(ac_discover_state_t *ds,
                                 const ac_announce_t *announce,
                                 const ac_address_t *peer_addr);

/*
 * ac_discover_add_static_peer — Add a static peer (--peer flag).
 * Static peers are never evicted.
 */
int ac_discover_add_static_peer(ac_discover_state_t *ds,
                                const ac_address_t *addr,
                                uint16_t sync_port);

/*
 * ac_discover_prune — Remove peers not seen within timeout.
 * Does not remove static peers.
 */
void ac_discover_prune(ac_discover_state_t *ds, uint64_t now);

/*
 * ac_discover_best_peer — Get the peer with highest chain height.
 * Returns pointer or NULL if no active peers.
 */
const ac_peer_t *ac_discover_best_peer(const ac_discover_state_t *ds);

/*
 * ac_discover_mark_failed — Record a sync failure for a peer.
 * Marks unreachable after 3 consecutive failures.
 */
void ac_discover_mark_failed(ac_discover_state_t *ds,
                             const uint8_t pubkey[AC_PUBKEY_LEN]);

/*
 * ac_discover_mark_success — Clear failure count for a peer.
 */
void ac_discover_mark_success(ac_discover_state_t *ds,
                              const uint8_t pubkey[AC_PUBKEY_LEN]);

/*
 * ac_discover_peer_count — Number of active (non-unreachable) peers.
 */
uint32_t ac_discover_peer_count(const ac_discover_state_t *ds);

#endif /* AC_DISCOVER_H */
