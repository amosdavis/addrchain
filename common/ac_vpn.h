/*
 * ac_vpn.h — VPN state machine interface
 *
 * Protocol-agnostic VPN tunnel lifecycle: IDLE → KEYED → ACTIVE → CLOSED.
 * Validates VPN_KEY and VPN_TUNNEL transactions against chain state.
 * Platform-specific tunnel setup is in ac_linux_vpn.c / ac_win_vpn.c / ac_darwin_vpn.c.
 *
 * Mitigates: K42,K43,K44,K45,N25,N26,N27,N28,P28,P29,P30,P31,P32,P33,P34
 */

#ifndef AC_VPN_H
#define AC_VPN_H

#include "ac_proto.h"
#include "ac_platform.h"

/* ------------------------------------------------------------------ */
/*  Limits                                                             */
/* ------------------------------------------------------------------ */

#define AC_MAX_VPN_TUNNELS      128
#define AC_VPN_HANDSHAKE_TIMEOUT_SEC  30
#define AC_VPN_KEEPALIVE_INTERVAL_SEC 25
#define AC_VPN_MAX_REKEY_ATTEMPTS     3

/* ------------------------------------------------------------------ */
/*  Tunnel state machine                                               */
/* ------------------------------------------------------------------ */

typedef enum {
    AC_VPN_STATE_IDLE      = 0,  /* no keys exchanged */
    AC_VPN_STATE_KEYED     = 1,  /* VPN_KEY published, awaiting tunnel */
    AC_VPN_STATE_ACTIVE    = 2,  /* tunnel established, traffic flowing */
    AC_VPN_STATE_REKEYING  = 3,  /* re-keying in progress */
    AC_VPN_STATE_CLOSED    = 4,  /* torn down */
    AC_VPN_STATE_ERROR     = 5,  /* unrecoverable error */
} ac_vpn_state_t;

/* ------------------------------------------------------------------ */
/*  Tunnel record                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    /* Identity */
    uint8_t         local_pubkey[AC_PUBKEY_LEN];
    uint8_t         remote_pubkey[AC_PUBKEY_LEN];

    /* VPN parameters */
    uint8_t         vpn_proto;          /* ac_vpn_proto_t */
    uint8_t         vpn_pubkey[AC_PUBKEY_LEN]; /* WG/IKE public key */
    ac_address_t    endpoint;           /* remote endpoint address */
    uint16_t        listen_port;
    ac_address_t    allowed_ips[AC_MAX_VPN_ALLOWED_IPS];
    uint8_t         allowed_ip_count;
    uint16_t        mtu;
    uint8_t         persistent_keepalive;
    uint8_t         nat_hint;

    /* State */
    ac_vpn_state_t  state;
    uint64_t        created_at;         /* unix timestamp */
    uint64_t        last_handshake;     /* unix timestamp */
    uint64_t        bytes_tx;
    uint64_t        bytes_rx;
    uint8_t         rekey_attempts;
    uint32_t        block_registered;   /* block that registered this tunnel */

    uint8_t         active;             /* 1 = allocated slot */
} ac_vpn_tunnel_t;

/* ------------------------------------------------------------------ */
/*  VPN store                                                          */
/* ------------------------------------------------------------------ */

typedef struct {
    ac_vpn_tunnel_t tunnels[AC_MAX_VPN_TUNNELS];
    uint32_t        tunnel_count;
    ac_mutex_t      lock;
} ac_vpn_store_t;

/* ------------------------------------------------------------------ */
/*  API                                                                */
/* ------------------------------------------------------------------ */

int ac_vpn_init(ac_vpn_store_t *vs);
void ac_vpn_destroy(ac_vpn_store_t *vs);

/*
 * ac_vpn_validate_block — Validate all VPN txs in a block.
 * Does not modify state.
 */
int ac_vpn_validate_block(ac_vpn_store_t *vs, const ac_block_t *blk);

/*
 * ac_vpn_apply_block — Apply validated VPN txs to state.
 */
int ac_vpn_apply_block(ac_vpn_store_t *vs, const ac_block_t *blk);

/*
 * ac_vpn_find — Find tunnel by remote pubkey.
 * Returns pointer or NULL.
 */
const ac_vpn_tunnel_t *ac_vpn_find(const ac_vpn_store_t *vs,
                                    const uint8_t remote_pubkey[AC_PUBKEY_LEN]);

/*
 * ac_vpn_find_by_proto — Find tunnel by remote pubkey and protocol.
 */
const ac_vpn_tunnel_t *ac_vpn_find_by_proto(
    const ac_vpn_store_t *vs,
    const uint8_t remote_pubkey[AC_PUBKEY_LEN],
    uint8_t vpn_proto);

/*
 * ac_vpn_transition — Advance tunnel state machine.
 * Returns AC_OK if transition is valid, AC_ERR_INVAL if not.
 */
int ac_vpn_transition(ac_vpn_store_t *vs,
                      const uint8_t remote_pubkey[AC_PUBKEY_LEN],
                      ac_vpn_state_t new_state);

/*
 * ac_vpn_mark_handshake — Record a successful handshake.
 */
void ac_vpn_mark_handshake(ac_vpn_store_t *vs,
                           const uint8_t remote_pubkey[AC_PUBKEY_LEN],
                           uint64_t now);

/*
 * ac_vpn_update_traffic — Update traffic counters.
 */
void ac_vpn_update_traffic(ac_vpn_store_t *vs,
                           const uint8_t remote_pubkey[AC_PUBKEY_LEN],
                           uint64_t tx_bytes, uint64_t rx_bytes);

/*
 * ac_vpn_prune_stale — Close tunnels with no handshake within timeout.
 */
void ac_vpn_prune_stale(ac_vpn_store_t *vs, uint64_t now);

/*
 * ac_vpn_count — Number of active (non-CLOSED) tunnels.
 */
uint32_t ac_vpn_count(const ac_vpn_store_t *vs);

/*
 * ac_vpn_rebuild — Rebuild VPN state from chain.
 */
int ac_vpn_rebuild(ac_vpn_store_t *vs,
                   const ac_block_t *blocks,
                   uint32_t block_count);

#endif /* AC_VPN_H */
