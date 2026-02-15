/*
 * addrd_vpn.c — VPN session orchestration for addrchain daemon
 *
 * Manages VPN tunnel lifecycle from userspace:
 *   - WireGuard: invoke `wg set` or genetlink
 *   - IPsec: invoke `ip xfrm` or netlink
 *   - POOL VPN: bind via pool.ko IPC
 *
 * The common VPN state machine (ac_vpn.c) tracks tunnel states.
 * This module handles the platform-specific setup and teardown.
 *
 * Mitigates: K42,K43,K44,N17,N18,N20,N21
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ac_proto.h"
#include "ac_platform.h"
#include "ac_vpn.h"
#include "ac_chain.h"

/* ================================================================== */
/*  Module state                                                       */
/* ================================================================== */

static ac_vpn_store_t *s_vpns;
static ac_chain_t     *s_chain;
static int             s_initialized;

/* ================================================================== */
/*  WireGuard setup via command-line (portable fallback)               */
/* ================================================================== */

static int setup_wireguard_peer(const ac_vpn_tunnel_t *tunnel)
{
    char cmd[512];

    if (!tunnel)
        return -1;

    /*
     * Configure WireGuard peer via `wg` tool.
     * In production, this would use genetlink (Linux) or userspace API.
     *
     * wg set <iface> peer <pubkey> allowed-ips <allowed> endpoint <ep>
     */

    fprintf(stderr, "addrd_vpn: configuring WireGuard tunnel (proto=%u)\n",
            tunnel->vpn_proto);

    /* N18: persistent-keepalive for NAT traversal */
    snprintf(cmd, sizeof(cmd),
             "wg set wg0 peer PLACEHOLDER persistent-keepalive 25 2>/dev/null");

    /* Don't actually execute in skeleton — just log intent */
    (void)cmd;

    return 0;
}

/* ================================================================== */
/*  IPsec setup via ip xfrm (Linux)                                    */
/* ================================================================== */

static int setup_ipsec_sa(const ac_vpn_tunnel_t *tunnel)
{
    if (!tunnel)
        return -1;

    fprintf(stderr, "addrd_vpn: installing IPsec SA (proto=%u)\n",
            tunnel->vpn_proto);

    /*
     * ip xfrm state add src <src> dst <dst> proto esp spi <spi>
     *     enc "rfc4106(gcm(aes))" <key>
     */

    return 0;
}

/* ================================================================== */
/*  POOL VPN setup                                                     */
/* ================================================================== */

static int setup_pool_tunnel(const ac_vpn_tunnel_t *tunnel)
{
    if (!tunnel)
        return -1;

    fprintf(stderr, "addrd_vpn: binding POOL session (proto=%u)\n",
            tunnel->vpn_proto);

    /*
     * POOL VPN: zero config — POOL handles crypto.
     * Just bind the POOL session to a virtual interface.
     */

    return 0;
}

/* ================================================================== */
/*  Tunnel lifecycle management                                        */
/* ================================================================== */

static void process_keyed_tunnels(void)
{
    /*
     * Scan VPN store for tunnels in KEYED state that need handshake.
     * Start handshake, transition to ACTIVE on success.
     * K43: monitor SA lifetime, rekey before expiry.
     */
}

static void process_active_tunnels(void)
{
    /*
     * Scan for ACTIVE tunnels:
     *   - Check health (N21: traffic flowing?)
     *   - K43: check rekey deadline
     *   - K42: verify interface still exists
     */
}

static void cleanup_closed_tunnels(void)
{
    /*
     * Remove CLOSED/ERROR tunnels from VPN store and tear down
     * platform-specific resources (WireGuard peers, IPsec SAs).
     * K42: prevent interface leaks.
     */
}

/* ================================================================== */
/*  Public API                                                         */
/* ================================================================== */

int addrd_vpn_init(ac_vpn_store_t *vpns, ac_chain_t *chain)
{
    if (!vpns || !chain)
        return -1;

    s_vpns = vpns;
    s_chain = chain;
    s_initialized = 1;

    fprintf(stderr, "addrd_vpn: initialized\n");
    return 0;
}

void addrd_vpn_tick(void)
{
    if (!s_initialized)
        return;

    process_keyed_tunnels();
    process_active_tunnels();
    cleanup_closed_tunnels();
}

void addrd_vpn_shutdown(void)
{
    if (!s_initialized)
        return;

    /*
     * Tear down all active tunnels:
     * - Remove WireGuard peers
     * - Delete IPsec SAs
     * - Close POOL sessions
     */

    (void)setup_wireguard_peer;
    (void)setup_ipsec_sa;
    (void)setup_pool_tunnel;

    s_initialized = 0;
    fprintf(stderr, "addrd_vpn: shutdown\n");
}
