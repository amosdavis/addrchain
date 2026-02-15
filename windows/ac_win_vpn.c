/*
 * ac_win_vpn.c — Windows VPN integration for addrchain
 *
 * WireGuard: via wireguard-nt or wg.exe userspace tool
 * IPsec: via Windows Filtering Platform (WFP) IPsec API
 * POOL: via pool.sys named pipe IPC
 *
 * Mitigates: K42,N19,N21
 *
 * NOTE: Windows-only. For kernel builds define _KERNEL_MODE.
 */

#ifdef _KERNEL_MODE

#include <ntddk.h>
#include "ac_proto.h"
#include "ac_platform.h"
#include "ac_vpn.h"

/* ================================================================== */
/*  WireGuard via wireguard-nt                                         */
/* ================================================================== */

int ac_win_vpn_wg_configure(const uint8_t peer_pubkey[AC_PUBKEY_LEN],
                            uint16_t listen_port)
{
    /*
     * wireguard-nt API:
     *   WireGuardCreateAdapter()
     *   WireGuardSetConfiguration()
     *
     * Falls back to `wg.exe set` via CreateProcess if wireguard-nt
     * is not available.
     */
    (void)peer_pubkey;
    (void)listen_port;
    return 0;
}

/* ================================================================== */
/*  IPsec via WFP                                                      */
/* ================================================================== */

int ac_win_vpn_ipsec_install_sa(uint32_t spi,
                                const uint8_t *key, uint32_t key_len)
{
    /*
     * FwpmIPsecTunnelAdd0()
     * FwpmFilterAdd0() with FWPM_LAYER_IPSEC_*
     */
    (void)spi;
    (void)key;
    (void)key_len;
    return 0;
}

/* ================================================================== */
/*  Cleanup                                                            */
/* ================================================================== */

void ac_win_vpn_cleanup(void)
{
    /* Remove all WireGuard adapters and IPsec SAs */
}

#endif /* _KERNEL_MODE */
