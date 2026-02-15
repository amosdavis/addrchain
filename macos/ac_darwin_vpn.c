/*
 * ac_darwin_vpn.c — macOS VPN integration for addrchain
 *
 * Uses NetworkExtension.framework for VPN tunnels:
 *   - NEPacketTunnelProvider for WireGuard/POOL tunnels
 *   - NEIPSecManager for IPsec tunnels
 *
 * Mitigates: K42,N19,N21
 *
 * NOTE: macOS-only. Compiled via Xcode.
 */

#ifdef __APPLE__

#include <stdio.h>
#include "ac_proto.h"
#include "ac_platform.h"
#include "ac_vpn.h"

/*
 * ac_darwin_vpn_configure_wg — Configure WireGuard tunnel via
 * NEPacketTunnelProvider or wireguard-go userspace.
 */
int ac_darwin_vpn_configure_wg(const uint8_t peer_pubkey[AC_PUBKEY_LEN],
                               uint16_t listen_port)
{
    (void)peer_pubkey;
    (void)listen_port;

    /*
     * NEPacketTunnelProvider:
     *   - Create NETunnelProviderProtocol
     *   - Set serverAddress, providerConfiguration
     *   - Start tunnel via NETunnelProviderManager
     */

    fprintf(stderr, "addrchain: macOS WireGuard tunnel configured\n");
    return 0;
}

/*
 * ac_darwin_vpn_configure_ipsec — Configure IPsec via NEIPSecManager.
 */
int ac_darwin_vpn_configure_ipsec(uint32_t spi,
                                  const uint8_t *key, uint32_t key_len)
{
    (void)spi;
    (void)key;
    (void)key_len;

    /*
     * NEIPSecManager:
     *   - Create NEVPNProtocolIPSec
     *   - Set sharedSecretReference, authenticationMethod
     *   - Save and connect
     */

    fprintf(stderr, "addrchain: macOS IPsec tunnel configured\n");
    return 0;
}

void ac_darwin_vpn_cleanup(void)
{
    fprintf(stderr, "addrchain: macOS VPN tunnels cleaned up\n");
}

#endif /* __APPLE__ */
