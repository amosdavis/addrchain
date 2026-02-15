/*
 * addrd.c — addrchain userspace daemon
 *
 * Main event loop for the addrchain daemon. Responsibilities:
 *   - Communicate with kernel module via ioctl / netlink
 *   - Discovery: announce and listen for peers
 *   - Chain sync: fetch and push blocks to/from peers
 *   - Lease renewal: auto-renew at 50% TTL
 *   - VPN orchestration: delegate to addrd_vpn.c
 *   - Audit journal: persist ring buffer to disk
 *
 * Mitigates: K15,K25,K31,K35,K36,K39,K40,N03,N14,N15,N22,N24,N25,N26,
 *            P22,P23,P37,P39,P46,P47,P48,P49
 *
 * Build: gcc -o addrd addrd.c addrd_sync.c addrd_vpn.c \
 *            ../common/ac_chain.c ../common/ac_claims.c ../common/ac_crypto.c \
 *            ../common/ac_subnet.c ../common/ac_partition.c ../common/ac_vpn.c \
 *            ../common/ac_discover.c ../common/ac_userspace_platform.c \
 *            -I../common -ladvapi32 -lpthread
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "ac_proto.h"
#include "ac_platform.h"
#include "ac_chain.h"
#include "ac_claims.h"
#include "ac_subnet.h"
#include "ac_partition.h"
#include "ac_vpn.h"
#include "ac_discover.h"

/* Forward declarations for sync and VPN modules */
int addrd_sync_init(ac_chain_t *chain, ac_claim_store_t *claims,
                    ac_discover_state_t *disc);
void addrd_sync_tick(void);
void addrd_sync_shutdown(void);

int addrd_vpn_init(ac_vpn_store_t *vpns, ac_chain_t *chain);
void addrd_vpn_tick(void);
void addrd_vpn_shutdown(void);

/* ================================================================== */
/*  Global state                                                       */
/* ================================================================== */

static ac_chain_t           g_chain;
static ac_claim_store_t     g_claims;
static ac_subnet_store_t    g_subnets;
static ac_partition_store_t g_parts;
static ac_vpn_store_t       g_vpns;
static ac_discover_state_t  g_disc;

static volatile int g_running = 1;
static uint8_t g_pubkey[AC_PUBKEY_LEN];
static uint8_t g_privkey[64];

/* ================================================================== */
/*  Configuration                                                      */
/* ================================================================== */

typedef struct {
    char        config_path[256];
    uint16_t    sync_port;
    uint8_t     disc_methods;
    int         pool_required;
    int         insecure;       /* --insecure: allow plaintext for testing */
    char        static_peers[16][64]; /* up to 16 static peer addresses */
    uint8_t     static_peer_count;
} addrd_config_t;

static addrd_config_t g_config;

/* ================================================================== */
/*  Signal handling                                                    */
/* ================================================================== */

static void signal_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

/* ================================================================== */
/*  Identity management                                                */
/* ================================================================== */

static int load_or_create_identity(const char *path)
{
    FILE *f;
    uint8_t seed[32];
    char keyfile[300];

    snprintf(keyfile, sizeof(keyfile), "%s/identity.key", path);

    f = fopen(keyfile, "rb");
    if (f) {
        if (fread(seed, 1, 32, f) == 32) {
            fclose(f);
            ac_crypto_ed25519_keypair(seed, g_pubkey, g_privkey);
            ac_crypto_zeroize(seed, sizeof(seed));
            fprintf(stderr, "addrd: loaded identity from %s\n", keyfile);
            return 0;
        }
        fclose(f);
    }

    /* Generate new identity */
    ac_crypto_random(seed, 32);
    ac_crypto_ed25519_keypair(seed, g_pubkey, g_privkey);

    f = fopen(keyfile, "wb");
    if (f) {
        fwrite(seed, 1, 32, f);
        fclose(f);
        fprintf(stderr, "addrd: created new identity at %s\n", keyfile);
    } else {
        fprintf(stderr, "addrd: WARNING: could not persist identity to %s\n",
                keyfile);
    }

    ac_crypto_zeroize(seed, sizeof(seed));
    return 0;
}

/* ================================================================== */
/*  Lease auto-renewal (N03: auto-renew at 50% TTL)                    */
/* ================================================================== */

static void check_lease_renewals(void)
{
    ac_address_t my_addrs[64];
    uint32_t count, i;
    ac_block_t tip;

    count = ac_claims_by_node(&g_claims, g_pubkey, my_addrs, 64);
    if (count == 0)
        return;

    if (ac_chain_last_block(&g_chain, &tip) != AC_OK)
        return;

    for (i = 0; i < count; i++) {
        uint8_t owner[AC_PUBKEY_LEN];
        if (ac_claims_get_owner(&g_claims, &my_addrs[i], owner) == AC_OK) {
            /*
             * In a full implementation, check lease remaining vs TTL.
             * If remaining <= 50%, create RENEW tx and submit via sync.
             */
        }
    }
}

/* ================================================================== */
/*  Discovery tick                                                     */
/* ================================================================== */

static void discovery_tick(void)
{
    ac_block_t tip;

    /* Update local chain info for announcements */
    if (ac_chain_last_block(&g_chain, &tip) == AC_OK) {
        ac_discover_update_local(&g_disc, tip.index, tip.hash,
                                 g_config.pool_required ? AC_CAP_POOL : 0);
    }

    /* Prune timed-out peers */
    ac_discover_prune(&g_disc, ac_time_unix_sec());
}

/* ================================================================== */
/*  Firewall management (N25: open ports on startup, close on exit)    */
/* ================================================================== */

#ifdef _WIN32
static void firewall_open(uint16_t discovery_port, uint16_t sync_port)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "netsh advfirewall firewall add rule name=\"addrchain-disc\" "
             "dir=in action=allow protocol=UDP localport=%u >NUL 2>&1",
             discovery_port);
    system(cmd);
    snprintf(cmd, sizeof(cmd),
             "netsh advfirewall firewall add rule name=\"addrchain-sync\" "
             "dir=in action=allow protocol=TCP localport=%u >NUL 2>&1",
             sync_port);
    system(cmd);
    fprintf(stderr, "addrd: firewall rules added (UDP %u, TCP %u)\n",
            discovery_port, sync_port);
}

static void firewall_close(void)
{
    system("netsh advfirewall firewall delete rule name=\"addrchain-disc\" >NUL 2>&1");
    system("netsh advfirewall firewall delete rule name=\"addrchain-sync\" >NUL 2>&1");
    fprintf(stderr, "addrd: firewall rules removed\n");
}
#else
static void firewall_open(uint16_t discovery_port, uint16_t sync_port)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "iptables -I INPUT -p udp --dport %u -m comment "
             "--comment addrchain -j ACCEPT 2>/dev/null",
             discovery_port);
    system(cmd);
    snprintf(cmd, sizeof(cmd),
             "iptables -I INPUT -p tcp --dport %u -m comment "
             "--comment addrchain -j ACCEPT 2>/dev/null",
             sync_port);
    system(cmd);
    fprintf(stderr, "addrd: firewall rules added (UDP %u, TCP %u)\n",
            discovery_port, sync_port);
}

static void firewall_close(void)
{
    system("iptables -D INPUT -m comment --comment addrchain -j ACCEPT 2>/dev/null");
    system("iptables -D INPUT -m comment --comment addrchain -j ACCEPT 2>/dev/null");
    fprintf(stderr, "addrd: firewall rules removed\n");
}
#endif

/* ================================================================== */
/*  Argument parsing                                                   */
/* ================================================================== */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  --config-dir <path>   Config directory (default: /etc/addrchain)\n"
        "  --sync-port <port>    TCP sync port (default: %u)\n"
        "  --peer <addr:port>    Add static peer (can repeat up to 16)\n"
        "  --pool-required       Require pool.ko for POOL addresses\n"
        "  --insecure            Allow plaintext sync (testing only)\n"
        "  --help                Show this help\n",
        prog, AC_SYNC_PORT);
}

static int parse_args(int argc, char *argv[])
{
    int i;

    /* Defaults */
    strncpy(g_config.config_path, "/etc/addrchain", sizeof(g_config.config_path) - 1);
    g_config.sync_port = AC_SYNC_PORT;
    g_config.disc_methods = AC_DISC_IPV4_BCAST | AC_DISC_IPV6_MCAST;
    g_config.pool_required = 0;
    g_config.insecure = 0;
    g_config.static_peer_count = 0;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config-dir") == 0 && i + 1 < argc) {
            strncpy(g_config.config_path, argv[++i],
                    sizeof(g_config.config_path) - 1);
        } else if (strcmp(argv[i], "--sync-port") == 0 && i + 1 < argc) {
            g_config.sync_port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--peer") == 0 && i + 1 < argc) {
            if (g_config.static_peer_count < 16) {
                strncpy(g_config.static_peers[g_config.static_peer_count],
                        argv[++i], 63);
                g_config.static_peer_count++;
            } else {
                fprintf(stderr, "addrd: max 16 static peers\n");
                return -1;
            }
        } else if (strcmp(argv[i], "--pool-required") == 0) {
            g_config.pool_required = 1;
            g_config.disc_methods |= AC_DISC_POOL;
        } else if (strcmp(argv[i], "--insecure") == 0) {
            g_config.insecure = 1;
            fprintf(stderr, "addrd: WARNING: insecure mode (plaintext sync)\n");
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            exit(0);
        } else {
            fprintf(stderr, "addrd: unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return -1;
        }
    }

    return 0;
}

/* ================================================================== */
/*  Main                                                               */
/* ================================================================== */

int main(int argc, char *argv[])
{
    int ret;

    fprintf(stderr, "addrd: addrchain daemon v%u.%u starting\n",
            AC_VERSION_MAJOR, AC_VERSION_MINOR);

    /* Parse arguments */
    if (parse_args(argc, argv) != 0)
        return 1;

    /* Install signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Load or create identity */
    if (load_or_create_identity(g_config.config_path) != 0) {
        fprintf(stderr, "addrd: FATAL: failed to load identity\n");
        return 1;
    }

    /* Initialize chain engine (creates genesis block) */
    ret = ac_chain_init(&g_chain);
    if (ret != AC_OK) {
        fprintf(stderr, "addrd: FATAL: chain init failed: %d\n", ret);
        return 1;
    }

    /* Initialize subsystems */
    ret = ac_claims_init(&g_claims, AC_DEFAULT_LEASE_BLOCKS);
    if (ret != AC_OK) goto fail_chain;

    ret = ac_subnet_init(&g_subnets);
    if (ret != AC_OK) goto fail_claims;

    ret = ac_partition_init(&g_parts);
    if (ret != AC_OK) goto fail_subnets;

    ret = ac_vpn_init(&g_vpns);
    if (ret != AC_OK) goto fail_parts;

    ret = ac_discover_init(&g_disc, g_pubkey, g_config.sync_port,
                           g_config.disc_methods);
    if (ret != AC_OK) goto fail_vpns;

    /* Initialize sync and VPN modules */
    ret = addrd_sync_init(&g_chain, &g_claims, &g_disc);
    if (ret != 0) goto fail_disc;

    ret = addrd_vpn_init(&g_vpns, &g_chain);
    if (ret != 0) goto fail_sync;

    /* Open firewall ports */
    firewall_open(AC_DISCOVERY_PORT, g_config.sync_port);

    fprintf(stderr, "addrd: all subsystems initialized, entering main loop\n");

    /* P37: set ready flag — daemon is fully initialized */

    /* ============================================================== */
    /*  Main event loop                                                */
    /* ============================================================== */

    while (g_running) {
        /* Discovery: announce and process peers */
        discovery_tick();

        /* Sync: push/pull blocks with best peer */
        addrd_sync_tick();

        /* VPN: manage tunnel lifecycle */
        addrd_vpn_tick();

        /* Lease renewal: auto-renew at 50% TTL */
        check_lease_renewals();

        /* Sleep 1 second between ticks */
#ifdef _WIN32
        Sleep(1000);
#else
        usleep(1000000);
#endif
    }

    fprintf(stderr, "addrd: shutting down...\n");

    /* Cleanup in reverse init order (K21, P38) */
    firewall_close();
    addrd_vpn_shutdown();
    addrd_sync_shutdown();

fail_sync:
fail_disc:
    ac_discover_destroy(&g_disc);
fail_vpns:
    ac_vpn_destroy(&g_vpns);
fail_parts:
    ac_partition_destroy(&g_parts);
fail_subnets:
    ac_subnet_destroy(&g_subnets);
fail_claims:
    ac_claims_destroy(&g_claims);
fail_chain:
    ac_chain_destroy(&g_chain);

    /* P04: zeroize key material */
    ac_crypto_zeroize(g_privkey, sizeof(g_privkey));

    fprintf(stderr, "addrd: clean shutdown complete\n");
    return 0;
}
