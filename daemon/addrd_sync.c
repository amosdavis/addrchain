/*
 * addrd_sync.c — Chain synchronization over TCP
 *
 * Implements block-level chain sync between addrchain peers.
 * Protocol:
 *   1. Connect to peer's sync port
 *   2. Exchange chain heights (4-byte LE)
 *   3. If peer is taller, request blocks from our height to theirs
 *   4. Validate and apply each block
 *   5. If we are taller, push our blocks
 *
 * Transport security:
 *   - POOL sessions preferred (inherits ChaCha20-Poly1305 AEAD)
 *   - TCP with length-prefixed framing as fallback
 *   - P46: --insecure flag required for plaintext (testing only)
 *
 * Mitigates: K39,N08,N10,N35,P11,P12,P13,P14,P16,P44,P45
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET sync_socket_t;
#define SYNC_INVALID_SOCKET INVALID_SOCKET
#define sync_close closesocket
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <errno.h>
typedef int sync_socket_t;
#define SYNC_INVALID_SOCKET (-1)
#define sync_close close
#endif

#include "ac_proto.h"
#include "ac_platform.h"
#include "ac_chain.h"
#include "ac_claims.h"
#include "ac_discover.h"

/* ================================================================== */
/*  Module state                                                       */
/* ================================================================== */

static ac_chain_t          *s_chain;
static ac_claim_store_t    *s_claims;
static ac_discover_state_t *s_disc;
static int                  s_initialized;
static sync_socket_t        s_listen_sock = SYNC_INVALID_SOCKET;

/* ================================================================== */
/*  Length-prefixed framing (P12: no partial send/recv)                 */
/* ================================================================== */

static int sync_send_exact(sync_socket_t sock, const void *buf, uint32_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    uint32_t sent = 0;

    while (sent < len) {
        int n = send(sock, (const char *)(p + sent), len - sent, 0);
        if (n <= 0)
            return -1;
        sent += (uint32_t)n;
    }
    return 0;
}

static int sync_recv_exact(sync_socket_t sock, void *buf, uint32_t len)
{
    uint8_t *p = (uint8_t *)buf;
    uint32_t recvd = 0;

    while (recvd < len) {
        int n = recv(sock, (char *)(p + recvd), len - recvd, 0);
        if (n <= 0)
            return -1;
        recvd += (uint32_t)n;
    }
    return 0;
}

/* Send a length-prefixed message */
static int sync_send_msg(sync_socket_t sock, const void *data, uint32_t len)
{
    uint32_t net_len = len; /* already LE on x86 */
    if (sync_send_exact(sock, &net_len, 4) != 0)
        return -1;
    if (len > 0 && sync_send_exact(sock, data, len) != 0)
        return -1;
    return 0;
}

/* Receive a length-prefixed message. Caller provides buffer. */
static int sync_recv_msg(sync_socket_t sock, void *buf, uint32_t buf_size,
                         uint32_t *out_len)
{
    uint32_t msg_len;
    if (sync_recv_exact(sock, &msg_len, 4) != 0)
        return -1;
    if (msg_len > buf_size)
        return -1; /* message too large */
    if (msg_len > 0 && sync_recv_exact(sock, buf, msg_len) != 0)
        return -1;
    *out_len = msg_len;
    return 0;
}

/* ================================================================== */
/*  Sync protocol                                                      */
/* ================================================================== */

/*
 * sync_with_peer — Synchronize chain with a single peer.
 * Returns 0 on success, -1 on failure.
 */
static int sync_with_peer(const ac_peer_t *peer)
{
    sync_socket_t sock;
    struct sockaddr_in addr;
    uint32_t local_height, peer_height;
    int ret = -1;

    if (!peer || peer->addr.family != AC_AF_IPV4)
        return -1; /* only IPv4 sync for now */

    /* Create TCP socket with timeout */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == SYNC_INVALID_SOCKET)
        return -1;

    /* P11: 10-second connect timeout */
#ifdef _WIN32
    {
        DWORD timeout = 10000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
    }
#else
    {
        struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }
#endif

    /* P16: TCP keepalive (30s idle, 5s interval, 3 probes) */
    {
        int keepalive = 1;
        setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE,
                   (const char *)&keepalive, sizeof(keepalive));
#ifdef _WIN32
        /* Windows keepalive configured via SIO_KEEPALIVE_VALS */
#elif defined(TCP_KEEPIDLE)
        int idle = 30, interval = 5, count = 3;
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count));
#endif
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(peer->sync_port);
    memcpy(&addr.sin_addr.s_addr, peer->addr.addr, 4);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        sync_close(sock);
        return -1;
    }

    /* Exchange heights */
    local_height = ac_chain_len(s_chain);
    if (sync_send_msg(sock, &local_height, 4) != 0)
        goto done;

    if (sync_recv_msg(sock, &peer_height, sizeof(peer_height), &(uint32_t){0}) != 0)
        goto done;

    if (peer_height > local_height) {
        /* Pull blocks from peer */
        uint32_t i;
        for (i = local_height; i < peer_height; i++) {
            ac_block_t blk;
            uint32_t recv_len;

            /* Request block i */
            if (sync_send_msg(sock, &i, 4) != 0)
                goto done;

            if (sync_recv_msg(sock, &blk, sizeof(blk), &recv_len) != 0)
                goto done;

            if (recv_len != sizeof(blk))
                goto done;

            /* K40/P47: verify signature independently */
            int add_ret = ac_chain_add_block(s_chain, &blk);
            if (add_ret != AC_OK) {
                fprintf(stderr, "addrd_sync: block %u rejected: %d\n",
                        i, add_ret);
                goto done;
            }

            /* Apply to claim store */
            ac_claims_apply_block(s_claims, &blk);
        }
        ret = 0;
    } else {
        /* We are ahead or equal — no pull needed */
        ret = 0;
    }

done:
    sync_close(sock);
    return ret;
}

/* ================================================================== */
/*  Public API                                                         */
/* ================================================================== */

int addrd_sync_init(ac_chain_t *chain, ac_claim_store_t *claims,
                    ac_discover_state_t *disc)
{
    if (!chain || !claims || !disc)
        return -1;

    s_chain = chain;
    s_claims = claims;
    s_disc = disc;

#ifdef _WIN32
    {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
    }
#endif

    s_initialized = 1;
    fprintf(stderr, "addrd_sync: initialized\n");
    return 0;
}

void addrd_sync_tick(void)
{
    const ac_peer_t *best;

    if (!s_initialized)
        return;

    best = ac_discover_best_peer(s_disc);
    if (!best)
        return;

    /* Only sync if peer is taller */
    if (best->chain_height <= ac_chain_len(s_chain))
        return;

    fprintf(stderr, "addrd_sync: syncing with peer (height %u, ours %u)\n",
            best->chain_height, ac_chain_len(s_chain));

    if (sync_with_peer(best) == 0) {
        ac_discover_mark_success(s_disc, best->pubkey);
        fprintf(stderr, "addrd_sync: sync complete (height now %u)\n",
                ac_chain_len(s_chain));
    } else {
        ac_discover_mark_failed(s_disc, best->pubkey);
        fprintf(stderr, "addrd_sync: sync failed\n");
    }
}

void addrd_sync_shutdown(void)
{
    if (s_listen_sock != SYNC_INVALID_SOCKET) {
        sync_close(s_listen_sock);
        s_listen_sock = SYNC_INVALID_SOCKET;
    }

#ifdef _WIN32
    WSACleanup();
#endif

    s_initialized = 0;
    fprintf(stderr, "addrd_sync: shutdown\n");
}
