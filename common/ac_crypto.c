/*
 * ac_crypto.c -- Portable userspace cryptographic primitives for addrchain
 *
 * Self-contained implementations of:
 *   - SHA-256 (FIPS 180-4)
 *   - SHA-512 (TweetNaCl's crypto_hash, used by Ed25519)
 *   - Ed25519 sign/verify (verbatim TweetNaCl, public domain)
 *   - OS-level CSPRNG (CryptGenRandom / /dev/urandom)
 *   - Secure zeroization
 *
 * No external dependencies beyond libc and OS headers.
 */

#include "ac_crypto.h"

#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <stdio.h>
#endif

/* ================================================================== */
/*  SHA-256 (FIPS 180-4)                                               */
/* ================================================================== */

static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t sha256_rotr(uint32_t x, int n)
{
    return (x >> n) | (x << (32 - n));
}

static uint32_t sha256_ch(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (~x & z);
}

static uint32_t sha256_maj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

static uint32_t sha256_sigma0(uint32_t x)
{
    return sha256_rotr(x, 2) ^ sha256_rotr(x, 13) ^ sha256_rotr(x, 22);
}

static uint32_t sha256_sigma1(uint32_t x)
{
    return sha256_rotr(x, 6) ^ sha256_rotr(x, 11) ^ sha256_rotr(x, 25);
}

static uint32_t sha256_gamma0(uint32_t x)
{
    return sha256_rotr(x, 7) ^ sha256_rotr(x, 18) ^ (x >> 3);
}

static uint32_t sha256_gamma1(uint32_t x)
{
    return sha256_rotr(x, 17) ^ sha256_rotr(x, 19) ^ (x >> 10);
}

static uint32_t load32_be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

static void store32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8);
    p[3] = (uint8_t)(v);
}

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
} sha256_ctx;

static void sha256_init(sha256_ctx *ctx)
{
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

static void sha256_transform(sha256_ctx *ctx, const uint8_t block[64])
{
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = load32_be(block + 4 * i);
    for (i = 16; i < 64; i++)
        w[i] = sha256_gamma1(w[i-2]) + w[i-7] +
               sha256_gamma0(w[i-15]) + w[i-16];

    a = ctx->state[0]; b = ctx->state[1];
    c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5];
    g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; i++) {
        uint32_t t1 = h + sha256_sigma1(e) + sha256_ch(e, f, g) +
                       sha256_k[i] + w[i];
        uint32_t t2 = sha256_sigma0(a) + sha256_maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b;
    ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f;
    ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len)
{
    size_t buf_used = (size_t)(ctx->count % 64);
    ctx->count += len;

    if (buf_used > 0) {
        size_t space = 64 - buf_used;
        if (len < space) {
            memcpy(ctx->buf + buf_used, data, len);
            return;
        }
        memcpy(ctx->buf + buf_used, data, space);
        sha256_transform(ctx, ctx->buf);
        data += space;
        len  -= space;
    }
    while (len >= 64) {
        sha256_transform(ctx, data);
        data += 64;
        len  -= 64;
    }
    if (len > 0)
        memcpy(ctx->buf, data, len);
}

static void sha256_final(sha256_ctx *ctx, uint8_t out[32])
{
    uint64_t bits = ctx->count * 8;
    size_t buf_used = (size_t)(ctx->count % 64);
    int i;

    ctx->buf[buf_used++] = 0x80;
    if (buf_used > 56) {
        memset(ctx->buf + buf_used, 0, 64 - buf_used);
        sha256_transform(ctx, ctx->buf);
        buf_used = 0;
    }
    memset(ctx->buf + buf_used, 0, 56 - buf_used);

    /* Big-endian 64-bit bit count */
    ctx->buf[56] = (uint8_t)(bits >> 56);
    ctx->buf[57] = (uint8_t)(bits >> 48);
    ctx->buf[58] = (uint8_t)(bits >> 40);
    ctx->buf[59] = (uint8_t)(bits >> 32);
    ctx->buf[60] = (uint8_t)(bits >> 24);
    ctx->buf[61] = (uint8_t)(bits >> 16);
    ctx->buf[62] = (uint8_t)(bits >>  8);
    ctx->buf[63] = (uint8_t)(bits);

    sha256_transform(ctx, ctx->buf);

    for (i = 0; i < 8; i++)
        store32_be(out + 4 * i, ctx->state[i]);
}

int ac_crypto_sha256(const void *data, size_t len, uint8_t out[AC_HASH_LEN])
{
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)data, len);
    sha256_final(&ctx, out);
    return AC_OK;
}

/* ================================================================== */
/*  TweetNaCl Ed25519 + SHA-512 (verbatim, public domain)              */
/*                                                                     */
/*  All TweetNaCl internals are static to avoid symbol conflicts.      */
/* ================================================================== */

typedef int64_t gf[16];

static const gf
  tn_gf0,
  tn_gf1 = {1},
  tn_D = {0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
           0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203},
  tn_D2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
            0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406},
  tn_X = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
           0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169},
  tn_Y = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
           0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666},
  tn_I = {0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
           0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83};

static uint64_t tn_dl64(const uint8_t *x)
{
    uint64_t i, u = 0;
    for (i = 0; i < 8; ++i) u = (u << 8) | x[i];
    return u;
}

static void tn_ts64(uint8_t *x, uint64_t u)
{
    int i;
    for (i = 7; i >= 0; --i) { x[i] = (uint8_t)u; u >>= 8; }
}

static int tn_vn(const uint8_t *x, const uint8_t *y, int n)
{
    uint32_t i, d = 0;
    for (i = 0; (int)i < n; ++i) d |= x[i] ^ y[i];
    return (1 & ((d - 1) >> 8)) - 1;
}

static int tn_crypto_verify_32(const uint8_t *x, const uint8_t *y)
{
    return tn_vn(x, y, 32);
}

static void tn_set25519(gf r, const gf a)
{
    int i;
    for (i = 0; i < 16; ++i) r[i] = a[i];
}

static void tn_car25519(gf o)
{
    int i;
    int64_t c;
    for (i = 0; i < 16; ++i) {
        o[i] += (1LL << 16);
        c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

static void tn_sel25519(gf p, gf q, int b)
{
    int64_t t, c = ~(b - 1);
    int i;
    for (i = 0; i < 16; ++i) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void tn_pack25519(uint8_t *o, const gf n)
{
    int i, j, b;
    gf m, t;
    for (i = 0; i < 16; ++i) t[i] = n[i];
    tn_car25519(t);
    tn_car25519(t);
    tn_car25519(t);
    for (j = 0; j < 2; ++j) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; ++i) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (int)((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        tn_sel25519(t, m, 1 - b);
    }
    for (i = 0; i < 16; ++i) {
        o[2 * i] = (uint8_t)(t[i] & 0xff);
        o[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
}

static int tn_neq25519(const gf a, const gf b)
{
    uint8_t c[32], d[32];
    tn_pack25519(c, a);
    tn_pack25519(d, b);
    return tn_crypto_verify_32(c, d);
}

static uint8_t tn_par25519(const gf a)
{
    uint8_t d[32];
    tn_pack25519(d, a);
    return d[0] & 1;
}

static void tn_unpack25519(gf o, const uint8_t *n)
{
    int i;
    for (i = 0; i < 16; ++i) o[i] = n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

static void tn_A(gf o, const gf a, const gf b)
{
    int i;
    for (i = 0; i < 16; ++i) o[i] = a[i] + b[i];
}

static void tn_Z(gf o, const gf a, const gf b)
{
    int i;
    for (i = 0; i < 16; ++i) o[i] = a[i] - b[i];
}

static void tn_M(gf o, const gf a, const gf b)
{
    int64_t i, j, t[31];
    for (i = 0; i < 31; ++i) t[i] = 0;
    for (i = 0; i < 16; ++i)
        for (j = 0; j < 16; ++j)
            t[i + j] += a[i] * b[j];
    for (i = 0; i < 15; ++i) t[i] += 38 * t[i + 16];
    for (i = 0; i < 16; ++i) o[i] = t[i];
    tn_car25519(o);
    tn_car25519(o);
}

static void tn_S(gf o, const gf a)
{
    tn_M(o, a, a);
}

static void tn_inv25519(gf o, const gf i)
{
    gf c;
    int a;
    for (a = 0; a < 16; ++a) c[a] = i[a];
    for (a = 253; a >= 0; --a) {
        tn_S(c, c);
        if (a != 2 && a != 4) tn_M(c, c, i);
    }
    for (a = 0; a < 16; ++a) o[a] = c[a];
}

static void tn_pow2523(gf o, const gf i)
{
    gf c;
    int a;
    for (a = 0; a < 16; ++a) c[a] = i[a];
    for (a = 250; a >= 0; --a) {
        tn_S(c, c);
        if (a != 1) tn_M(c, c, i);
    }
    for (a = 0; a < 16; ++a) o[a] = c[a];
}

/* ---- TweetNaCl SHA-512 ---- */

static uint64_t tn_R(uint64_t x, int c) { return (x >> c) | (x << (64 - c)); }
static uint64_t tn_Ch(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (~x & z); }
static uint64_t tn_Maj(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static uint64_t tn_Sigma0(uint64_t x) { return tn_R(x, 28) ^ tn_R(x, 34) ^ tn_R(x, 39); }
static uint64_t tn_Sigma1(uint64_t x) { return tn_R(x, 14) ^ tn_R(x, 18) ^ tn_R(x, 41); }
static uint64_t tn_sigma0(uint64_t x) { return tn_R(x, 1) ^ tn_R(x, 8) ^ (x >> 7); }
static uint64_t tn_sigma1(uint64_t x) { return tn_R(x, 19) ^ tn_R(x, 61) ^ (x >> 6); }

static const uint64_t tn_K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static int tn_crypto_hashblocks(uint8_t *x, const uint8_t *m, uint64_t n)
{
    uint64_t z[8], b[8], a[8], w[16], t;
    int i, j;

    for (i = 0; i < 8; ++i) z[i] = a[i] = tn_dl64(x + 8 * i);

    while (n >= 128) {
        for (i = 0; i < 16; ++i) w[i] = tn_dl64(m + 8 * i);

        for (i = 0; i < 80; ++i) {
            for (j = 0; j < 8; ++j) b[j] = a[j];
            t = a[7] + tn_Sigma1(a[4]) + tn_Ch(a[4], a[5], a[6]) + tn_K[i] + w[i % 16];
            b[7] = t + tn_Sigma0(a[0]) + tn_Maj(a[0], a[1], a[2]);
            b[3] += t;
            for (j = 0; j < 8; ++j) a[(j + 1) % 8] = b[j];
            if (i % 16 == 15)
                for (j = 0; j < 16; ++j)
                    w[j] += w[(j + 9) % 16] + tn_sigma0(w[(j + 1) % 16]) + tn_sigma1(w[(j + 14) % 16]);
        }

        for (i = 0; i < 8; ++i) { a[i] += z[i]; z[i] = a[i]; }

        m += 128;
        n -= 128;
    }

    for (i = 0; i < 8; ++i) tn_ts64(x + 8 * i, z[i]);

    return (int)n;
}

static const uint8_t tn_iv[64] = {
    0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08,
    0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
    0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b,
    0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
    0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1,
    0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
    0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b,
    0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79
};

static int tn_crypto_hash(uint8_t *out, const uint8_t *m, uint64_t n)
{
    uint8_t h[64], x[256];
    uint64_t i, b = n;

    for (i = 0; i < 64; ++i) h[i] = tn_iv[i];

    tn_crypto_hashblocks(h, m, n);
    m += n;
    n &= 127;
    m -= n;

    for (i = 0; i < 256; ++i) x[i] = 0;
    for (i = 0; i < n; ++i) x[i] = m[i];
    x[n] = 128;

    n = 256 - 128 * (n < 112);
    x[n - 9] = (uint8_t)(b >> 61);
    tn_ts64(x + n - 8, b << 3);
    tn_crypto_hashblocks(h, x, n);

    for (i = 0; i < 64; ++i) out[i] = h[i];

    return 0;
}

/* ---- Ed25519 point operations ---- */

static void tn_add(gf p[4], gf q[4])
{
    gf a, b, c, d, t, e, f, g, h;

    tn_Z(a, p[1], p[0]);
    tn_Z(t, q[1], q[0]);
    tn_M(a, a, t);
    tn_A(b, p[0], p[1]);
    tn_A(t, q[0], q[1]);
    tn_M(b, b, t);
    tn_M(c, p[3], q[3]);
    tn_M(c, c, tn_D2);
    tn_M(d, p[2], q[2]);
    tn_A(d, d, d);
    tn_Z(e, b, a);
    tn_Z(f, d, c);
    tn_A(g, d, c);
    tn_A(h, b, a);

    tn_M(p[0], e, f);
    tn_M(p[1], h, g);
    tn_M(p[2], g, f);
    tn_M(p[3], e, h);
}

static void tn_cswap(gf p[4], gf q[4], uint8_t b)
{
    int i;
    for (i = 0; i < 4; ++i)
        tn_sel25519(p[i], q[i], b);
}

static void tn_pack(uint8_t *r, gf p[4])
{
    gf tx, ty, zi;
    tn_inv25519(zi, p[2]);
    tn_M(tx, p[0], zi);
    tn_M(ty, p[1], zi);
    tn_pack25519(r, ty);
    r[31] ^= tn_par25519(tx) << 7;
}

static void tn_scalarmult(gf p[4], gf q[4], const uint8_t *s)
{
    int i;
    tn_set25519(p[0], tn_gf0);
    tn_set25519(p[1], tn_gf1);
    tn_set25519(p[2], tn_gf1);
    tn_set25519(p[3], tn_gf0);
    for (i = 255; i >= 0; --i) {
        uint8_t b = (s[i / 8] >> (i & 7)) & 1;
        tn_cswap(p, q, b);
        tn_add(q, p);
        tn_add(p, p);
        tn_cswap(p, q, b);
    }
}

static void tn_scalarbase(gf p[4], const uint8_t *s)
{
    gf q[4];
    tn_set25519(q[0], tn_X);
    tn_set25519(q[1], tn_Y);
    tn_set25519(q[2], tn_gf1);
    tn_M(q[3], tn_X, tn_Y);
    tn_scalarmult(p, q, s);
}

/* ---- Scalar operations ---- */

static const uint64_t tn_L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0x10
};

static void tn_modL(uint8_t *r, int64_t x[64])
{
    int64_t carry, i, j;
    for (i = 63; i >= 32; --i) {
        carry = 0;
        for (j = i - 32; j < i - 12; ++j) {
            x[j] += carry - 16 * x[i] * (int64_t)tn_L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
        }
        x[j] += carry;
        x[i] = 0;
    }
    carry = 0;
    for (j = 0; j < 32; ++j) {
        x[j] += carry - (x[31] >> 4) * (int64_t)tn_L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for (j = 0; j < 32; ++j) x[j] -= carry * (int64_t)tn_L[j];
    for (i = 0; i < 32; ++i) {
        x[i + 1] += x[i] >> 8;
        r[i] = (uint8_t)(x[i] & 255);
    }
}

static void tn_reduce(uint8_t *r)
{
    int64_t x[64];
    int i;
    for (i = 0; i < 64; ++i) x[i] = (uint64_t)r[i];
    for (i = 0; i < 64; ++i) r[i] = 0;
    tn_modL(r, x);
}

static int tn_crypto_sign(uint8_t *sm, uint64_t *smlen,
                          const uint8_t *m, uint64_t n, const uint8_t *sk)
{
    uint8_t d[64], h[64], r[64];
    int64_t i, j, x[64];
    gf p[4];

    tn_crypto_hash(d, sk, 32);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    *smlen = n + 64;
    for (i = 0; i < (int64_t)n; ++i) sm[64 + i] = m[i];
    for (i = 0; i < 32; ++i) sm[32 + i] = d[32 + i];

    tn_crypto_hash(r, sm + 32, n + 32);
    tn_reduce(r);
    tn_scalarbase(p, r);
    tn_pack(sm, p);

    for (i = 0; i < 32; ++i) sm[i + 32] = sk[i + 32];
    tn_crypto_hash(h, sm, n + 64);
    tn_reduce(h);

    for (i = 0; i < 64; ++i) x[i] = 0;
    for (i = 0; i < 32; ++i) x[i] = (uint64_t)r[i];
    for (i = 0; i < 32; ++i)
        for (j = 0; j < 32; ++j)
            x[i + j] += h[i] * (uint64_t)d[j];
    tn_modL(sm + 32, x);

    return 0;
}

static int tn_unpackneg(gf r[4], const uint8_t p[32])
{
    gf t, chk, num, den, den2, den4, den6;
    tn_set25519(r[2], tn_gf1);
    tn_unpack25519(r[1], p);
    tn_S(num, r[1]);
    tn_M(den, num, tn_D);
    tn_Z(num, num, r[2]);
    tn_A(den, r[2], den);

    tn_S(den2, den);
    tn_S(den4, den2);
    tn_M(den6, den4, den2);
    tn_M(t, den6, num);
    tn_M(t, t, den);

    tn_pow2523(t, t);
    tn_M(t, t, num);
    tn_M(t, t, den);
    tn_M(t, t, den);
    tn_M(r[0], t, den);

    tn_S(chk, r[0]);
    tn_M(chk, chk, den);
    if (tn_neq25519(chk, num)) tn_M(r[0], r[0], tn_I);

    tn_S(chk, r[0]);
    tn_M(chk, chk, den);
    if (tn_neq25519(chk, num)) return -1;

    if (tn_par25519(r[0]) == (p[31] >> 7)) tn_Z(r[0], tn_gf0, r[0]);

    tn_M(r[3], r[0], r[1]);
    return 0;
}

static int tn_crypto_sign_open(uint8_t *m, uint64_t *mlen,
                               const uint8_t *sm, uint64_t n,
                               const uint8_t *pk)
{
    int i;
    uint8_t t[32], h[64];
    gf p[4], q[4];

    *mlen = (uint64_t)-1;
    if (n < 64) return -1;

    if (tn_unpackneg(q, pk)) return -1;

    for (i = 0; i < (int)n; ++i) m[i] = sm[i];
    for (i = 0; i < 32; ++i) m[i + 32] = pk[i];
    tn_crypto_hash(h, m, n);
    tn_reduce(h);
    tn_scalarmult(p, q, h);

    tn_scalarbase(q, sm + 32);
    tn_add(p, q);
    tn_pack(t, p);

    n -= 64;
    if (tn_crypto_verify_32(sm, t)) {
        for (i = 0; i < (int)n; ++i) m[i] = 0;
        return -1;
    }

    for (i = 0; i < (int)n; ++i) m[i] = sm[i + 64];
    *mlen = n;
    return 0;
}

/* ================================================================== */
/*  Ed25519 public API (wrapping TweetNaCl internals)                  */
/* ================================================================== */

int ac_crypto_ed25519_keypair(const uint8_t seed[32],
                              uint8_t pubkey[AC_PUBKEY_LEN],
                              uint8_t privkey[64])
{
    uint8_t d[64];
    gf p[4];
    int i;

    tn_crypto_hash(d, seed, 32);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    tn_scalarbase(p, d);
    tn_pack(pubkey, p);

    for (i = 0; i < 32; ++i) privkey[i] = seed[i];
    for (i = 0; i < 32; ++i) privkey[32 + i] = pubkey[i];
    return AC_OK;
}

int ac_crypto_ed25519_sign(const uint8_t privkey[64],
                           const void *msg, size_t msg_len,
                           uint8_t sig[AC_SIG_LEN])
{
    uint64_t smlen = 0;
    uint8_t *sm = (uint8_t *)malloc(msg_len + 64);
    if (!sm) return AC_ERR_CRYPTO;

    tn_crypto_sign(sm, &smlen, (const uint8_t *)msg, (uint64_t)msg_len, privkey);

    memcpy(sig, sm, 64);
    free(sm);
    return AC_OK;
}

int ac_crypto_ed25519_verify(const uint8_t pubkey[AC_PUBKEY_LEN],
                             const void *msg, size_t msg_len,
                             const uint8_t sig[AC_SIG_LEN])
{
    uint64_t mlen = 0;
    uint64_t smlen = msg_len + 64;
    int rc;

    uint8_t *sm = (uint8_t *)malloc(smlen);
    uint8_t *m  = (uint8_t *)malloc(smlen);
    if (!sm || !m) {
        free(sm);
        free(m);
        return AC_ERR_CRYPTO;
    }

    memcpy(sm, sig, 64);
    memcpy(sm + 64, msg, msg_len);

    rc = tn_crypto_sign_open(m, &mlen, sm, smlen, pubkey);

    free(sm);
    free(m);
    return (rc == 0) ? AC_OK : AC_ERR_CRYPTO;
}

/* ================================================================== */
/*  Secure random                                                      */
/* ================================================================== */

int ac_crypto_random(void *buf, size_t len)
{
#ifdef _WIN32
    HCRYPTPROV prov;
    if (!CryptAcquireContextA(&prov, NULL, NULL, PROV_RSA_FULL,
                              CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
        return AC_ERR_CRYPTO;
    if (!CryptGenRandom(prov, (DWORD)len, (BYTE *)buf)) {
        CryptReleaseContext(prov, 0);
        return AC_ERR_CRYPTO;
    }
    CryptReleaseContext(prov, 0);
    return AC_OK;
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f)
        return AC_ERR_CRYPTO;
    if (fread(buf, 1, len, f) != len) {
        fclose(f);
        return AC_ERR_CRYPTO;
    }
    fclose(f);
    return AC_OK;
#endif
}

/* ================================================================== */
/*  Zeroize                                                            */
/* ================================================================== */

void ac_crypto_zeroize(void *buf, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)buf;
    while (len--)
        *p++ = 0;
}