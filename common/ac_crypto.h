/*
 * ac_crypto.h — Crypto interface for addrchain
 *
 * Declares the cryptographic primitives used by addrchain:
 *   - SHA-256 hashing
 *   - Ed25519 key generation, signing, and verification
 *   - Cryptographic random number generation
 *   - Secure memory zeroization
 *
 * Implementations are in ac_crypto.c (portable, self-contained).
 * All functions conform to the signatures declared in ac_platform.h.
 */

#ifndef AC_CRYPTO_H
#define AC_CRYPTO_H

#include "ac_platform.h"

/* ------------------------------------------------------------------ */
/*  SHA-256                                                            */
/* ------------------------------------------------------------------ */

/* Hash `data` of `len` bytes, writing 32-byte digest to `out`. */
int ac_crypto_sha256(const void *data, size_t len, uint8_t out[AC_HASH_LEN]);

/* ------------------------------------------------------------------ */
/*  Ed25519                                                            */
/* ------------------------------------------------------------------ */

/* Derive keypair from a 32-byte seed.
 * pubkey:  32 bytes (compressed Edwards-y point)
 * privkey: 64 bytes (seed ∥ pubkey, matching NaCl convention) */
int ac_crypto_ed25519_keypair(const uint8_t seed[32],
                              uint8_t pubkey[AC_PUBKEY_LEN],
                              uint8_t privkey[64]);

/* Sign `msg` of `msg_len` bytes with `privkey`, writing 64-byte sig. */
int ac_crypto_ed25519_sign(const uint8_t privkey[64],
                           const void *msg, size_t msg_len,
                           uint8_t sig[AC_SIG_LEN]);

/* Verify `sig` over `msg` with `pubkey`.
 * Returns AC_OK on success, AC_ERR_CRYPTO on failure. */
int ac_crypto_ed25519_verify(const uint8_t pubkey[AC_PUBKEY_LEN],
                             const void *msg, size_t msg_len,
                             const uint8_t sig[AC_SIG_LEN]);

/* ------------------------------------------------------------------ */
/*  Random and zeroize                                                 */
/* ------------------------------------------------------------------ */

/* Fill `buf` with `len` cryptographically secure random bytes. */
int ac_crypto_random(void *buf, size_t len);

/* Securely zero `len` bytes at `buf` (not optimized away). */
void ac_crypto_zeroize(void *buf, size_t len);

#endif /* AC_CRYPTO_H */
