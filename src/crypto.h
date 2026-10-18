/*
 * crypto.h - cryptographic primitives for ZIP password verification.
 *
 *   - CRC-32 (ZIP polynomial, table driven)
 *   - ZipCrypto (PKWARE stream cipher) key schedule + header check + decrypt
 *   - SHA-1 with runtime-dispatched SIMD back ends
 *       * ARMv8 Crypto Extensions (Apple Silicon, Snapdragon, ...)
 *       * x86 SHA-NI (Zen 3+, Ice Lake+, ...) via function multi-target
 *       * portable C fallback
 *   - PBKDF2-HMAC-SHA1 (WinZip AE key derivation, 1000 iterations)
 *   - AES-128/192/256 (encrypt only, for WinZip CTR) + HMAC-SHA1 auth check
 */
#ifndef ZR_CRYPTO_H
#define ZR_CRYPTO_H

#include "platform.h"
#include "gen.h"           /* ZR_MAX_PWLEN */

/* ---------------- CRC-32 (0xEDB88320) ---------------- */
extern uint32_t zr_crc_tab[256];
void     zr_crc32_init(void);
uint32_t zr_crc32(const uint8_t *p, size_t n);

/*
 * Hardware CRC byte-step for the ZipCrypto hot loop.
 *   ARMv8 CRC (Apple Silicon, all arm64 Macs): __crc32b — ~1 cycle/byte
 *   x86 SSE4.2 (every Win11-era CPU):          _mm_crc32_u8
 * Both compute exactly table[(c^b)&0xff]^(c>>8) for poly 0xEDB88320.
 */
#if defined(__ARM_FEATURE_CRC32) || (defined(__aarch64__) && defined(__APPLE__))
#include <arm_acle.h>
static inline uint32_t zr_crc_byte(uint32_t c, uint8_t b) { return __crc32b(c, b); }
#elif defined(__SSE4_2__) || defined(_M_X64)
#include <nmmintrin.h>
static inline uint32_t zr_crc_byte(uint32_t c, uint8_t b) {
    return (uint32_t)_mm_crc32_u8(c, b);
}
#else
static inline uint32_t zr_crc_byte(uint32_t c, uint8_t b) {
    return zr_crc_tab[(c ^ b) & 0xff] ^ (c >> 8);
}
#endif

/* ---------------- ZipCrypto ---------------- */
typedef struct { uint32_t k0, k1, k2; } zc_keys;

static inline void zc_update(zc_keys *k, uint8_t b) {
    k->k0 = zr_crc_byte(k->k0, b);
    k->k1 = k->k1 + (k->k0 & 0xff);
    k->k1 = k->k1 * 134775813u + 1;
    k->k2 = zr_crc_byte(k->k2, (uint8_t)(k->k1 >> 24));
}
static inline uint8_t zc_stream(const zc_keys *k) {
    uint32_t t = (k->k2 & 0xffff) | 2;
    return (uint8_t)((t * (t ^ 1)) >> 8);
}
static inline void zc_key_init(zc_keys *k, const uint8_t *pw, int len) {
    k->k0 = 0x12345678u; k->k1 = 0x23456789u; k->k2 = 0x34567890u;
    for (int i = 0; i < len; i++) zc_update(k, pw[i]);
}
/*
 * Decrypt the 12-byte ZipCrypto header in-place check.
 * check16 = expected bytes 10..11 little-endian:
 *   flags&8 -> high byte of mod time in byte 11 (byte10 unchecked)
 *   else    -> crc32 >> 16 (both bytes checked)
 * returns 1 if candidate passes the filter.
 */
int  zc_header_check(const uint8_t *pw, int len, const uint8_t hdr[12],
                     uint16_t check16, int check_bytes);
void zc_decrypt(const uint8_t *pw, int len, const uint8_t *in, uint8_t *out, size_t n);

/*
 * Per-worker prefix cache: consecutive candidates from the mask/brute
 * generators share pw[0..len-2], so the key-init work for that prefix
 * is done once and reused. Pass NULL-safe per-worker storage.
 */
typedef struct {
    zc_keys k;                    /* key state after pw[0..len-2]      */
    uint8_t pw[ZR_MAX_PWLEN];     /* the pw[0..len-2] that produced k  */
    int     len;                  /* 0 = cache empty                   */
} zc_cache;
void zc_cache_init(zc_cache *c);
/* initialize *k with pw, reusing *c when the len-1 prefix matches */
void zc_key_init_cached(zc_keys *k, const uint8_t *pw, int len, zc_cache *c);
/* header check from an already-initialized key state */
int  zc_header_check_k(const zc_keys *init, const uint8_t hdr[12],
                       uint16_t check16, int check_bytes);

/* ---------------- SHA-1 ---------------- */
typedef struct {
    uint32_t h[5];
    uint64_t len;          /* total bytes */
    uint8_t  buf[64];
    size_t   buflen;
} sha1_ctx;

void sha1_init(sha1_ctx *c);
void sha1_update(sha1_ctx *c, const void *data, size_t n);
void sha1_final(sha1_ctx *c, uint8_t out[20]);

/* compress one 64-byte block, h in/out; backend chosen at zr_crypto_init */
extern void (*zr_sha1_compress)(uint32_t h[5], const uint8_t block[64]);
const char *zr_sha1_backend(void);
void zr_crypto_init(void);   /* call once at startup */

/* HMAC-SHA1 with precomputed pad states (hot path for PBKDF2) */
typedef struct { uint32_t ipad[5], opad[5]; } hmac_sha1_keys;
void hmac_sha1_setkey(hmac_sha1_keys *k, const uint8_t *pw, int len);
void hmac_sha1_fast(const hmac_sha1_keys *k, const uint8_t *msg, size_t mlen, uint8_t out[20]);
void hmac_sha1(const uint8_t *key, int klen, const uint8_t *msg, size_t mlen, uint8_t out[20]);

void pbkdf2_sha1(const uint8_t *pw, int pwlen, const uint8_t *salt, int slen,
                 uint32_t iters, uint8_t *dk, int dklen);

/* ---------------- AES (encrypt-only, for WinZip CTR) ---------------- */
#define AES_MAXRK 60
typedef struct { uint32_t rk[AES_MAXRK]; int nr; } aes_ctx;
void aes_setkey(aes_ctx *c, const uint8_t *key, int keybits); /* 128/192/256 */
void aes_encrypt(const aes_ctx *c, const uint8_t in[16], uint8_t out[16]);

/* WinZip AES counter mode: counter block = LE128(counter), counter starts at 1 */
void winzip_aes_ctr(const aes_ctx *c, const uint8_t *in, uint8_t *out, size_t n);

/* ---------------- high-level candidate checks ---------------- */
#include "zipfile.h"

/*
 * Fast per-candidate filter for the primary target entry.
 * Returns 1 if the candidate survives the cheap check and should be
 * promoted to zr_full_verify().
 */
extern int zr_check_bytes_override;
int zr_quick_check(const zr_archive *z, const uint8_t *pw, int len);
/* same as zr_quick_check but uses a per-worker ZipCrypto prefix cache */
int zr_quick_check2(const zr_archive *z, const uint8_t *pw, int len, zc_cache *cc);

/*
 * Definitive verification:
 *   ZipCrypto: header cross-check on secondary entries + decrypt target,
 *              inflate (method 8) or CRC (method 0), compare CRC.
 *   AES:       PBKDF2 -> verifier -> AES-CTR decrypt -> HMAC-SHA1 == auth code.
 * Returns 1 if password is confirmed.
 */
int zr_full_verify(const zr_archive *z, const uint8_t *pw, int len,
                   uint8_t *workbuf, size_t worklen);

/* bytes of scratch space zr_full_verify needs (>= target data_len + usize) */
size_t zr_verify_worksize(const zr_archive *z);

/* minimal DEFLATE decompressor (RFC 1951) used for final verification */
int zr_inflate(const uint8_t *src, size_t srclen, uint8_t *dst, size_t dstcap, size_t *dstlen);

#endif /* ZR_CRYPTO_H */
