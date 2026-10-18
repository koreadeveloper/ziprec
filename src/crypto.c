/*
 * crypto.c - see crypto.h for the interface contract.
 */
#include "crypto.h"
#include <string.h>
#include <stdlib.h>

#if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
#include <arm_neon.h>
#define ZR_HAVE_ARM_SHA1 1
#endif

#if defined(__x86_64__) || defined(_M_X64)
#if defined(__clang__) || defined(__GNUC__)
#include <immintrin.h>
#define ZR_HAVE_X86_SHA1 1
#elif defined(_MSC_VER)
#include <immintrin.h>
#include <intrin.h>
#define ZR_HAVE_X86_SHA1 1
#endif
#endif

/* ================= CRC-32 ================= */
uint32_t zr_crc_tab[256];

void zr_crc32_init(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
        zr_crc_tab[i] = c;
    }
}
uint32_t zr_crc32(const uint8_t *p, size_t n) {
    uint32_t c = 0xFFFFFFFFu;
#if defined(__ARM_FEATURE_CRC32) || (defined(__aarch64__) && defined(__APPLE__))
    while (n >= 8) { uint64_t w; memcpy(&w, p, 8); c = __crc32d(c, w); p += 8; n -= 8; }
    while (n--) c = __crc32b(c, *p++);
#elif defined(__SSE4_2__) || defined(_M_X64)
    while (n >= 8) { uint64_t w; memcpy(&w, p, 8); c = (uint32_t)_mm_crc32_u64(c, w); p += 8; n -= 8; }
    while (n--) c = (uint32_t)_mm_crc32_u8(c, *p++);
#else
    for (size_t i = 0; i < n; i++) c = zr_crc_tab[(c ^ p[i]) & 0xff] ^ (c >> 8);
#endif
    return c ^ 0xFFFFFFFFu;
}

/* ================= ZipCrypto ================= */
void zc_cache_init(zc_cache *c) { c->len = 0; }

void zc_key_init_cached(zc_keys *k, const uint8_t *pw, int len, zc_cache *c) {
    if (!c || len <= 1) { zc_key_init(k, pw, len); return; }
    if (c->len == len && !memcmp(c->pw, pw, (size_t)len - 1)) {
        *k = c->k;                       /* reuse state after len-1 prefix */
    } else {
        k->k0 = 0x12345678u; k->k1 = 0x23456789u; k->k2 = 0x34567890u;
        for (int i = 0; i < len - 1; i++) zc_update(k, pw[i]);
        c->k = *k;
        memcpy(c->pw, pw, (size_t)len - 1);
        c->len = len;
    }
    zc_update(k, pw[len - 1]);
}

int zc_header_check_k(const zc_keys *init, const uint8_t hdr[12],
                      uint16_t check16, int check_bytes) {
    zc_keys k = *init;
    uint8_t b[12];
    for (int i = 0; i < 12; i++) { b[i] = hdr[i] ^ zc_stream(&k); zc_update(&k, b[i]); }
    if (check_bytes == 2)
        return b[10] == (check16 & 0xff) && b[11] == (check16 >> 8);
    return b[11] == (check16 >> 8);
}

int zc_header_check(const uint8_t *pw, int len, const uint8_t hdr[12],
                    uint16_t check16, int check_bytes) {
    zc_keys k;
    zc_key_init(&k, pw, len);
    return zc_header_check_k(&k, hdr, check16, check_bytes);
}

/* Decrypt `in` continuing keystream after the 12-byte encryption header:
   caller must pass the header bytes first (they feed the key update chain). */
void zc_decrypt(const uint8_t *pw, int len, const uint8_t *in, uint8_t *out, size_t n) {
    zc_keys k;
    uint8_t b;
    zc_key_init(&k, pw, len);
    for (size_t i = 0; i < n; i++) { b = in[i] ^ zc_stream(&k); zc_update(&k, b); out[i] = b; }
}

/* ================= SHA-1 ================= */
static const uint32_t SHA1_IV[5] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};

static void sha1_compress_portable(uint32_t h[5], const uint8_t blk[64]) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++) w[i] = zr_be32(blk + 4 * i);
    for (int i = 16; i < 80; i++) w[i] = zr_rotl32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if      (i < 20) { f = (b & c) | ((~b) & d);      k = 0x5A827999u; }
        else if (i < 40) { f = b ^ c ^ d;                 k = 0x6ED9EBA1u; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDCu; }
        else             { f = b ^ c ^ d;                 k = 0xCA62C1D6u; }
        uint32_t t = zr_rotl32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = zr_rotl32(b, 30); b = a; a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

#ifdef ZR_HAVE_ARM_SHA1
/* Single-block ARMv8 SHA-1. Ported from the public-domain reference by
   Jeffrey Walton (noloader/SHA-Intrinsics), itself based on mbedTLS work
   by ARM. The key invariants:
     - e for the next 4-round group = vsha1h_u32(vgetq_lane(ABCD,0)) = ROL30(a)
     - wk operand = W[i] + K[i] (round constant pre-added)
     - message schedule: su0 right after first use, su1 to finish.        */
static void sha1_compress_arm(uint32_t h[5], const uint8_t blk[64]) {
    uint32x4_t ABCD = vld1q_u32(h);
    uint32_t   E0   = h[4], E1;
    uint32x4_t MSG0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(blk +  0)));
    uint32x4_t MSG1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(blk + 16)));
    uint32x4_t MSG2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(blk + 32)));
    uint32x4_t MSG3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(blk + 48)));
    uint32x4_t T0, T1;
    const uint32x4_t K0 = {0x5A827999u,0x5A827999u,0x5A827999u,0x5A827999u};
    const uint32x4_t K1 = {0x6ED9EBA1u,0x6ED9EBA1u,0x6ED9EBA1u,0x6ED9EBA1u};
    const uint32x4_t K2 = {0x8F1BBCDCu,0x8F1BBCDCu,0x8F1BBCDCu,0x8F1BBCDCu};
    const uint32x4_t K3 = {0xCA62C1D6u,0xCA62C1D6u,0xCA62C1D6u,0xCA62C1D6u};
    uint32x4_t ABCD_SAVED = ABCD; uint32_t E0_SAVED = E0;

    T0 = vaddq_u32(MSG0, K0);
    T1 = vaddq_u32(MSG1, K0);
    /* 0-3  */ E1 = vsha1h_u32(vgetq_lane_u32(ABCD,0)); ABCD = vsha1cq_u32(ABCD, E0, T0);
               T0 = vaddq_u32(MSG2, K0); MSG0 = vsha1su0q_u32(MSG0, MSG1, MSG2);
    /* 4-7  */ E0 = vsha1h_u32(vgetq_lane_u32(ABCD,0)); ABCD = vsha1cq_u32(ABCD, E1, T1);
               T1 = vaddq_u32(MSG3, K0); MSG0 = vsha1su1q_u32(MSG0, MSG3);
                                        MSG1 = vsha1su0q_u32(MSG1, MSG2, MSG3);
    /* 8-11 */ E1 = vsha1h_u32(vgetq_lane_u32(ABCD,0)); ABCD = vsha1cq_u32(ABCD, E0, T0);
               T0 = vaddq_u32(MSG0, K0); MSG1 = vsha1su1q_u32(MSG1, MSG0);
                                        MSG2 = vsha1su0q_u32(MSG2, MSG3, MSG0);
    /* 12-15*/ E0 = vsha1h_u32(vgetq_lane_u32(ABCD,0)); ABCD = vsha1cq_u32(ABCD, E1, T1);
               T1 = vaddq_u32(MSG1, K1); MSG2 = vsha1su1q_u32(MSG2, MSG1);
                                        MSG3 = vsha1su0q_u32(MSG3, MSG0, MSG1);
    /* 16-19*/ E1 = vsha1h_u32(vgetq_lane_u32(ABCD,0)); ABCD = vsha1cq_u32(ABCD, E0, T0);
               T0 = vaddq_u32(MSG2, K1); MSG3 = vsha1su1q_u32(MSG3, MSG2);
                                        MSG0 = vsha1su0q_u32(MSG0, MSG1, MSG2);
    /* 20-23*/ E0 = vsha1h_u32(vgetq_lane_u32(ABCD,0)); ABCD = vsha1pq_u32(ABCD, E1, T1);
               T1 = vaddq_u32(MSG3, K1); MSG0 = vsha1su1q_u32(MSG0, MSG3);
                                        MSG1 = vsha1su0q_u32(MSG1, MSG2, MSG3);
    /* 24-27*/ E1 = vsha1h_u32(vgetq_lane_u32(ABCD,0)); ABCD = vsha1pq_u32(ABCD, E0, T0);
               T0 = vaddq_u32(MSG0, K1); MSG1 = vsha1su1q_u32(MSG1, MSG0);
                                        MSG2 = vsha1su0q_u32(MSG2, MSG3, MSG0);
    /* 28-31*/ E0 = vsha1h_u32(vgetq_lane_u32(ABCD,0)); ABCD = vsha1pq_u32(ABCD, E1, T1);
               T1 = vaddq_u32(MSG1, K1); MSG2 = vsha1su1q_u32(MSG2, MSG1);
                                        MSG3 = vsha1su0q_u32(MSG3, MSG0, MSG1);
    /* 32-35*/ E1 = vsha1h_u32(vgetq_lane_u32(ABCD,0)); ABCD = vsha1pq_u32(ABCD, E0, T0);
               T0 = vaddq_u32(MSG2, K2); MSG3 = vsha1su1q_u32(MSG3, MSG2);
                                        MSG0 = vsha1su0q_u32(MSG0, MSG1, MSG2);
    /* 36-39*/ E0 = vsha1h_u32(vgetq_lane_u32(ABCD,0)); ABCD = vsha1pq_u32(ABCD, E1, T1);
               T1 = vaddq_u32(MSG3, K2); MSG0 = vsha1su1q_u32(MSG0, MSG3);
                                        MSG1 = vsha1su0q_u32(MSG1, MSG2, MSG3);
    /* 40-43*/ E1 = vsha1h_u32(vgetq_lane_u32(ABCD,0)); ABCD = vsha1mq_u32(ABCD, E0, T0);
               T0 = vaddq_u32(MSG0, K2); MSG1 = vsha1su1q_u32(MSG1, MSG0);
                                        MSG2 = vsha1su0q_u32(MSG2, MSG3, MSG0);
    /* 44-47*/ E0 = vsha1h_u32(vgetq_lane_u32(ABCD,0)); ABCD = vsha1mq_u32(ABCD, E1, T1);
               T1 = vaddq_u32(MSG1, K2); MSG2 = vsha1su1q_u32(MSG2, MSG1);
                                        MSG3 = vsha1su0q_u32(MSG3, MSG0, MSG1);
    /* 48-51*/ E1 = vsha1h_u32(vgetq_lane_u32(ABCD,0)); ABCD = vsha1mq_u32(ABCD, E0, T0);
               T0 = vaddq_u32(MSG2, K2); MSG3 = vsha1su1q_u32(MSG3, MSG2);
                                        MSG0 = vsha1su0q_u32(MSG0, MSG1, MSG2);
    /* 52-55*/ E0 = vsha1h_u32(vgetq_lane_u32(ABCD,0)); ABCD = vsha1mq_u32(ABCD, E1, T1);
               T1 = vaddq_u32(MSG3, K3); MSG0 = vsha1su1q_u32(MSG0, MSG3);
                                        MSG1 = vsha1su0q_u32(MSG1, MSG2, MSG3);
    /* 56-59*/ E1 = vsha1h_u32(vgetq_lane_u32(ABCD,0)); ABCD = vsha1mq_u32(ABCD, E0, T0);
               T0 = vaddq_u32(MSG0, K3); MSG1 = vsha1su1q_u32(MSG1, MSG0);
                                        MSG2 = vsha1su0q_u32(MSG2, MSG3, MSG0);
    /* 60-63*/ E0 = vsha1h_u32(vgetq_lane_u32(ABCD,0)); ABCD = vsha1pq_u32(ABCD, E1, T1);
               T1 = vaddq_u32(MSG1, K3); MSG2 = vsha1su1q_u32(MSG2, MSG1);
                                        MSG3 = vsha1su0q_u32(MSG3, MSG0, MSG1);
    /* 64-67*/ E1 = vsha1h_u32(vgetq_lane_u32(ABCD,0)); ABCD = vsha1pq_u32(ABCD, E0, T0);
               T0 = vaddq_u32(MSG2, K3); MSG3 = vsha1su1q_u32(MSG3, MSG2);
                                        MSG0 = vsha1su0q_u32(MSG0, MSG1, MSG2);
    /* 68-71*/ E0 = vsha1h_u32(vgetq_lane_u32(ABCD,0)); ABCD = vsha1pq_u32(ABCD, E1, T1);
               T1 = vaddq_u32(MSG3, K3); MSG0 = vsha1su1q_u32(MSG0, MSG3);
    /* 72-75*/ E1 = vsha1h_u32(vgetq_lane_u32(ABCD,0)); ABCD = vsha1pq_u32(ABCD, E0, T0);
    /* 76-79*/ E0 = vsha1h_u32(vgetq_lane_u32(ABCD,0)); ABCD = vsha1pq_u32(ABCD, E1, T1);

    E0 += E0_SAVED;
    vst1q_u32(h, vaddq_u32(ABCD_SAVED, ABCD));
    h[4] = E0;
}
#endif /* ZR_HAVE_ARM_SHA1 */

#ifdef ZR_HAVE_X86_SHA1
#if defined(__clang__) || defined(__GNUC__)
__attribute__((target("sha")))
#endif
static void sha1_compress_shani(uint32_t h[5], const uint8_t blk[64]) {
    const __m128i MASK = _mm_set_epi64x(0x0001020304050607LL, 0x08090a0b0c0d0e0fLL);
    __m128i ABCD = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i *)h), 0x1B);
    __m128i E0   = _mm_set_epi32((int)h[4], 0, 0, 0);
    __m128i E1, MSG0, MSG1, MSG2, MSG3;
    __m128i ABCD_SAVE = ABCD, E_SAVE = E0;

#define LDMSG(i) _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(blk + 16 * (i))), MASK)

    MSG0 = LDMSG(0); E0 = _mm_add_epi32(E0, MSG0); E1 = ABCD; ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);
    MSG1 = LDMSG(1); E1 = _mm_sha1nexte_epu32(E1, MSG1); E0 = ABCD; ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 0);
                     MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
    MSG2 = LDMSG(2); E0 = _mm_sha1nexte_epu32(E0, MSG2); E1 = ABCD; ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);
                     MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2); MSG0 = _mm_xor_si128(MSG0, MSG2);
    MSG3 = LDMSG(3); E1 = _mm_sha1nexte_epu32(E1, MSG3); E0 = ABCD;
                     MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3); ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 0);
                     MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3); MSG1 = _mm_xor_si128(MSG1, MSG3);
    /* 16-19 */ E0 = _mm_sha1nexte_epu32(E0, MSG0); E1 = ABCD;
                     MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0); ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);
                     MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0); MSG2 = _mm_xor_si128(MSG2, MSG0);
    /* 20-23 */ E1 = _mm_sha1nexte_epu32(E1, MSG1); E0 = ABCD;
                     MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1); ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
                     MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1); MSG3 = _mm_xor_si128(MSG3, MSG1);
    /* 24-27 */ E0 = _mm_sha1nexte_epu32(E0, MSG2); E1 = ABCD;
                     MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2); ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 1);
                     MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2); MSG0 = _mm_xor_si128(MSG0, MSG2);
    /* 28-31 */ E1 = _mm_sha1nexte_epu32(E1, MSG3); E0 = ABCD;
                     MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3); ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
                     MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3); MSG1 = _mm_xor_si128(MSG1, MSG3);
    /* 32-35 */ E0 = _mm_sha1nexte_epu32(E0, MSG0); E1 = ABCD;
                     MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0); ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 1);
                     MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0); MSG2 = _mm_xor_si128(MSG2, MSG0);
    /* 36-39 */ E1 = _mm_sha1nexte_epu32(E1, MSG1); E0 = ABCD;
                     MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1); ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
                     MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1); MSG3 = _mm_xor_si128(MSG3, MSG1);
    /* 40-43 */ E0 = _mm_sha1nexte_epu32(E0, MSG2); E1 = ABCD;
                     MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2); ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
                     MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2); MSG0 = _mm_xor_si128(MSG0, MSG2);
    /* 44-47 */ E1 = _mm_sha1nexte_epu32(E1, MSG0); E0 = ABCD;
                     MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3); ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 2);
                     MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3); MSG1 = _mm_xor_si128(MSG1, MSG3);
    /* 48-51 */ E0 = _mm_sha1nexte_epu32(E0, MSG1); E1 = ABCD;
                     MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0); ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
                     MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0); MSG2 = _mm_xor_si128(MSG2, MSG0);
    /* 52-55 */ E1 = _mm_sha1nexte_epu32(E1, MSG2); E0 = ABCD;
                     MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1); ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 2);
                     MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1); MSG3 = _mm_xor_si128(MSG3, MSG1);
    /* 56-59 */ E0 = _mm_sha1nexte_epu32(E0, MSG3); E1 = ABCD;
                     MSG3 = _mm_sha1msg2_epu32(MSG3, MSG0); ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
                     MSG1 = _mm_sha1msg1_epu32(MSG1, MSG0); MSG2 = _mm_xor_si128(MSG2, MSG0);
    /* 60-63 */ E1 = _mm_sha1nexte_epu32(E1, MSG0); E0 = ABCD;
                     MSG0 = _mm_sha1msg2_epu32(MSG0, MSG1); ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);
                     MSG2 = _mm_sha1msg1_epu32(MSG2, MSG1); MSG3 = _mm_xor_si128(MSG3, MSG1);
    /* 64-67 */ E0 = _mm_sha1nexte_epu32(E0, MSG1); E1 = ABCD;
                     MSG1 = _mm_sha1msg2_epu32(MSG1, MSG2); ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 3);
                     MSG3 = _mm_sha1msg1_epu32(MSG3, MSG2); MSG0 = _mm_xor_si128(MSG0, MSG1);
    /* 68-71 */ E1 = _mm_sha1nexte_epu32(E1, MSG2); E0 = ABCD;
                     MSG2 = _mm_sha1msg2_epu32(MSG2, MSG3); ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);
                     MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2); MSG3 = _mm_xor_si128(MSG3, MSG2);
    /* 72-75 */ E0 = _mm_sha1nexte_epu32(E0, MSG3); E1 = ABCD;
                     MSG3 = _mm_sha1msg2_epu32(MSG3, MSG0); ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 3);
    /* 76-79 */ E1 = _mm_sha1nexte_epu32(E1, MSG0); E0 = ABCD;
                     ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);
    E0 = _mm_sha1nexte_epu32(E0, E1);

    ABCD = _mm_add_epi32(ABCD, ABCD_SAVE);
    E0   = _mm_add_epi32(E0, E_SAVE);
    _mm_storeu_si128((__m128i *)h, _mm_shuffle_epi32(ABCD, 0x1B));
    h[4] = (uint32_t)_mm_extract_epi32(E0, 3);
#undef LDMSG
}

static int cpu_has_shani(void) {
#if defined(__clang__) || defined(__GNUC__)
    __builtin_cpu_init();
    return __builtin_cpu_supports("sha");
#elif defined(_MSC_VER)
    int r[4];
    __cpuid(r, 7);
    return (r[1] >> 29) & 1;  /* EBX bit 29 = SHA */
#else
    return 0;
#endif
}
#endif /* ZR_HAVE_X86_SHA1 */

void (*zr_sha1_compress)(uint32_t h[5], const uint8_t block[64]) = sha1_compress_portable;
static const char *sha1_backend_name = "portable";

const char *zr_sha1_backend(void) { return sha1_backend_name; }

void sha1_init(sha1_ctx *c) {
    memcpy(c->h, SHA1_IV, sizeof SHA1_IV);
    c->len = 0; c->buflen = 0;
}
void sha1_update(sha1_ctx *c, const void *data, size_t n) {
    const uint8_t *p = data;
    c->len += n;
    if (c->buflen) {
        size_t take = 64 - c->buflen < n ? 64 - c->buflen : n;
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take; p += take; n -= take;
        if (c->buflen == 64) { zr_sha1_compress(c->h, c->buf); c->buflen = 0; }
    }
    while (n >= 64) { zr_sha1_compress(c->h, p); p += 64; n -= 64; }
    if (n) { memcpy(c->buf, p, n); c->buflen = n; }
}
void sha1_final(sha1_ctx *c, uint8_t out[20]) {
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80;
    sha1_update(c, &pad, 1);
    pad = 0;
    while (c->buflen != 56) sha1_update(c, &pad, 1);
    uint8_t lb[8];
    for (int i = 0; i < 8; i++) lb[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha1_update(c, lb, 8);
    for (int i = 0; i < 5; i++) zr_wr32be(out + 4 * i, c->h[i]);
}

/* HMAC for messages < 56 bytes (all PBKDF2 uses). 2 compressions per call. */
void hmac_sha1_fast(const hmac_sha1_keys *k, const uint8_t *msg, size_t mlen, uint8_t out[20]) {
    uint8_t blk[64];
    uint32_t h[5];
    memcpy(h, k->ipad, sizeof h);
    memcpy(blk, msg, mlen);
    blk[mlen] = 0x80;
    memset(blk + mlen + 1, 0, 63 - mlen);
    zr_wr32be(blk + 60, (uint32_t)((64 + mlen) * 8));
    zr_sha1_compress(h, blk);
    /* inner digest -> outer */
    uint8_t dig[20];
    for (int i = 0; i < 5; i++) zr_wr32be(dig + 4 * i, h[i]);
    memcpy(h, k->opad, sizeof h);
    memcpy(blk, dig, 20);
    blk[20] = 0x80;
    memset(blk + 21, 0, 39);
    zr_wr32be(blk + 60, (uint32_t)((64 + 20) * 8));
    zr_sha1_compress(h, blk);
    for (int i = 0; i < 5; i++) zr_wr32be(out + 4 * i, h[i]);
}

void hmac_sha1_setkey(hmac_sha1_keys *k, const uint8_t *pw, int len) {
    uint8_t kb[64];
    memset(kb, 0, 64);
    if (len <= 64) {
        memcpy(kb, pw, (size_t)len);
    } else { /* long keys are hashed first per HMAC spec */
        sha1_ctx t; sha1_init(&t); sha1_update(&t, pw, (size_t)len);
        uint8_t d[20]; sha1_final(&t, d);
        memcpy(kb, d, 20);
    }
    uint8_t blk[64];
    memcpy(k->ipad, SHA1_IV, 20);
    memcpy(k->opad, SHA1_IV, 20);
    for (int i = 0; i < 64; i++) blk[i] = kb[i] ^ 0x36;
    zr_sha1_compress(k->ipad, blk);
    for (int i = 0; i < 64; i++) blk[i] = kb[i] ^ 0x5c;
    zr_sha1_compress(k->opad, blk);
}

void hmac_sha1(const uint8_t *key, int klen, const uint8_t *msg, size_t mlen, uint8_t out[20]) {
    hmac_sha1_keys k;
    hmac_sha1_setkey(&k, key, klen);
    if (mlen < 56) { hmac_sha1_fast(&k, msg, mlen, out); return; }
    /* generic streaming path for long messages */
    sha1_ctx c; uint8_t dig[20];
    memcpy(c.h, k.ipad, 20); c.len = 64; c.buflen = 0;
    sha1_update(&c, msg, mlen); sha1_final(&c, dig);
    memcpy(c.h, k.opad, 20); c.len = 64; c.buflen = 0;
    sha1_update(&c, dig, 20); sha1_final(&c, out);
}

void pbkdf2_sha1(const uint8_t *pw, int pwlen, const uint8_t *salt, int slen,
                 uint32_t iters, uint8_t *dk, int dklen) {
    hmac_sha1_keys hk;
    hmac_sha1_setkey(&hk, pw, pwlen);
    uint8_t msg[256];               /* salt || INT(i) : slen <= 48 assumed */
    uint8_t u[20], t[20];
    int off = 0;
    for (uint32_t i = 1; off < dklen; i++) {
        memcpy(msg, salt, (size_t)slen);
        zr_wr32be(msg + slen, i);
        hmac_sha1_fast(&hk, msg, (size_t)slen + 4, u);
        memcpy(t, u, 20);
        for (uint32_t j = 1; j < iters; j++) {
            hmac_sha1_fast(&hk, u, 20, u);
            for (int b = 0; b < 20; b++) t[b] ^= u[b];
        }
        int take = dklen - off < 20 ? dklen - off : 20;
        memcpy(dk + off, t, (size_t)take);
        off += 20;
    }
}

/* ================= AES ================= */
static const uint8_t AES_S[256] = {
 0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
 0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
 0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
 0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
 0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
 0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
 0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
 0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
 0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
 0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
 0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
 0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
 0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
 0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
 0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
 0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16 };

void aes_setkey(aes_ctx *c, const uint8_t *key, int keybits) {
    static const uint8_t RCON[10] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};
    int nk = keybits / 32;
    c->nr = nk + 6;
    int words = 4 * (c->nr + 1);
    for (int i = 0; i < nk; i++) c->rk[i] = zr_be32(key + 4 * i);
    for (int i = nk; i < words; i++) {
        uint32_t t = c->rk[i - 1];
        if (i % nk == 0) {
            t = ((uint32_t)AES_S[(t >> 16) & 0xff] << 24) | ((uint32_t)AES_S[(t >> 8) & 0xff] << 16) |
                ((uint32_t)AES_S[t & 0xff] << 8) | (uint32_t)AES_S[(t >> 24) & 0xff];
            t ^= (uint32_t)RCON[i / nk - 1] << 24;
        } else if (nk > 6 && i % nk == 4) {
            t = ((uint32_t)AES_S[(t >> 24) & 0xff] << 24) | ((uint32_t)AES_S[(t >> 16) & 0xff] << 16) |
                ((uint32_t)AES_S[(t >> 8) & 0xff] << 8) | (uint32_t)AES_S[t & 0xff];
        }
        c->rk[i] = c->rk[i - nk] ^ t;
    }
}

static inline uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0)); }

void aes_encrypt(const aes_ctx *c, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    /* rk[] words hold the key bytes big-endian; AddRoundKey */
    for (int i = 0; i < 4; i++) {
        uint32_t w = c->rk[i];
        s[4*i+0] = (uint8_t)(in[4*i+0] ^ (w >> 24));
        s[4*i+1] = (uint8_t)(in[4*i+1] ^ (w >> 16));
        s[4*i+2] = (uint8_t)(in[4*i+2] ^ (w >> 8));
        s[4*i+3] = (uint8_t)(in[4*i+3] ^ w);
    }
    for (int r = 1; r <= c->nr; r++) {
        /* SubBytes + ShiftRows */
        uint8_t t[16];
        t[ 0]=AES_S[s[ 0]]; t[ 1]=AES_S[s[ 5]]; t[ 2]=AES_S[s[10]]; t[ 3]=AES_S[s[15]];
        t[ 4]=AES_S[s[ 4]]; t[ 5]=AES_S[s[ 9]]; t[ 6]=AES_S[s[14]]; t[ 7]=AES_S[s[ 3]];
        t[ 8]=AES_S[s[ 8]]; t[ 9]=AES_S[s[13]]; t[10]=AES_S[s[ 2]]; t[11]=AES_S[s[ 7]];
        t[12]=AES_S[s[12]]; t[13]=AES_S[s[ 1]]; t[14]=AES_S[s[ 6]]; t[15]=AES_S[s[11]];
        if (r < c->nr) {
            for (int col = 0; col < 4; col++) {
                uint8_t a0=t[4*col],a1=t[4*col+1],a2=t[4*col+2],a3=t[4*col+3];
                s[4*col+0] = xtime(a0) ^ (xtime(a1)^a1) ^ a2 ^ a3;
                s[4*col+1] = a0 ^ xtime(a1) ^ (xtime(a2)^a2) ^ a3;
                s[4*col+2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3)^a3);
                s[4*col+3] = (xtime(a0)^a0) ^ a1 ^ a2 ^ xtime(a3);
            }
        } else memcpy(s, t, 16);
        for (int i = 0; i < 4; i++) {
            uint32_t w = c->rk[4 * r + i];
            s[4*i+0] ^= (uint8_t)(w >> 24); s[4*i+1] ^= (uint8_t)(w >> 16);
            s[4*i+2] ^= (uint8_t)(w >> 8);  s[4*i+3] ^= (uint8_t)w;
        }
    }
    memcpy(out, s, 16);
}

void winzip_aes_ctr(const aes_ctx *c, const uint8_t *in, uint8_t *out, size_t n) {
    uint8_t ctr[16] = {0}, ks[16];
    uint32_t cnt = 1;
    for (size_t off = 0; off < n; off += 16) {
        ctr[0] = (uint8_t)cnt; ctr[1] = (uint8_t)(cnt >> 8);
        ctr[2] = (uint8_t)(cnt >> 16); ctr[3] = (uint8_t)(cnt >> 24);
        aes_encrypt(c, ctr, ks);
        size_t take = n - off < 16 ? n - off : 16;
        for (size_t i = 0; i < take; i++) out[off + i] = in[off + i] ^ ks[i];
        cnt++;
    }
}

/* ================= high-level checks ================= */
static int aes_key_bits(int enc) { return enc == ZR_ENC_AES128 ? 128 : enc == ZR_ENC_AES192 ? 192 : 256; }
static int aes_saltlen(int enc) { return enc == ZR_ENC_AES128 ? 8 : enc == ZR_ENC_AES192 ? 12 : 16; }

int zr_check_bytes_override = 0;   /* --check-bytes N */

int zr_quick_check2(const zr_archive *z, const uint8_t *pw, int len, zc_cache *cc) {
    const zr_entry *e = &z->entries[z->verify_idx[0]];
    if (e->enc == ZR_ENC_ZIPCRYPTO) {
        /* Byte 11 of the 12-byte header is the only universally valid check
           byte (crc>>24, or modtime>>8 when flag bit3 set). Some writers
           (7-Zip) leave byte 10 random, so a 2-byte filter can reject the
           true password; default stays at 1 byte + cross-entry checks.
           --check-bytes 2 opts into the faster filter for Info-ZIP/WinZip
           archives. */
        uint16_t chk = (e->flags & 8) ? e->modtime : (uint16_t)(e->crc32 >> 16);
        int nbytes = zr_check_bytes_override ? zr_check_bytes_override : 1;
        zc_keys k;
        zc_key_init_cached(&k, pw, len, cc);
        return zc_header_check_k(&k, e->data, chk, nbytes);
    }
    /* WinZip AES: PBKDF2 -> compare 2-byte verifier */
    int kb = aes_key_bits(e->enc);
    int sl = aes_saltlen(e->enc);
    uint8_t dk[80];
    pbkdf2_sha1(pw, len, e->data, sl, 1000, dk, 2 * (kb / 8) + 2);
    return dk[2 * (kb / 8)] == e->data[sl] && dk[2 * (kb / 8) + 1] == e->data[sl + 1];
}

int zr_quick_check(const zr_archive *z, const uint8_t *pw, int len) {
    return zr_quick_check2(z, pw, len, NULL);
}

int zr_full_verify(const zr_archive *z, const uint8_t *pw, int len,
                   uint8_t *workbuf, size_t worklen) {
    const zr_entry *e = &z->entries[z->verify_idx[0]];
    if (e->enc == ZR_ENC_ZIPCRYPTO) {
        /* cross-check the 12-byte headers of up to 2 other entries first */
        for (int i = 1; i < z->n_verify; i++) {
            const zr_entry *o = &z->entries[z->verify_idx[i]];
            if (o->enc != ZR_ENC_ZIPCRYPTO) continue;
            uint16_t chk = (o->flags & 8) ? o->modtime : (uint16_t)(o->crc32 >> 16);
            int nb = (o->flags & 8) ? 1 : 2;
            if (!zc_header_check(pw, len, o->data, chk, nb)) return 0;
        }
        /* decrypt header+body as one stream (header feeds key updates) */
        size_t tlen = (size_t)e->data_len;          /* includes 12-byte header */
        if (worklen < tlen + (size_t)e->usize + 16) return 0;
        zc_decrypt(pw, len, e->data, workbuf, tlen);
        const uint8_t *body = workbuf + 12;
        size_t blen = tlen - 12;
        const uint8_t *plain = body; size_t plen = blen;
        if (e->method == ZR_METHOD_DEFLATE) {
            uint8_t *dst = workbuf + tlen;
            size_t dl = 0;
            if (zr_inflate(body, blen, dst, (size_t)e->usize, &dl) != 0) return 0;
            if (dl != (size_t)e->usize) return 0;
            plain = dst; plen = dl;
        } else if (e->method != ZR_METHOD_STORE) {
            /* unsupported method: header cross-checks already applied */
            return 1;
        }
        if (plen != (size_t)e->usize && e->method == ZR_METHOD_STORE) return 0;
        return zr_crc32(plain, plen) == e->crc32;
    }
    /* WinZip AE: verifier check, then encrypt-then-MAC auth:
       auth_code = HMAC-SHA1(auth_key, ciphertext)[0:10]  */
    int kb = aes_key_bits(e->enc), sl = aes_saltlen(e->enc);
    uint8_t dk[80];
    pbkdf2_sha1(pw, len, e->data, sl, 1000, dk, 2 * (kb / 8) + 2);
    if (dk[2 * (kb / 8)] != e->data[sl] || dk[2 * (kb / 8) + 1] != e->data[sl + 1]) return 0;
    size_t ctlen = (size_t)e->data_len - (size_t)sl - 2 - 10;
    const uint8_t *ct = e->data + sl + 2;
    uint8_t mac[20];
    hmac_sha1(dk + kb / 8, kb / 8, ct, ctlen, mac);
    if (memcmp(mac, ct + ctlen, 10)) return 0;
    /* definitive proof already; additionally decrypt + inflate to prove
       real decompression works (cheap, runs once on success) */
    if (worklen < ctlen + (size_t)e->usize + 16) return 1;  /* HMAC match = confirmed */
    aes_ctx ac;
    aes_setkey(&ac, dk, kb);
    winzip_aes_ctr(&ac, ct, workbuf, ctlen);
    if (e->real_method == ZR_METHOD_DEFLATE) {
        uint8_t *dst = workbuf + ctlen;
        size_t dl = 0;
        return zr_inflate(workbuf, ctlen, dst, (size_t)e->usize, &dl) == 0;
    }
    return 1;
}

size_t zr_verify_worksize(const zr_archive *z) {
    const zr_entry *e = &z->entries[z->verify_idx[0]];
    return (size_t)e->data_len + (size_t)e->usize + 64;
}

/* ================= crypto self-test ================= */
static int selftest(void) {
    /* SHA-1("abc") */
    sha1_ctx c; uint8_t d[20];
    static const uint8_t exp[20] = {0xa9,0x99,0x3e,0x36,0x47,0x06,0x81,0x6a,0xba,0x3e,
                                    0x25,0x71,0x78,0x50,0xc2,0x6c,0x9c,0xd0,0xd8,0x9d};
    sha1_init(&c); sha1_update(&c, "abc", 3); sha1_final(&c, d);
    if (memcmp(d, exp, 20)) return -1;
    /* PBKDF2-HMAC-SHA1 RFC 6070: P="password", S="salt", c=1, dkLen=20
       -> 0c60c80f961f0e71f3a9b524af6012062fe037a6 */
    static const uint8_t expb[20] = {0x0c,0x60,0xc8,0x0f,0x96,0x1f,0x0e,0x71,0xf3,0xa9,
                                     0xb5,0x24,0xaf,0x60,0x12,0x06,0x2f,0xe0,0x37,0xa6};
    pbkdf2_sha1((const uint8_t *)"password", 8, (const uint8_t *)"salt", 4, 1, d, 20);
    if (memcmp(d, expb, 20)) return -2;
    /* AES-256 FIPS-197 vector */
    uint8_t key[32] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
                       0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
    uint8_t pt[16]  = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    static const uint8_t ct_exp[16] = {0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,
                                       0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89};
    aes_ctx a; aes_setkey(&a, key, 256); aes_encrypt(&a, pt, d);
    if (memcmp(d, ct_exp, 16)) return -3;
    return 0;
}

void zr_crypto_init(void) {
    zr_crc32_init();
#ifdef ZR_HAVE_X86_SHA1
    if (cpu_has_shani()) {
        zr_sha1_compress = sha1_compress_shani;
        sha1_backend_name = "x86 SHA-NI";
    }
#endif
#ifdef ZR_HAVE_ARM_SHA1
    zr_sha1_compress = sha1_compress_arm;
    sha1_backend_name = "ARMv8 SHA";
#endif
    /* correctness gate: fall back to portable if the SIMD path is wrong */
    int rc = selftest();
    if (rc != 0) {
        zr_sha1_compress = sha1_compress_portable;
        sha1_backend_name = "portable (SIMD selftest failed)";
        if (selftest() != 0) {
            fprintf(stderr, "fatal: crypto self-test failed\n");
            exit(3);
        }
    }
}
