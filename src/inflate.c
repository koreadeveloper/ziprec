/*
 * inflate.c - minimal DEFLATE decompressor (RFC 1951), used only for
 * final verification of a cracked password. Not optimized for speed;
 * correctness and bounded memory use only.
 */
#include "crypto.h"
#include <string.h>

typedef struct {
    const uint8_t *in; size_t inlen, inpos;
    uint8_t *out; size_t outcap, outpos;
    uint32_t bitbuf; int bitcnt;
} inf;

static int need(inf *s, int n) { /* pull n bits into bitbuf, LSB-first */
    while (s->bitcnt < n) {
        if (s->inpos >= s->inlen) return -1;
        s->bitbuf |= (uint32_t)s->in[s->inpos++] << s->bitcnt;
        s->bitcnt += 8;
    }
    return 0;
}
static int bits(inf *s, int n) {
    if (need(s, n)) return -1;
    int v = (int)(s->bitbuf & ((1u << n) - 1));
    s->bitbuf >>= n; s->bitcnt -= n;
    return v;
}
static int put(inf *s, uint8_t b) {
    if (s->outpos >= s->outcap) return -1;
    s->out[s->outpos++] = b;
    return 0;
}

/* canonical huffman table */
typedef struct { uint16_t cnt[16]; uint16_t sym[320]; } huff;
static void huff_build(huff *h, const uint8_t *lens, int n) {
    memset(h->cnt, 0, sizeof h->cnt);
    for (int i = 0; i < n; i++) h->cnt[lens[i]]++;
    h->cnt[0] = 0;
    uint16_t offs[16], off = 0;
    for (int i = 1; i < 16; i++) { offs[i] = off; off = (uint16_t)(off + h->cnt[i]); }
    for (int i = 0; i < n; i++) if (lens[i]) h->sym[offs[lens[i]]++] = (uint16_t)i;
}
/* decode one symbol; returns symbol or -1 */
static int huff_dec(inf *s, const huff *h) {
    uint32_t code = 0, first = 0; int index = 0;
    for (int len = 1; len < 16; len++) {
        int b = bits(s, 1);
        if (b < 0) return -1;
        code |= (uint32_t)b;
        int cnt = h->cnt[len];
        if (code - first < (uint32_t)cnt) return h->sym[index + (int)(code - first)];
        index += cnt; first = (first + cnt) << 1; code <<= 1;
    }
    return -1;
}

static const uint16_t LBASE[29] = {3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258};
static const uint8_t  LEXT[29]  = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
static const uint16_t DBASE[30] = {1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577};
static const uint8_t DEXT[30]  = {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};
static const uint8_t CLORD[19] = {16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15};

static int block(inf *s, const huff *lh, const huff *dh) {
    for (;;) {
        int sym = huff_dec(s, lh);
        if (sym < 0) return -1;
        if (sym < 256) { if (put(s, (uint8_t)sym)) return -1; continue; }
        if (sym == 256) return 0;
        sym -= 257;
        if (sym >= 29) return -1;
        int len = LBASE[sym], eb = LEXT[sym];
        if (eb) { int x = bits(s, eb); if (x < 0) return -1; len += x; }
        int dsym = huff_dec(s, dh);
        if (dsym < 0 || dsym >= 30) return -1;
        int dist = DBASE[dsym]; eb = DEXT[dsym];
        if (eb) { int x = bits(s, eb); if (x < 0) return -1; dist += x; }
        if ((size_t)dist > s->outpos || s->outpos + (size_t)len > s->outcap) return -1;
        for (int i = 0; i < len; i++) {
            s->out[s->outpos] = s->out[s->outpos - (size_t)dist];
            s->outpos++;
        }
    }
}

int zr_inflate(const uint8_t *src, size_t srclen, uint8_t *dst, size_t dstcap, size_t *dstlen) {
    inf s; memset(&s, 0, sizeof s);
    s.in = src; s.inlen = srclen; s.out = dst; s.outcap = dstcap;
    for (;;) {
        int last = bits(&s, 1), type = bits(&s, 2);
        if (last < 0 || type < 0) return -1;
        if (type == 0) {
            s.bitbuf = 0; s.bitcnt = 0;
            if (s.inpos + 4 > s.inlen) return -1;
            int len = zr_rd16(s.in + s.inpos);
            if (zr_rd16(s.in + s.inpos + 2) != (uint16_t)~len) return -1;
            s.inpos += 4;
            if (s.inpos + (size_t)len > s.inlen || s.outpos + (size_t)len > s.outcap) return -1;
            memcpy(s.out + s.outpos, s.in + s.inpos, (size_t)len);
            s.inpos += len; s.outpos += (size_t)len;
        } else {
            huff lh, dh;
            if (type == 1) {
                uint8_t lens[288], dl[30];
                for (int i = 0; i < 144; i++) lens[i] = 8;
                for (int i = 144; i < 256; i++) lens[i] = 9;
                for (int i = 256; i < 280; i++) lens[i] = 7;
                for (int i = 280; i < 288; i++) lens[i] = 8;
                for (int i = 0; i < 30; i++) dl[i] = 5;
                huff_build(&lh, lens, 288);
                huff_build(&dh, dl, 30);
            } else if (type == 2) {
                int hlit = bits(&s, 5), hdist = bits(&s, 5), hclen = bits(&s, 4);
                if (hlit < 0 || hdist < 0 || hclen < 0) return -1;
                hlit += 257; hdist += 1; hclen += 4;
                if (hlit > 286 || hdist > 30) return -1;
                uint8_t cl[19]; memset(cl, 0, sizeof cl);
                for (int i = 0; i < hclen; i++) { int v = bits(&s, 3); if (v < 0) return -1; cl[CLORD[i]] = (uint8_t)v; }
                huff ch; huff_build(&ch, cl, 19);
                uint8_t lens[320]; int n = 0, total = hlit + hdist;
                while (n < total) {
                    int sym = huff_dec(&s, &ch);
                    if (sym < 0) return -1;
                    if (sym < 16) lens[n++] = (uint8_t)sym;
                    else {
                        int rep, val = 0;
                        if (sym == 16) { if (!n) return -1; val = lens[n - 1]; int x = bits(&s, 2); if (x < 0) return -1; rep = 3 + x; }
                        else if (sym == 17) { int x = bits(&s, 3); if (x < 0) return -1; rep = 3 + x; }
                        else { int x = bits(&s, 7); if (x < 0) return -1; rep = 11 + x; }
                        if (n + rep > total) return -1;
                        while (rep--) lens[n++] = (uint8_t)val;
                    }
                }
                huff_build(&lh, lens, hlit);
                huff_build(&dh, lens + hlit, hdist);
            } else return -1;
            if (block(&s, &lh, &dh)) return -1;
        }
        if (last) break;
    }
    *dstlen = s.outpos;
    return 0;
}
