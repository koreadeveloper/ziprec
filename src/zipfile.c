/*
 * zipfile.c - ZIP parsing per APPNOTE 6.x.
 *
 * Layout targets:
 *   Local header      sig 0x04034b50
 *   Central directory sig 0x02014b50
 *   EOCD              sig 0x06054b50  (scanned from tail, last 64 KiB + sig)
 *   ZIP64 EOCD locator 0x07064b50 / record 0x06064b50
 *   AES extra field   tag 0x9901
 */
#include "zipfile.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static int aes_salt_len(int strength) { return strength == 1 ? 8 : strength == 2 ? 12 : 16; }

const char *zr_enc_name(int enc) {
    switch (enc) {
    case ZR_ENC_ZIPCRYPTO: return "ZipCrypto (PKWARE)";
    case ZR_ENC_AES128:    return "WinZip AES-128";
    case ZR_ENC_AES192:    return "WinZip AES-192";
    case ZR_ENC_AES256:    return "WinZip AES-256";
    default:               return "none";
    }
}

/* read exactly n bytes at offset; returns 0 on success */
static int read_at(FILE *f, uint64_t off, void *buf, size_t n) {
    if (fseek(f, (long)off, SEEK_SET)) return -1;
    return fread(buf, 1, n, f) == n ? 0 : -1;
}

/* Parse AES extra field (0x9901). Returns strength 1..3 or 0. */
static int parse_aes_extra(const uint8_t *ex, int exlen, int *ae_ver, uint16_t *real_method) {
    for (int i = 0; i + 4 <= exlen;) {
        uint16_t tag = zr_rd16(ex + i), len = zr_rd16(ex + i + 2);
        if (tag == 0x9901 && len >= 7) {
            *ae_ver      = zr_rd16(ex + i + 4);          /* AE-1 or AE-2 */
            int strength = ex[i + 8];                    /* 1/2/3 */
            *real_method = zr_rd16(ex + i + 9);
            return strength;
        }
        i += 4 + len;
    }
    return 0;
}

/* Load encrypted payload for entry at local header offset lho. */
static int load_entry_data(FILE *f, zr_entry *e, uint64_t lho, uint64_t fsize, char *err, size_t el) {
    uint8_t lh[30];
    if (read_at(f, lho, lh, 30) || zr_rd32(lh) != 0x04034b50) {
        snprintf(err, el, "invalid local header for '%s'", e->name);
        return -1;
    }
    uint16_t fnl = zr_rd16(lh + 26), exl = zr_rd16(lh + 28);
    uint64_t data_off = lho + 30 + fnl + exl;
    e->version = zr_rd16(lh + 4);
    e->lho = lho;
    e->data_off = data_off;

    uint64_t need;
    if (e->enc == ZR_ENC_ZIPCRYPTO) {
        if (e->csize < 12) { snprintf(err, el, "'%s' too small for ZipCrypto header", e->name); return -1; }
        need = e->csize;                       /* 12-byte header + ciphertext */
    } else {
        int slen = aes_salt_len(e->enc);       /* enc 2/3/4 -> strength 1/2/3 */
        need = e->csize;                       /* salt+pv+ct+auth */
        if (e->csize < (uint64_t)(slen + 2 + 10)) { snprintf(err, el, "'%s' too small for AES fields", e->name); return -1; }
    }
    if (data_off + need > fsize) { snprintf(err, el, "'%s' data truncated", e->name); return -1; }

    e->data = malloc((size_t)need);
    if (!e->data) { snprintf(err, el, "out of memory"); return -1; }
    e->data_len = need;
    if (read_at(f, data_off, e->data, (size_t)need)) {
        snprintf(err, el, "failed reading '%s' data", e->name);
        free(e->data); e->data = NULL;
        return -1;
    }
    return 0;
}

int zr_zip_load(zr_archive *z, const char *path, char *err, size_t el) {
    memset(z, 0, sizeof(*z));
    snprintf(z->path, sizeof(z->path), "%s", path);

    struct stat st;
    if (stat(path, &st) || !S_ISREG(st.st_mode)) { snprintf(err, el, "cannot stat '%s'", path); return -1; }
    z->size  = (uint64_t)st.st_size;
    z->mtime = (uint64_t)st.st_mtime;

    FILE *f = fopen(path, "rb");
    if (!f) { snprintf(err, el, "cannot open '%s'", path); return -1; }

    /* locate EOCD in last 64 KiB */
    uint64_t scan = z->size < 66000 ? z->size : 66000;
    uint8_t *tail = malloc((size_t)scan);
    if (!tail || read_at(f, z->size - scan, tail, (size_t)scan)) {
        free(tail); fclose(f);
        snprintf(err, el, "failed reading file tail");
        return -1;
    }
    long eocd = -1;
    for (long i = (long)scan - 22; i >= 0; i--)
        if (zr_rd32(tail + i) == 0x06054b50) { eocd = i; break; }
    if (eocd < 0) { free(tail); fclose(f); snprintf(err, el, "not a ZIP file (no EOCD)"); return -1; }

    uint16_t cd_count = zr_rd16(tail + eocd + 10);
    uint64_t cd_off   = zr_rd32(tail + eocd + 16);
    uint64_t cd_size  = zr_rd32(tail + eocd + 12);
    free(tail);

    /* ZIP64 if fields are saturated */
    if (cd_count == 0xFFFF || cd_off == 0xFFFFFFFF) {
        uint8_t loc[20];
        uint64_t locoff = z->size - scan + eocd - 20;
        if (!read_at(f, locoff, loc, 20) && zr_rd32(loc) == 0x07064b50) {
            uint64_t eocd64 = zr_rd64(loc + 8);
            uint8_t rec[56];
            if (!read_at(f, eocd64, rec, 56) && zr_rd32(rec) == 0x06064b50) {
                cd_count = (uint16_t)zr_rd64(rec + 32);
                cd_off   = zr_rd64(rec + 48);
            }
        }
    }
    if (cd_count > ZR_MAX_ENTRIES) cd_count = ZR_MAX_ENTRIES; /* parse first N; target may be chosen among them */
    (void)cd_size;

    /* walk central directory */
    uint8_t hdr[46];
    for (int i = 0; i < (int)cd_count; i++) {
        if (read_at(f, cd_off, hdr, 46) || zr_rd32(hdr) != 0x02014b50) break;
        uint16_t fnl = zr_rd16(hdr + 28), exl = zr_rd16(hdr + 30), cml = zr_rd16(hdr + 32);
        zr_entry *e = &z->entries[z->n_entries];
        memset(e, 0, sizeof(*e));

        e->flags   = zr_rd16(hdr + 8);
        e->method  = zr_rd16(hdr + 10);
        e->modtime = zr_rd16(hdr + 12);
        e->crc32   = zr_rd32(hdr + 16);
        e->csize   = zr_rd32(hdr + 20);
        e->usize   = zr_rd32(hdr + 24);
        uint64_t lho = zr_rd32(hdr + 42);

        /* ZIP64 sizes may sit in the extra field */
        uint8_t *extra = NULL;
        if (exl) {
            extra = malloc(exl);
            if (extra && read_at(f, cd_off + 46 + fnl, extra, exl)) { free(extra); extra = NULL; }
        }
        if (e->usize == 0xFFFFFFFF || e->csize == 0xFFFFFFFF || lho == 0xFFFFFFFF) {
            for (int k = 0; extra && k + 4 <= exl;) {
                uint16_t tag = zr_rd16(extra + k), len = zr_rd16(extra + k + 2);
                if (tag == 0x0001) {
                    const uint8_t *p = extra + k + 4;
                    if (e->usize == 0xFFFFFFFF) { e->usize = zr_rd64(p); p += 8; }
                    if (e->csize == 0xFFFFFFFF) { e->csize = zr_rd64(p); p += 8; }
                    if (lho == 0xFFFFFFFF)      { lho = zr_rd64(p); }
                    break;
                }
                k += 4 + len;
            }
        }

        uint8_t nbuf[ZR_MAX_NAME];
        if (read_at(f, cd_off + 46, nbuf, fnl < ZR_MAX_NAME - 1 ? fnl : ZR_MAX_NAME - 1)) { free(extra); break; }
        nbuf[fnl < ZR_MAX_NAME - 1 ? fnl : ZR_MAX_NAME - 1] = 0;
        snprintf(e->name, sizeof(e->name), "%s", (char *)nbuf);

        if (!(e->flags & 1)) {
            e->enc = ZR_ENC_NONE;
        } else if (e->method == ZR_METHOD_AES) {
            int ae_ver = 0; uint16_t rm = 0;
            int strength = parse_aes_extra(extra, exl, &ae_ver, &rm);
            if (strength >= 1 && strength <= 3) {
                e->enc = ZR_ENC_AES128 + strength - 1;
                e->ae_version = ae_ver;
                e->real_method = rm;
            } else {
                e->enc = ZR_ENC_ZIPCRYPTO; /* AES marked but no 0x9901: treat as unknown encrypted */
            }
        } else {
            e->enc = ZR_ENC_ZIPCRYPTO;
        }

        if (e->enc != ZR_ENC_NONE) {
            z->n_encrypted++;
            load_entry_data(f, e, lho, z->size, err, el); /* soft-fail: keep parsing */
        }
        free(extra);
        z->n_entries++;
        cd_off += 46 + fnl + exl + cml;
        if (z->n_entries >= ZR_MAX_ENTRIES) break;
    }
    fclose(f);

    if (!z->n_entries) { snprintf(err, el, "no entries parsed"); return -1; }
    if (!z->n_encrypted) { snprintf(err, el, "no encrypted entries"); return -1; }

    /* pick verification targets: smallest encrypted entries with data loaded */
    for (int rep = 0; rep < 3; rep++) {
        int best = -1;
        for (int i = 0; i < z->n_entries; i++) {
            zr_entry *e = &z->entries[i];
            if (e->enc == ZR_ENC_NONE || !e->data) continue;
            int used = 0;
            for (int j = 0; j < rep; j++) if (z->verify_idx[j] == i) used = 1;
            if (used) continue;
            if (best < 0 || e->data_len < z->entries[best].data_len) best = i;
        }
        if (best < 0) break;
        z->verify_idx[z->n_verify++] = best;
    }
    return z->n_verify ? 0 : -1;
}

void zr_zip_free(zr_archive *z) {
    for (int i = 0; i < z->n_entries; i++) { free(z->entries[i].data); z->entries[i].data = NULL; }
}
