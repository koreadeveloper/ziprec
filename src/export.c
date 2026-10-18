/*
 * export.c - hash extraction.
 *
 * WinZip AES  -> "$zip2$*0*MODE*0*<salthex>*<pvhex>*0**<auth10hex>*$/zip2$"
 *                identical to zip2john output; accepted by John (zip format)
 *                and hashcat -m 13600.
 * ZipCrypto   -> "$pkzip2$<n>*1*2*0*<clen>*<ulen>*<crc>*0*<off>*<icount>*<misc>
 *                *<cdata-hex>*$/pkzip2$" (John's pkzip2 format). For hashcat
 *                the -m 17200 family expects a closely related $pkzip2$ line.
 *
 * Format reference: john's zip2john.c and hashcat module_13600/17200.
 * Verified in tests by cracking our own output with `john`.
 */
#include "export.h"
#include <string.h>
#include <stdio.h>

static char *hex(char *o, const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) { snprintf(o, 3, "%02x", p[i]); o += 2; }
    return o;
}

const char *zr_export_mode(const zr_archive *z, int for_hashcat) {
    const zr_entry *e = &z->entries[z->verify_idx[0]];
    if (for_hashcat) {
        if (e->enc >= ZR_ENC_AES128) return "13600";            /* WinZip */
        return e->method == ZR_METHOD_DEFLATE ? "17200" : "17210"; /* PKZIP compr/stored */
    }
    if (e->enc >= ZR_ENC_AES128) return "zip";
    return e->method == ZR_METHOD_DEFLATE ? "pkzip" : "zip";
}

int zr_export_hash(const zr_archive *z, char *out, size_t outlen,
                   char *tool, size_t tool_len) {
    return zr_export_hash_ent(z, z->verify_idx[0], out, outlen, tool, tool_len);
}

int zr_export_hash_ent(const zr_archive *z, int ent_idx, char *out, size_t outlen,
                       char *tool, size_t tool_len) {
    const zr_entry *e = &z->entries[ent_idx];
    char *o = out, *end = out + outlen - 2;

    if (e->enc >= ZR_ENC_AES128) {
        int mode = e->enc - ZR_ENC_AES128 + 1;   /* 1/2/3 */
        int sl = e->enc == ZR_ENC_AES128 ? 8 : e->enc == ZR_ENC_AES192 ? 12 : 16;
        size_t ct = (size_t)e->data_len - (size_t)sl - 2 - 10;
        o += snprintf(o, (size_t)(end - o), "%s:$zip2$*0*%d*0*", e->name, mode);
        o = hex(o, e->data, (size_t)sl);                    /* salt */
        *o++ = '*';
        o = hex(o, e->data + sl, 2);                        /* verifier */
        if ((size_t)(end - o) > ct * 2 + 32) {
            o += snprintf(o, (size_t)(end - o), "*%zx*", ct); /* inline data form */
            o = hex(o, e->data + sl + 2, ct);
        } else {
            o += snprintf(o, (size_t)(end - o), "*0*");       /* short form, no data */
        }
        *o++ = '*';
        o = hex(o, e->data + sl + 2 + ct, 10);              /* auth code */
        o += snprintf(o, (size_t)(end - o), "*$/zip2$");
        snprintf(tool, tool_len, "hashcat -m 13600 | john --format=zip");
    } else {
        /* $pkzip2$C*B*[DT*MT*CL*UL*CR*OF*OX*CT*DL*CS*TC*DA]*$/pkzip2$
           C=1 single hash, B=2/1 valid checksum bytes (version<20 -> 2),
           DT=2 inline data, MT=0, OF/OX locate blob, CT=0 store / 8 deflate,
           CS=crc>>16 (BE hex), TC=modtime (BE hex), DA=full blob hex.   */
        int b = e->version >= 20 ? 1 : 2;
        size_t cl = (size_t)e->data_len;
        o += snprintf(o, (size_t)(end - o),
                      "%s:$pkzip2$1*%x*2*0*%zx*%zx*%x*%llx*%llx*%x*%zx*%04x*%04x*",
                      e->name, b, cl, (size_t)e->usize, e->crc32,
                      (unsigned long long)e->lho, (unsigned long long)e->data_off,
                      e->method, cl, (e->crc32 >> 16) & 0xffff, e->modtime);
        o = hex(o, e->data, cl);
        o += snprintf(o, (size_t)(end - o), "*$/pkzip2$");
        snprintf(tool, tool_len, "john | hashcat -m %s",
                 e->method == ZR_METHOD_DEFLATE ? "17200" : "17210");
    }
    *o = 0;
    return 0;
}

int zr_gpu_pick_entry(const zr_archive *z) {
    int prim = z->verify_idx[0];
    if (z->entries[prim].enc != ZR_ENC_ZIPCRYPTO) return prim;   /* AES: any */
    for (int i = 0; i < z->n_entries; i++)
        if (z->entries[i].enc == ZR_ENC_ZIPCRYPTO &&
            z->entries[i].method == ZR_METHOD_STORE) return i;
    return prim;
}
