/* unit.c - direct unit tests for crypto/verify paths */
#include "../src/platform.h"
#include "../src/zipfile.h"
#include "../src/crypto.h"
#include "../src/gen.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static zr_archive z;

int main(int argc, char **argv) {
    zr_crypto_init();
    if (argc < 3) { fprintf(stderr, "usage: %s file.zip password\n", argv[0]); return 2; }
    char err[256];
    if (zr_zip_load(&z, argv[1], err, sizeof err)) { fprintf(stderr, "load: %s\n", err); return 1; }
    const zr_entry *e = &z.entries[z.verify_idx[0]];
    printf("entry %s enc=%d flags=%x crc=%08x method=%d data_len=%llu\n",
           e->name, e->enc, e->flags, e->crc32, e->method, (unsigned long long)e->data_len);
    printf("data[0..15]: ");
    for (int i = 0; i < 16 && i < (int)e->data_len; i++) printf("%02x", e->data[i]);
    printf("\n");

    const char *pw = argv[2];
    int qc = zr_quick_check(&z, (const uint8_t *)pw, (int)strlen(pw));
    printf("quick_check(%s) = %d\n", pw, qc);
    size_t wl = zr_verify_worksize(&z);
    uint8_t *wb = malloc(wl);
    int fv = zr_full_verify(&z, (const uint8_t *)pw, (int)strlen(pw), wb, wl);
    printf("full_verify(%s) = %d\n", pw, fv);
    /* sanity: wrong password should fail */
    int wq = zr_quick_check(&z, (const uint8_t *)"zzz_wrong", 9);
    int wf = zr_full_verify(&z, (const uint8_t *)"zzz_wrong", 9, wb, wl);
    printf("wrong: quick=%d full=%d (expect 0 0)\n", wq, wf);

    /* generator sanity: mask ?l?d -> idx0 "a0", idx25 "z0", idx26 "a1" */
    gen_t g;
    if (!gen_init_mask(&g, "?l?d", err, sizeof err)) {
        uint8_t o[64];
        int l0 = gen_at(&g, 0, o);   o[l0] = 0; printf("mask[0]=%s\n", o);
        int l25 = gen_at(&g, 25, o); o[l25] = 0; printf("mask[25]=%s\n", o);
        int l26 = gen_at(&g, 26, o); o[l26] = 0; printf("mask[26]=%s\n", o);
        printf("total=%llu (expect 260)\n", (unsigned long long)g.total);
    }
    return 0;
}
