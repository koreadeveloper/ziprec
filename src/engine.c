#include "engine.h"
#include "crypto.h"
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
static unsigned __stdcall worker(void *arg);
#else
static void *worker(void *arg);
#endif

typedef struct {
    engine_t *e;
    uint8_t  *workbuf;
    size_t    worklen;
    zc_cache  cc;          /* ZipCrypto prefix cache (per worker) */
    int       slot;        /* worker index; 0 also mirrors cur_pw */
} worker_ctx;

#if defined(_WIN32)
static unsigned __stdcall worker(void *arg)
#else
static void *worker(void *arg)
#endif
{
    worker_ctx *wc = arg;
    engine_t *e = wc->e;
    uint8_t pw[ZR_MAX_PWLEN + 4];
    zc_cache_init(&wc->cc);

    for (;;) {
        if (zr_atomic_load(&e->quit) || zr_atomic_load(&e->found)) return 0;
        uint64_t base = zr_atomic_fetch_add(&e->cursor, e->chunk);
        if (base >= e->total) break;
        uint64_t end = base + e->chunk;
        if (end > e->total) end = e->total;

        gen_cur_t gc;
        gen_cur_seek(e->g, base, &gc);
        for (uint64_t i = base; i < end; i++) {
            int len = gen_cur_emit(e->g, &gc, pw);
            gen_cur_advance(e->g, &gc);
            if (len < 0) break;      /* space exhausted early */
            if (!len) continue;
            if (wc->slot == 0 && (i & 0x3ff) == 0) {   /* ~1024th: display */
                memcpy(e->cur_pw, pw, (size_t)len);
                e->cur_pw[len] = 0;
                e->cur_len = len;
            }
            if (!zr_quick_check2(e->z, pw, len, &wc->cc)) continue;
            zr_atomic_add(&e->hits, 1);
            zr_atomic_add(&e->verified, 1);
            if (zr_full_verify(e->z, pw, len, wc->workbuf, wc->worklen)) {
                zr_mutex_lock(&e->found_mu);
                if (!zr_atomic_load(&e->found)) {
                    memcpy(e->found_pw, pw, (size_t)len);
                    e->found_pw[len] = 0;
                    e->found_len = len;
                    e->found_idx = i;
                }
                zr_mutex_unlock(&e->found_mu);
                zr_atomic_store(&e->found, 1);
                return 0;
            }
        }
        zr_atomic_add(&e->done, end - base);
    }
    return 0;
}

static uint64_t default_chunk(const zr_archive *z) {
    const zr_entry *e = &z->entries[z->verify_idx[0]];
    return e->enc == ZR_ENC_ZIPCRYPTO ? 1u << 16 : 1u << 8;
}

void engine_run(engine_t *e) {
    zr_atomic_store(&e->cursor, e->start);
    zr_atomic_store(&e->done, 0);
    zr_atomic_store(&e->hits, 0);
    zr_atomic_store(&e->verified, 0);
    zr_atomic_store(&e->found, 0);
    zr_atomic_store(&e->quit, 0);
    zr_mutex_init(&e->found_mu);
    if (!e->chunk) e->chunk = default_chunk(e->z);
    e->t_start = zr_now();

    size_t wl = zr_verify_worksize(e->z);
    zr_thread_t *ths = malloc(sizeof(zr_thread_t) * (size_t)e->nthreads);
    worker_ctx *wcs = malloc(sizeof(worker_ctx) * (size_t)e->nthreads);
    for (int i = 0; i < e->nthreads; i++) {
        wcs[i].e = e;
        wcs[i].workbuf = malloc(wl);
        wcs[i].worklen = wl;
        wcs[i].slot = i;
        zr_thread_create(&ths[i], worker, &wcs[i]);
    }
    for (int i = 0; i < e->nthreads; i++) {
        zr_thread_join(ths[i]);
        free(wcs[i].workbuf);
    }
    free(ths); free(wcs);
    e->t_end = zr_now();
    zr_mutex_destroy(&e->found_mu);
}
