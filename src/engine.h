/*
 * engine.h - parallel search engine.
 *
 * Work distribution: one global atomic cursor hands out index chunks.
 * Each worker generates candidates locally and runs zr_quick_check;
 * survivors go through zr_full_verify. The cursor value doubles as
 * the checkpoint position.
 */
#ifndef ZR_ENGINE_H
#define ZR_ENGINE_H

#include "platform.h"
#include "zipfile.h"
#include "gen.h"

typedef struct {
    const zr_archive *z;
    const gen_t      *g;
    uint64_t  start;
    uint64_t  total;
    int       nthreads;
    uint64_t  chunk;
    zr_atomic_u64 cursor;   /* next index to hand out */
    zr_atomic_u64 done;     /* candidates fully processed */
    zr_atomic_u64 hits;     /* passed quick check */
    zr_atomic_u64 verified; /* ran full verify */
    zr_atomic_u64 found;    /* !=0 when password confirmed */
    zr_atomic_u64 quit;     /* signal-requested stop */
    uint8_t   found_pw[ZR_MAX_PWLEN + 1];
    int       found_len;
    uint64_t  found_idx;
    zr_mutex_t found_mu;
    /* live candidate display: worker 0 mirrors its current pw here
       (cosmetic; torn reads are acceptable for a progress hint) */
    uint8_t   cur_pw[ZR_MAX_PWLEN + 1];
    int       cur_len;
    double    t_start, t_end;
} engine_t;

void engine_run(engine_t *e);

/* request cooperative stop (Ctrl-C handler) */
static inline void engine_stop(engine_t *e) { zr_atomic_store(&e->quit, 1); }

#endif
