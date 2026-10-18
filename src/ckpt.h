/*
 * ckpt.h - checkpoint save/restore. Text format, atomic rename.
 * The generator index fully determines resume position.
 */
#ifndef ZR_CKPT_H
#define ZR_CKPT_H

#include "platform.h"

typedef struct {
    char     file[4096];
    uint64_t fsize, fmtime;
    char     params[512];
    uint64_t next;
    uint64_t done_at_save;
} zr_ckpt;

int zr_ckpt_save(const char *path, const zr_ckpt *c);
int zr_ckpt_load(const char *path, zr_ckpt *c);

#endif
