/*
 * gpu.h - delegate cracking to hashcat when a supported GPU is present.
 * We extract the hash in hashcat format and spawn `hashcat` with attack
 * parameters derived from the user's strategy. Result is read back from
 * hashcat's -o output file. Fully offline; requires hashcat installed.
 */
#ifndef ZR_GPU_H
#define ZR_GPU_H

#include "zipfile.h"
#include "gen.h"

/* Run hashcat against the archive's primary target.
 * strategy args mirror the CLI: dict path / mask / brute range.
 * Returns: 1 found (pw written into out/outlen), 0 not found, -1 error. */
int zr_gpu_run(const zr_archive *z, const char *dict_path, const char *mask,
               int brute, const uint8_t *cs, int csn, int minl, int maxl,
               const char *extra_args, char *out, int outlen, char *err, size_t el);

int zr_gpu_available(void);   /* hashcat binary found in PATH */

#endif
