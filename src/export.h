/*
 * export.h - emit extracted hashes in formats understood by
 * John the Ripper (zip2john style) and hashcat (-m 13600 / -m 172xx),
 * so a user with a supported GPU can hand the job to a proven engine.
 */
#ifndef ZR_EXPORT_H
#define ZR_EXPORT_H

#include "zipfile.h"

/* writes the hash line for the primary target entry to `out` (must be >= 64KB).
 * Returns 0 on success. */
int zr_export_hash(const zr_archive *z, char *out, size_t outlen,
                   char *tool, size_t tool_len);
/* same, but exports a specific entry index (for stored-entry GPU preference) */
int zr_export_hash_ent(const zr_archive *z, int ent_idx, char *out, size_t outlen,
                       char *tool, size_t tool_len);
/* pick a stored ZipCrypto entry for delegation when possible (17210 is the
   only PKZIP mode that works on Apple GPU drivers); returns verify_idx[0]
   when no stored entry exists or the archive is AES */
int zr_gpu_pick_entry(const zr_archive *z);
/* returns suggested hashcat -m number, or john format name */
const char *zr_export_mode(const zr_archive *z, int for_hashcat);

#endif
