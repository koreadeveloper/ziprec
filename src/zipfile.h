/*
 * zipfile.h - ZIP archive parsing and encryption identification.
 *
 * Reads only the bytes needed for recovery:
 *   - end-of-central-directory record
 *   - central directory entry metadata
 *   - for each selected entry: local header + the smallest possible
 *     amount of encrypted payload needed for verification
 */
#ifndef ZR_ZIPFILE_H
#define ZR_ZIPFILE_H

#include "platform.h"

#define ZR_ENC_NONE      0
#define ZR_ENC_ZIPCRYPTO 1
#define ZR_ENC_AES128    2
#define ZR_ENC_AES192    3
#define ZR_ENC_AES256    4

#define ZR_METHOD_DEFLATE 8
#define ZR_METHOD_STORE   0
#define ZR_METHOD_AES     99

#define ZR_MAX_ENTRIES 256
#define ZR_MAX_NAME    512

typedef struct {
    char     name[ZR_MAX_NAME];
    uint16_t flags;
    uint16_t version;       /* "version needed" from local header */
    uint16_t method;        /* outer method (99 = WinZip AES wrapper) */
    uint16_t real_method;   /* for AES: actual method from 0x9901 extra */
    uint16_t modtime;
    uint64_t lho;           /* local header offset */
    uint64_t data_off;      /* encrypted blob offset within file */
    uint32_t crc32;
    uint64_t csize;         /* compressed size (incl. crypto overhead) */
    uint64_t usize;
    int      enc;           /* ZR_ENC_* */
    int      ae_version;    /* 1 or 2 for AES entries */
    /* payload bytes: ZipCrypto -> 12-byte header + ciphertext.
       AES -> salt || 2-byte verifier || ciphertext || 10-byte auth code. */
    uint8_t *data;
    uint64_t data_len;
} zr_entry;

typedef struct {
    char     path[4096];
    uint64_t size;
    uint64_t mtime;
    zr_entry entries[ZR_MAX_ENTRIES];
    int      n_entries;
    int      n_encrypted;
    /* up to 3 verification targets, indexes into entries[]:
       primary = smallest encrypted entry; secondaries used for
       cheap cross-checks when full verification is not possible */
    int      verify_idx[3];
    int      n_verify;
} zr_archive;

int  zr_zip_load(zr_archive *z, const char *path, char *err, size_t errlen);
void zr_zip_free(zr_archive *z);
const char *zr_enc_name(int enc);

#endif
