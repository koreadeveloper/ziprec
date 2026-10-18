/*
 * ext.h - delegated cracking for non-ZIP containers (RAR3/RAR5, 7z).
 *
 * Pipeline:  <fmt>2john (john-jumbo)  ->  hash line
 *            hashcat (GPU, --gpu) or john (CPU)  ->  candidate
 *            7zz t -p<pw>  ->  independent re-verification
 * Only the verified password is reported.
 */
#ifndef ZR_EXT_H
#define ZR_EXT_H

#include <stddef.h>

typedef enum { EXT_NONE = 0, EXT_RAR3, EXT_RAR5, EXT_SEVENZ } ext_fmt;

/* sniff file magic; falls back to extension when magic is ambiguous */
ext_fmt ext_detect(const char *path);
const char *ext_fmt_name(ext_fmt f);

/*
 * Returns:  1 password found (out_pw filled)
 *           0 search completed, not found
 *          -1 error (err filled)
 */
int ext_run(const char *path, ext_fmt f, const char *dict, const char *mask,
            int brute, const char *cs_spec, int minl, int maxl, int use_gpu,
            const char *extra, char *out_pw, int outlen, char *err, size_t el);

#endif /* ZR_EXT_H */
