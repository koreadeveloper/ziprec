#include "gpu.h"
#include "export.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define DEVNULL "NUL"
#define POPEN _popen
#define PCLOSE _pclose
#include <process.h>
#define getpid _getpid
#else
#define DEVNULL "/dev/null"
#define POPEN popen
#define PCLOSE pclose
#include <unistd.h>
#endif

int zr_gpu_available(void) {
#if defined(_WIN32)
    FILE *f = POPEN("where hashcat.exe 2>" DEVNULL, "r");
#else
    FILE *f = POPEN("command -v hashcat 2>" DEVNULL, "r");
#endif
    if (!f) return 0;
    char b[8];
    int ok = fgets(b, sizeof b, f) != NULL;
    PCLOSE(f);
    return ok;
}

/* wrap src in "..." escaping sh metachars; returns dst or NULL if too long */
static char *sh_quote(char *dst, size_t n, const char *src) {
    size_t o = 0;
    dst[o++] = '"';
    for (const char *p = src; *p; p++) {
        char c = *p;
        if (c == '"' || c == '\\' || c == '`' || c == '$') {
            if (o + 2 >= n) return NULL;
            dst[o++] = '\\';
        }
        if (o + 1 >= n) return NULL;
        dst[o++] = c;
    }
    if (o + 2 >= n) return NULL;
    dst[o++] = '"'; dst[o] = 0;
    return dst;
}

/* map our charset spec to hashcat charset args (-1..-4) for brute mode */
static void hc_charset_args(const uint8_t *cs, int csn, char *out, size_t n) {
    char lit[600];
    if (csn >= (int)sizeof lit) csn = (int)sizeof lit - 1;
    memcpy(lit, cs, (size_t)csn); lit[csn] = 0;
    char *q = sh_quote(out, n, lit);
    if (!q) { out[0] = 0; return; }
    memmove(out + 3, out, strlen(out) + 1);
    memcpy(out, "-1 ", 3);
}

int zr_gpu_run(const zr_archive *z, const char *dict_path, const char *mask,
               int brute, const uint8_t *cs, int csn, int minl, int maxl,
               const char *extra_args, char *out, int outlen, char *err, size_t el) {
    if (!zr_gpu_available()) { snprintf(err, el, "hashcat not found in PATH"); return -1; }

    char hfile[1024], ofile[1024], cmd[8192];
#if defined(_WIN32)
    snprintf(hfile, sizeof hfile, "%s\\zr_hash.txt", getenv("TEMP") ? getenv("TEMP") : ".");
    snprintf(ofile, sizeof ofile, "%s\\zr_found.txt", getenv("TEMP") ? getenv("TEMP") : ".");
#else
    snprintf(hfile, sizeof hfile, "/tmp/ziprec_hash.%d", (int)getpid());
    snprintf(ofile, sizeof ofile, "/tmp/ziprec_found.%d", (int)getpid());
#endif
    FILE *hf = fopen(hfile, "w");
    if (!hf) { snprintf(err, el, "cannot write temp hash file"); return -1; }
    static char line[1 << 20];
    char tool[128];
    int pick = zr_gpu_pick_entry(z);       /* prefer stored PKZIP entry */
    zr_export_hash_ent(z, pick, line, sizeof line, tool, sizeof tool);
    char *p = strchr(line, ':');          /* strip name prefix for hashcat */
    fprintf(hf, "%s\n", p ? p + 1 : line);
    fclose(hf);

    const zr_entry *e = &z->entries[pick];
    int mode = e->enc >= ZR_ENC_AES128 ? 13600
             : e->method == ZR_METHOD_DEFLATE ? 17200 : 17210;

    char attack[2048] = {0}, qbuf[1600];
    if (dict_path) {
        if (!sh_quote(qbuf, sizeof qbuf, dict_path)) { snprintf(err, el, "dict path too long"); return -1; }
        snprintf(attack, sizeof attack, "-a 0 %s", qbuf);
    } else if (mask) {
        if (!sh_quote(qbuf, sizeof qbuf, mask)) { snprintf(err, el, "mask too long"); return -1; }
        snprintf(attack, sizeof attack, "-a 3 %s", qbuf);
    } else if (brute) {
        char csarg[700]; hc_charset_args(cs, csn, csarg, sizeof csarg);
        if (!csarg[0]) { snprintf(err, el, "charset too long"); return -1; }
        char m[128]; memset(m, 0, sizeof m);
        for (int i = 0; i < maxl && i < 55; i++) strcat(m, "?1");
        if (!sh_quote(qbuf, sizeof qbuf, m)) { snprintf(err, el, "mask too long"); return -1; }
        snprintf(attack, sizeof attack, "-a 3 --increment --increment-min %d --increment-max %d %s %s",
                 minl, maxl, csarg, qbuf);
    } else {
        snprintf(err, el, "no strategy for GPU mode"); return -1;
    }

    snprintf(cmd, sizeof cmd,
             "hashcat -m %d --potfile-disable --quiet -o \"%s\" \"%s\" %s %s",
             mode, ofile, hfile, attack, extra_args ? extra_args : "");
    fprintf(stderr, "[gpu] %s\n", cmd);
    remove(ofile);
    int rc = system(cmd);
    (void)rc;

    FILE *of = fopen(ofile, "r");
    int found = 0;
    if (of) {
        char l[1024];
        while (fgets(l, sizeof l, of)) {
            char *sep = strchr(l, ':');           /* hash has no ':'; plain may */
            if (sep) {
                sep++;
                sep[strcspn(sep, "\r\n")] = 0;
                snprintf(out, outlen, "%s", sep);
                found = 1;
            }
        }
        fclose(of);
    }
    remove(hfile); remove(ofile);
    return found;
}
