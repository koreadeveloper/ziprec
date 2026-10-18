/* ext.c - delegated cracking for RAR/7z via john-jumbo + hashcat + 7zz verify */
#include "ext.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define DEVNULL "NUL"
#define POPEN _popen
#define PCLOSE _pclose
#include <process.h>
#include <windows.h>
#define getpid _getpid
#else
#define DEVNULL "/dev/null"
#define POPEN popen
#define PCLOSE pclose
#include <unistd.h>
#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif
#endif

/* directory containing the running executable (for vendored resources) */
static int self_dir(char *out, size_t n) {
#if defined(_WIN32)
    DWORD l = GetModuleFileNameA(NULL, out, (DWORD)n);
    if (!l || l >= n) return -1;
    for (char *p = out + l; p > out; p--) if (*p == '\\' || *p == '/') { *p = 0; break; }
    return 0;
#elif defined(__APPLE__)
    uint32_t sz = (uint32_t)n;
    if (_NSGetExecutablePath(out, &sz)) return -1;
    char *p = strrchr(out, '/');
    if (!p) return -1;
    *p = 0;
    return 0;
#else
    ssize_t l = readlink("/proc/self/exe", out, n - 1);
    if (l <= 0) return -1;
    out[l] = 0;
    char *p = strrchr(out, '/');
    if (!p) return -1;
    *p = 0;
    return 0;
#endif
}

/* PERL5LIB prefix covering vendored + user-local Compress::Raw::Lzma */
static void perl5lib_prefix(char *out, size_t n) {
    out[0] = 0;
    const char *env = getenv("ZIPREC_PERL5LIB");
    if (env && env[0]) { snprintf(out, n, "PERL5LIB=\"%s\" ", env); return; }
    char sd[1024];
    if (self_dir(sd, sizeof sd)) return;
    const char *home = getenv("HOME");
    snprintf(out, n,
             "PERL5LIB=\"%s/tools/perl5:%s/../Resources/perl5:%s\" ",
             sd, sd, home ? home : ".");
    /* append the local::lib default location */
    size_t l = strlen(out);
    if (home && l + strlen(home) + 24 < n) {
        out[l - 2] = 0;    /* drop closing quote+space */
        snprintf(out + l - 2, n - (l - 2), ":%s/perl5/lib/perl5\" ", home);
    }
}

/* ---------- small helpers ---------- */
static int which(const char *tool, char *out, size_t n) {
    char cmd[512];
#if defined(_WIN32)
    snprintf(cmd, sizeof cmd, "where \"%s\" 2>" DEVNULL, tool);
#else
    snprintf(cmd, sizeof cmd, "command -v \"%s\" 2>" DEVNULL, tool);
#endif
    FILE *f = POPEN(cmd, "r");
    if (!f) return 0;
    int ok = fgets(out, (int)n, f) != NULL;
    PCLOSE(f);
    if (ok) out[strcspn(out, "\r\n")] = 0;
    return ok;
}

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

ext_fmt ext_detect(const char *path) {
    FILE *f = fopen(path, "rb");
    uint8_t m[8] = {0};
    ext_fmt r = EXT_NONE;
    if (f) {
        if (fread(m, 1, 8, f) >= 6) {
            if (!memcmp(m, "Rar!\x1a\x07\x00", 7)) r = EXT_RAR3;
            else if (!memcmp(m, "Rar!\x1a\x07\x01\x00", 8)) r = EXT_RAR5;
            else if (!memcmp(m, "7z\xbc\xaf\x27\x1c", 6)) r = EXT_SEVENZ;
        }
        fclose(f);
    }
    if (r == EXT_NONE) {                       /* extension fallback */
        const char *e = strrchr(path, '.');
        if (e) {
            if (!strcasecmp(e, ".rar")) r = EXT_RAR5;
            else if (!strcasecmp(e, ".7z")) r = EXT_SEVENZ;
        }
    }
    return r;
}

const char *ext_fmt_name(ext_fmt f) {
    return f == EXT_RAR3 ? "RAR3" : f == EXT_RAR5 ? "RAR5"
         : f == EXT_SEVENZ ? "7z" : "?";
}

/* john share dir holding *2john tools (homebrew layout) */
static int find_2john(const char *name, char *out, size_t n) {
    if (which(name, out, n)) return 0;
    static const char *dirs[] = {
        "/opt/homebrew/share/john",
        "/usr/local/share/john",
        "/usr/share/john",
        NULL
    };
    char p[1024];
    for (int i = 0; dirs[i]; i++) {
        snprintf(p, sizeof p, "%s/%s", dirs[i], name);
        FILE *f = fopen(p, "r");
        if (f) { fclose(f); snprintf(out, n, "%s", p); return 0; }
        snprintf(p, sizeof p, "%s/%s.pl", dirs[i], name);   /* 7z2john.pl */
        f = fopen(p, "r");
        if (f) { fclose(f); snprintf(out, n, "%s", p); return 0; }
    }
    return -1;
}

static int hc_mode_for(ext_fmt f, const char *hash) {
    if (f == EXT_SEVENZ) return 11600;
    if (f == EXT_RAR5 || strstr(hash, "$rar5$")) return 13000;
    /* RAR3: *1* variant = -p (23700); else -hp (12500) */
    return strstr(hash, "$RAR3$*1*") ? 23700 : 12500;
}

/* ---------------- extraction-verification ----------------
   returns 1 verified, 0 failed, -1 no usable verifier */
static int verify_archive(ext_fmt f, const char *sevenz, const char *path,
                          const char *pw) {
    char q1[1600], q2[1600], cmd[4096], pwp[1200];
    snprintf(pwp, sizeof pwp, "-p%s", pw);
    if (!sh_quote(q1, sizeof q1, pwp) || !sh_quote(q2, sizeof q2, path)) return 0;
    if (f == EXT_RAR5 || f == EXT_RAR3) {
        /* 7z cannot test-integrity RAR5-encrypted; need unrar/rar */
        char unrar[512] = {0};
        if (which("unrar", unrar, sizeof unrar) || which("rar", unrar, sizeof unrar)) {
            snprintf(cmd, sizeof cmd, "\"%s\" t %s %s -y >" DEVNULL " 2>&1",
                     unrar, q1, q2);
            return system(cmd) == 0 ? 1 : 0;
        }
        return -1;                                   /* no rar tester installed */
    }
    snprintf(cmd, sizeof cmd, "\"%s\" t %s %s -y >" DEVNULL " 2>&1",
             sevenz, q1, q2);
    return system(cmd) == 0 ? 1 : 0;
}

int ext_run(const char *path, ext_fmt f, const char *dict, const char *mask,
            int brute, const char *cs_spec, int minl, int maxl, int use_gpu,
            const char *extra, char *out_pw, int outlen, char *err, size_t el) {
    char john[512] = {0}, hashcat[512] = {0}, sz[512] = {0}, tool[1024] = {0};
    which("john", john, sizeof john);
    which("hashcat", hashcat, sizeof hashcat);
    if (f == EXT_SEVENZ) {
        if (!which("7zz", sz, sizeof sz) && !which("7z", sz, sizeof sz)) {
            snprintf(err, el, "7zz/7z not found (needed to verify 7z results)");
            return -1;
        }
    } else {
        /* RAR: unrar/rar preferred; 7zz is a last-resort (cannot test RAR5 enc) */
        if (!which("unrar", sz, sizeof sz) && !which("rar", sz, sizeof sz) &&
            !which("7zz", sz, sizeof sz) && !which("7z", sz, sizeof sz)) {
            snprintf(err, el, "no verifier found (need unrar/rar or 7zz)");
            return -1;
        }
    }
    const char *t2j = f == EXT_SEVENZ ? "7z2john" : "rar2john";
    if (find_2john(t2j, tool, sizeof tool)) {
        snprintf(err, el, "%s not found (install john-jumbo)", t2j); return -1;
    }

    /* ---- 1. extract hash ---- */
    char hfile[256];
    snprintf(hfile, sizeof hfile,
#if defined(_WIN32)
             "%s\\zr_ext_hash.txt", getenv("TEMP") ? getenv("TEMP") : ".");
#else
             "/tmp/ziprec_ext.%d", (int)getpid());
#endif
    char q[1600], cmd[4096];
    if (!sh_quote(q, sizeof q, path)) { snprintf(err, el, "path too long"); return -1; }
    const char *ext2 = strrchr(tool, '.');
    if (ext2 && !strcmp(ext2, ".pl")) {
        char pl[2300]; perl5lib_prefix(pl, sizeof pl);
        snprintf(cmd, sizeof cmd, "%sperl \"%s\" %s > \"%s\" 2>" DEVNULL,
                 pl, tool, q, hfile);
    } else {
        snprintf(cmd, sizeof cmd, "\"%s\" %s > \"%s\" 2>" DEVNULL, tool, q, hfile);
    }
    fprintf(stderr, "[ext] %s\n", cmd);
    if (system(cmd)) { snprintf(err, el, "%s failed", t2j); remove(hfile); return -1; }

    char hash[1 << 20] = {0};
    FILE *hf = fopen(hfile, "r");
    if (!hf || !fgets(hash, sizeof hash, hf)) {
        if (hf) fclose(hf);
        snprintf(err, el, "%s produced no hash (archive unencrypted or corrupt?)",
                 t2j);
        remove(hfile); return -1;
    }
    fclose(hf);
    hash[strcspn(hash, "\r\n")] = 0;
    if (!strstr(hash, "$")) {
        snprintf(err, el, "archive is not password-protected");
        remove(hfile); return -1;
    }
    /* hashcat wants the bare hash; john accepts 'name:hash' as-is */

    /* ---- 2. crack ---- */
    char ofile[256];
    snprintf(ofile, sizeof ofile,
#if defined(_WIN32)
             "%s\\zr_ext_found.txt", getenv("TEMP") ? getenv("TEMP") : ".");
#else
             "/tmp/ziprec_ext_found.%d", (int)getpid());
#endif
    remove(ofile);
    int rc = -1;

    /* hashcat 11600 cannot verify $7z$0$ (uncompressed payload) hashes;
       john handles them via padding checks, so skip the GPU attempt */
    int hc_ok = 1;
    {
        const char *sig = strstr(hash, "$7z$");
        if (sig && !strncmp(sig + 4, "0$", 2)) {
            hc_ok = 0;
            fprintf(stderr, "[ext] 7z type-0 (uncompressed) hash: hashcat cannot verify, using john\n");
        }
    }
    if (use_gpu && hashcat[0] && hc_ok) {
        int mode = hc_mode_for(f, hash);
        char *body = strchr(hash, ':');          /* strip name: prefix */
        char bh[1024];
        snprintf(bh, sizeof bh, "/tmp/ziprec_exth.%d", (int)getpid());
        FILE *b = fopen(bh, "w");
        if (b) { fprintf(b, "%s\n", body ? body + 1 : hash); fclose(b); }
        char attack[2048] = {0}, qb[1600];
        if (dict)      snprintf(attack, sizeof attack, "-a 0 %s", sh_quote(qb, sizeof qb, dict));
        else if (mask) snprintf(attack, sizeof attack, "-a 3 %s", sh_quote(qb, sizeof qb, mask));
        else if (brute) {
            /* approximate charset with -1 + incremental */
            char cs[600]; snprintf(cs, sizeof cs, "%s", cs_spec ? cs_spec : "?l?d");
            /* expand ?-tokens to literals for hashcat -1 */
            char lit[600]; int o = 0;
            for (const char *p = cs; *p && o < 590;) {
                if (p[0] == '?' && p[1]) {
                    const char *t = p[1]=='l'?"abcdefghijklmnopqrstuvwxyz":
                                    p[1]=='u'?"ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                                    p[1]=='d'?"0123456789":
                                    p[1]=='s'?" !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~":
                                    p[1]=='a'?"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~":NULL;
                    if (t) { int tl = (int)strlen(t); memcpy(lit+o, t, (size_t)tl); o += tl; p += 2; }
                    else lit[o++] = *p++;
                } else lit[o++] = *p++;
            }
            lit[o] = 0;
            char qc[700], qm[200];
            sh_quote(qc, sizeof qc, lit);
            char m[64]; int ml = 0;
            for (int i = 0; i < maxl && i < 55; i++) ml += snprintf(m+ml, 4, "?1");
            sh_quote(qm, sizeof qm, m);
            snprintf(attack, sizeof attack,
                     "-a 3 --increment --increment-min %d --increment-max %d -1 %s %s",
                     minl, maxl, qc, qm);
        } else {
            snprintf(err, el, "no strategy for GPU mode"); remove(hfile); remove(bh); return -1;
        }
        snprintf(cmd, sizeof cmd,
                 "\"%s\" -m %d --potfile-disable --quiet -o \"%s\" \"%s\" %s %s",
                 hashcat, mode, ofile, bh, attack, extra ? extra : "");
        fprintf(stderr, "[ext-gpu] %s\n", cmd);
        system(cmd);
        FILE *of = fopen(ofile, "r");
        if (of) {
            char l[2048];
            while (fgets(l, sizeof l, of)) {
                char *sep = strchr(l, ':');      /* first ':' splits hash|plain */
                if (sep) {
                    sep++;
                    sep[strcspn(sep, "\r\n")] = 0;
                    snprintf(out_pw, outlen, "%s", sep);
                    rc = 1;
                }
            }
            fclose(of);
        }
        remove(bh);
        if (rc <= 0) { fprintf(stderr, "[ext-gpu] not found or no device; trying john\n"); }
    }

    if (rc <= 0 && john[0]) {
        /* john: name:hash file works directly; --format for determinism */
        char pot[256], jf[1024], fmt[16];
        snprintf(fmt, sizeof fmt, "%s",
                 f == EXT_SEVENZ ? "7z" : f == EXT_RAR5 ? "rar5" : "rar");
        snprintf(pot, sizeof pot,
#if defined(_WIN32)
                 "%s\\zr_ext.pot", getenv("TEMP") ? getenv("TEMP") : ".");
#else
                 "/tmp/ziprec_ext.%d.pot", (int)getpid());
#endif
        snprintf(jf, sizeof jf, "\"%s\" --pot=\"%s\" --format=%s \"%s\"",
                 john, pot, fmt, hfile);
        if (dict) {
            char qd[1600]; sh_quote(qd, sizeof qd, dict);
            snprintf(cmd, sizeof cmd, "%s --wordlist=%s --rules %s >" DEVNULL " 2>&1",
                     jf, qd, extra ? extra : "");
        } else if (mask) {
            char qm[1600]; sh_quote(qm, sizeof qm, mask);
            snprintf(cmd, sizeof cmd, "%s --mask=%s %s >" DEVNULL " 2>&1",
                     jf, qm, extra ? extra : "");
        } else {  /* brute */
            snprintf(cmd, sizeof cmd,
                     "%s --incremental --min-length=%d --max-length=%d %s >" DEVNULL " 2>&1",
                     jf, minl, maxl, extra ? extra : "");
        }
        fprintf(stderr, "[ext-cpu] %s\n", cmd);
        system(cmd);
        /* read result via --show (same pot, hashfile passed once) */
        snprintf(cmd, sizeof cmd,
                 "\"%s\" --pot=\"%s\" --format=%s --show \"%s\"",
                 john, pot, fmt, hfile);
        FILE *sf = POPEN(cmd, "r");
        if (sf) {
            char l[4096];
            while (fgets(l, sizeof l, sf)) {
                /* format: name:password  (password may itself contain ':') */
                char *c1 = strchr(l, ':');
                if (c1 && c1[1]) {
                    c1++;
                    c1[strcspn(c1, "\r\n")] = 0;
                    if (*c1) { snprintf(out_pw, outlen, "%s", c1); rc = 1; }
                }
            }
            PCLOSE(sf);
        }
        remove(pot);
    }

    remove(hfile); remove(ofile);
    if (rc != 1) {
        if (!john[0] && !hashcat[0])
            snprintf(err, el, "no cracking engine available (need john or hashcat)");
        else
            snprintf(err, el, "search exhausted (password not in the tried space)");
        return rc;
    }

    /* ---- 3. independent verification: actual archive test ---- */
    int v = verify_archive(f, sz, path, out_pw);
    if (v == 0) {
        fprintf(stderr, "[ext] candidate '%s' failed archive integrity test\n", out_pw);
        return 0;
    }
    if (v < 0) {
        fprintf(stderr, "[ext] no unrar/rar for RAR verify; result is unverified\n");
        return 2;
    }
    return 1;
}
