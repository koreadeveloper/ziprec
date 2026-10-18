/*
 * ziprec - local ZIP password recovery tool.
 * Usage: see --help.
 */
#include "platform.h"
#include "zipfile.h"
#include "crypto.h"
#include "gen.h"
#include "engine.h"
#include "ckpt.h"
#include "export.h"
#include "gpu.h"
#include "ext.h"
#include "i18n.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#ifdef _WIN32
#include <process.h>   /* _exit, _getpid */
#endif

static engine_t ENG;           /* signal handler needs access */
static volatile sig_atomic_t sig_count = 0;
static volatile sig_atomic_t pause_req = 0;
static void on_sigint(int s) {
    (void)s;
    if (++sig_count == 1) engine_stop(&ENG);
    else _exit(130);
}
#ifndef _WIN32
static void on_sigtstp(int s) { (void)s; pause_req = 1; }
#endif

static void usage(FILE *o) {
    fprintf(o,
"ziprec - offline archive password recovery\n"
"\n");
    fprintf(o, "%s\n\n", TR(M_USAGE_HEAD));
    fprintf(o,
"%s\n"
"  -m, --mask MASK        mask attack, e.g. \"?u?l?l?l?d?d\"\n"
"  -d, --dict FILE        dictionary attack (+rules below)\n"
"  -b, --brute            brute force: --min N --max N --charset X\n"
"                         (default with no mode: builtin dictionary + rules)\n"
"\n",
TR(M_USAGE_MODES));
    fprintf(o,
"%s ?l a-z | ?u A-Z | ?d 0-9 | ?s special | ?h hex |\n"
"             ?a printable | ?b binary | ?1-?4 custom | ?? literal '?'\n"
"             any other char is literal  (e.g. \"Pass?d?d?d?d\")\n"
"\n", TR(M_USAGE_MASKHDR));
    fprintf(o,
"%s\n"
"  --rules FILE           rule file (one hashcat-style rule per line)\n"
"  --rulestr \"RULES\"      inline rules, ',' separated (e.g. \"c,$1,c$!\")\n"
"  --rules-builtin        apply builtin mutation set\n"
"\n", TR(M_USAGE_DICTOPT));
    fprintf(o,
"%s\n"
"  --min N --max N        length range (1..64)\n"
"  --charset X            ?-token or literal charset (default ?l)\n"
"  --charset-N \"chars\"    define custom charset ?N (N=1..4)\n"
"\n", TR(M_USAGE_BRUTEOPT));
    fprintf(o,
"%s\n"
"  -t, --threads N        worker threads (default: all cores)\n"
"  --gpu                  delegate cracking to hashcat (GPU), then\n"
"                         re-verify the answer natively; falls back\n"
"                         to the CPU engine if hashcat is missing\n"
"  --gpu-args \"ARGS\"      extra args passed verbatim to hashcat\n"
"  --chunk N              candidates per work item (auto default)\n"
"  --start N              start index (overrides resume position)\n"
"  --target NAME          crack this entry instead of smallest\n"
"  --check-bytes 1|2      ZipCrypto filter width (default 2)\n"
"  --lang XX              UI language: en ko ja zh es de fr\n"
"                         (default: auto-detect from environment)\n"
"\n", TR(M_USAGE_ENGINE));
    fprintf(o,
"%s\n"
"  --ckpt FILE            checkpoint path (default: FILE.zip.zck)\n"
"  --ckpt-interval S      seconds between saves (default 5)\n"
"  --resume FILE          resume from checkpoint file\n"
"  --no-ckpt              disable checkpointing\n"
"  --log FILE             append events to log (no passwords unless --log-pw)\n"
"  --log-pw               allow writing recovered password to log\n"
"  -q, --quiet            no status line\n"
"  --info                 print archive/encryption info and exit (no crack)\n"
"  --export FILE          write hashcat/john hash line for target, then exit\n"
"                         ('-' for stdout)\n"
"  --bench [SEC]          measure throughput for SEC seconds, then exit\n"
"  --selftest             run crypto self-test and exit\n"
"  -y, --yes              skip ownership confirmation prompt\n"
"  -h, --help             this help\n"
"\n", TR(M_USAGE_CKPT));
    fprintf(o,
"%s\n"
"  ziprec secret.zip -d rockyou.txt --rules-builtin\n"
"  ziprec secret.zip -m \"?l?l?l?l?l?l\"\n"
"  ziprec secret.zip -b --min 1 --max 8 --charset ?d\n"
"  ziprec secret.zip --export h.txt   # then: hashcat -m 13600 -a 3 h.txt MASK\n"
, TR(M_USAGE_EXAMPLES));
}

/* pretty number helpers */
static void fmt_num(uint64_t v, char *o) {
    if (v == UINT64_MAX) { snprintf(o, 16, "inf"); return; }
    if (v >= 1000000000ULL) snprintf(o, 16, "%.2fG", (double)v / 1e9);
    else if (v >= 1000000ULL) snprintf(o, 16, "%.2fM", (double)v / 1e6);
    else if (v >= 1000) snprintf(o, 16, "%.1fK", (double)v / 1e3);
    else snprintf(o, 16, "%llu", (unsigned long long)v);
}
static void fmt_time(double s, char *o, size_t n) {
    if (!(s >= 0) || s > 1e15) { snprintf(o, n, "?"); return; }
    if (s < 60) snprintf(o, n, "%.0fs", s);
    else if (s < 3600) snprintf(o, n, "%dm%02ds", (int)(s / 60), (int)s % 60);
    else if (s < 86400) snprintf(o, n, "%dh%02dm", (int)(s / 3600), ((int)s / 60) % 60);
    else snprintf(o, n, "%.1fd", s / 86400.0);
}

static int consent(const char *path) {
    fprintf(stderr, TR(M_CONSENT), path);
    char b[8];
    if (!fgets(b, sizeof b, stdin)) return 0;
    return b[0] == 'y' || b[0] == 'Y';
}

/* engine trampoline (thread proc signature differs by OS) */
#if defined(_WIN32)
static unsigned __stdcall engine_runner(void *p) { engine_run(p); return 0; }
#else
static void *engine_runner(void *p) { engine_run(p); return 0; }
#endif

int main(int argc, char **argv) {
    const char *zip_path = NULL, *dict_path = NULL, *rules_path = NULL,
               *rules_inline = NULL, *ckpt_path = NULL, *resume_path = NULL,
               *log_path = NULL, *export_path = NULL, *target_name = NULL,
               *charset_arg = "?l", *mask = NULL;
    int brute = 0, minlen = 1, maxlen = 8, nthreads = (int)zr_num_cpus();
    int builtin_rules = 0, quiet = 0, log_pw = 0, yes = 0, no_ckpt = 0;
    int check_bytes = 0, gpu_mode = 0, info_only = 0;
    const char *gpu_args = NULL;
    uint64_t chunk = 0, start_idx = 0;
    double ckpt_iv = 5.0, bench_sec = 0;
    int have_start = 0;

    /* pre-scan for --lang so detection is set before any output */
    const char *lang_arg = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strncmp(argv[i], "--lang=", 7)) { lang_arg = argv[i] + 7; break; }
        if (!strcmp(argv[i], "--lang") && i + 1 < argc) { lang_arg = argv[i + 1]; break; }
    }
    zr_lang_init(lang_arg);

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
#define NEXT() (i + 1 < argc ? argv[++i] : (fprintf(stderr, TR(M_MISSING_VALUE), a), exit(2), (const char *)NULL))
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(stdout); return 0; }
        else if (!strcmp(a, "-m") || !strcmp(a, "--mask")) mask = NEXT();
        else if (!strncmp(a, "--mask=", 7)) mask = a + 7;
        else if (!strcmp(a, "-d") || !strcmp(a, "--dict")) dict_path = NEXT();
        else if (!strncmp(a, "--dict=", 7)) dict_path = a + 7;
        else if (!strcmp(a, "-b") || !strcmp(a, "--brute")) brute = 1;
        else if (!strcmp(a, "--min")) minlen = atoi(NEXT());
        else if (!strcmp(a, "--max")) maxlen = atoi(NEXT());
        else if (!strcmp(a, "--charset")) charset_arg = NEXT();
        else if (!strncmp(a, "--charset-", 10) && a[10] >= '1' && a[10] <= '4' && !a[11])
            zr_set_user_charset(a[10] - '1', NEXT());
        else if (!strcmp(a, "--rules")) rules_path = NEXT();
        else if (!strcmp(a, "--rulestr")) rules_inline = NEXT();
        else if (!strcmp(a, "--rules-builtin")) builtin_rules = 1;
        else if (!strcmp(a, "-t") || !strcmp(a, "--threads")) nthreads = atoi(NEXT());
        else if (!strncmp(a, "--threads=", 10)) nthreads = atoi(a + 10);
        else if (!strcmp(a, "--chunk")) chunk = strtoull(NEXT(), 0, 10);
        else if (!strcmp(a, "--start")) { start_idx = strtoull(NEXT(), 0, 10); have_start = 1; }
        else if (!strcmp(a, "--target")) target_name = NEXT();
        else if (!strcmp(a, "--check-bytes")) check_bytes = atoi(NEXT());
        else if (!strcmp(a, "--ckpt")) ckpt_path = NEXT();
        else if (!strcmp(a, "--ckpt-interval")) ckpt_iv = atof(NEXT());
        else if (!strcmp(a, "--resume")) resume_path = NEXT();
        else if (!strcmp(a, "--no-ckpt")) no_ckpt = 1;
        else if (!strcmp(a, "--log")) log_path = NEXT();
        else if (!strcmp(a, "--log-pw")) log_pw = 1;
        else if (!strcmp(a, "-q") || !strcmp(a, "--quiet")) quiet = 1;
        else if (!strcmp(a, "--gpu")) gpu_mode = 1;
        else if (!strcmp(a, "--gpu-args")) gpu_args = NEXT();
        else if (!strcmp(a, "--export")) export_path = NEXT();
        else if (!strcmp(a, "--info")) info_only = 1;
        else if (!strcmp(a, "--bench")) {
            bench_sec = 10;
            if (i + 1 < argc && isdigit((unsigned char)argv[i + 1][0])) bench_sec = atof(argv[++i]);
        }
        else if (!strcmp(a, "--selftest")) { zr_crypto_init(); printf("crypto self-test OK (%s)\n", zr_sha1_backend()); return 0; }
        else if (!strcmp(a, "-y") || !strcmp(a, "--yes")) yes = 1;
        else if (!strcmp(a, "--lang")) (void)NEXT();   /* handled in pre-scan */
        else if (!strncmp(a, "--lang=", 7)) ;
        else if (a[0] != '-') zip_path = a;
        else { fprintf(stderr, TR(M_UNKNOWN_OPTION), a); return 2; }
    }

    if (!zip_path) { usage(stderr); return 2; }
    if (nthreads < 1) nthreads = 1;
    if (nthreads > 256) nthreads = 256;

    zr_crypto_init();
    zr_enable_ansi();

    if (!yes && !consent(zip_path)) { fprintf(stderr, "%s\n", TR(M_ABORTED)); return 3; }

    /* ---------- non-ZIP container (RAR/7z): delegated pipeline ---------- */
    ext_fmt xf = ext_detect(zip_path);
    if (xf != EXT_NONE) {
        fprintf(stderr, "file       : %s\nformat     : %s %s\n",
                zip_path, ext_fmt_name(xf), TR(M_DELEGATED));
        if (info_only) {
            fprintf(stderr, "note       : %s\n", TR(M_NOTE_EXT));
            return 0;
        }
        char pw[256], gerr[256];
        int rc = ext_run(zip_path, xf, dict_path, mask, brute,
                         charset_arg, minlen, maxlen, gpu_mode, gpu_args,
                         pw, sizeof pw, gerr, sizeof gerr);
        if (rc >= 1) {
            printf("PASSWORD FOUND: %s\n", pw);
            fprintf(stderr, "verified   : %s\n",
                    rc == 1 ? "yes (archive integrity test)"
                            : "NO (no verifier installed)");
            rc = 1;
            if (log_path) {
                FILE *lf = fopen(log_path, "a");
                if (lf) {
                    fprintf(lf, "[%s] FOUND%s\n", zip_path,
                            log_pw ? "" : " (password withheld)");
                    if (log_pw) fprintf(lf, "password=%s\n", pw);
                    fclose(lf);
                }
            }
            return 0;
        }
        if (rc == 0) { fprintf(stderr, "search finished: not found\n"); return 1; }
        fprintf(stderr, "error: %s\n", gerr);
        return 1;
    }

    /* ---------- load archive ---------- */
    static zr_archive z;
    char err[256];
    if (zr_zip_load(&z, zip_path, err, sizeof err)) {
        fprintf(stderr, "error: %s\n", err);
        return 1;
    }
    if (target_name) {
        for (int i = 0; i < z.n_entries; i++)
            if (!strcmp(z.entries[i].name, target_name) && z.entries[i].enc)
                z.verify_idx[0] = i;
    }
    const zr_entry *te = &z.entries[z.verify_idx[0]];
    if (!te->data) { fprintf(stderr, "error: target entry has no data\n"); return 1; }
    zr_check_bytes_override = check_bytes;

    fprintf(stderr, "file       : %s (%llu bytes)\n", z.path, (unsigned long long)z.size);
    fprintf(stderr, "entries    : %d total, %d encrypted\n", z.n_entries, z.n_encrypted);
    fprintf(stderr, "target     : %s\n", te->name);
    fprintf(stderr, "encryption : %s\n", zr_enc_name(te->enc));
    fprintf(stderr, "sha1       : %s\n", zr_sha1_backend());

    /* ---------- info-only mode (GUI file-confirm step) ---------- */
    if (info_only) {
        for (int i = 0; i < z.n_entries; i++) {
            const zr_entry *e = &z.entries[i];
            int m = e->method == ZR_METHOD_AES ? e->real_method : e->method;
            fprintf(stderr, "entry      : %s  %s  %s  %lluB->%lluB\n",
                    e->enc ? zr_enc_name(e->enc) : "plain",
                    m == ZR_METHOD_DEFLATE ? "deflate" : "stored",
                    e->name,
                    (unsigned long long)e->csize, (unsigned long long)e->usize);
        }
        zr_zip_free(&z);
        return 0;
    }

    /* ---------- hash export ---------- */
    if (export_path) {
        char tool[128];
        static char line[1 << 20];
        zr_export_hash(&z, line, sizeof line, tool, sizeof tool);
        FILE *f = strcmp(export_path, "-") ? fopen(export_path, "w") : stdout;
        if (!f) { fprintf(stderr, "cannot write %s\n", export_path); return 1; }
        fprintf(f, "%s\n", line);
        if (f != stdout) fclose(f);
        fprintf(stderr, "exported for: %s\n", tool);
        return 0;
    }

    /* ---------- generator ---------- */
    static gen_t g;
    if (dict_path) {
        if (gen_init_dict(&g, dict_path, rules_path, rules_inline, builtin_rules, err, sizeof err)) {
            fprintf(stderr, "error: %s\n", err); return 1;
        }
    } else if (mask) {
        if (gen_init_mask(&g, mask, err, sizeof err)) { fprintf(stderr, "error: %s\n", err); return 1; }
    } else if (brute) {
        static uint8_t csbuf[512];
        int csn = zr_charset_expand(charset_arg, csbuf, sizeof csbuf);
        if (csn <= 0) { fprintf(stderr, "error: bad --charset '%s'\n", charset_arg); return 1; }
        /* dedupe */
        int w = 0;
        for (int i = 0; i < csn; i++) {
            int dup = 0;
            for (int j = 0; j < w; j++) if (csbuf[j] == csbuf[i]) { dup = 1; break; }
            if (!dup) csbuf[w++] = csbuf[i];
        }
        if (gen_init_brute(&g, csbuf, w, minlen, maxlen, err, sizeof err)) {
            fprintf(stderr, "error: %s\n", err); return 1;
        }
    } else {
        /* default strategy: builtin dictionary + builtin rules */
        char tmpdict[4096];
        snprintf(tmpdict, sizeof tmpdict, "%s.ziprec-default-dict", zip_path);
        FILE *df = fopen(tmpdict, "w");
        if (!df) { fprintf(stderr, "error: cannot write temp dict\n"); return 1; }
        for (int i = 0; i < ZR_N_BUILTIN_DICT; i++) fprintf(df, "%s\n", ZR_BUILTIN_DICT[i]);
        fclose(df);
        int rc = gen_init_dict(&g, tmpdict, NULL, NULL, 1, err, sizeof err);
        remove(tmpdict);
        if (rc) { fprintf(stderr, "error: %s\n", err); return 1; }
    }

    /* ---------- resume ---------- */
    zr_ckpt ck; memset(&ck, 0, sizeof ck);
    char ckfile[4096];
    if (resume_path) {
        if (zr_ckpt_load(resume_path, &ck)) { fprintf(stderr, "cannot read checkpoint %s\n", resume_path); return 1; }
        if (strcmp(ck.file, z.path) || ck.fsize != z.size) {
            fprintf(stderr, "checkpoint refers to a different file (%s)\n", ck.file); return 1;
        }
        if (strcmp(ck.params, g.params)) {
            fprintf(stderr, "checkpoint params differ:\n  saved: %s\n  now  : %s\n(use identical options)\n",
                    ck.params, g.params); return 1;
        }
        if (!have_start) start_idx = ck.next;
        fprintf(stderr, "resuming at index %llu\n", (unsigned long long)start_idx);
    }
    if (ckpt_path) snprintf(ckfile, sizeof ckfile, "%s", ckpt_path);
    else snprintf(ckfile, sizeof ckfile, "%s.zck", zip_path);

    FILE *logf = log_path ? fopen(log_path, "a") : NULL;

    /* ---------- GPU delegation ---------- */
    if (gpu_mode) {
        char pw[256], gerr[256];
        static uint8_t csb[512]; int cn = 0;
        if (brute) {
            cn = zr_charset_expand(charset_arg, csb, sizeof csb);
            if (cn <= 0) { fprintf(stderr, "error: bad --charset\n"); return 1; }
        }
        fprintf(stderr, "gpu        : %s\n", TR(M_GPU_DELEG));
        int rc = zr_gpu_run(&z, dict_path, mask, brute, csb, cn,
                            minlen, maxlen, gpu_args, pw, sizeof pw, gerr, sizeof gerr);
        if (rc > 0) {
            /* never trust the delegated engine: re-verify natively */
            size_t wl = zr_verify_worksize(&z);
            uint8_t *wb = malloc(wl);
            int ok = wb && zr_full_verify(&z, (const uint8_t *)pw,
                                          (int)strlen(pw), wb, wl);
            free(wb);
            if (ok) {
                printf("PASSWORD FOUND: %s\n", pw);
                fprintf(stderr, "verified   : yes (native decrypt + integrity)\n");
                if (logf) {
                    fprintf(logf, "[%s] FOUND (gpu)%s\n", z.path,
                            log_pw ? "" : " (password withheld)");
                    if (log_pw) fprintf(logf, "password=%s\n", pw);
                }
                gen_free(&g); zr_zip_free(&z);
                if (logf) fclose(logf);
                return 0;
            }
            fprintf(stderr, "%s\n", TR(M_VERIF_FAIL));
        } else if (rc == 0) {
            fprintf(stderr, "gpu search finished: not found\n");
            gen_free(&g); zr_zip_free(&z);
            if (logf) fclose(logf);
            return 1;
        } else {
            fprintf(stderr, "gpu error: %s\nfalling back to CPU engine\n", gerr);
        }
    }

    fprintf(stderr, "strategy   : %s\n", g.desc);
    char nb[16]; fmt_num(g.total, nb);
    fprintf(stderr, "space      : %s candidates\n", nb);
    fprintf(stderr, "threads    : %d\n", nthreads);

    /* ---------- engine ---------- */
    memset(&ENG, 0, sizeof ENG);
    ENG.z = &z; ENG.g = &g; ENG.start = start_idx; ENG.total = g.total;
    ENG.nthreads = nthreads; ENG.chunk = chunk;

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);
#ifndef _WIN32
    signal(SIGTSTP, on_sigtstp);    /* Ctrl-Z: ckpt-save then freeze */
#endif

    zr_thread_t et;
    zr_thread_create(&et, engine_runner, &ENG);

    double t0 = zr_now();
    uint64_t last_done = 0; double last_t = t0, last_ck = t0;
    double rate = 0;

    for (;;) {
        zr_sleep_ms(200);
        uint64_t done = zr_atomic_load(&ENG.done);
        double now = zr_now();
        double inst = (double)(done - last_done) / (now - last_t);
        rate = rate > 0 ? rate * 0.7 + inst * 0.3 : inst;
        last_done = done; last_t = now;

        if (!quiet) {
            char nbb[16], tb[16], rb[24], eb[24];
            fmt_num(done, nbb); fmt_num(ENG.total, tb);
            double pct = ENG.total && ENG.total != UINT64_MAX ? 100.0 * (double)done / (double)ENG.total : 0;
            fmt_time(ENG.total != UINT64_MAX && rate > 0 ? (double)(ENG.total - done) / rate : -1, eb, sizeof eb);
            if (rate >= 1e9) snprintf(rb, sizeof rb, "%.2fG/s", rate / 1e9);
            else if (rate >= 1e6) snprintf(rb, sizeof rb, "%.2fM/s", rate / 1e6);
            else snprintf(rb, sizeof rb, "%.1fK/s", rate / 1e3);
            fprintf(stderr, "\r\033[K[%s] %s/%s (%.1f%%) %s | ETA %s | %d thr | cur %s",
                    g.desc, nbb, tb, pct, rb, eb, nthreads,
                    (const char *)ENG.cur_pw);
            fflush(stderr);
        }
        if (!no_ckpt && now - last_ck >= ckpt_iv) {
            zr_ckpt c; memset(&c, 0, sizeof c);
            snprintf(c.file, sizeof c.file, "%s", z.path);
            c.fsize = z.size; c.fmtime = z.mtime;
            snprintf(c.params, sizeof c.params, "%s", g.params);
            c.next = zr_atomic_load(&ENG.cursor);
            if (c.next > ENG.total) c.next = ENG.total;
            c.done_at_save = done;
            zr_ckpt_save(ckfile, &c);
            last_ck = now;
        }
#ifndef _WIN32
        if (pause_req) {
            pause_req = 0;
            zr_ckpt c; memset(&c, 0, sizeof c);
            snprintf(c.file, sizeof c.file, "%s", z.path);
            c.fsize = z.size; c.fmtime = z.mtime;
            snprintf(c.params, sizeof c.params, "%s", g.params);
            c.next = zr_atomic_load(&ENG.cursor);
            if (c.next > ENG.total) c.next = ENG.total;
            c.done_at_save = done;
            zr_ckpt_save(ckfile, &c);
            last_ck = now;
            if (!quiet) fprintf(stderr, "%s", TR(M_PAUSED));
            raise(SIGSTOP);                     /* resumes here on SIGCONT */
            last_t = zr_now();                 /* don't count frozen time */
            last_done = zr_atomic_load(&ENG.done);
            rate = 0;
        }
#endif
        if (zr_atomic_load(&ENG.found) || done >= ENG.total ||
            zr_atomic_load(&ENG.quit)) break;
        if (bench_sec > 0 && now - t0 >= bench_sec) { engine_stop(&ENG); break; }
    }
    int stopped_early = zr_atomic_load(&ENG.quit) && !zr_atomic_load(&ENG.found)
                        && zr_atomic_load(&ENG.done) < ENG.total;
    engine_stop(&ENG);
    zr_thread_join(et);
    if (!quiet) fprintf(stderr, "\n");

    double elapsed = zr_now() - t0;
    uint64_t done = zr_atomic_load(&ENG.done);

    if (bench_sec > 0) {
        char db[16];
        fmt_num(done, db);
        printf("bench: %s candidates in %.1fs = %.0f pw/s (%s, %d threads)\n",
               db, elapsed, done / elapsed, g.desc, nthreads);
        remove(ckfile);
        if (logf) fclose(logf);
        gen_free(&g); zr_zip_free(&z);
        return 0;
    }

    if (zr_atomic_load(&ENG.found)) {
        printf("PASSWORD FOUND: %s\n", ENG.found_pw);
        fprintf(stderr, "verified   : yes (decrypted + integrity checked)\n");
        fmt_num(done, nb);
        fprintf(stderr, "index      : %llu | tried %s candidates in %.2fs\n",
                (unsigned long long)ENG.found_idx, nb, elapsed);
        if (logf) {
            fprintf(logf, "[%s] FOUND%s\n", z.path, log_pw ? "" : " (password withheld)");
            if (log_pw) fprintf(logf, "password=%s\n", ENG.found_pw);
        }
        remove(ckfile);
    } else {
        if (stopped_early) {
            zr_ckpt c; memset(&c, 0, sizeof c);
            snprintf(c.file, sizeof c.file, "%s", z.path);
            c.fsize = z.size; c.fmtime = z.mtime;
            snprintf(c.params, sizeof c.params, "%s", g.params);
            c.next = zr_atomic_load(&ENG.cursor);
            if (c.next > ENG.total) c.next = ENG.total;
            c.done_at_save = done;
            zr_ckpt_save(ckfile, &c);
            fprintf(stderr, "stopped    : checkpoint saved to %s (index %llu)\n",
                    ckfile, (unsigned long long)c.next);
        } else {
            fprintf(stderr, "exhausted  : password not in search space (%llu tried)\n",
                    (unsigned long long)done);
            remove(ckfile);
        }
        if (logf) fprintf(logf, "[%s] exhausted/stopped after %llu\n", z.path, (unsigned long long)done);
    }
    if (logf) fclose(logf);
    gen_free(&g);
    zr_zip_free(&z);
    return zr_atomic_load(&ENG.found) ? 0 : 1;
}
