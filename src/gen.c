/*
 * gen.c - candidate generators + hashcat-style rule engine.
 */
#include "gen.h"
#include "crypto.h"   /* zr_crc32 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------------- charsets ---------------- */
static const uint8_t CS_LOWER_B[]   = "abcdefghijklmnopqrstuvwxyz";
static const uint8_t CS_UPPER_B[]   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const uint8_t CS_DIGIT_B[]   = "0123456789";
static const uint8_t CS_SPECIAL_B[] = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
static const uint8_t CS_HEX_B[]     = "0123456789abcdef";
static uint8_t CS_PRINT_B[95];
static uint8_t CS_BIN_B[256];
static uint8_t cs_user[4][256];
static int     cs_user_n[4];
static int     cs_ready = 0;

static void cs_init_once(void) {
    if (cs_ready) return;
    for (int i = 0; i < 95; i++)  CS_PRINT_B[i] = (uint8_t)(32 + i);
    for (int i = 0; i < 256; i++) CS_BIN_B[i] = (uint8_t)i;
    cs_ready = 1;
}

void zr_set_user_charset(int slot, const char *s) { /* slot 0..3 for ?1..?4 */
    cs_init_once();
    int n = 0;
    for (const char *p = s; *p && n < 255; p++) {
        if (*p == '%' && p[1] && p[2]) { /* allow %XX hex escapes for binary chars */
            int v = 0; sscanf(p + 1, "%2x", &v);
            cs_user[slot][n++] = (uint8_t)v; p += 2;
        } else cs_user[slot][n++] = (uint8_t)*p;
    }
    cs_user_n[slot] = n;
}

const uint8_t *zr_charset(int id, int *n) {
    cs_init_once();
    switch (id) {
    case CS_LOWER:   *n = 26;  return CS_LOWER_B;
    case CS_UPPER:   *n = 26;  return CS_UPPER_B;
    case CS_DIGIT:   *n = 10;  return CS_DIGIT_B;
    case CS_SPECIAL: *n = 33;  return CS_SPECIAL_B;
    case CS_PRINT:   *n = 95;  return CS_PRINT_B;
    case CS_HEX:     *n = 16;  return CS_HEX_B;
    case CS_C1: case CS_C2: case CS_C3: case CS_C4:
        *n = cs_user_n[id - CS_C1]; return cs_user[id - CS_C1];
    }
    *n = 0; return NULL;
}

/* expand a charset spec like "?l?d" or "abc123" into a flat byte set.
   Returns count, or -1 on bad token. Fills caller buffer. */
int zr_charset_expand(const char *spec, uint8_t *out, int cap) {
    cs_init_once();
    int n = 0;
    for (const char *s = spec; *s; ) {
        if (*s == '?' && s[1]) {
            int id = zr_charset_id_from_token(s);
            if (id == -2) { if (n < cap) out[n++] = '?'; s += 2; continue; }
            if (id == 0x40) { for (int i = 0; i < 256 && n < cap; i++) out[n++] = (uint8_t)i; s += 2; continue; }
            if (id < 0) return -1;
            int cn; const uint8_t *t = zr_charset(id, &cn);
            for (int i = 0; i < cn && n < cap; i++) out[n++] = t[i];
            s += 2;
        } else {
            if (n < cap) out[n++] = (uint8_t)*s;
            s++;
        }
    }
    return n;
}

int zr_charset_id_from_token(const char *t) {
    if (t[0] != '?' || !t[1]) return -1;
    switch (t[1]) {
    case 'l': return CS_LOWER;  case 'u': return CS_UPPER;
    case 'd': return CS_DIGIT;  case 's': return CS_SPECIAL;
    case 'a': return CS_PRINT;  case 'h': return CS_HEX;
    case 'b': return 0x40;      /* binary: handled below via special id */
    case '1': return CS_C1; case '2': return CS_C2;
    case '3': return CS_C3; case '4': return CS_C4;
    case '?': return -2;        /* literal '?' */
    }
    return -1;
}

/* saturated multiply/add for space counting */
static uint64_t sat_add(uint64_t a, uint64_t b) {
    return UINT64_MAX - a < b ? UINT64_MAX : a + b;
}
static uint64_t sat_mul(uint64_t a, uint64_t b) {
    if (a && b > UINT64_MAX / a) return UINT64_MAX;
    return a * b;
}

/* ---------------- mask / brute ---------------- */
int gen_init_mask(gen_t *g, const char *mask, char *err, size_t el) {
    cs_init_once();
    memset(g, 0, sizeof *g);
    int p = 0;
    for (const char *s = mask; *s; ) {
        if (p >= ZR_MAX_POS) { snprintf(err, el, "mask too long"); return -1; }
        if (*s == '?') {
            int id = zr_charset_id_from_token(s);
            if (id == -2) { g->cs_id[p] = CS_LITERAL; g->lit[p] = '?'; g->cs_n[p] = 1; }
            else if (id == 0x40) { g->cs_tab[p] = CS_BIN_B; g->cs_n[p] = 256; g->cs_id[p] = 0x40; }
            else if (id >= 0) {
                int n; const uint8_t *t = zr_charset(id, &n);
                if (!n) { snprintf(err, el, "charset '%c%c' is empty (set --charset-%c)", s[0], s[1], s[1]); return -1; }
                g->cs_id[p] = (uint8_t)id; g->cs_tab[p] = t; g->cs_n[p] = n;
            } else { snprintf(err, el, "unknown mask token '?%c'", s[1]); return -1; }
            s += 2;
        } else {
            g->cs_id[p] = CS_LITERAL; g->lit[p] = (uint8_t)*s; g->cs_n[p] = 1;
            s++;
        }
        p++;
    }
    g->npos = p;
    g->min_len = g->max_len = p;
    g->variable_len = 0;
    g->total = 1;
    for (int i = 0; i < p; i++) g->total = sat_mul(g->total, (uint64_t)g->cs_n[i]);
    snprintf(g->desc, sizeof g->desc, "mask '%s' (len %d)", mask, p);
    snprintf(g->params, sizeof g->params, "mode=mask\nmask=%s", mask);
    return 0;
}

int gen_init_brute(gen_t *g, const uint8_t *cs, int csn, int minl, int maxl, char *err, size_t el) {
    cs_init_once();
    if (!cs || csn <= 0) { snprintf(err, el, "empty charset"); return -1; }
    if (minl < 1 || maxl < minl || maxl > ZR_MAX_POS) { snprintf(err, el, "bad length range"); return -1; }
    memset(g, 0, sizeof *g);
    for (int i = 0; i < maxl; i++) { g->cs_tab[i] = cs; g->cs_n[i] = csn; g->cs_id[i] = 0; }
    g->npos = maxl;
    g->min_len = minl; g->max_len = maxl;
    g->variable_len = 1;
    g->len_base[minl] = 0;
    g->total = 0;
    for (int L = minl; L <= maxl; L++) {
        uint64_t sp = 1;
        for (int i = 0; i < L; i++) sp = sat_mul(sp, (uint64_t)csn);
        g->total = sat_add(g->total, sp);
        if (L < ZR_MAX_POS) g->len_base[L + 1] = g->total;
    }
    snprintf(g->desc, sizeof g->desc, "brute force (%d chars, len %d-%d)", csn, minl, maxl);
    /* canonical params: hex charset to survive checkpoint round-trip */
    char hex[600];
    for (int i = 0, o = 0; i < csn && o < 500; i++, o += 2) snprintf(hex + o, 3, "%02x", cs[i]);
    snprintf(g->params, sizeof g->params, "mode=brute\nmin=%d\nmax=%d\ncs=%s", minl, maxl, hex);
    return 0;
}

static int mask_candidate(const gen_t *g, uint64_t idx, uint8_t *out) {
    int lo = g->variable_len ? g->min_len : g->npos;
    int hi = g->npos;
    for (int L = lo; L <= hi; L++) {
        uint64_t sp = 1;
        for (int i = 0; i < L; i++) sp = sat_mul(sp, (uint64_t)g->cs_n[i]);
        if (idx >= sp) { idx -= sp; continue; }
        for (int p = L - 1; p >= 0; p--) {
            int n = g->cs_n[p];
            out[p] = (g->cs_id[p] & CS_LITERAL) ? g->lit[p]
                                              : g->cs_tab[p][idx % n];
            idx /= (uint64_t)n;
        }
        return L;
    }
    return -1;
}

/* ---------------- dictionary + rules ---------------- */
int gen_init_dict(gen_t *g, const char *path, const char *rules_path,
                  const char *rules_inline, int builtin_rules, char *err, size_t el) {
    memset(g, 0, sizeof *g);
    FILE *f = fopen(path, "rb");
    if (!f) { snprintf(err, el, "cannot open dict '%s'", path); return -1; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    g->dict = malloc((size_t)sz + 1);
    if (!g->dict || fread(g->dict, 1, (size_t)sz, f) != (size_t)sz) {
        fclose(f); snprintf(err, el, "cannot read dict"); return -1;
    }
    fclose(f);
    g->dict_size = (uint64_t)sz;
    g->dict[sz] = '\n';
    /* line offset table */
    g->nwords = 0;
    uint64_t cap = 1 << 16;
    g->offs = malloc(cap * sizeof(uint64_t));
    int at_start = 1;
    for (uint64_t i = 0; i <= g->dict_size; i++) {
        if (at_start) {
            if (g->nwords == cap) { cap *= 2; g->offs = realloc(g->offs, cap * sizeof(uint64_t)); }
            g->offs[g->nwords++] = i;
            at_start = 0;
        }
        if (g->dict[i] == '\n') at_start = 1;
    }
    if (!g->nwords) { snprintf(err, el, "empty dictionary"); return -1; }

    /* load rules */
    char rlbuf[64];
    const char *srcs[1024]; int nsrc = 0;
    if (rules_inline) srcs[nsrc++] = rules_inline;
    if (rules_path) {
        FILE *r = fopen(rules_path, "rb");
        if (!r) { snprintf(err, el, "cannot open rules '%s'", rules_path); return -1; }
        while (nsrc < 1000 && fgets(rlbuf, sizeof rlbuf, r)) {
            size_t ln = strcspn(rlbuf, "\r\n");
            char *line = malloc(ln + 1);
            memcpy(line, rlbuf, ln); line[ln] = 0;
            if (line[0] == '#' || !line[0]) { free(line); continue; }
            srcs[nsrc++] = line;
        }
        fclose(r);
    }
    g->nrules = 0;
    g->rules = malloc(sizeof(rule_t) * (nsrc + (builtin_rules ? ZR_N_BUILTIN_RULES : 0) + 1));
    if (builtin_rules)
        for (int i = 0; i < ZR_N_BUILTIN_RULES; i++) srcs[nsrc++] = ZR_BUILTIN_RULES[i];
    char e2[64];
    for (int i = 0; i < nsrc; i++)
        if (rule_parse(srcs[i], &g->rules[g->nrules], e2, sizeof e2) == 0)
            g->nrules++;
    if (!g->nrules) { /* fallback: identity */
        rule_parse(":", &g->rules[0], e2, sizeof e2); g->nrules = 1;
    }
    g->total = sat_mul(g->nwords, (uint64_t)g->nrules);
    snprintf(g->desc, sizeof g->desc, "dictionary '%s' x %d rules", path, g->nrules);
    snprintf(g->params, sizeof g->params, "mode=dict\nwords=%llu\nrules=%d\nfingerprint=%llx",
             (unsigned long long)g->nwords, g->nrules,
             (unsigned long long)zr_crc32(g->dict, (size_t)(g->dict_size > 1 << 20 ? 1 << 20 : g->dict_size)));
    return 0;
}

/* index -> (word, rule); word-major ordering */
static int dict_candidate(const gen_t *g, uint64_t idx, uint8_t *out) {
    if (idx >= g->total) return -1;
    uint64_t w = idx / (uint64_t)g->nrules;
    int r = (int)(idx % (uint64_t)g->nrules);
    uint64_t so = g->offs[w];
    uint64_t eo = w + 1 < g->nwords ? g->offs[w + 1] : g->dict_size + 1;
    while (eo > so && (g->dict[eo - 1] == '\n' || g->dict[eo - 1] == '\r')) eo--;
    int wl = (int)(eo - so);
    if (wl > ZR_MAX_PWLEN) wl = ZR_MAX_PWLEN;
    return rule_apply(&g->rules[r], g->dict + so, wl, out);
}

int gen_at(const gen_t *g, uint64_t idx, uint8_t *out) {
    if (g->dict) return dict_candidate(g, idx, out);
    if (idx >= g->total) return -1;
    return mask_candidate(g, idx, out);
}

/* ---------------- odometer cursor (division-free hot path) ---------------- */
void gen_cur_seek(const gen_t *g, uint64_t idx, gen_cur_t *c) {
    memset(c->d, 0, sizeof c->d);
    c->w = 0; c->r = 0;
    if (g->dict) {                       /* word-major: idx = w*nrules + r */
        c->w = g->nrules ? idx / (uint64_t)g->nrules : 0;
        c->r = g->nrules ? (int)(idx % (uint64_t)g->nrules) : 0;
        c->L = 0;
        return;
    }
    int lo = g->variable_len ? g->min_len : g->npos;
    c->L = lo;
    /* walk length classes to locate idx, then split into digits */
    for (int L = lo; L <= g->npos; L++) {
        uint64_t sp = 1;
        for (int i = 0; i < L; i++) sp = sat_mul(sp, (uint64_t)g->cs_n[i]);
        if (idx >= sp) { idx -= sp; continue; }
        c->L = L;
        for (int p = L - 1; p >= 0; p--) {
            uint64_t n = (uint64_t)g->cs_n[p];
            c->d[p] = (uint32_t)(idx % n);
            idx /= n;
        }
        return;
    }
    c->L = g->npos + 1;                  /* past the end */
}

int gen_cur_emit(const gen_t *g, const gen_cur_t *c, uint8_t *out) {
    if (g->dict) {
        if (c->w >= g->nwords) return -1;
        uint64_t so = g->offs[c->w];
        uint64_t eo = c->w + 1 < g->nwords ? g->offs[c->w + 1] : g->dict_size + 1;
        while (eo > so && (g->dict[eo - 1] == '\n' || g->dict[eo - 1] == '\r')) eo--;
        int wl = (int)(eo - so);
        if (wl > ZR_MAX_PWLEN) wl = ZR_MAX_PWLEN;
        return rule_apply(&g->rules[c->r], g->dict + so, wl, out);
    }
    if (c->L > g->npos) return -1;
    for (int p = 0; p < c->L; p++)
        out[p] = (g->cs_id[p] & CS_LITERAL) ? g->lit[p] : g->cs_tab[p][c->d[p]];
    return c->L;
}

void gen_cur_advance(const gen_t *g, gen_cur_t *c) {
    if (g->dict) {
        if (++c->r >= g->nrules) { c->r = 0; c->w++; }
        return;
    }
    if (c->L > g->npos) return;
    for (int p = c->L - 1; p >= 0; p--) {
        if (++c->d[p] < (uint32_t)g->cs_n[p]) return;
        c->d[p] = 0;
    }
    /* carry out of position 0: next length class */
    c->L++;
    memset(c->d, 0, sizeof c->d);
}

void gen_free(gen_t *g) {
    free(g->dict); free(g->offs); free(g->rules);
    g->dict = NULL; g->offs = NULL; g->rules = NULL;
}

/* ---------------- rule engine ---------------- */
static int b36(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'Z') return c - 'A' + 10;
    if (c >= 'a' && c <= 'z') return c - 'a' + 10;
    return -1;
}

int rule_parse(const char *line, rule_t *r, char *err, size_t el) {
    r->n = 0;
    const char *p = line;
    while (*p && *p != ' ') {   /* space ends the rule (hashcat allows comments) */
        if (r->n >= RULE_MAX_OPS) { snprintf(err, el, "rule too long: %s", line); return -1; }
        rule_op *o = &r->ops[r->n];
        o->a = o->b = 0;
        int c = (uint8_t)*p++;
        switch (c) {
        case ':': case 'l': case 'u': case 'c': case 'C': case 't':
        case 'r': case 'd': case 'f': case '{': case '}':
        case '[': case ']': case 'q': case 'k': case 'K': case 'E':
            o->op = (uint8_t)c; break;
        case 'T': case 'D': case 'x': case 'O': case 'i': case 'o': case 'p':
        case 'z': case 'Z': case '*': case 'L': case 'R': case '\'': case 's': case '@':
        case '$': case '^':
            o->op = (uint8_t)c;
            if (c == 's' || c == 'i' || c == 'o' || c == '*') {
                if (!p[0] || !p[1]) { snprintf(err, el, "truncated rule op %c", c); return -1; }
                if (c == 's' || c == 'i' || c == 'o') { o->a = (uint8_t)p[0]; o->b = (uint8_t)p[1]; }
                else { int a = b36(p[0]), b = b36(p[1]); if (a < 0 || b < 0) { snprintf(err, el, "bad pos in %c", c); return -1; } o->a = (uint8_t)a; o->b = (uint8_t)b; }
                p += 2;
            } else if (c == '$' || c == '^') {
                o->a = (uint8_t)*p++;
            } else if (c == '@') {
                o->a = (uint8_t)*p++;
            } else { /* T D x O p z Z ' L R : one or two base-36 numbers */
                int a = b36((uint8_t)*p); if (a < 0) { snprintf(err, el, "bad arg for %c", c); return -1; }
                o->a = (uint8_t)a; p++;
                if (c == 'x' || c == 'O' || c == '*' || c == 'L' || c == 'R') {
                    int b = b36((uint8_t)*p); if (b < 0) { snprintf(err, el, "bad arg2 for %c", c); return -1; }
                    o->b = (uint8_t)b; p++;
                }
            }
            break;
        default:
            snprintf(err, el, "unknown rule op '%c'", c); return -1;
        }
        r->n++;
    }
    return 0;
}

int rule_apply(const rule_t *r, const uint8_t *w, int wlen, uint8_t *out) {
    uint8_t b1[256], b2[256];
    memcpy(b1, w, (size_t)wlen); int n = wlen;
    for (int i = 0; i < r->n; i++) {
        const rule_op *o = &r->ops[i];
        switch (o->op) {
        case ':': break;
        case 'l': for (int j = 0; j < n; j++) if (b1[j] >= 'A' && b1[j] <= 'Z') b1[j] += 32; break;
        case 'u': for (int j = 0; j < n; j++) if (b1[j] >= 'a' && b1[j] <= 'z') b1[j] -= 32; break;
        case 'c': for (int j = 0; j < n; j++) if (b1[j] >= 'A' && b1[j] <= 'Z') b1[j] += 32;
                  if (n && b1[0] >= 'a' && b1[0] <= 'z') b1[0] -= 32; break;
        case 'C': for (int j = 0; j < n; j++) if (b1[j] >= 'a' && b1[j] <= 'z') b1[j] -= 32;
                  if (n && b1[0] >= 'A' && b1[0] <= 'Z') b1[0] += 32; break;
        case 't': for (int j = 0; j < n; j++) {
                      if (b1[j] >= 'a' && b1[j] <= 'z') b1[j] -= 32;
                      else if (b1[j] >= 'A' && b1[j] <= 'Z') b1[j] += 32;
                  } break;
        case 'T': if (o->a < n) {
                      uint8_t c = b1[o->a];
                      b1[o->a] = (c >= 'a' && c <= 'z') ? c - 32 : (c >= 'A' && c <= 'Z') ? c + 32 : c;
                  } break;
        case 'r': for (int j = 0; j < n / 2; j++) { uint8_t t = b1[j]; b1[j] = b1[n-1-j]; b1[n-1-j] = t; } break;
        case 'd': if (n * 2 <= 255) { memcpy(b1 + n, b1, (size_t)n); n *= 2; } break;
        case 'f': if (n * 2 <= 255) { for (int j = 0; j < n; j++) b1[n + j] = b1[n - 1 - j]; n *= 2; } break;
        case '{': if (n) { uint8_t t = b1[0]; memmove(b1, b1 + 1, (size_t)n - 1); b1[n-1] = t; } break;
        case '}': if (n) { uint8_t t = b1[n-1]; memmove(b1 + 1, b1, (size_t)n - 1); b1[0] = t; } break;
        case '[': if (n) { memmove(b1, b1 + 1, (size_t)--n); } break;
        case ']': if (n) n--; break;
        case 'q': if (n * 2 <= 255) { int m = n; n = 0; for (int j = 0; j < m; j++) { b2[2*j] = b2[2*j+1] = b1[j]; n += 2; } memcpy(b1, b2, (size_t)n); } break;
        case 'k': if (n >= 2) { uint8_t t = b1[0]; b1[0] = b1[1]; b1[1] = t; } break;
        case 'K': if (n >= 2) { uint8_t t = b1[n-1]; b1[n-1] = b1[n-2]; b1[n-2] = t; } break;
        case 'E': { int sp = 1; for (int j = 0; j < n; j++) {
                        if (b1[j] >= 'A' && b1[j] <= 'Z') b1[j] += 32;
                        else if (sp && b1[j] >= 'a' && b1[j] <= 'z') b1[j] -= 32;
                        sp = (b1[j] == ' ');
                    } } break;
        case 'D': if (o->a < n) { memmove(b1 + o->a, b1 + o->a + 1, (size_t)(n - o->a - 1)); n--; } break;
        case 'x': if (o->a < n) { int m = o->b; if (o->a + m > n) m = n - o->a;
                      memmove(b1, b1 + o->a, (size_t)m); n = m; } break;
        case 'O': if (o->a < n) { int m = o->b; if (o->a + m > n) m = n - o->a;
                      memmove(b1 + o->a, b1 + o->a + m, (size_t)(n - o->a - m)); n -= m; } break;
        case 'i': if (o->a <= n && n < 255) { memmove(b1 + o->a + 1, b1 + o->a, (size_t)(n - o->a));
                      b1[o->a] = o->b; n++; } break;
        case 'o': if (o->a < n) b1[o->a] = o->b; break;
        case 's': for (int j = 0; j < n; j++) if (b1[j] == o->a) b1[j] = o->b; break;
        case '@': { int m = 0; for (int j = 0; j < n; j++) if (b1[j] != o->a) b2[m++] = b1[j];
                      memcpy(b1, b2, (size_t)m); n = m; } break;
        case '$': if (n < 255) b1[n++] = o->a; break;
        case '^': if (n < 255) { memmove(b1 + 1, b1, (size_t)n); b1[0] = o->a; n++; } break;
        case 'p': if (o->a && n * (o->a + 1) <= 255) { int m = n;
                      for (int j = 0; j < o->a; j++) memcpy(b1 + n + j * m, b1, (size_t)m);
                      n += o->a * m; } break;
        case 'z': if (n + o->a <= 255 && n) { memmove(b1 + o->a, b1, (size_t)n);
                      memset(b1, b1[o->a], o->a); n += o->a; } break;
        case 'Z': if (n + o->a <= 255 && n) { memset(b1 + n, b1[n-1], o->a); n += o->a; } break;
        case '*': if (o->a < n && o->b < n) { uint8_t t = b1[o->a]; b1[o->a] = b1[o->b]; b1[o->b] = t; } break;
        case 'L': if (o->a < n) b1[o->a] <<= o->b; break;
        case 'R': if (o->a < n) b1[o->a] >>= o->b; break;
        case '\'': if (o->a < n) n = o->a; break;
        default: break;
        }
    }
    if (n > ZR_MAX_PWLEN) n = ZR_MAX_PWLEN;
    memcpy(out, b1, (size_t)n);
    return n;
}

/* ---------------- builtin content ---------------- */
const char *ZR_BUILTIN_RULES[] = {
    ":", "l", "u", "c", "C", "t", "r", "d", "f",
    "$0","$1","$2","$3","$4","$5","$6","$7","$8","$9",
    "$!","$@","$#","$?","$.","$*","^1","^2","^0","^!",
    "c$0","c$1","c$2","c$3","c$4","c$5","c$9","c$!",
    "sa@","so0","si1","sl3","se3","sa@se3","sa@so0","sa@so0si1","so0si1se3",
    "$1$9$8$9","$2$0$2$4","$2$0$2$5","$1$2$3","$1$2$3$4","$0$0","$1$1","$6$9","$0$1",
    "{", "}", "[", "]",
    "T0", "T0$1", "c] ","r$1"
};
const int ZR_N_BUILTIN_RULES = (int)(sizeof(ZR_BUILTIN_RULES) / sizeof(ZR_BUILTIN_RULES[0]));

/* ~300 most common real-world passwords (public-domain frequency lists) */
const char *ZR_BUILTIN_DICT[] = {
    "password","123456","12345678","1234","qwerty","12345","dragon","pussy","baseball",
    "football","letmein","monkey","696969","abc123","mustang","michael","shadow","master",
    "jennifer","111111","2000","jordan","superman","harley","1234567","fuckme","hunter",
    "fuckyou","trustno1","ranger","buster","thomas","tigger","robert","soccer","fuck",
    "batman","test","pass","killer","hockey","george","charlie","andrew","michelle",
    "love","sunshine","jessica","asshole","6969","pepper","daniel","access","123456789",
    "654321","joshua","maggie","starwars","silver","william","dallas","yankees","123123",
    "ashley","666666","hello","amanda","orange","biteme","freedom","computer","sexy",
    "nicole","thunder","ginger","hammer","summer","corvette","taylor","fucker","austin",
    "1111","merlin","matthew","121212","golfer","cheese","princess","martin","chelsea",
    "patrick","richard","diamond","yellow","bigdog","secret","asdfgh","sparky","cowboy",
    "camaro","anthony","matrix","falcon","iloveyou","bailey","guitar","jackson","purple",
    "scooter","phoenix","aaaaaa","morgan","tigers","porsche","mickey","maverick","cookie",
    "nascar","peanut","justin","131313","money","horny","samantha","panties","steelers",
    "joseph","snoopy","boomer","whatever","iceman","smokey","gateway","dakota","cowboys",
    "eagles","chicken","dick","black","zxcvbn","please","andrea","ferrari","knight",
    "hardcore","melissa","compaq","coffee","booboo","bitch","johnny","bulldog","xxxxxx",
    "welcome","james","player","ncc1701","wizard","scooby","charles","junior","internet",
    "bigdick","mike","brandy","tennis","blowjob","banana","monster","spider","lakers",
    "miller","rabbit","enter","mercedes","brandon","steven","fender","john","yamaha",
    "diablo","chris","boston","tiger","marine","chicago","rangers","gandalf","winter",
    "bigtits","barney","edward","raiders","porn","badboy","blowme","spanky","bigdaddy",
    "johnson","chester","london","midnight","blue","fishing","000000","hannah","slayer",
    "11111111","rachel","sexsex","redsox","thx1138","asdf","marlboro","panther","zxcvbnm",
    "arsenal","oliver","qazwsx","mother","victoria","7777777","jasper","angel","david",
    "winner","crystal","golden","butthead","viking","jack","iwantu","shannon","murphy",
    "angels","prince","cameron","girls","madison","wilson","carlos","hooters","willie",
    "startrek","captain","maddog","jasmine","butter","booger","angela","golf","lauren",
    "rocket","tiffany","theman","dennis","liverpoo","flower","forever","green","jackie",
    "muffin","turtle","sophie","danielle","redskins","toyota","jason","sierra","winston",
    "debbie","giants","packers","newyork","jeremy","casper","bubba","112233","sandra",
    "lovers","mountain","united","cooper","driver","tucker","helpme","fucking","pookie",
    "lucky","maxwell","8675309","bear","suckit","gators","5150","222222","shithead",
    "fuckoff","jaguar","monica","fred","happy","hotdog","tits","gemini","lover",
    "xxxxxxxx","777777","canada","nathan","victor","florida","88888888","nicholas",
    "rosebud","metallic","doctor","trouble","success","stupid","tomcat","warrior",
    "peaches","apples","fish","qwertyui","magic","buddy","dolphins","rainbow","gunner",
    "987654321","freddy","alexis","braves","cock","2112","1212","cocacola","xavier",
    "dolphin","testing","bond007","member","calvin","voodoo","7777","samson","alex",
    "apollo","fire","tester","walter","beavis","voyager","peter","porno","bonnie",
    "rush2112","beer","apple","scorpio","jonathan","skippy","sydney","scott","red123",
    "power","gordon","travis","beaver","star","jackass","flyers","boobs","232323",
    "zzzzzz","steve","rebecca","scorpion","doggie","legend","ou812","yankee","blazer",
    "bill","runner","birdie","bitches","555555","parker","topgun","asdfasdf","heaven",
    "viper","animal","2222","bigboy","4444","arthur","baby","private","godzilla",
    "donald","williams","lifehack","phantom","dave","rock","august","sammy","cool",
    "brian","platinum","jake","bronco","paul","mark","frank","heka6w2","copper",
    "billy","cumshot","garfield","willow","cunt","little","carter","slut","albert",
    "69696969","kitten","super","jordan23","eagle1","shelby","america","11111","jessie",
    "house","free","123321","chevy","bullshit","white","broncos","horney","surfer",
    "nissan","999999","saturn","airborne","elephant","marvin","shit","action","adidas",
    "qwert","kevin","1313","explorer","walker","police","christin","december","benjamin",
    "wolf","sweet","therock","king","online","dickhead","brooklyn","teresa","cricket",
    "sharon","dexter","racing","penis","gregory","0000","teens","redwings","dreams",
    "michigan","hentai","magnum","87654321","nothing","donkey","trinity","digital",
    "333333","stella","cartman","guinness","123abc","speedy","buffalo","kitty","pimpin",
    "eagle","einstein","kelly","nelson","nirvana","vampire","xxxx","playboy","louise",
    "pumpkin","snowball","test123","girl","sucker","mexico","beatles","fantasy","ford",
    "gibson","celtic","marcus","cherry","cassie","888888","natasha","sniper","chance",
    "genesis","hotrod","reddog","alexande","college","jester","passw0rd","bigcock",
    "smith","lasvegas","carmen","slipknot","3333","death","kimberly","1q2w3e","eclipse",
    "1q2w3e4r","stanley","samuel","drpepper","mitchell","destiny","abcdef","fedex",
    "4747","georgia","chocolate","1469","goforit","lucas","magma","bf109","loser","sso",
    "mushroom","55555","omega","tinkerbell","sassy","hendrix","loki","qazwsxedc",
    "freedom1","wildcat","292929","cloud9","hacker","darkness","louie","asdfg","pizza",
    "excalibu","loveme","miranda","panty","redred","golfnut","camille","predator",
    "sporting","heather","shadow1","spring","vortex","timmy","alfa","eatme","kevin1",
    "bananas","ferrari1","whocares","wanker","dilbert","golfing","dusty","colt45",
    "pavilion","pickles","homer","moneys","pitcher","edge","simon","snowman","lesbian",
    "flipper","killme","nicky","school","hooter","maple","lespaul","weather","hello1",
    "catfish","admin","omega1","trixie","cleveland","allison","sailor","internet1",
    "foobar","password1","master1","charlie1","jordan1","michael1","dragon1","shadow2"
};
const int ZR_N_BUILTIN_DICT = (int)(sizeof(ZR_BUILTIN_DICT) / sizeof(ZR_BUILTIN_DICT[0]));
