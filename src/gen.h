/*
 * gen.h - candidate generators. Every generator is a pure function
 *   gen_at(g, index, out, &len)
 * so the whole search space is addressable by a single u64 index;
 * that index is also the resume token.
 */
#ifndef ZR_GEN_H
#define ZR_GEN_H

#include "platform.h"

#define ZR_MAX_PWLEN 64
#define ZR_MAX_POS   64

/* predefined charset ids */
enum {
    CS_LOWER = 0, CS_UPPER, CS_DIGIT, CS_SPECIAL, CS_ALNUM, CS_PRINT, CS_HEX,
    CS_C1, CS_C2, CS_C3, CS_C4,      /* user-defined via --charset-N */
    CS_LITERAL = 0x80              /* flag: position is a literal byte */
};

/* a parsed rule = sequence of ops; args hold char/pos values */
typedef struct { uint8_t op, a, b; } rule_op;
#define RULE_MAX_OPS 8
typedef struct { rule_op ops[RULE_MAX_OPS]; int n; } rule_t;

typedef struct {
    /* ---- mask / brute generator ---- */
    int      npos;                          /* positions in mask */
    uint8_t  cs_id[ZR_MAX_POS];             /* charset id or CS_LITERAL flag */
    uint8_t  lit[ZR_MAX_POS];               /* literal byte when CS_LITERAL */
    const uint8_t *cs_tab[ZR_MAX_POS];      /* resolved charset bytes */
    int      cs_n[ZR_MAX_POS];
    int      min_len, max_len;              /* brute: length range (uniform charset per pos) */
    int      variable_len;                  /* 1 for brute mode */
    uint64_t len_base[ZR_MAX_POS + 1];      /* cumulative space by length */
    /* ---- dict generator ---- */
    uint8_t *dict; uint64_t dict_size;
    uint64_t *offs; uint64_t nwords;
    rule_t *rules; int nrules;
    /* ---- shared ---- */
    uint64_t total;                         /* total candidates (0 = unbounded stream) */
    char     desc[256];                     /* human-readable description for UI */
    char     params[512];                   /* canonical params for checkpoint */
} gen_t;

/* charset access */
const uint8_t *zr_charset(int id, int *n);
int  zr_charset_id_from_token(const char *tok); /* "?l" -> CS_LOWER ... */
void zr_set_user_charset(int slot, const char *s); /* slot 0..3 -> ?1..?4 */
int  zr_charset_expand(const char *spec, uint8_t *out, int cap); /* "?l?d"/literal */

/* mask string like "?u?l?l?d?d" or "Abc?d?d"; ?0-?4 custom, ?? literal '?' */
int  gen_init_mask(gen_t *g, const char *mask, char *err, size_t el);
int  gen_init_brute(gen_t *g, const uint8_t *cs, int csn, int minl, int maxl, char *err, size_t el);
int  gen_init_dict(gen_t *g, const char *path, const char *rules_path,
                   const char *rules_inline, int builtin_rules, char *err, size_t el);
void gen_free(gen_t *g);

/* produce candidate for index; returns length or -1 if idx >= total */
int  gen_at(const gen_t *g, uint64_t idx, uint8_t *out);

/*
 * Per-worker odometer cursor: division-free emission for consecutive
 * indices. seek() once per chunk, then emit()+advance() per candidate.
 * Same index<->candidate bijection as gen_at (checkpoint-compatible).
 */
typedef struct {
    int      L;                 /* current length (mask/brute) */
    uint32_t d[ZR_MAX_POS];     /* digit odometer per position */
    uint64_t w;                 /* dict: word index */
    int      r;                 /* dict: rule index */
} gen_cur_t;
void gen_cur_seek(const gen_t *g, uint64_t idx, gen_cur_t *c);
int  gen_cur_emit(const gen_t *g, const gen_cur_t *c, uint8_t *out); /* len or -1 */
void gen_cur_advance(const gen_t *g, gen_cur_t *c);

/* rule engine */
int  rule_parse(const char *line, rule_t *r, char *err, size_t el);
int  rule_apply(const rule_t *r, const uint8_t *w, int wlen, uint8_t *out);

/* builtin rule set for dictionary attacks */
extern const char *ZR_BUILTIN_RULES[];
extern const int   ZR_N_BUILTIN_RULES;

/* builtin mini dictionary (~500 common passwords) */
extern const char *ZR_BUILTIN_DICT[];
extern const int   ZR_N_BUILTIN_DICT;

#endif
