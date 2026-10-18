#include "ckpt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int zr_ckpt_save(const char *path, const zr_ckpt *c) {
    char tmp[4200];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) return -1;
    fprintf(f, "ZIPREC-CKPT v1\n");
    fprintf(f, "file=%s\n", c->file);
    fprintf(f, "fsize=%llu\nfmtime=%llu\n",
            (unsigned long long)c->fsize, (unsigned long long)c->fmtime);
    fprintf(f, "%s\n", c->params);        /* params is a multi-line block, ends at 'next=' */
    fprintf(f, "next=%llu\ndone=%llu\n",
            (unsigned long long)c->next, (unsigned long long)c->done_at_save);
    fclose(f);
    return zr_rename(tmp, path);
}

/* params occupies lines between 'fmtime=' and 'next=' */
int zr_ckpt_load(const char *path, zr_ckpt *c) {
    memset(c, 0, sizeof *c);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[512];
    if (!fgets(line, sizeof line, f) || strncmp(line, "ZIPREC-CKPT v1", 14)) { fclose(f); return -1; }
    int stage = 0;
    char *pp = c->params;
    size_t pr = sizeof(c->params) - 1;
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (!strncmp(line, "file=", 5))   snprintf(c->file, sizeof c->file, "%s", line + 5);
        else if (!strncmp(line, "fsize=", 6))  c->fsize  = strtoull(line + 6, 0, 10);
        else if (!strncmp(line, "fmtime=", 7)) c->fmtime = strtoull(line + 7, 0, 10);
        else if (!strncmp(line, "next=", 5))  { c->next = strtoull(line + 5, 0, 10); stage = 1; }
        else if (!strncmp(line, "done=", 5))    c->done_at_save = strtoull(line + 5, 0, 10);
        else if (!stage) {
            size_t l = strlen(line);
            if (l + 1 < pr) { memcpy(pp, line, l + 1); pp += l; *pp++ = '\n'; pr -= l + 1; }
        }
    }
    fclose(f);
    if (pp > c->params && pp[-1] == '\n') pp--;
    *pp = 0;
    return 0;
}
