#ifndef ZR_I18N_H
#define ZR_I18N_H

/* i18n - tiny message catalog with auto language detection.
   Detection order: --lang flag > ZIPREC_LANG > LC_ALL > LC_MESSAGES > LANG
   > APPLE_LANGUAGE > GetUserDefaultUILanguage (Windows) > English.
   Machine-parseable stderr lines (stopped:/exhausted:/verified:/gpu...)
   intentionally stay English; human-facing text is localized. */

typedef enum {
    ZR_EN = 0, ZR_KO, ZR_JA, ZR_ZH, ZR_ES, ZR_DE, ZR_FR, ZR_LANG_COUNT
} zr_lang;

typedef enum {
    M_USAGE_HEAD = 0, M_USAGE_MODES, M_USAGE_MASKHDR, M_USAGE_DICTOPT,
    M_USAGE_BRUTEOPT, M_USAGE_ENGINE, M_USAGE_CKPT, M_USAGE_EXAMPLES,
    M_CONSENT, M_ABORTED, M_PAUSED,
    M_MISSING_VALUE, M_UNKNOWN_OPTION,
    M_DELEGATED, M_NOTE_EXT, M_GPU_DELEG,
    M_VERIF_FAIL, M_NEED_MODE, M_ERR_GEN,
    M_COUNT
} zr_msg;

void       zr_lang_init(const char *cli_arg);  /* call once, early in main */
zr_lang    zr_lang_current(void);
const char *zr_lang_name(zr_lang l);           /* "en","ko",... */
const char *TR(zr_msg m);                      /* localized string */

#endif
