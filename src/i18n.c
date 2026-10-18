/* i18n.c - message catalog; English index 0 is the fallback for gaps */
#include "i18n.h"
#include <string.h>
#include <stdlib.h>

#if defined(_WIN32)
#include <windows.h>
#endif

static zr_lang cur = ZR_EN;
static int   initialized = 0;

zr_lang zr_lang_current(void) { return cur; }

const char *zr_lang_name(zr_lang l) {
    static const char *n[] = {"en","ko","ja","zh","es","de","fr"};
    return (l >= 0 && l < ZR_LANG_COUNT) ? n[l] : "en";
}

static zr_lang parse_tag(const char *s) {
    if (!s || !*s) return (zr_lang)-1;
    if (!strncasecmp(s, "ko", 2)) return ZR_KO;
    if (!strncasecmp(s, "ja", 2)) return ZR_JA;
    if (!strncasecmp(s, "zh", 2)) return ZR_ZH;
    if (!strncasecmp(s, "es", 2)) return ZR_ES;
    if (!strncasecmp(s, "de", 2)) return ZR_DE;
    if (!strncasecmp(s, "fr", 2)) return ZR_FR;
    if (!strncasecmp(s, "en", 2)) return ZR_EN;
    return (zr_lang)-1;
}

void zr_lang_init(const char *cli_arg) {
    if (initialized) return;
    initialized = 1;
    zr_lang l;
    if (cli_arg && (l = parse_tag(cli_arg)) >= 0) { cur = l; return; }
    const char *names[] = {
        "ZIPREC_LANG", "LC_ALL", "LC_MESSAGES", "LANG", "APPLE_LANGUAGE", NULL
    };
    for (int i = 0; names[i]; i++) {
        const char *v = getenv(names[i]);
        if (v && (l = parse_tag(v)) >= 0) { cur = l; return; }
    }
#if defined(_WIN32)
    LANGID id = GetUserDefaultUILanguage();
    switch (PRIMARYLANGID(id)) {
        case LANG_KOREAN:   cur = ZR_KO; return;
        case LANG_JAPANESE: cur = ZR_JA; return;
        case LANG_CHINESE:  cur = ZR_ZH; return;
        case LANG_SPANISH:  cur = ZR_ES; return;
        case LANG_GERMAN:   cur = ZR_DE; return;
        case LANG_FRENCH:   cur = ZR_FR; return;
        default: break;
    }
#endif
    cur = ZR_EN;
}

/* [M_COUNT][ZR_LANG_COUNT] — NULL cell falls back to English */
static const char *const T[M_COUNT][ZR_LANG_COUNT] = {
[M_USAGE_HEAD] = {
    "usage: ziprec ARCHIVE [options]",
    "사용법: ziprec ARCHIVE [옵션]",
    "使い方: ziprec ARCHIVE [オプション]",
    "用法: ziprec ARCHIVE [选项]",
    "uso: ziprec ARCHIVE [opciones]",
    "Aufruf: ziprec ARCHIVE [Optionen]",
    "usage : ziprec ARCHIVE [options]",
},
[M_USAGE_MODES] = {
    "search modes (pick one):",
    "탐색 모드 (하나 선택):",
    "探索モード (いずれか選択):",
    "搜索模式 (任选其一):",
    "modos de búsqueda (elige uno):",
    "Suchmodi (einen wählen):",
    "modes de recherche (en choisir un) :",
},
[M_USAGE_MASKHDR] = {
    "mask tokens:",
    "마스크 토큰:",
    "マスクトークン:",
    "掩码标记:",
    "tokens de máscara:",
    "Masken-Tokens:",
    "jetons de masque :",
},
[M_USAGE_DICTOPT] = {
    "dictionary options:",
    "사전 옵션:",
    "辞書オプション:",
    "字典选项:",
    "opciones de diccionario:",
    "Wörterbuch-Optionen:",
    "options du dictionnaire :",
},
[M_USAGE_BRUTEOPT] = {
    "brute options:",
    "전체 탐색 옵션:",
    "総当たりオプション:",
    "暴力搜索选项:",
    "opciones de fuerza bruta:",
    "Brute-Force-Optionen:",
    "options de force brute :",
},
[M_USAGE_ENGINE] = {
    "engine:",
    "엔진:",
    "エンジン:",
    "引擎:",
    "motor:",
    "Engine:",
    "moteur :",
},
[M_USAGE_CKPT] = {
    "checkpoint / output:",
    "체크포인트 / 출력:",
    "チェックポイント / 出力:",
    "检查点 / 输出:",
    "punto de control / salida:",
    "Checkpoint / Ausgabe:",
    "point de contrôle / sortie :",
},
[M_USAGE_EXAMPLES] = {
    "examples:",
    "예시:",
    "例:",
    "示例:",
    "ejemplos:",
    "Beispiele:",
    "exemples :",
},
[M_CONSENT] = {
    "ziprec: recover only files you own or are authorized to recover.\n        Proceed for '%s'? [y/N] ",
    "ziprec: 본인 소유 또는 복구 권한이 있는 파일만 복구하세요.\n        '%s' 진행할까요? [y/N] ",
    "ziprec: 所有権または回復権限のあるファイルのみ回復してください。\n        '%s' を実行しますか? [y/N] ",
    "ziprec: 仅恢复您拥有或获授权恢复的文件。\n        继续处理 '%s'? [y/N] ",
    "ziprec: recupere solo archivos que posea o tenga autorización.\n        ¿Continuar con '%s'? [y/N] ",
    "ziprec: Stellen Sie nur Dateien wieder her, die Ihnen gehören.\n        Fortfahren mit '%s'? [y/N] ",
    "ziprec : ne récupérez que vos propres fichiers autorisés.\n         Continuer pour '%s' ? [o/N] ",
},
[M_ABORTED] = {
    "aborted.", "중단됨.", "中止しました.", "已中止.", "cancelado.",
    "Abgebrochen.", "annulé.",
},
[M_PAUSED] = {
    "\n[paused — checkpoint saved; resume with SIGCONT/fg]\n",
    "\n[일시정지 — 체크포인트 저장됨; SIGCONT/fg로 재개]\n",
    "\n[一時停止 — チェックポイント保存済み; SIGCONT/fg で再開]\n",
    "\n[已暂停 — 检查点已保存; 用 SIGCONT/fg 恢复]\n",
    "\n[pausado — punto de control guardado; reanudar con SIGCONT/fg]\n",
    "\n[pausiert — Checkpoint gespeichert; Fortsetzen mit SIGCONT/fg]\n",
    "\n[pause — point de contrôle enregistré ; reprendre avec SIGCONT/fg]\n",
},
[M_MISSING_VALUE] = {
    "missing value for %s\n", "%s 옵션에 값이 없습니다\n",
    "%s の値がありません\n", "%s 缺少参数值\n",
    "falta el valor de %s\n", "fehlender Wert für %s\n",
    "valeur manquante pour %s\n",
},
[M_UNKNOWN_OPTION] = {
    "unknown option: %s\n", "알 수 없는 옵션: %s\n",
    "不明なオプション: %s\n", "未知选项: %s\n",
    "opción desconocida: %s\n", "unbekannte Option: %s\n",
    "option inconnue : %s\n",
},
[M_DELEGATED] = {
    "(delegated engine)", "(위임 엔진)", "(委任エンジン)",
    "(委托引擎)", "(motor delegado)", "(delegierte Engine)",
    "(moteur délégué)",
},
[M_NOTE_EXT] = {
    "entry listing needs 7zz; cracking uses 2john + hashcat/john + archive verify",
    "엔트리 목록은 7zz 필요; 크랙은 2john + hashcat/john + 아카이브 검증 사용",
    "エントリ一覧には 7zz が必要; クラックは 2john + hashcat/john + アーカイブ検証を使用",
    "列出条目需要 7zz; 破解使用 2john + hashcat/john + 归档验证",
    "el listado necesita 7zz; el crackeo usa 2john + hashcat/john + verificación",
    "Eintragsliste benötigt 7zz; Knacken via 2john + hashcat/john + Archiv-Test",
    "le listage requiert 7zz ; le craquage utilise 2john + hashcat/john + test",
},
[M_GPU_DELEG] = {
    "delegating to hashcat", "hashcat에 위임", "hashcat に委任",
    "委托给 hashcat", "delegando a hashcat", "an hashcat delegieren",
    "délégation à hashcat",
},
[M_VERIF_FAIL] = {
    "gpu-reported candidate failed native verify; continuing...",
    "GPU 후보가 네이티브 검증 실패; 계속합니다...",
    "GPU の候補がネイティブ検証に失敗; 継続します...",
    "GPU 候选未通过原生验证; 继续...",
    "el candidato de GPU falló la verificación nativa; continuando...",
    "GPU-Kandidat fiel native Prüfung nicht; weiter...",
    "le candidat GPU a échoué à la vérification native ; poursuite...",
},
[M_NEED_MODE] = {
    "no search mode: defaulting to builtin dictionary + rules",
    "탐색 모드 없음: 내장 사전+규칙으로 진행",
    "探索モード未指定: 内蔵辞書+ルールを使用",
    "未指定搜索模式: 使用内置字典+规则",
    "sin modo de búsqueda: diccionario interno + reglas",
    "kein Suchmodus: eingebautes Wörterbuch + Regeln",
    "aucun mode : dictionnaire interne + règles",
},
[M_ERR_GEN] = {
    "error: %s\n", "오류: %s\n", "エラー: %s\n", "错误: %s\n",
    "error: %s\n", "Fehler: %s\n", "erreur : %s\n",
},
};

const char *TR(zr_msg m) {
    const char *s = T[m][cur];
    return s ? s : T[m][ZR_EN];
}
