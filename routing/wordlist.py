"""Roteador programatico de wordlists por evidencia acumulada.

O LLM nao ve catalogo e nao informa wordlist. Ele escolhe apenas ferramenta + url;
escolhemos a wordlist pelo que os resultados anteriores mostram:
ex.: se ja comprovamos WordPress, usamos wordlists de WordPress (gobuster enumerate e
wfuzz fuzz); se nao ha evidencia, usamos genericas de alto recall.
"""
from __future__ import annotations

import re
import unicodedata
from pathlib import Path

BASE = Path("wordlists/SecLists")

FALLBACK_GOBUSTER = "Discovery/Web-Content/common.txt"
FALLBACK_WFUZZ_SQLI = "Fuzzing/Databases/SQLi/quick-SQLi.txt"
FALLBACK_WFUZZ_XSS = "Fuzzing/XSS/robot-friendly/XSS-BruteLogic.txt"
FALLBACK_WFUZZ_SSTI = "Fuzzing/template-engines-special-vars.txt"
FALLBACK_WFUZZ_LFI = "Fuzzing/LFI/LFI-Jhaddix.txt"


# Tecnologia -> wordlists (gobuster dir / wfuzz)
TECH_RULES: list[tuple[list[str], str, str, str]] = [
    ([r"wordpress", r"\bwp-[a-z]", r"wp-content|wp-admin|wp-includes"],
     "Discovery/Web-Content/CMS/wordpress.fuzz.txt",
     "Discovery/Web-Content/CMS/trickest-cms-wordlist/wordpress.txt",
     "wordpress"),
    ([r"joomla"],
     "Discovery/Web-Content/CMS/trickest-cms-wordlist/joomla.txt",
     "Discovery/Web-Content/CMS/joomla-plugins.fuzz.txt",
     "joomla"),
    ([r"drupal"],
     "Discovery/Web-Content/CMS/trickest-cms-wordlist/drupal.txt",
     "Discovery/Web-Content/CMS/Drupal.txt",
     "drupal"),
    ([r"magento"],
     "Discovery/Web-Content/CMS/trickest-cms-wordlist/magento.txt",
     "Discovery/Web-Content/CMS/sitemap-magento.txt",
     "magento"),
    ([r"django"],
     "Discovery/Web-Content/CMS/trickest-cms-wordlist/django-cms.txt",
     "Discovery/Web-Content/CMS/Django.txt",
     "django"),
    # servidor Web sem evidencia de app/CMS: listas de servidor rendem ~0 na SPA;
    # raft-small (medir: 358 linhas api/admin vs 10 no Apache.txt) cobre app paths
    ([r"apache", r"tomcat"],
     "Discovery/Web-Content/raft-small-directories.txt",
     "Discovery/Web-Content/Web-Servers/Apache-Tomcat.txt",
     "apache"),
    ([r"nginx"],
     "Discovery/Web-Content/raft-small-directories.txt",
     "Discovery/Web-Content/Web-Servers/nginx.txt",
     "nginx"),
    ([r"express|node\.js|angular|react|webpack|vite|haste"],
     "Discovery/Web-Content/raft-small-directories.txt",
     FALLBACK_WFUZZ_SQLI,
     "spa_node"),
    ([r"php"],
     "Discovery/Web-Content/raft-medium-directories.txt",
     FALLBACK_WFUZZ_SQLI,
     "php"),
    ([r"graphql"],
     "Discovery/Web-Content/graphql.txt",
     "Discovery/Web-Content/graphql.txt",
     "graphql"),
    ([r"swagger|openapi"],
     "Discovery/Web-Content/common-api-endpoints-mazen160.txt",
     "Discovery/Web-Content/common-api-endpoints-mazen160.txt",
     "api"),
]

# Falha/sintoma -> wordlists de wfuzz
WFUZZ_DETECTORS: list[tuple[str, list[str], str]] = [
    ("sql_error",
     [r"mysql|sqlite|postgres|syntax error.*sql|sql.*syntax|you have an error",
      r"sqlstate|psql|odbc.*sql|mariadb"],
     "Fuzzing/Databases/SQLi/Generic-SQLi.txt"),
    ("nosql",
     [r"nosql|mongodb|mongo.*error|bson"],
     "Fuzzing/Databases/SQLi/NoSQL.txt"),
    ("xss_reflected",
     [r"<script|onerror|alert\(|xss"],
     FALLBACK_WFUZZ_XSS),
    ("ssti",
     [r"\{\{.*\}\}|ssti|jinja|twig|smarty|template.*error"],
     FALLBACK_WFUZZ_SSTI),
    ("lfi_path_traversal",
     [r"\.\./\.\./|/etc/passwd|path traversal|lfi"],
     FALLBACK_WFUZZ_LFI),
    ("blind_time_based",
     [r"time.*delay|time.*sleep|blind.*sql|boolean.*blind"],
     "Fuzzing/Databases/SQLi/sqlmap-risk-classified/Low-Risk-Payloads/time_blind.txt"),
]


def _normalize(text: str) -> str:
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    return text.lower()


def _exists(rel: str | None) -> bool:
    return bool(rel) and (BASE / rel).exists()


def _history_text(history: list[dict]) -> str:
    parts: list[str] = []
    for h in history:
        for k in ("result_summary", "summary", "interpretation", "stdout",
                  "stderr", "command", "rationale", "hypothesis"):
            v = h.get(k)
            if v:
                parts.append(str(v))
        params = h.get("params") or {}
        if params:
            parts.append(str(params))
    return _normalize(" ".join(parts))


def choose_wordlist(tool: str, history: list[dict]) -> tuple[str, str]:
    """Retorna (wordlist_relativa, motivo). Sem consulta ao LLM."""
    if tool not in ("gobuster", "wfuzz"):
        return "", "nao_aplicavel"

    text = _history_text(history)

    # 1) tecnologia especifica (CMS / servidor / framework)
    for patterns, g_word, w_word, label in TECH_RULES:
        if any(re.search(p, text) for p in patterns):
            wl = g_word if tool == "gobuster" else w_word
            if _exists(wl):
                return wl, f"evidencia_tech:{label}"

    # 2) tipo de falha observado (so para wfuzz)
    if tool == "wfuzz":
        for label, patterns, wl in WFUZZ_DETECTORS:
            if any(re.search(p, text) for p in patterns) and _exists(wl):
                return wl, f"evidencia_falha:{label}"

    # 3) fallback generico (sem evidencia)
    if tool == "gobuster":
        return (
            FALLBACK_GOBUSTER if _exists(FALLBACK_GOBUSTER) else "Discovery/Web-Content/raft-small-directories.txt",
            "fallback_generico",
        )
    return (
        FALLBACK_WFUZZ_SQLI if _exists(FALLBACK_WFUZZ_SQLI) else "Fuzzing/Databases/SQLi/Generic-SQLi.txt",
        "fallback_generico",
    )


def describe_choice(tool: str, wl: str, motivo: str) -> str:
    if not wl:
        return "wordlist: nao aplicavel para esta ferramenta"
    if motivo.startswith("evidencia_tech:"):
        return f"wordlist [{motivo.split(':', 1)[1]} por evidencia] -> {wl}"
    if motivo.startswith("evidencia_falha:"):
        return f"wordlist [{motivo.split(':', 1)[1]} por evidencia] -> {wl}"
    return f"wordlist [fallback generico — sem evidencia] -> {wl}"
