"""Fases OWASP (WSTG) do fluxo de investigacao + allowlist de flags.

Ideias:
- Fases sao puro codigo: a lista completa, as flags validas e as transicoes
  sao computaveis/testaveis sem LLM. O LLM pode declarar flags numa proposta;
  o codigo saneia contra FLAG_NAMES e o humano aprova no painel.
- "Pular recon" eh permitido pre-semeando flags a partir do conhecimento humano
  (endpoints/suspeita): fase inicial = Validacao (3).
"""
from __future__ import annotations

PHASES: list[dict] = [
    {"id": 0, "key": "parceria", "nome": "Parceria/intake", "wstg": "",
     "tools": [],
     "flags_sugeridas": [],
     "sair_quando": "humano descreve objetivo e confirma a fase inicial"},
    {"id": 1, "key": "reconhecimento", "nome": "Reconhecimento", "wstg": "WSTG-INFO",
     "tools": ["nmap", "http_request"],
     "flags_sugeridas": ["nmap_sweep_feito", "nmap_versoes_feitas", "portas_abertas", "http_confirmado"],
     "sair_quando": "http_confirmado ou objetivo cumprido"},
    {"id": 2, "key": "enumeracao", "nome": "Enumeracao/Config", "wstg": "WSTG-CONF-05 + WSTG-INFO",
     "tools": ["gobuster", "wfuzz", "nikto"],
     "flags_sugeridas": ["tech_detectada", "rotas_encontradas", "headers_verificados", "nikto_feito"],
     "sair_quando": "rotas/arquivos encontrados ou headers verificados"},
    {"id": 3, "key": "validacao", "nome": "Validacao de vulnerabilidades", "wstg": "WSTG-INPVAL",
     "tools": ["wapiti", "wfuzz", "nikto"],
     "flags_sugeridas": ["endpoint_conhecido", "sqli_suspeita", "xss_suspeita", "lfi_suspeita",
                          "ssrf_suspeita", "ssti_suspeita", "rce_suspeita", "upload_suspeita",
                          "vuln_confirmada"],
     "sair_quando": "vuln_confirmada ou objetivo cumprido"},
    {"id": 4, "key": "relatorio", "nome": "Encerramento/Relatorio", "wstg": "",
     "tools": ["conclude"],
     "flags_sugeridas": ["relatorio_gerado"],
     "sair_quando": "relatorio OWASP gerado ou humano encerra"},
]

PHASE_BY_ID = {p["id"]: p for p in PHASES}

# Registro fixo de flags (allowlist) — o LLM declara; o codigo saneia; o humano aprova.
FLAG_NAMES: frozenset[str] = frozenset({
    # recon / mapeamento
    "nmap_sweep_feito", "nmap_versoes_feitas", "portas_abertas", "http_confirmado",
    # superficie / config
    "tech_detectada", "rotas_encontradas", "headers_verificados", "nikto_feito",
    # suspeitas/confirmacao
    "endpoint_conhecido", "sqli_suspeita", "xss_suspeita", "lfi_suspeita",
    "ssrf_suspeita", "ssti_suspeita", "rce_suspeita", "upload_suspeita",
    "vuln_confirmada",
    # destino final
    "relatorio_gerado",
})

_SUSPEITA_PATTERNS: list[tuple[str, tuple[str, ...]]] = [
    ("sqli_suspeita", ("sqli", "sql injection", "injecao sql", "injencao sql", "union select", "' or ", "blind sql")),
    ("xss_suspeita", ("xss", "cross-site", "cross site", "<script")),
    ("lfi_suspeita", ("lfi", "path traversal", "directory traversal", "../", "file inclusion")),
    ("ssrf_suspeita", ("ssrf", "server-side request")),
    ("ssti_suspeita", ("ssti", "template injection", "{{7*7")),
    ("rce_suspeita", ("rce", "command injection", "cmd injection", "execucao de comando")),
    ("upload_suspeita", ("upload", "deseriali", "file upload")),
]


def phase(phase_id: int) -> dict:
    try:
        return PHASE_BY_ID[int(phase_id)]
    except (KeyError, TypeError, ValueError):
        raise ValueError(f"fase invalida: {phase_id!r}; validas: 0-4") from None


def sanitize_flags(flags) -> tuple[list[str], list[str]]:
    """Divide flags em (validas, desconhecidas). Dedup preservando ordem."""
    validas: list[str] = []
    desconhecidas: list[str] = []
    seen: set[str] = set()
    for f in flags or []:
        name = str(f).strip().lower()
        if not name:
            continue
        if name in seen:
            continue
        seen.add(name)
        (validas if name in FLAG_NAMES else desconhecidas).append(name)
    return validas, desconhecidas


def initial_flags_from_knowledge(conhecimento: dict | None) -> list[str]:
    """Pre-semeia flags a partir do conhecimento humano (endpoints/suspeita)."""
    if not isinstance(conhecimento, dict):
        return []
    flags: list[str] = []
    if conhecimento.get("endpoints"):
        flags.append("endpoint_conhecido")
    suspeita = str(conhecimento.get("suspeita") or "").lower()
    for flag, needles in _SUSPEITA_PATTERNS:
        if any(n in suspeita for n in needles):
            flags.append(flag)
            break
    return flags


def fase_inicial_from_knowledge(conhecimento: dict | None, fase_inicial: int | None = None) -> int:
    """Humano com endpoints/suspeita pula o recon; senao comeca no recon."""
    if fase_inicial is not None:
        return phase(fase_inicial)["id"]
    if isinstance(conhecimento, dict) and (conhecimento.get("endpoints") or conhecimento.get("suspeita")):
        return 3
    return 1


def merge_flags(acum: list[str], novas: list[str]) -> list[str]:
    out = list(acum)
    for f in novas:
        if f not in out:
            out.append(f)
    return out


def phase_header(fase: int) -> str:
    p = phase(fase)
    return f"Fase {p['id']} — {p['nome']}" + (f" ({p['wstg']})" if p["wstg"] else "")


def phase_prompt_block(fase: int, flags: list[str]) -> str:
    """Bloco compacto para o prompt: onde estamos, flags, tools da fase."""
    p = phase(fase)
    lines = [f"Fase atual: {p['id']} — {p['nome']}" + (f" ({p['wstg']})" if p["wstg"] else "")]
    if p["tools"]:
        lines.append("Ferramentas recomendadas na fase: " + ", ".join(p["tools"]))
    lines.append("Flags acumuladas: " + (", ".join(flags) if flags else "nenhuma"))
    lines.append("Sair da fase quando: " + p["sair_quando"])
    lines.append("Voce PODE propor ferramenta fora da fase, mas explique por que ela ajuda o objetivo agora.")
    return "\n".join(lines)
