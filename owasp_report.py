"""Relatorio de investigacao baseado no OWASP (WSTG + Top 10 2021).

Regra de ouro: so entra como achado aquilo que o analista humano confirmou
no veredito (human_validation.verdict == "confirmado"). O resto vai para a
trilha completa de passos, rotulado como inconclusivo/refutado/etc.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from reporter import _row_fields, normalizar_veredito

# (wstg_id, top10_2021, cwe_indicativo, severidade_indicativa) por ferramenta
_OWASP = {
    "nmap": ("WSTG-INFO-09", None, None, "Informativo"),
    "http_request": ("WSTG-INFO-09", None, None, "Informativo"),
    "gobuster": ("WSTG-CONF-05", "A05:2021 - Security Misconfiguration",
                 "CWE-200 (exposicao de informacao)", "Baixa/Media (indicativa)"),
    "wfuzz": ("WSTG-INPVAL-01", "A03:2021 - Injection",
              "CWE-89 / CWE-79", "Media (indicativa)"),
    "wapiti": ("WSTG-INPVAL-05", "A03:2021 - Injection",
               "CWE-89 (sqli; outros modulos variam)", "Media/Alta (indicativa)"),
    "nikto": ("WSTG-CONF-05", "A05:2021 - Security Misconfiguration",
              "CWE-16 (configuracao) / CWE-200 (exposicao de informacao)", "Baixa/Media (indicativa)"),
}
_DEFAULT_OWASP = ("WSTG-INFO", None, None, "Informativo")

_WSTG_METHOD = {
    "nmap": "WSTG-INFO-09 — reconhecimento de rede/servico e fingerprint",
    "http_request": "WSTG-INFO-09 — reconhecimento de aplicacao (resposta HTTP)",
    "gobuster": "WSTG-CONF-05 — enumeracao de diretorios/interfaces",
    "wfuzz": "WSTG-INPVAL-01 — validacao de entrada (fuzzing)",
    "wapiti": "WSTG-INPVAL-05 / WSTG-INPVAL-01 — scan de vulnerabilidades",
    "nikto": "WSTG-CONF-05 — configuracao, cabecalhos e arquivos default do servidor",
}

_REMEDIACAO = {
    "A03:2021 - Injection": ("OWASP Cheat Sheet — SQL Injection Prevention: "
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html "
        "| XSS Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"),
    "A05:2021 - Security Misconfiguration": ("OWASP Cheat Sheet — Configuration and Deployment Management: "
        "https://cheatsheetseries.owasp.org/cheatsheets/Configuration_and_Deployment_Management_Cheat_Sheet.html "
        "| WSTG: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Configuration_and_Deployment_Management"),
}
_WSTG_FALLBACK = "OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/"


def owasp_for_tool(tool: str) -> tuple[str, str | None, str | None, str]:
    """Retorna (wstg_id, top10_2021_ou_None, cwe_ou_None, severidade_indicativa)."""
    return _OWASP.get(tool, _DEFAULT_OWASP)


def _finding_md(idx: int, row) -> str:
    _id, hip, p, d, tool, cmd, r, interp, v = _row_fields(row)
    wstg, top10, cwe, sev = owasp_for_tool(tool)
    md = [f"### {idx}. [CONFIRMADO] {hip}", "",
          f"- **Ferramenta:** `{tool}` · **id:** {_id}",
          f"- **Comando:** `{cmd}`",
          f"- **OWASP:** {wstg} · {top10 or 'reconhecimento (sem categoria Top 10)'} · "
          f"CWE indicado: {cwe or 'n/a'}",
          f"- **Severidade indicativa:** {sev} (confirmar com PoC manual)",
          "",
          "**Saida (bruta, truncada):**",
          "```",
          (r.get("stdout") or r.get("summary") or "(sem saida)")[:1500],
          "```",
          "",
          f"**Interpretacao do agente (veredito humano confirmou):** {interp}",
          "",
          f"- **Veredito humano:** {normalizar_veredito(v.get('verdict'))}" +
          (f" · **Instrucao do humano:** {v.get('instruction')}" if v.get("instruction") else ""),
          ]
    missing = v.get("refs_missing") or []
    if missing:
        md.append(f"- **Verificacao de referencias:** ATENCAO — citadas na interpretacao "
                  f"mas ausentes na saida: {', '.join('`' + m + '`' for m in missing)}")
    remediation = _REMEDIACAO.get(top10) or _WSTG_FALLBACK
    md.append(f"- **Remediacao:** {remediation}")
    return "\n".join(md)


def render_owasp_report(rows: list[tuple], investigation_id: str, objective: str) -> str:
    items = [_row_fields(row) for row in rows]
    verdicts = [normalizar_veredito(i[8].get("verdict")) for i in items]
    n = len(items)
    n_conf = sum(1 for v in verdicts if v == "confirmado")
    n_incon = sum(1 for v in verdicts if v == "inconclusivo")
    n_ref = sum(1 for v in verdicts if v == "refutado")
    tools_used = []
    for i in items:
        if i[4] not in tools_used:
            tools_used.append(i[4])

    achados = [(_idx + 1, row) for _idx, row in enumerate(rows)
               if normalizar_veredito(_row_fields(row)[8].get("verdict")) == "confirmado"]

    lines = [
        f"# Relatorio de investigacao — {investigation_id}",
        "",
        f"**Objetivo:** {objective}",
        f"**Data:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} · "
        f"**Passos executados:** {n} · **Evidencia:** events.jsonl + evidence.db (reconstruivel)",
        "",
        "## Sumário executivo",
        "",
        f"Investigacao conduzida em alvo autorizado, com aprovacao humana a cada passo, seguindo a "
        f"**OWASP Web Security Testing Guide (WSTG)**. De {n} passos registrados, **{n_conf} foram "
        f"confirmados** pelo analista humano ({n_incon} inconclusivos, {n_ref} refutados).",
        "",
        f"- Ferramentas utilizadas: {', '.join(tools_used) or 'nenhuma'}",
        f"- Achados confirmados: {len(achados)} — ver secao Achados",
        "- Nenhum achado entra neste relatorio sem veredito humano `confirmado` sobre a interpretacao.",
        "",
        "## Metodologia (OWASP WSTG)",
        "",
        "| Fase WSTG | Ferramenta |",
        "|---|---|",
    ]
    for t in tools_used:
        lines.append(f"| {_WSTG_METHOD.get(t, 'WSTG-INFO — informacao geral')} | `{t}` |")

    lines += ["", "## Achados", ""]
    if achados:
        for n_ach, (_orig_idx, row) in enumerate(achados, start=1):
            lines.append(_finding_md(n_ach, row))
            lines.append("")
    else:
        lines.append("Nenhum achado confirmado nesta investigacao.")
        lines.append("")

    lines += [
        "## Todos os passos (trilha completa)",
        "",
        "| # | Tool | Veredito | Decisao |",
        "|---|------|----------|---------|",
    ]
    for idx, row in enumerate(rows):
        _id, hip, p, d, tool, cmd, r, interp, v = _row_fields(row)
        lines.append(f"| {idx + 1} | `{tool}` | {normalizar_veredito(v.get('verdict'))} | {d.get('action', '')} |")

    lines += [
        "",
        "## Limitações",
        "",
        "- Escopo limitado ao alvo autorizado e aos modulos/flags efetivamente executados; outros vetores "
        "(autenticacao, logica de negocio, autorizacao) nao foram necessariamente testados.",
        "- A interpretacao inicial e do LLM (modelo local); cada achado so consta aqui porque o analista "
        "humano confirmou no veredito. Refutacoes e inconclusivos aparecem na trilha.",
        "- Categorias WSTG/Top 10 e severidades sao **indicativas** — confirmar com PoC manual antes de "
        "reportar como vulnerabilidade definitiva.",
        "- Referencias: OWASP WSTG (https://owasp.org/www-project-web-security-testing-guide/) · "
        "OWASP Top 10 2021 (https://owasp.org/Top10/) · OWASP Cheat Sheet Series "
        "(https://cheatsheetseries.owasp.org/)",
        "",
    ]
    return "\n".join(lines)


def write_owasp_report(rows: list[tuple], investigation_id: str,
                       objective: str, runs_dir) -> Path:
    out_dir = Path(runs_dir) / investigation_id
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "owasp_report.md"
    out.write_text(render_owasp_report(rows, investigation_id, objective), encoding="utf-8")
    return out
