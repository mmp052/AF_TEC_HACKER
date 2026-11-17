"""wapiti: scan de vulnerabilidades web. Mesmo modelo supervisionado das outras
tools: alvo allowlist, flags validadas aqui (allowlist) e aprovacao humana no loop."""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from agent_schemas import ToolResult
from guardrails import validate_url, ALLOWED_HOSTS
from tools.base import run_cmd

# wapiti 3.3.2 --list-modules — nomes exatos; nao ampliar sem conferir o help da versao
MODULES = frozenset({
    "backup", "brute_login_form", "buster", "cms", "crlf", "csrf", "exec", "file",
    "htaccess", "htp", "ldap", "log4shell", "methods", "network_device", "nikto",
    "permanentxss", "printer", "redirect", "shellshock", "spring4shell", "sql",
    "ssl", "ssrf", "takeover", "timesql", "upload", "wapp", "wp_enum", "xss", "xxe",
})
# mesmo host apenas; domain/punk/subdomain nao sao oferecidos ao agente
SCOPES = frozenset({"url", "page", "folder"})
_INT_RANGES = {"level": (1, 4), "depth": (1, 5), "max_scan_time": (30, 900),
               "max_attack_time": (1, 300), "max_parameters": (1, 100),
               "tasks": (1, 10), "timeout": (1, 30)}
_ALLOWED = frozenset({"url", "modules", "scope", "level", "depth", "max_scan_time",
                      "max_attack_time", "max_parameters", "tasks", "timeout", "data"})
_FLAG = {"level": "-l", "depth": "-d", "max_scan_time": "--max-scan-time",
         "max_attack_time": "--max-attack-time", "max_parameters": "--max-parameters",
         "tasks": "--tasks", "timeout": "-t"}


def build_wapiti_command(url: str, params: dict, report_path: str | Path) -> list[str]:
    p = dict(params or {})
    unknown = set(p) - _ALLOWED
    if unknown:
        raise ValueError(f"params desconhecidos: {sorted(unknown)}; "
                         f"params permitidos: {sorted(_ALLOWED)}")
    url_param = p.get("url", url) or url
    cmd = ["wapiti", "-u", url_param, "-f", "txt", "-o", str(report_path)]

    mods = p.get("modules")
    if mods is not None:
        items = [str(m).strip().lower()
                 for m in (mods if isinstance(mods, (list, tuple)) else str(mods).split(","))]
        items = [m for m in items if m]
        bad = [m for m in items if m not in MODULES]
        if bad:
            raise ValueError(f"modulo(s) desconhecido(s): {bad}; veja `wapiti --list-modules`")
        if items:
            cmd += ["-m", ",".join(items)]

    scope = str(p.get("scope", "folder")).lower()
    if scope not in SCOPES:
        raise ValueError(f"scope invalido: {scope}; permitidos: {sorted(SCOPES)}")
    cmd += ["--scope", scope]

    for key, (lo, hi) in _INT_RANGES.items():
        v = p.get(key)
        if v is None:
            v = 300 if key == "max_scan_time" else None  # limite padrao do scan
        if v is None:
            continue
        try:
            v = int(v)
        except (TypeError, ValueError):
            raise ValueError(f"{key} precisa ser inteiro") from None
        if not lo <= v <= hi:
            raise ValueError(f"{key} fora da faixa [{lo}, {hi}]")
        cmd += [_FLAG[key], str(v)]

    data = p.get("data")
    if data is not None:
        if len(str(data)) > 500:
            raise ValueError("data longo demais (maximo 500 caracteres)")
        cmd += ["--data", str(data)]
    return cmd


def _collect_report(tmp: Path) -> str:
    partes = []
    for f in sorted(p for p in tmp.iterdir() if p.is_file()):
        try:
            partes.append(f.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            pass
    return "\n---\n".join(p for p in partes if p).strip()


def run_wapiti(params: dict, timeout: int | None = None,
               allowed_hosts: set[str] | None = None) -> ToolResult:
    url = (params or {}).get("url")
    if not url:
        raise ValueError("url obrigatoria")
    validate_url(url, allowed_hosts or ALLOWED_HOSTS)
    scan_time = int((params or {}).get("max_scan_time", 300))
    tmp = Path(tempfile.mkdtemp(prefix="wapiti-"))
    report = tmp / "report"
    try:
        cmd = build_wapiti_command(url, params, report)
        r = run_cmd(cmd, timeout or scan_time + 120)
        collected = _collect_report(tmp)
        if collected:
            r.stdout = (r.stdout + "\n[report]\n" + collected)[:8000]
            r.summary = (r.summary + "\n[report]\n" + collected)[:4000]
        return r
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
