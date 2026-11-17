"""nikto: scan de servidor/aplicacao web (cabecalhos, arquivos default, configs).
Mesmo modelo supervisionado das outras tools: alvo allowlist, flags validadas
aqui (allowlist) e aprovacao humana no loop. Sem fallback Docker (Ubuntu:
`sudo apt install nikto`)."""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from agent_schemas import ToolResult
from guardrails import validate_url, ALLOWED_HOSTS
from tools.base import run_cmd

# categorias do -Tuning (veja `nikto -Help`): 1..9, 0, a..e, x (reverso: tudo exceto)
_TUNING_ALLOWED = frozenset("1234567890abcde ".replace(" ", "") + "x")
_INT_RANGES = {"maxtime": (30, 900), "timeout": (1, 30)}
_ALLOWED = frozenset({"url", "tuning", "maxtime", "timeout"})
_FLAG = {"maxtime": "-maxtime", "timeout": "-timeout"}


def build_nikto_command(url: str, params: dict, report_path: str | Path) -> list[str]:
    p = dict(params or {})
    unknown = set(p) - _ALLOWED
    if unknown:
        raise ValueError(f"params desconhecidos: {sorted(unknown)}; "
                         f"params permitidos: {sorted(_ALLOWED)}")
    url_param = p.get("url", url) or url
    cmd = ["nikto", "-h", url_param,
           "-Format", "txt", "-o", str(report_path),
           "-nointeractive", "-nolookup", "-ask", "no"]

    tuning = p.get("tuning")
    if tuning is not None:
        t = str(tuning).strip().lower()
        bad = [c for c in t if c not in _TUNING_ALLOWED]
        if not t or bad:
            raise ValueError(f"tuning invalido: {tuning!r}; "
                             f"use combinacao dos caracteres {sorted(_TUNING_ALLOWED)} "
                             f"(1=file,2=misconfig,3=disclosure,4=xss,5=rfr-inside,6=dos,7=rfr-server,8=cmd-exec,9=sqli,0=upload,a=auth-bypass,b=sw-id,c=rfi,d=webservice,e=admin-console,x=reverse)")
        cmd += ["-Tuning", t]

    for key, (lo, hi) in _INT_RANGES.items():
        v = p.get(key)
        if v is None:
            v = 300 if key == "maxtime" else None  # limite padrao do scan
        if v is None:
            continue
        try:
            v = int(v)
        except (TypeError, ValueError):
            raise ValueError(f"{key} precisa ser inteiro") from None
        if not lo <= v <= hi:
            raise ValueError(f"{key} fora da faixa [{lo}, {hi}]")
        cmd += [_FLAG[key], f"{v}s" if key == "maxtime" else str(v)]
    return cmd


def _collect_report(tmp: Path) -> str:
    partes = []
    for f in sorted(p for p in tmp.iterdir() if p.is_file()):
        try:
            partes.append(f.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            pass
    return "\n---\n".join(p for p in partes if p).strip()


def run_nikto(params: dict, timeout: int | None = None,
              allowed_hosts: set[str] | None = None) -> ToolResult:
    url = (params or {}).get("url")
    if not url:
        raise ValueError("url obrigatoria")
    validate_url(url, allowed_hosts or ALLOWED_HOSTS)
    scan_time = int((params or {}).get("maxtime", 300))
    tmp = Path(tempfile.mkdtemp(prefix="nikto-"))
    report = tmp / "report.txt"
    try:
        cmd = build_nikto_command(url, params, report)
        r = run_cmd(cmd, timeout or scan_time + 120)
        collected = _collect_report(tmp)
        if collected:
            r.stdout = (r.stdout + "\n[report]\n" + collected)[:8000]
            r.summary = (r.summary + "\n[report]\n" + collected)[:4000]
        return r
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
