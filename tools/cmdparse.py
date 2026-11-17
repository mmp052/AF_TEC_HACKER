"""`cmd -> params` para as 6 ferramentas (inverso de cada build_*_command) e
`preview_command` para o painel mostrar a linha exata antes de aprovar.

Seguranca: o comando digitado pelo humano NUNCA vira argv direto — ele eh
parseado para (tool, params) e revalidado pelos mesmos builders/guardrails.
Wordlist fica confinada a wordlists/SecLists/ (absoluta eh rejeitada)."""
from __future__ import annotations

import re
import shlex
from pathlib import Path

from guardrails import validate_url, validate_nmap_args, ALLOWED_HOSTS
from tools import gobuster_tool, wapiti_tool, nikto_tool, wfuzz_tool
from tools.nmap_tool import normalize_target, parse_extra_args, version_args, sweep_args
from tools.http_tool import build_command_str
from tools.base import has_binary

SECLISTS = Path("wordlists/SecLists")

_EXCLUDE_LEN_RE = r"^[0-9]+(-[0-9]+)?$"


def resolve_seclists_rel(path: str) -> str:
    p = (path or "").strip()
    if not p:
        raise ValueError("wordlist obrigatoria; informe um caminho relativo ao SecLists")
    rp = Path(p)
    if rp.is_absolute():
        raise ValueError(f"caminho absoluto rejeitado — confine ao SecLists: {p}")
    # tolera prefixo "wordlists/SecLists/"
    parts = rp.parts
    if len(parts) >= 2 and parts[0] == "wordlists" and parts[1] == "SecLists":
        rp = Path(*parts[2:])
    target = (SECLISTS / rp)
    try:
        resolved = target.resolve()
        root = SECLISTS.resolve()
    except OSError as e:
        raise ValueError(f"wordlist invalida: {e}") from None
    if root != resolved and root not in resolved.parents:
        raise ValueError(f"path fora do SecLists: {p}")
    resolved_rel = str(resolved.relative_to(root))
    if not resolved.exists():
        raise ValueError(f"wordlist nao encontrada no SecLists: {resolved_rel}")
    return resolved_rel


def _kv_next(tokens: list[str], i: int, flag: str) -> str:
    if i + 1 >= len(tokens):
        raise ValueError(f"flag {flag} precisa de valor")
    return tokens[i + 1]


def _parse_nmap(tokens: list[str]) -> dict:
    if not tokens:
        raise ValueError("nmap precisa de um alvo")
    rest = tokens
    target_tok = rest[-1]
    if target_tok.startswith("-"):
        raise ValueError("o alvo do nmap precisa vir por ultimo (ex.: 'nmap -sV -p 3000 localhost')")
    extra = rest[:-1]
    target = normalize_target(target_tok)
    validate_url(f"http://{target}", ALLOWED_HOSTS)
    params: dict = {"target": target}
    if extra:
        extra = parse_extra_args(" ".join(extra), default=None, target=target)
        validate_nmap_args(extra)
        params["extra_args"] = " ".join(extra)
    return params


def _parse_http(tokens: list[str]) -> dict:
    rest = tokens
    if rest and rest[0].lower() == "curl":
        rest = rest[1:]
    url = None
    headers: dict = {}
    body = ""
    i = 0
    while i < len(rest):
        t = rest[i]
        if t in ("--header", "-H"):
            v = _kv_next(rest, i, t)
            if ":" not in v:
                raise ValueError("--header precisa ser 'Nome: valor'")
            k, val = v.split(":", 1)
            if "\n" in k or "\n" in val or "\r" in k or "\r" in val:
                raise ValueError("header nao pode conter newline")
            headers[k.strip()] = val.strip()
            i += 2
            continue
        if t == "--data":
            body = _kv_next(rest, i, t)
            i += 2
            continue
        if t.startswith("-"):
            raise ValueError(f"flag http_request nao suportada: {t} (use apenas url [--header 'K: V'] [--data 'corpo'])")
        if url:
            raise ValueError(f"URL inesperada: {t}")
        url = t
        i += 1
    if not url:
        raise ValueError("http_request precisa de uma URL")
    validate_url(url, ALLOWED_HOSTS)
    params: dict = {"url": url}
    if headers:
        params["headers"] = headers
    if body:
        params["body"] = body
    return params


def _parse_gobuster(tokens: list[str]) -> dict:
    if not tokens or tokens[0].lower() != "dir":
        raise ValueError("formato: gobuster dir -u <url> -w <wordlist Seclists relativa> [--exclude-length N]")
    url = None
    wordlist = None
    exclude_length = None
    i = 1
    while i < len(tokens):
        t = tokens[i]
        if t == "-u":
            url = _kv_next(tokens, i, t)
            i += 2
            continue
        if t == "-w":
            wordlist = resolve_seclists_rel(_kv_next(tokens, i, t))
            i += 2
            continue
        if t == "--exclude-length":
            exclude_length = str(_kv_next(tokens, i, t)).strip()
            if not re.match(_EXCLUDE_LEN_RE, exclude_length):
                raise ValueError(f"--exclude-length invalido: {exclude_length!r} (ex.: 9984 ou 1000-2000)")
            i += 2
            continue
        raise ValueError(f"flag gobuster nao suportada: {t} (suportadas: -u, -w, --exclude-length)")
    if not url:
        raise ValueError("gobuster precisa de -u <url>")
    validate_url(url, ALLOWED_HOSTS)
    params: dict = {"url": url}
    if wordlist:
        params["wordlist"] = wordlist
    if exclude_length:
        params["exclude_length"] = exclude_length
    return params


def _parse_wfuzz(tokens: list[str]) -> dict:
    url = None
    wordlist = None
    extra: list[str] = []
    _allowed_extra = {"--hc", "--hh", "--hl"}
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t == "-c":
            i += 1
            continue
        if t == "-z":
            v = _kv_next(tokens, i, t)
            if not v.startswith("file,"):
                raise ValueError("-z precisa ser 'file,<wordlist>' confinada ao SecLists")
            wordlist = resolve_seclists_rel(v[len("file,"):])
            i += 2
            continue
        if t == "-u":
            url = _kv_next(tokens, i, t)
            if "FUZZ" not in url:
                raise ValueError("url wfuzz precisa conter FUZZ")
            i += 2
            continue
        if t in _allowed_extra:
            v = _kv_next(tokens, i, t)
            if not v.isdigit():
                raise ValueError(f"{t} precisa ser um inteiro")
            extra += [t, v]
            i += 2
            continue
        raise ValueError(f"flag wfuzz nao suportada: {t} (suportadas: -c, -z file,<wl>, -u, --hc/--hh/--hl N)")
    if not url:
        raise ValueError("wfuzz precisa de -u <url com FUZZ>")
    wfuzz_tool.validate_wfuzz_url(url, ALLOWED_HOSTS)
    params: dict = {"url": url}
    if wordlist:
        params["wordlist"] = wordlist
    if extra:
        params["extra_args"] = " ".join(extra)
    return params


def _parse_wapiti(tokens: list[str]) -> dict:
    url = None
    params: dict = {}
    i = 0
    _int_flags = {"-l": "level", "-d": "depth", "--max-scan-time": "max_scan_time",
                  "--max-attack-time": "max_attack_time", "--max-parameters": "max_parameters",
                  "--tasks": "tasks", "-t": "timeout"}
    while i < len(tokens):
        t = tokens[i]
        if t == "-u":
            url = _kv_next(tokens, i, t)
            i += 2
            continue
        if t == "-m":
            params["modules"] = [m.strip().lower() for m in _kv_next(tokens, i, t).split(",") if m.strip()]
            i += 2
            continue
        if t == "--scope":
            params["scope"] = _kv_next(tokens, i, t).lower()
            i += 2
            continue
        if t in _int_flags:
            v = _kv_next(tokens, i, t).removesuffix("s")
            params[_int_flags[t]] = v
            i += 2
            continue
        if t == "--data":
            params["data"] = _kv_next(tokens, i, t)
            i += 2
            continue
        raise ValueError(f"flag wapiti nao suportada: {t}")
    if not url:
        raise ValueError("wapiti precisa de -u <url>")
    validate_url(url, ALLOWED_HOSTS)
    params["url"] = url
    # revalida tudo pelos mesmos builders (allowlist de modulos/faixas/escopo)
    wapiti_tool.build_wapiti_command(url, params, "/tmp/.preview-wapiti-report")
    return params


def _parse_nikto(tokens: list[str]) -> dict:
    url = None
    params: dict = {}
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t in ("-h", "--host"):
            url = _kv_next(tokens, i, t)
            i += 2
            continue
        if t == "-Tuning":
            params["tuning"] = _kv_next(tokens, i, t).lower()
            i += 2
            continue
        if t == "-maxtime":
            params["maxtime"] = _kv_next(tokens, i, t).removesuffix("s")
            i += 2
            continue
        if t == "-timeout":
            params["timeout"] = _kv_next(tokens, i, t)
            i += 2
            continue
        raise ValueError(f"flag nikto nao suportada: {t} (suportadas: -h, -Tuning, -maxtime, -timeout)")
    if not url:
        raise ValueError("nikto precisa de -h <url>")
    validate_url(url, ALLOWED_HOSTS)
    params["url"] = url
    nikto_tool.build_nikto_command(url, params, "/tmp/.preview-nikto-report")
    return params


_PARSERS = {
    "nmap": _parse_nmap,
    "http_request": _parse_http,
    "gobuster": _parse_gobuster,
    "wfuzz": _parse_wfuzz,
    "wapiti": _parse_wapiti,
    "nikto": _parse_nikto,
}


def parse_command(tool: str, cmd: str) -> dict:
    parser = _PARSERS.get(tool)
    if parser is None:
        raise ValueError(f"tool sem parser de comando: {tool!r} (tools: {sorted(_PARSERS)})")
    try:
        toks = shlex.split(str(cmd))
    except ValueError as e:
        raise ValueError(f"comando mal formado: {e}") from None
    prog = {"nmap": "nmap", "http_request": ("http_request", "curl"),
            "gobuster": "gobuster", "wfuzz": "wfuzz", "wapiti": "wapiti", "nikto": "nikto"}[tool]
    progs = prog if isinstance(prog, tuple) else (prog,)
    if toks and toks[0].lower() in progs:
        toks = toks[1:]
    return parser(toks)


def preview_command(tool: str, params: dict) -> str:
    p = dict(params or {})
    if tool == "nmap":
        target = normalize_target(p.get("target") or p.get("host"))
        extra = p.get("extra_args")
        if extra:
            extra_list = parse_extra_args(str(extra), default=None, target=target)
            return " ".join(["nmap", *extra_list, target])
        return ("nmap -p- --open -Pn " + target + " && "
                "nmap -sV -p <abertas> --open -Pn " + target + "   # duas fases")
    if tool == "http_request":
        return build_command_str("GET", p.get("url", ""), p.get("headers", {}), p.get("body", ""))
    if tool == "gobuster":
        wl = resolve_seclists_rel(p["wordlist"]) if p.get("wordlist") else "<wordlist via routing>"
        return shlex.join(gobuster_tool.build_gobuster_command(
            str(p.get("url", "")), wl, not has_binary("gobuster"),
            exclude_length=str(p["exclude_length"]) if p.get("exclude_length") else None))
    if tool == "wfuzz":
        wl = resolve_seclists_rel(p["wordlist"]) if p.get("wordlist") else "<wordlist via routing>"
        extra = (p.get("extra_args") or "")
        return shlex.join(wfuzz_tool.build_wfuzz_command(
            str(p.get("url", "")), wl, not has_binary("wfuzz"),
            wfuzz_tool.normalize_extra_args(extra)))
    if tool == "wapiti":
        return shlex.join(wapiti_tool.build_wapiti_command(str(p.get("url", "")), p, "<tmpdir>/report.txt"))
    if tool == "nikto":
        return shlex.join(nikto_tool.build_nikto_command(str(p.get("url", "")), p, "<tmpdir>/report.txt"))
    return f"{tool} {shlex.join([f'{k}={v}' for k, v in p.items()])}"
