"""gobuster dir com fallback Docker; wordlist escolhida pelo routing por evidencia."""
from __future__ import annotations

import re
from pathlib import Path

from agent_schemas import ToolResult
from guardrails import validate_url, ALLOWED_HOSTS
from tools.base import has_binary, run_cmd

SECLISTS = Path("wordlists/SecLists")
DOCKER_IMAGE = "mdiqib/gobuster:latest"
# sem --no-error: o stderr e necessario (wildcard do SPA) e agora vai para a evidencia
FLAGS = ("-k", "-t", "20")
_WILDCARD_RE = re.compile(r"Length:\s*([0-9]+(?:-[0-9]+)?)")


def resolve_wordlist(wordlist_rel: str) -> Path:
    if not wordlist_rel:
        raise ValueError("wordlist obrigatoria (routing escolhe por evidencia; nao informe wordlist do LLM)")
    wl_path = SECLISTS / wordlist_rel
    if not wl_path.exists():
        raise ValueError(f"wordlist nao encontrada: {wl_path}")
    return wl_path


def build_gobuster_command(url: str, wordlist_rel: str, use_docker: bool,
                            exclude_length: str | None = None) -> list[str]:
    extra = ["--exclude-length", str(exclude_length)] if exclude_length else []
    if use_docker:
        abs_seclists = str(SECLISTS.resolve())
        return ["docker", "run", "--rm", "--network", "host",
                "-v", f"{abs_seclists}:/wl:ro", DOCKER_IMAGE,
                "dir", "-u", url, "-w", f"/wl/{wordlist_rel}", *FLAGS, *extra]
    return ["gobuster", "dir", "-u", url, "-w",
            str(SECLISTS / wordlist_rel), *FLAGS, *extra]


def run_gobuster(params: dict, timeout: int = 120,
                 allowed_hosts: set[str] | None = None) -> ToolResult:
    url = params.get("url", "http://localhost:3000")
    wordlist = params.get("wordlist", "")
    validate_url(url, allowed_hosts or ALLOWED_HOSTS)
    resolve_wordlist(wordlist)  # valida existencia; routing escolhe o arquivo

    cmd = build_gobuster_command(url, wordlist, not has_binary("gobuster"))
    r = run_cmd(cmd, timeout)
    if r.exit_code != 0:
        m = _WILDCARD_RE.search(r.stderr or "")
        if m:
            # SPA responde 200 com corpo fixo para URLs inexistentes: exclui o
            # comprimento do corpo e tenta de novo (uma vez), como o proprio
            # gobuster sugere. Tentativa e resultado ficam registrados na evidencia.
            retry = run_cmd(build_gobuster_command(url, wordlist, not has_binary("gobuster"),
                                                    exclude_length=m.group(1)), timeout)
            retry.summary = (f"[wildcard detectado: Length {m.group(1)} excluido via "
                             f"--exclude-length]\n" + retry.summary)[:4000]
            return retry
    return r
