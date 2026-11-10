"""gobuster dir com fallback Docker; wordlist escolhida pelo routing por evidencia."""
from __future__ import annotations

from pathlib import Path

from agent_schemas import ToolResult
from guardrails import validate_url, ALLOWED_HOSTS
from tools.base import has_binary, run_cmd

SECLISTS = Path("wordlists/SecLists")
DOCKER_IMAGE = "mdiqib/gobuster:latest"
FLAGS = ("-k", "-t", "20", "--no-error")


def resolve_wordlist(wordlist_rel: str) -> Path:
    if not wordlist_rel:
        raise ValueError("wordlist obrigatoria (routing escolhe por evidencia; nao informe wordlist do LLM)")
    wl_path = SECLISTS / wordlist_rel
    if not wl_path.exists():
        raise ValueError(f"wordlist nao encontrada: {wl_path}")
    return wl_path


def build_gobuster_command(url: str, wordlist_rel: str, use_docker: bool) -> list[str]:
    if use_docker:
        abs_seclists = str(SECLISTS.resolve())
        return ["docker", "run", "--rm", "--network", "host",
                "-v", f"{abs_seclists}:/wl:ro", DOCKER_IMAGE,
                "dir", "-u", url, "-w", f"/wl/{wordlist_rel}", *FLAGS]
    return ["gobuster", "dir", "-u", url, "-w",
            str(SECLISTS / wordlist_rel), *FLAGS]


def run_gobuster(params: dict, timeout: int = 120,
                 allowed_hosts: set[str] | None = None) -> ToolResult:
    url = params.get("url", "http://localhost:3000")
    wordlist = params.get("wordlist", "")
    validate_url(url, allowed_hosts or ALLOWED_HOSTS)
    resolve_wordlist(wordlist)  # valida existencia; routing escolhe o arquivo

    return run_cmd(build_gobuster_command(url, wordlist, not has_binary("gobuster")), timeout)
