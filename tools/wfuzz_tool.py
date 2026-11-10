"""wfuzz com fallback Docker; a URL deve conter FUZZ."""
from __future__ import annotations

from pathlib import Path

from agent_schemas import ToolResult
from guardrails import validate_url, ALLOWED_HOSTS
from tools.base import has_binary, run_cmd

SECLISTS = Path("wordlists/SecLists")
DOCKER_IMAGE = "huntertier/wfuzz:latest"


def normalize_extra_args(extra) -> list[str]:
    if isinstance(extra, str):
        items = extra.split()
    else:
        items = list(extra or [])
    if "--hc" not in " ".join(items):
        items += ["--hc", "404"]
    return items


def resolve_wordlist(wordlist_rel: str) -> Path:
    if not wordlist_rel:
        raise ValueError("wordlist obrigatoria (routing escolhe por evidencia; nao informe wordlist do LLM)")
    wl_path = SECLISTS / wordlist_rel
    if not wl_path.exists():
        raise ValueError(f"wordlist nao encontrada: {wl_path}")
    return wl_path


def validate_wfuzz_url(url: str, allowed_hosts: set[str] | None = None) -> None:
    if "FUZZ" not in url:
        raise ValueError("url wfuzz deve conter FUZZ")
    validate_url(url.replace("FUZZ", "x"), allowed_hosts or ALLOWED_HOSTS)


def build_wfuzz_command(url: str, wordlist_rel: str, use_docker: bool,
                        extra_list: list[str]) -> list[str]:
    if use_docker:
        abs_seclists = str(SECLISTS.resolve())
        return ["docker", "run", "--rm", "--network", "host",
                "-v", f"{abs_seclists}:/wl:ro", DOCKER_IMAGE,
                "-c", "-z", f"file,/wl/{wordlist_rel}", "-u", url, *extra_list]
    return ["wfuzz", "-c", "-z", f"file,{SECLISTS / wordlist_rel}", "-u", url, *extra_list]


def run_wfuzz(params: dict, timeout: int = 120,
              allowed_hosts: set[str] | None = None) -> ToolResult:
    url = params.get("url", "")
    wordlist = params.get("wordlist", "")
    allowed = allowed_hosts or ALLOWED_HOSTS
    validate_wfuzz_url(url, allowed)
    resolve_wordlist(wordlist)
    extra_list = normalize_extra_args(params.get("extra_args"))

    return run_cmd(build_wfuzz_command(url, wordlist, not has_binary("wfuzz"), extra_list), timeout)
