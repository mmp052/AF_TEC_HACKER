"""nmap em duas fases: sweep de portas -> service/version scan nas abertas.

Fase 1 (sweep): `nmap -p- --open -Pn <alvo>` — rapido, sem -sV, so acha abertas.
Fase 2 (versao):  `nmap -sV -p <portas> --open -Pn <alvo>` — service detection so nas abertas (sem scripts).
Se o sweep nao achar nada aberto, a fase 2 nao roda.

Override single-shot: se o LLM/humano informar extra_args, o scan e um unico
comando com esses argumentos (comportamento antigo).
"""
from __future__ import annotations

import re

from agent_schemas import ToolResult
from guardrails import validate_nmap_args, validate_url, ALLOWED_HOSTS
from tools.base import has_binary, run_cmd

DEFAULT_ARGS = "-p- --open -Pn"  # sweep default (sem service detection)
DOCKER_IMAGE = "instrumentisto/nmap:latest"

_TARGET_RE = re.compile(r"^(?:[a-zA-Z]+://)?([^/:]+)")
_PORT_RE = re.compile(r"(\d+)/tcp\s+open")


def normalize_target(raw: str | None) -> str:
    if not raw:
        return "localhost"
    m = _TARGET_RE.match(str(raw).strip())
    return m.group(1).strip() if m and m.group(1) else "localhost"


def parse_extra_args(extra, default: str | None = None) -> list[str]:
    if extra is None:
        extra = default if default is not None else DEFAULT_ARGS
    if isinstance(extra, str):
        return extra.split()
    return list(extra)


def sweep_args() -> list[str]:
    return ["-p-", "--open", "-Pn"]


def version_args(ports: list[str]) -> list[str]:
    return ["-sV", "-p", ",".join(ports), "--open", "-Pn"]


def parse_open_ports(stdout: str) -> list[str]:
    seen = []
    for port in _PORT_RE.findall(stdout or ""):
        if port not in seen:
            seen.append(port)
    return seen


def build_nmap_command(target: str, extra_list: list[str], use_docker: bool) -> list[str]:
    if use_docker:
        return ["docker", "run", "--rm", "--network", "host", DOCKER_IMAGE, *extra_list, target]
    return ["nmap", *extra_list, target]


def _fmt(cmd: list[str]) -> str:
    return " ".join(cmd)


def _summary_from(ports: list[str], stdout: str) -> str:
    if not ports:
        return "nenhuma porta aberta encontrada no sweep"
    svc_lines = [l for l in stdout.splitlines()
                 if re.match(r"\d+/tcp\s+open", l.strip())]
    head = f"portas abertas: {','.join(ports)}"
    return (head + "\n" + "\n".join(svc_lines[:30]))[:4000]


def run_nmap(params: dict, timeout: int = 300,
             allowed_hosts: set[str] | None = None) -> ToolResult:
    # aceita alias comuns do LLM ('host') alem de 'target'
    target = normalize_target(params.get("target") or params.get("host"))
    allowed = allowed_hosts or ALLOWED_HOSTS
    validate_url(f"http://{target}", allowed)
    use_docker = not has_binary("nmap")

    extra = params.get("extra_args")
    if extra:
        # override: single-shot com os args informados (comportamento antigo)
        extra_list = parse_extra_args(extra)
        validate_nmap_args(extra_list)
        return run_cmd(build_nmap_command(target, extra_list, use_docker), timeout)

    # fase 1: sweep
    sweep_cmd = build_nmap_command(target, sweep_args(), use_docker)
    r1 = run_cmd(sweep_cmd, timeout)
    ports = parse_open_ports(r1.stdout)

    if not ports:
        return ToolResult(
            exit_code=r1.exit_code,
            stdout=f"== sweep ==\n{r1.stdout}",
            stderr=r1.stderr,
            duration_ms=r1.duration_ms,
            command=_fmt(sweep_cmd),
            summary=_summary_from([], r1.stdout),
        )

    # fase 2: service detection so nas portas abertas
    version_cmd = build_nmap_command(target, version_args(ports), use_docker)
    r2 = run_cmd(version_cmd, timeout)
    combined = f"== sweep ==\n{r1.stdout}\n== versao ==\n{r2.stdout}"
    return ToolResult(
        exit_code=r2.exit_code,
        stdout=combined[:16000],
        stderr="\n".join(filter(None, [r1.stderr, r2.stderr]))[:8000],
        duration_ms=r1.duration_ms + r2.duration_ms,
        command=f"{_fmt(sweep_cmd)} && {_fmt(version_cmd)}",
        summary=_summary_from(ports, r2.stdout),
    )
