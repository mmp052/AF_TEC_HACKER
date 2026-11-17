#!/usr/bin/env python3
"""CLI do agente supervisionado.

Sem argumentos: modo interativo (check + intake conversacional + loop).
Subcomandos: check | run --file hypothesis.yaml | report --investigation ID.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import httpx
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

from agent.loop import run_investigation
from agent.phases import initial_flags_from_knowledge, fase_inicial_from_knowledge, phase
from evidence_store import EvidenceStore
from reporter import generate_html, generate_summary_md

console = Console()

BASE = Path(__file__).parent
CONFIG = BASE / "config.yaml"


def load_config() -> dict:
    return yaml.safe_load(CONFIG.read_text(encoding="utf-8"))


def resolve_unique_run_id(runs_root: Path, investigation_id: str) -> str:
    """Evita colisao de evidencia: se o id ja tem diretoria em runs/, sufixa -2, -3, ...

    Evidencia nunca eh sobrescrita — uma execucao nova vira uma investigacao nova.
    """
    if not (Path(runs_root) / investigation_id).exists():
        return investigation_id
    n = 2
    while (Path(runs_root) / f"{investigation_id}-{n}").exists():
        n += 1
    return f"{investigation_id}-{n}"


# binarios verificados pelo `main.py check`; wapiti NAO tem fallback Docker — se sumir do PATH, a tool falha na hora
CHECK_BINARIES = ["nmap", "gobuster", "wfuzz", "wapiti", "nikto", "curl", "docker"]


def check_lab(cfg: dict) -> None:
    console.print(Panel("Checagens do laboratorio", title="lab", border_style="cyan"))
    base_url = cfg["target"]["base_url"]
    try:
        r = httpx.get(base_url, timeout=5)
        console.print(f"[green]Juice Shop responde: {base_url} -> {r.status_code}[/]")
    except Exception as e:
        console.print(f"[red]Juice Shop nao responde em {base_url}: {e}[/]\nRode: bash lab/reset.sh")
        raise SystemExit(1)

    try:
        import time
        from agent.ollama_client import build_prewarm_payload
        t0 = time.time()
        r = httpx.post(
            "http://localhost:11434/api/chat",
            json=build_prewarm_payload(cfg["model"]["name"], cfg["model"]["num_ctx"]),
            timeout=cfg["model"]["timeout_sec"],
        )
        dt = time.time() - t0
        r.raise_for_status()
        console.print(f"[green]Ollama pre-warm ok ({dt:.1f}s) — modelo carregado com keep_alive 30m[/]")
    except Exception as e:
        console.print(f"[red]Ollama nao responde em /api/chat: {e}[/]")
        raise SystemExit(1)

    seclists = Path(cfg["paths"]["seclists"])
    if not (seclists / "Discovery" / "Web-Content").exists():
        console.print(f"[yellow]SecLists nao encontrado em {seclists}. Clone: git clone --depth 1 https://github.com/danielmiessler/SecLists {seclists}[/]")

    for cmd in CHECK_BINARIES:
        import shutil
        if shutil.which(cmd):
            console.print(f"[green]✓ {cmd}[/]")
        elif cmd == "wapiti":
            console.print("[yellow]✗ wapiti nao no PATH (sem fallback Docker; instale: python3 -m pip install --break-system-packages wapiti3)[/]")
        elif cmd == "nikto":
            console.print("[yellow]✗ nikto nao no PATH (sem fallback Docker; instale: sudo apt install nikto)[/]")
        else:
            console.print(f"[yellow]✗ {cmd} nao no PATH (fallback Docker usado)[/]")


def _intake_interativo() -> tuple[str, int, list[str]]:
    console.print(Panel("Descreva a situacao e o que voce quer. Enter em branco para pular.",
                        title="parceria", border_style="magenta"))
    objetivo = Prompt.ask("Situacao/objetivo").strip()
    while not objetivo:
        objetivo = Prompt.ask("Objetivo obrigatorio").strip()
    suspeita = Prompt.ask("Suspeita de alguma vulnerabilidade? (Enter = nenhuma)", default="").strip()
    endpoints = Prompt.ask("Endpoints conhecidos (virgula; Enter = nenhum)", default="").strip()
    evidencias = Prompt.ask("Evidencias que voce ja tem? (Enter = nenhuma)", default="").strip()

    conhecimento = {}
    if endpoints:
        conhecimento["endpoints"] = [e.strip() for e in endpoints.split(",") if e.strip()]
    if suspeita:
        conhecimento["suspeita"] = suspeita
    if evidencias:
        conhecimento["evidencias"] = evidencias

    flags = initial_flags_from_knowledge(conhecimento)
    fase = fase_inicial_from_knowledge(conhecimento)
    console.print(Panel(
        f"Vou comecar na fase {fase} — {phase(fase)['nome']}"
        + (f"\nFlags semeadas do seu contexto: {', '.join(flags)}" if flags else "")
        + "\nSe for outra fase, diga o numero (0-4, Enter = manter).",
        title="fase inicial", border_style="cyan"))
    escolha = Prompt.ask("Fase inicial", default=str(fase),
                         choices=["0", "1", "2", "3", "4"]).strip()
    fase = int(escolha)
    return objetivo, fase, flags


def cmd_interactive(cfg: dict) -> None:
    check_lab(cfg)
    objetivo, fase, flags = _intake_interativo()
    investigation_id = resolve_unique_run_id(Path(cfg["paths"]["runs"]), "interativo")
    console.print(f"[dim]evidencias em runs/{investigation_id}/[/]")
    model = cfg["model"]["name"]
    endpoint = cfg["model"]["endpoint"]
    store = EvidenceStore(Path(cfg["paths"]["runs"]) / investigation_id)
    allowed_hosts = set(cfg["target"]["allowed_hosts"])
    run_investigation(store, endpoint, model, objetivo, investigation_id,
                      max_iter=cfg["limits"]["max_iter"], allowed_hosts=allowed_hosts,
                      runs_dir=cfg["paths"]["runs"],
                      fase_inicial=fase, flags_iniciais=flags)
    generate_summary_md(investigation_id)


def cmd_run(cfg: dict, args) -> None:
    check_lab(cfg)
    data = yaml.safe_load(Path(args.file).read_text(encoding="utf-8"))
    objective = data.get("objective", "")
    investigation_id = data.get("investigation_id", "investigacao")
    conhecimento = data.get("conhecimento") or None
    fase_inicial = data.get("fase_inicial")
    fase = fase_inicial_from_knowledge(conhecimento, int(fase_inicial) if fase_inicial is not None else None)
    flags = initial_flags_from_knowledge(conhecimento)
    unique_id = resolve_unique_run_id(Path(cfg["paths"]["runs"]), investigation_id)
    if unique_id != investigation_id:
        console.print(f"[yellow]Ja existe runs/{investigation_id}/ — esta execucao vai para runs/{unique_id}/ (a anterior permanece intacta)[/]")
    investigation_id = unique_id
    model = args.model or cfg["model"]["name"]
    endpoint = cfg["model"]["endpoint"]
    store = EvidenceStore(Path(cfg["paths"]["runs"]) / investigation_id)
    allowed_hosts = set(cfg["target"]["allowed_hosts"])
    run_investigation(store, endpoint, model, objective, investigation_id,
                      max_iter=args.max_iter, allowed_hosts=allowed_hosts,
                      runs_dir=cfg["paths"]["runs"],
                      fase_inicial=fase, flags_iniciais=flags)
    generate_summary_md(investigation_id)
    console.print(f"[green]summary.md gerado em runs/{investigation_id}/[/]")


def main():
    p = argparse.ArgumentParser(prog="agente")
    sub = p.add_subparsers(dest="cmd")

    r = sub.add_parser("run", help="executa investigacao")
    r.add_argument("--file", required=True, help="yaml com objective e investigation_id")
    r.add_argument("--model", default=None)
    r.add_argument("--max-iter", type=int, default=20)

    rr = sub.add_parser("report", help="gera summary.md + html")
    rr.add_argument("--investigation", required=True)

    c = sub.add_parser("check", help="checagens de lab")

    args = p.parse_args()
    cfg = load_config()

    if args.cmd is None:
        if not sys.stdin.isatty():
            p.print_help()
            print("\nmain.py sem argumentos so funciona em terminal interativo; "
                  "em pipe, use: check | run --file x.yaml | report --investigation ID")
            raise SystemExit(2)
        cmd_interactive(cfg)
        return
    if args.cmd == "check":
        check_lab(cfg)
    elif args.cmd == "run":
        cmd_run(cfg, args)
    elif args.cmd == "report":
        generate_summary_md(args.investigation)
        generate_html(args.investigation)
        console.print(f"[green]Relatorios gerados em runs/{args.investigation}/[/]")


if __name__ == "__main__":
    main()
