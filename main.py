#!/usr/bin/env python3
"""CLI do agente supervisionado. Uso: python main.py run --file hypothesis.yaml"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import httpx
import yaml
from rich.console import Console
from rich.panel import Panel

from agent.loop import run_investigation
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

    for cmd in ["nmap", "gobuster", "wfuzz", "curl", "docker"]:
        import shutil
        if shutil.which(cmd):
            console.print(f"[green]✓ {cmd}[/]")
        else:
            console.print(f"[yellow]✗ {cmd} nao no PATH (fallback Docker usado)[/]")


def main():
    p = argparse.ArgumentParser(prog="agente")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="executa investigacao")
    r.add_argument("--file", required=True, help="yaml com objective e investigation_id")
    r.add_argument("--model", default=None)
    r.add_argument("--max-iter", type=int, default=20)

    rr = sub.add_parser("report", help="gera summary.md + html")
    rr.add_argument("--investigation", required=True)

    c = sub.add_parser("check", help="checagens de lab")

    args = p.parse_args()
    cfg = load_config()

    if args.cmd == "check":
        check_lab(cfg)
    elif args.cmd == "run":
        check_lab(cfg)
        data = yaml.safe_load(Path(args.file).read_text(encoding="utf-8"))
        objective = data.get("objective", "")
        investigation_id = data.get("investigation_id", "investigacao")
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
                          runs_dir=cfg["paths"]["runs"])
        generate_summary_md(investigation_id)
        console.print("[green]summary.md gerado em runs/{investigation_id}/[/]")
    elif args.cmd == "report":
        generate_summary_md(args.investigation)
        generate_html(args.investigation)
        console.print(f"[green]Relatorios gerados em runs/{args.investigation}/[/]")


if __name__ == "__main__":
    main()
