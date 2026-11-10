"""Gera summary.md + HTML do Rich a partir de evidence.db."""
from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from evidence_store import EvidenceStore


# --- funcoes puras ---------------------------------------------------------

def _row_fields(row):
    _id, _ts, _inv, hip, prop, dec, tool, cmd, res, interp, valid = row
    try:
        p, d, r, v = json.loads(prop), json.loads(dec), json.loads(res), json.loads(valid)
    except Exception:
        p, d, r, v = {}, {}, {}, {}
    return _id, hip, p, d, tool, cmd, r, interp, v


def render_markdown(investigation_id: str, rows: list[tuple]) -> str:
    lines = [f"# Investigacao: {investigation_id}\n",
             f"- Total de passos: {len(rows)}\n",
             "| # | Ferramenta | Hipotese | Decisao | Veredito |",
             "|---|------------|----------|---------|----------|"]
    for idx, row in enumerate(rows):
        _id, hip, p, d, tool, cmd, r, interp, v = _row_fields(row)
        lines.append(f"| {idx+1} | {tool} | {hip[:80].replace('|', ' ')} | "
                     f"{d.get('action', '')} | {v.get('verdict', '')} |")
    lines.append("\n## Detalhes")
    for row in rows:
        _id, hip, p, d, tool, cmd, r, interp, v = _row_fields(row)
        lines.append(f"\n### {_id} — {tool}")
        lines.append(f"- **Hipotese:** {hip}")
        lines.append(f"- **Proposta LLM:** {p.get('rationale', '')} | esperada: {p.get('expected_evidence', '')}")
        lines.append(f"- **Params finais:** `{d.get('final_params') or p.get('params')}`")
        lines.append(f"- **Comando:** `{cmd}`")
        lines.append(f"- **Resultado (resumo):**\n```\n{r.get('summary', '')[:1000]}\n```")
        lines.append(f"- **Interpretacao LLM:** {interp}")
        lines.append(f"- **Veredito humano:** {v.get('verdict', '')}")
    return "\n".join(lines)


def build_summary_table(investigation_id: str, rows: list[tuple]) -> Table:
    table = Table(title=f"Investigacao: {investigation_id}")
    table.add_column("#")
    table.add_column("Ferramenta")
    table.add_column("Hipotese")
    table.add_column("Decisao")
    table.add_column("Veredito")
    for idx, row in enumerate(rows):
        _id, hip, p, d, tool, cmd, r, interp, v = _row_fields(row)
        table.add_row(str(idx + 1), tool, hip[:60],
                      d.get("action", ""), v.get("verdict", ""))
    return table


# --- I/O -------------------------------------------------------------------

def _get_store(investigation_id: str) -> EvidenceStore:
    return EvidenceStore(Path("runs") / investigation_id)


def generate_summary_md(investigation_id: str) -> Path:
    store = _get_store(investigation_id)
    rows = store.list(investigation_id)
    out = Path("runs") / investigation_id / "summary.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_markdown(investigation_id, rows), encoding="utf-8")
    return out


def generate_html(investigation_id: str) -> Path:
    console = Console(record=True, width=120)
    store = _get_store(investigation_id)
    rows = store.list(investigation_id)
    console.print(Panel(f"Investigacao: {investigation_id} — {len(rows)} passos",
                        title="Evidences", border_style="magenta"))
    console.print(build_summary_table(investigation_id, rows))
    out = Path("runs") / investigation_id / "evidences.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(console.export_html(), encoding="utf-8")
    return out
