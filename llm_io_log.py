"""Registro por turno do I/O bruto com o LLM (antes da interpretação).

Complementa events.jsonl/evidence.db (passos aprovados) com o que realmente
entrou e saiu do modelo — requisito de auditabilidade para a AF.
"""
from __future__ import annotations

import json
import time
from pathlib import Path


def append_llm_io(runs_dir: str | Path, investigation_id: str, payload: dict) -> None:
    out = Path(runs_dir) / investigation_id / "llm_io.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {**payload, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    with out.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False) + "\n")
