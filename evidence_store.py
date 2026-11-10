"""Registro reconstrutivel: JSONL append-only + SQLite index."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# --- funcoes puras ---------------------------------------------------------

def item_to_row(item: dict):
    """Mapeia a evidencia (dict) -> tupla para o INSERT (ordem do CREATE TABLE)."""
    return (
        item.get("id", ""),
        item.get("ts", ""),
        item.get("investigation_id", ""),
        item.get("hypothesis", ""),
        json.dumps(item.get("proposed_action", {}), ensure_ascii=False),
        json.dumps(item.get("human_decision", {}), ensure_ascii=False),
        item.get("tool", ""),
        item.get("command", ""),
        json.dumps(item.get("result", {}), ensure_ascii=False),
        item.get("llm_interpretation", ""),
        json.dumps(item.get("human_validation", {}), ensure_ascii=False),
    )


def item_to_jsonl(item: dict) -> str:
    return json.dumps(item, ensure_ascii=False) + "\n"


# --- I/O -------------------------------------------------------------------

class EvidenceStore:
    def __init__(self, runs_dir: str | Path):
        self.base = Path(runs_dir)
        self.base.mkdir(parents=True, exist_ok=True)
        self.db_path = self.base / "evidence.db"
        self.jsonl_path = self.base / "events.jsonl"
        self.jsonl_path.touch(exist_ok=True)
        self._db = sqlite3.connect(self.db_path)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS evidences (
                id TEXT PRIMARY KEY,
                ts TEXT,
                investigation_id TEXT,
                hypothesis TEXT,
                proposed_action TEXT,
                human_decision TEXT,
                tool TEXT,
                command TEXT,
                result TEXT,
                llm_interpretation TEXT,
                human_validation TEXT
            )
        """)
        self._db.commit()

    def append(self, item: dict) -> dict:
        item.setdefault("ts", _utcnow())
        with self.jsonl_path.open("a", encoding="utf-8") as f:
            f.write(item_to_jsonl(item))

        self._db.execute(
            "INSERT INTO evidences VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            item_to_row(item),
        )
        self._db.commit()
        return item

    def list(self, investigation_id: str | None = None):
        query = "SELECT * FROM evidences"
        args = []
        if investigation_id:
            query += " WHERE investigation_id = ?"
            args.append(investigation_id)
        return self._db.execute(query, args).fetchall()
