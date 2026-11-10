import json

import pytest

from evidence_store import EvidenceStore, item_to_jsonl, item_to_row


def fixture_item():
    return {
        "id": "inv-001",
        "investigation_id": "inv",
        "hypothesis": "ha rotas ocultas",
        "proposed_action": {"tool": "gobuster", "params": {"url": "http://localhost:3000"}},
        "human_decision": {"action": "approved", "final_params": {"url": "http://localhost:3000"}},
        "tool": "gobuster",
        "command": "gobuster dir -u http://localhost:3000 -w wordlists/SecLists/Discovery/Web-Content/common.txt",
        "result": {"exit_code": 0, "summary": "status=200 /rest"},
        "llm_interpretation": "ha superfice",
        "human_validation": {"verdict": "confirmed"},
    }


def test_item_to_row_serializina_json_embutido():
    item = fixture_item()
    row = item_to_row(item)
    assert row[0] == "inv-001"
    assert row[2] == "inv"
    assert json.loads(row[4])["tool"] == "gobuster"
    assert json.loads(row[5])["action"] == "approved"
    assert json.loads(row[8])["exit_code"] == 0
    assert json.loads(row[10])["verdict"] == "confirmed"


def test_item_to_jsonl_e_uma_linha_json():
    item = fixture_item()
    line = item_to_jsonl(item)
    parsed = json.loads(line.strip())
    assert parsed["tool"] == "gobuster"
    assert line.endswith("\n")


def test_store_append_persiste_jsonl_e_sqlite(tmp_path):
    store = EvidenceStore(tmp_path / "run1")
    store.append(fixture_item())
    rows = store.list("inv")
    assert len(rows) == 1
    row = rows[0]
    assert row[0] == "inv-001" and row[6] == "gobuster"
    jsonl = (tmp_path / "run1" / "events.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(jsonl) == 1
    assert json.loads(jsonl[0])["id"] == "inv-001"


def test_list_filtra_por_investigation_id(tmp_path):
    store = EvidenceStore(tmp_path / "run2")
    a = fixture_item()
    b = fixture_item()
    b["id"] = "inv-002"
    b["investigation_id"] = "outra"
    store.append(a)
    store.append(b)
    assert len(store.list("inv")) == 1
    assert len(store.list("outra")) == 1
    assert len(store.list()) == 2
