import json

import pytest

import reporter
from evidence_store import EvidenceStore


def _store_in_tmp(tmp_path):
    store = EvidenceStore(tmp_path / "runs" / "report-fixture")
    store.append({
        "id": "inv-001",
        "investigation_id": "report-fixture",
        "hypothesis": "ha rotas ocultas",
        "proposed_action": {"tool": "gobuster", "params": {}, "rationale": "teste",
                            "expected_evidence": "rotas 200"},
        "human_decision": {"action": "approved", "final_params": {"url": "http://localhost:3000"}},
        "tool": "gobuster",
        "command": "gobuster dir -u http://localhost:3000 -w wl",
        "result": {"summary": "status=200"},
        "llm_interpretation": "rota achada",
        "human_validation": {"verdict": "confirmed"},
    })
    return store


def test_render_markdown_contem_hipotese_e_veredito(tmp_path):
    store = _store_in_tmp(tmp_path)
    rows = store.list("report-fixture")
    md = reporter.render_markdown("report-fixture", rows)
    assert "# Investigacao: report-fixture" in md
    assert "ha rotas ocultas" in md
    assert "confirmed" in md
    assert "gobuster dir" in md


def test_build_summary_table_monta_colunas(tmp_path):
    store = _store_in_tmp(tmp_path)
    rows = store.list("report-fixture")
    table = reporter.build_summary_table("report-fixture", rows)
    assert table.row_count == 1
    assert [c.header for c in table.columns] == ["#", "Ferramenta", "Hipotese", "Decisao", "Veredito"]


def test_generate_summary_md_grava_arquivo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    store = _store_in_tmp(tmp_path)
    out = reporter.generate_summary_md("report-fixture")
    text = out.read_text(encoding="utf-8")
    assert out.exists()
    assert "ha rotas ocultas" in text
    assert "inv-001" in text


def test_generate_html_grava_arquivo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _store_in_tmp(tmp_path)
    out = reporter.generate_html("report-fixture")
    assert out.exists()
    assert "gobuster" in out.read_text(encoding="utf-8")
