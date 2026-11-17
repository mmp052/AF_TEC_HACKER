import json

import pytest

import owasp_report
from evidence_store import EvidenceStore


def _store(tmp_path, items):
    store = EvidenceStore(tmp_path / "runs" / "inv-owasp")
    for it in items:
        it.setdefault("investigation_id", "inv-owasp")
        it.setdefault("proposed_action", {"tool": it["tool"], "params": {}, "rationale": "r",
                                          "expected_evidence": "e"})
        it.setdefault("human_decision", {"action": "approved", "final_params": {}})
        it.setdefault("command", "")
        it.setdefault("result", {"exit_code": 0, "summary": "resumo", "stdout": ""})
        it.setdefault("llm_interpretation", "interp")
        it.setdefault("human_validation", {"verdict": "inconclusive"})
        store.append(it)
    return store


def _fixture_items():
    return [
        {"id": "inv-owasp-000", "tool": "nmap", "hypothesis": "porta 3000 web",
         "human_validation": {"verdict": "inconclusive"},
         "command": "nmap -sV -p 3000 localhost",
         "result": {"exit_code": 0, "summary": "3000/tcp open ppp?", "stdout": "3000/tcp open ppp?"}},
        {"id": "inv-owasp-001", "tool": "gobuster", "hypothesis": "app expoe /admin",
         "human_validation": {"verdict": "confirmed"},
         "command": "gobuster dir -u http://localhost:3000 -w wl",
         "result": {"exit_code": 0, "summary": "", "stdout": "/admin (Status: 200)\n/ftp (Status: 200)"}},
        {"id": "inv-owasp-002", "tool": "wfuzz", "hypothesis": "sqli no parametro q",
         "human_validation": {"verdict": "refuted"},
         "command": "wfuzz -z file,x -u http://localhost:3000/s?q=FUZZ",
         "result": {"exit_code": 0, "summary": "", "stdout": "sem erro SQL"}},
    ]


def test_relatorio_tem_secoes_owasp_e_objetivo(tmp_path):
    store = _store(tmp_path, _fixture_items())
    md = owasp_report.render_owasp_report(store.list("inv-owasp"), "inv-owasp", "Recon do Juice Shop")
    assert "Recon do Juice Shop" in md
    assert "OWASP" in md
    assert "WSTG" in md
    assert "Sumário executivo" in md
    assert "## Achados" in md
    assert "## Limitações" in md


def test_achados_listam_apenas_veredito_confirmed(tmp_path):
    store = _store(tmp_path, _fixture_items())
    md = owasp_report.render_owasp_report(store.list("inv-owasp"), "inv-owasp", "obj")
    achados = md.split("## Achados", 1)[1].split("\n## ", 1)[0]
    assert "app expoe /admin" in achados
    assert "/admin (Status: 200)" in achados           # saida bruta entra no achado
    assert "WSTG-CONF-05" in achados
    assert "porta 3000 web" not in achados              # inconclusive nao vira achado
    assert "sqli no parametro q" not in achados         # refuted nao vira achado


def test_owasp_for_tool_mapeia_wstg_e_top10():
    assert owasp_report.owasp_for_tool("gobuster")[0] == "WSTG-CONF-05"
    assert "A05" in owasp_report.owasp_for_tool("gobuster")[1]
    assert owasp_report.owasp_for_tool("wapiti")[0] == "WSTG-INPVAL-05"
    assert "A03" in owasp_report.owasp_for_tool("wapiti")[1]
    assert owasp_report.owasp_for_tool("nikto")[0] == "WSTG-CONF-05"
    assert "A05" in owasp_report.owasp_for_tool("nikto")[1]


def test_write_owasp_report_grava_arquivo(tmp_path):
    store = _store(tmp_path, _fixture_items())
    out = owasp_report.write_owasp_report(store.list("inv-owasp"), "inv-owasp", "obj", tmp_path / "runs")
    assert out.exists()
    assert out.name == "owasp_report.md"
    assert "WSTG" in out.read_text(encoding="utf-8")


def test_veredicto_pt_vai_para_achados(tmp_path):
    store = _store(tmp_path, [
        {"id": "pt-000", "tool": "gobuster", "hypothesis": "app expoe /ftp",
         "human_validation": {"verdict": "confirmado"},
         "command": "gobuster dir -u http://localhost:3000 -w wl",
         "result": {"exit_code": 0, "summary": "", "stdout": "/ftp (Status: 200)"}},
    ])
    md = owasp_report.render_owasp_report(store.list("inv-owasp"), "inv-owasp", "obj")
    assert "app expoe /ftp" in md
    assert "confirmado" in md


def test_veredicto_rejeitado_continua_separado(tmp_path):
    store = _store(tmp_path, [
        {"id": "pt-001", "tool": "nmap", "hypothesis": "h",
         "human_validation": {"verdict": "rejeitado"},
         "result": {"exit_code": 0, "summary": "s", "stdout": ""}},
    ])
    md = owasp_report.render_owasp_report(store.list("inv-owasp"), "inv-owasp", "obj")
    assert "nenhum achado confirmado" in md.lower()
