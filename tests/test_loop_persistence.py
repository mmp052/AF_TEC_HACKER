"""Regressoes e contrato de persistencia por turno (I/O bruto com o LLM)."""
import json
from pathlib import Path
from unittest import mock

import pytest

import agent.loop as loop
import tools.nmap_tool as nmap_tool
from llm_io_log import append_llm_io


# --- BUG: nmap nunca aceita host:porta como alvo (a porta vai no -p) ---------

def test_normalize_target_remove_esquema_path_e_porta():
    assert nmap_tool.normalize_target("http://localhost:3000") == "localhost"
    assert nmap_tool.normalize_target("https://127.0.0.1:3000/") == "127.0.0.1"
    assert nmap_tool.normalize_target("localhost") == "localhost"
    assert nmap_tool.normalize_target("juice-shop:3000") == "juice-shop"


def test_comando_nmap_nunca_leva_host_com_porta():
    def echo(cmd, timeout=120):
        from agent_schemas import ToolResult
        return ToolResult(exit_code=0, stdout="|".join(cmd), stderr="",
                          duration_ms=1, command=" ".join(cmd), summary="ok")
    with mock.patch.object(nmap_tool, "has_binary", return_value=True), \
         mock.patch.object(nmap_tool, "run_cmd", side_effect=echo):
        r = nmap_tool.run_nmap({"host": "http://localhost:3000"})
    target = r.command.split()[-1]
    assert target == "localhost"
    assert "localhost:3000" not in r.command.split(" ", maxsplit=1)[1]


# --- PERSISTENCIA: I/O bruto do LLM por turno, imediatamente -----------------

def test_append_llm_io_grava_uma_linha_json_por_chamada(tmp_path):
    append_llm_io(tmp_path, "inv", {"stage": "propose", "model": "qwen3:4b",
                                    "messages": [{"role": "user", "content": "oi"}],
                                    "raw_response": '{"tool": "nmap"}'})
    lines = (tmp_path / "inv" / "llm_io.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["stage"] == "propose"
    assert rec["raw_response"] == '{"tool": "nmap"}'
    assert "ts" in rec


def test_append_llm_io_acrescenta_multiplas_linhas(tmp_path):
    for i in range(3):
        append_llm_io(tmp_path, "inv", {"stage": f"s{i}"})
    lines = (tmp_path / "inv" / "llm_io.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 3


ACTION_JSON = json.dumps({
    "tool": "http_request",
    "params": {"url": "http://localhost:3000/"},
    "hypothesis": "h",
    "rationale": "r",
    "risk": "baixo",
    "expected_evidence": "status 200",
})


def test_run_investigation_grava_llm_io_mesmo_se_usuario_interpretar(tmp_path, capsys):
    from agent_schemas import ToolResult
    from evidence_store import EvidenceStore

    def fake_tool(params, **kw):
        return ToolResult(exit_code=0, stdout="ok", stderr="", duration_ms=1,
                          command="http GET http://localhost:3000/", summary="status=200")

    store = EvidenceStore(tmp_path / "runs" / "inv-io")
    with mock.patch("agent.ollama_client.ask_ollama", return_value=ACTION_JSON), \
         mock.patch.object(loop, "ask_ollama", return_value="interpretacao"), \
         mock.patch.object(loop, "TOOLS", {"http_request": fake_tool}), \
         mock.patch.object(loop, "Prompt") as PromptMock, \
         mock.patch.object(loop, "Confirm") as ConfirmMock:
        PromptMock.ask.side_effect = ["y", "confirmed", ""]
        ConfirmMock.ask.return_value = False
        loop.run_investigation(store, "http://localhost:11434/api/chat", "qwen3:4b",
                               "objetivo", "inv-io", max_iter=1,
                               runs_dir=tmp_path / "runs")

    io_file = tmp_path / "runs" / "inv-io" / "llm_io.jsonl"
    assert io_file.exists()
    stages = [json.loads(l)["stage"] for l in io_file.read_text(encoding="utf-8").splitlines()]
    assert "propose" in stages
    assert "interpret" in stages
