from unittest import mock

import pytest

import agent.loop as loop
from agent_schemas import ActionProposal, ToolResult
from evidence_store import EvidenceStore
from routing.wordlist import FALLBACK_GOBUSTER, FALLBACK_WFUZZ_SQLI


def _proposal(tool="http_request", params=None):
    return ActionProposal(
        tool=tool,
        params=params or {"url": "http://localhost:3000/"},
        hypothesis="ha uma rota sensivel",
        rationale="exploracao basica",
        risk="baixo",
        expected_evidence="status 200",
    )


def test_inject_wordlist_ignora_nmap():
    p = _proposal("nmap", {"target": "localhost"})
    out, note = loop.inject_wordlist(p, [])
    assert out is p
    assert note is None


def test_inject_wordlist_injeta_fallback_gobuster():
    p = _proposal("gobuster", {"url": "http://localhost:3000"})
    out, note = loop.inject_wordlist(p, [])
    assert out.params["wordlist"] == FALLBACK_GOBUSTER
    assert "fallback" in note


def test_inject_wordlist_substitui_wordlist_do_llm():
    p = _proposal("wfuzz", {"url": "http://localhost:3000/s?q=FUZZ", "wordlist": "inventada/pelo/llm.txt"})
    out, note = loop.inject_wordlist(p, [])
    assert out.params["wordlist"] == FALLBACK_WFUZZ_SQLI
    assert out.params["wordlist"] != "inventada/pelo/llm.txt"


def test_build_evidence_item_estrutura():
    res = ToolResult(exit_code=0, stdout="out", stderr="", duration_ms=5,
                     command="cmd", summary="summ")
    decision = mock.Mock(model_dump=lambda: {"action": "approved", "final_params": {}})
    item = loop.build_evidence_item("inv", 0, _proposal(), decision, res, "interp", "confirmed")
    assert item["id"] == "inv-000"
    assert item["investigation_id"] == "inv"
    assert item["tool"] == "http_request"
    assert item["human_validation"]["verdict"] == "confirmed"
    assert item["result"]["summary"] == "summ"


def _run_one_iteration(tmp_path, fake_tool_fn, tool="http_request", params=None):
    store = EvidenceStore(tmp_path / "runs" / "inv-test")
    with mock.patch.object(loop, "propose_action",
                           side_effect=[_proposal(tool, params)]), \
         mock.patch.object(loop, "ask_ollama", return_value="interpretacao"), \
         mock.patch.object(loop, "TOOLS", {tool: fake_tool_fn}), \
         mock.patch.object(loop, "Prompt") as PromptMock, \
         mock.patch.object(loop, "Confirm") as ConfirmMock:
        PromptMock.ask.side_effect = ["y", "confirmed", ""]
        ConfirmMock.ask.return_value = False
        loop.run_investigation(store, "http://localhost:11434/api/chat", "qwen3:4b",
                               "objetivo", "inv-test", max_iter=1,
                               runs_dir=tmp_path / "runs")
    return store


def test_run_investigation_http_request_registra_evidencia(tmp_path):
    chamadas = []

    def fake_tool(params, **kwargs):
        chamadas.append(params)
        return ToolResult(exit_code=0, stdout="body", stderr="", duration_ms=3,
                          command="http GET http://localhost:3000/", summary="status=200")

    store = _run_one_iteration(tmp_path, fake_tool)
    assert chamadas and chamadas[0]["url"] == "http://localhost:3000/"
    rows = store.list("inv-test")
    assert len(rows) == 1
    assert rows[0][6] == "http_request"


def test_run_investigation_gobuster_recebe_wordlist_do_routing(tmp_path):
    chamadas = []

    def fake_tool(params, **kwargs):
        chamadas.append(params)
        return ToolResult(exit_code=0, stdout="..", stderr="", duration_ms=3,
                          command="gobuster dir ...", summary="scan ok")

    store = _run_one_iteration(tmp_path, fake_tool, tool="gobuster",
                               params={"url": "http://localhost:3000"})
    assert chamadas[0]["wordlist"] == FALLBACK_GOBUSTER
    rows = store.list("inv-test")
    assert len(rows) == 1


def test_interpret_nao_forca_json(tmp_path):
    chamado = {}

    def fake_ask(endpoint, model, messages, **kwargs):
        chamado.update(kwargs)
        return "interpretacao"

    def fake_tool(params, **kwargs):
        return ToolResult(exit_code=0, stdout="body", stderr="", duration_ms=3,
                          command="http GET http://localhost:3000/", summary="status=200")

    store = EvidenceStore(tmp_path / "runs" / "inv-fmt")
    with mock.patch.object(loop, "propose_action",
                           side_effect=[_proposal("http_request", {"url": "http://localhost:3000/"})]), \
         mock.patch.object(loop, "ask_ollama", side_effect=fake_ask), \
         mock.patch.object(loop, "TOOLS", {"http_request": fake_tool}), \
         mock.patch.object(loop, "Prompt") as PromptMock, \
         mock.patch.object(loop, "Confirm") as ConfirmMock:
        PromptMock.ask.side_effect = ["y", "confirmed", ""]
        ConfirmMock.ask.return_value = False
        loop.run_investigation(store, "http://localhost:11434/api/chat", "qwen3:4b",
                               "objetivo", "inv-fmt", max_iter=1, runs_dir=tmp_path / "runs")
    assert chamado.get("format_json") is False


def test_interpretacao_impressa_sem_bloco_think(tmp_path, capsys):
    def fake_ask(endpoint, model, messages, **kwargs):
        return "pensando muito...\n</think>\n\nHipotese confirmada."

    def fake_tool(params, **kwargs):
        return ToolResult(exit_code=0, stdout="body", stderr="", duration_ms=3,
                          command="http GET http://localhost:3000/", summary="status=200")

    store = EvidenceStore(tmp_path / "runs" / "inv-think")
    with mock.patch.object(loop, "propose_action",
                           side_effect=[_proposal("http_request", {"url": "http://localhost:3000/"})]), \
         mock.patch.object(loop, "ask_ollama", side_effect=fake_ask), \
         mock.patch.object(loop, "TOOLS", {"http_request": fake_tool}), \
         mock.patch.object(loop, "Prompt") as PromptMock, \
         mock.patch.object(loop, "Confirm") as ConfirmMock:
        PromptMock.ask.side_effect = ["y", "confirmed", ""]
        ConfirmMock.ask.return_value = False
        loop.run_investigation(store, "http://localhost:11434/api/chat", "qwen3:4b",
                               "objetivo", "inv-think", max_iter=1, runs_dir=tmp_path / "runs")
    out = capsys.readouterr().out
    assert "Hipotese confirmada." in out
    assert "pensando muito" not in out
