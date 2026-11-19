"""Item 2: o loop passa o estado das sessoes para o LLM fora do digest truncado."""
from unittest import mock

from agent import loop
from agent_schemas import ToolResult
from evidence_store import EvidenceStore
from tests.test_loop import _proposal
from tools import session_store


def test_loop_passa_state_note_com_sessoes_registradas(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    session_store.save_session(
        "A",
        {"cookies": {}, "authorization": "Bearer SESSAO-A-SECRETO",
         "bid": 7, "subject": "a@b.c"},
        base=tmp_path / "runs" / ".sessions",
    )

    def fake_tool(params, **kwargs):
        return ToolResult(exit_code=0, stdout="status=200", stderr="", duration_ms=3,
                          command="GET http://localhost:3000/", summary="status=200")

    captured = {}

    def fake_propose(endpoint, model, history, objective, **kwargs):
        captured.update(kwargs)
        return _proposal("http_request", {"url": "http://localhost:3000/"})

    store = EvidenceStore(tmp_path / "runs" / "inv-sess")
    with mock.patch.object(loop, "propose_action", side_effect=fake_propose), \
         mock.patch.object(loop, "ask_ollama", return_value="interpretacao"), \
         mock.patch.object(loop, "TOOLS", {"http_request": fake_tool}), \
         mock.patch.object(loop, "Prompt") as PromptMock, \
         mock.patch.object(loop, "_sim_nao", return_value=False):
        PromptMock.ask.side_effect = ["s", "inconclusivo", ""]
        loop.run_investigation(store, "http://localhost:11434/api/chat", "qwen3:4b",
                               "objetivo", "inv-sess", max_iter=1,
                               runs_dir=tmp_path / "runs")

    note = captured.get("state_note", "")
    assert "Sessoes registradas" in note
    assert "A" in note and "a@b.c" in note
    assert "SESSAO-A-SECRETO" not in note   # token nao vai para o prompt


def test_loop_sem_sessoes_nao_passa_state_note(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    def fake_tool(params, **kwargs):
        return ToolResult(exit_code=0, stdout="", stderr="", duration_ms=3,
                          command="cmd", summary="s")

    captured = {}

    def fake_propose(endpoint, model, history, objective, **kwargs):
        captured.update(kwargs)
        return _proposal("http_request", {"url": "http://localhost:3000/"})

    store = EvidenceStore(tmp_path / "runs" / "inv-sess2")
    with mock.patch.object(loop, "propose_action", side_effect=fake_propose), \
         mock.patch.object(loop, "ask_ollama", return_value="interpretacao"), \
         mock.patch.object(loop, "TOOLS", {"http_request": fake_tool}), \
         mock.patch.object(loop, "Prompt") as PromptMock, \
         mock.patch.object(loop, "_sim_nao", return_value=False):
        PromptMock.ask.side_effect = ["s", "inconclusivo", ""]
        loop.run_investigation(store, "http://localhost:11434/api/chat", "qwen3:4b",
                               "objetivo", "inv-sess2", max_iter=1,
                               runs_dir=tmp_path / "runs")

    assert not captured.get("state_note")
