"""Fluxo do loop com fases OWASP + flags + edicao por comando (sem LLM real)."""
import json
from unittest import mock

import pytest

import agent.loop as loop
from agent_schemas import ActionProposal, ToolResult
from evidence_store import EvidenceStore


def _proposal(tool, params, hypothesis="h", rationale="r", flags=(), fase_sugerida=None):
    p = ActionProposal(tool=tool, params=params, hypothesis=hypothesis,
                       rationale=rationale, expected_evidence="e")
    if flags:
        p.flags = list(flags)
    if fase_sugerida is not None:
        p.fase_sugerida = fase_sugerida
    return p


def _nmap_ok():
    return ToolResult(exit_code=0, stdout="22/tcp open ssh\n3000/tcp open http", stderr="",
                      duration_ms=5, command="nmap -p- --open -Pn localhost",
                      summary="portas abertas: 22,3000")


def test_propose_recebe_fase_e_flags_na_chamada(tmp_path):
    captured = {}

    def fake_propose(*args, **kwargs):
        captured.update(kwargs)
        return _proposal("http_request", {"url": "http://localhost:3000"})

    def fake_tool(params, **kwargs):
        return _nmap_ok()

    store = EvidenceStore(tmp_path / "runs" / "inv-fase")
    with mock.patch.object(loop, "propose_action", fake_propose), \
         mock.patch.object(loop, "ask_ollama", return_value="interp"), \
         mock.patch.object(loop, "TOOLS", {"http_request": fake_tool}), \
         mock.patch.object(loop, "Prompt") as PromptMock, \
         mock.patch.object(loop, "_sim_nao") as SimNao:
        PromptMock.ask.side_effect = ["s", "confirmado", ""]
        SimNao.side_effect = [False, False]
        loop.run_investigation(store, "http://localhost:11434/api/chat", "qwen3:4b",
                               "objetivo", "inv-fase", max_iter=1, runs_dir=tmp_path / "runs",
                               fase_inicial=3, flags_iniciais=["sqli_suspeita"])
    assert captured.get("fase") == 3
    assert captured.get("flags") == ["sqli_suspeita"]


def test_sem_fase_inicial_padrao_eh_reconhecimento(tmp_path):
    captured = {}

    def fake_propose(*args, **kwargs):
        captured.update(kwargs)
        return _proposal("http_request", {"url": "http://localhost:3000"})

    def fake_tool(params, **kwargs):
        return _nmap_ok()

    store = EvidenceStore(tmp_path / "runs" / "inv-fase1")
    with mock.patch.object(loop, "propose_action", fake_propose), \
         mock.patch.object(loop, "ask_ollama", return_value="interp"), \
         mock.patch.object(loop, "TOOLS", {"http_request": fake_tool}), \
         mock.patch.object(loop, "Prompt") as PromptMock, \
         mock.patch.object(loop, "_sim_nao") as SimNao:
        PromptMock.ask.side_effect = ["s", "inconclusivo", ""]
        SimNao.side_effect = [False, False]
        loop.run_investigation(store, "http://localhost:11434/api/chat", "qwen3:4b",
                               "objetivo", "inv-fase1", max_iter=1, runs_dir=tmp_path / "runs")
    assert captured.get("fase") == 1


def test_opcao_pular_nao_executa_e_registra_pulado(tmp_path):
    execs = []

    def fake_tool(params, **kwargs):
        execs.append(params)
        return _nmap_ok()

    store = EvidenceStore(tmp_path / "runs" / "inv-pular")
    with mock.patch.object(loop, "propose_action",
                           return_value=_proposal("http_request", {"url": "http://localhost:3000"})), \
         mock.patch.object(loop, "ask_ollama", return_value="interp"), \
         mock.patch.object(loop, "TOOLS", {"http_request": fake_tool}), \
         mock.patch.object(loop, "Prompt") as PromptMock, \
         mock.patch.object(loop, "_sim_nao") as SimNao:
        PromptMock.ask.side_effect = ["pular"]
        SimNao.side_effect = [False, False]  # continuar? nao; gerar relatorio? nao
        loop.run_investigation(store, "http://localhost:11434/api/chat", "qwen3:4b",
                               "objetivo", "inv-pular", max_iter=1, runs_dir=tmp_path / "runs")
    assert execs == []
    rows = store.list("inv-pular")
    hv = json.loads(rows[-1][10])
    assert hv["verdict"] == "pulado"


def test_flags_declaradas_desconhecidas_sao_ignoradas_e_validas_acumulam(tmp_path):
    execs = []

    def fake_tool(params, **kwargs):
        execs.append(params)
        return _nmap_ok()

    store = EvidenceStore(tmp_path / "runs" / "inv-flags")
    with mock.patch.object(loop, "propose_action",
                           return_value=_proposal("http_request",
                                                  {"url": "http://localhost:3000"},
                                                  flags=["http_confirmado", "flag_fantasma"])), \
         mock.patch.object(loop, "ask_ollama", return_value="interp"), \
         mock.patch.object(loop, "TOOLS", {"http_request": fake_tool}), \
         mock.patch.object(loop, "Prompt") as PromptMock, \
         mock.patch.object(loop, "_sim_nao") as SimNao:
        PromptMock.ask.side_effect = ["s", "confirmado", ""]
        SimNao.side_effect = [False, False]
        loop.run_investigation(store, "http://localhost:11434/api/chat", "qwen3:4b",
                               "objetivo", "inv-flags", max_iter=1, runs_dir=tmp_path / "runs")
    hist = json.loads((tmp_path / "runs" / "inv-flags" / "history.json").read_text())
    http_entry = next(h for h in hist if h.get("tool") == "http_request")
    assert http_entry["flags"] == ["http_confirmado"]


def test_fase_sugerida_avanca_so_com_sim_do_humano(tmp_path):
    def fake_tool(params, **kwargs):
        return _nmap_ok()

    store = EvidenceStore(tmp_path / "runs" / "inv-avanca")
    with mock.patch.object(loop, "propose_action",
                           return_value=_proposal("http_request",
                                                  {"url": "http://localhost:3000"},
                                                  fase_sugerida=2)), \
         mock.patch.object(loop, "ask_ollama", return_value="interp"), \
         mock.patch.object(loop, "TOOLS", {"http_request": fake_tool}), \
         mock.patch.object(loop, "Prompt") as PromptMock, \
         mock.patch.object(loop, "_sim_nao") as SimNao:
        PromptMock.ask.side_effect = ["s", "confirmado", ""]
        SimNao.side_effect = [True, False, False]  # avancar para fase 2? sim; continuar? nao; relatorio? nao
        loop.run_investigation(store, "http://localhost:11434/api/chat", "qwen3:4b",
                               "objetivo", "inv-avanca", max_iter=1, runs_dir=tmp_path / "runs",
                               fase_inicial=1, flags_iniciais=[])
    hist = json.loads((tmp_path / "runs" / "inv-avanca" / "history.json").read_text())
    http_entry = next(h for h in hist if h.get("tool") == "http_request")
    assert http_entry["fase"] == 2


def test_editar_comando_substitui_params(tmp_path):
    captured = {}

    def fake_tool(params, **kwargs):
        captured.update(params)
        return _nmap_ok()

    store = EvidenceStore(tmp_path / "runs" / "inv-edit")
    with mock.patch.object(loop, "propose_action",
                           return_value=_proposal("nmap", {"target": "localhost"})), \
         mock.patch.object(loop, "ask_ollama", return_value="interp"), \
         mock.patch.object(loop, "TOOLS", {"nmap": fake_tool}), \
         mock.patch.object(loop, "Prompt") as PromptMock, \
         mock.patch.object(loop, "_sim_nao") as SimNao:
        PromptMock.ask.side_effect = ["editar", "nmap -sV -p 3000 localhost", "confirmado", ""]
        SimNao.side_effect = [True, False, False]  # rodar? sim; continuar? nao; relatorio? nao
        loop.run_investigation(store, "http://localhost:11434/api/chat", "qwen3:4b",
                               "objetivo", "inv-edit", max_iter=1, runs_dir=tmp_path / "runs")
    assert captured == {"target": "localhost", "extra_args": "-sV -p 3000"}


def test_editar_comando_invalido_volta_pro_menu_e_retorna_rejeitado(tmp_path):
    execs = []

    def fake_tool(params, **kwargs):
        execs.append(params)
        return _nmap_ok()

    store = EvidenceStore(tmp_path / "runs" / "inv-editbad")
    with mock.patch.object(loop, "propose_action",
                           return_value=_proposal("nmap", {"target": "localhost"})), \
         mock.patch.object(loop, "ask_ollama", return_value="interp"), \
         mock.patch.object(loop, "TOOLS", {"nmap": fake_tool}), \
         mock.patch.object(loop, "Prompt") as PromptMock, \
         mock.patch.object(loop, "_sim_nao") as SimNao:
        # editar -> comando invalido -> "Tentar de novo?" nao -> volta ao menu -> n (recusar)
        PromptMock.ask.side_effect = ["editar", "nmap --script=banner localhost", "n"]
        SimNao.side_effect = [False, False]  # tentar de novo? nao; (n direto, sem mais _sim_nao)
        loop.run_investigation(store, "http://localhost:11434/api/chat", "qwen3:4b",
                               "objetivo", "inv-editbad", max_iter=1, runs_dir=tmp_path / "runs")
    assert execs == []
