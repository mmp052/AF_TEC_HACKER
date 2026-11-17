"""Guardas de progressao do agente: estagnacao, conclude, next_step."""
import json
from unittest import mock

import pytest

import agent.loop as loop
from agent_schemas import ActionProposal, ToolResult
from evidence_store import EvidenceStore


def _proposal(tool, params=None, hypothesis="h", rationale="r"):
    return ActionProposal(tool=tool, params=params or {}, hypothesis=hypothesis,
                          rationale=rationale, risk="baixo", expected_evidence="e")


def _http_ok():
    return ToolResult(exit_code=0, stdout="ok", stderr="", duration_ms=1,
                      command="http GET http://localhost:3000/", summary="status=200")


def _nmap_ok():
    return ToolResult(exit_code=0, stdout="22/tcp open ssh", stderr="", duration_ms=1,
                      command="nmap -p- --open -Pn localhost", summary="portas abertas: 22")


# --- executed_key: chave canonica da acao executada -------------------------

def test_executed_key_normaliza_nmap_alvo():
    a = loop.executed_key("nmap", {"target": "http://localhost:3000"})
    b = loop.executed_key("nmap", {"target": "localhost"})
    c = loop.executed_key("nmap", {"host": "http://localhost:3000"})
    assert a == b == c
    # target tem precedencia sobre host (mesmo contrato de run_nmap)
    d = loop.executed_key("nmap", {"target": "127.0.0.1", "host": "http://localhost:3000"})
    assert d == loop.executed_key("nmap", {"target": "127.0.0.1"})


def test_executed_key_nmap_alvos_diferentes():
    assert loop.executed_key("nmap", {"target": "localhost"}) != \
           loop.executed_key("nmap", {"target": "127.0.0.1"})


def test_executed_key_ignora_wordlist():
    a = loop.executed_key("gobuster", {"url": "http://localhost:3000", "wordlist": "a.txt"})
    b = loop.executed_key("gobuster", {"url": "http://localhost:3000", "wordlist": "b.txt"})
    assert a == b


def test_executed_key_gobuster_url_diferente():
    assert loop.executed_key("gobuster", {"url": "http://localhost:3000"}) != \
           loop.executed_key("gobuster", {"url": "http://localhost:3000/api"})


# --- estagnacao: repeticao identica eh bloqueada e o LLM re-perguntado ------

def test_repeticao_identica_nao_executa_e_re_pergunta(tmp_path):
    execs = []

    def fake_tool(params, **kw):
        execs.append(params)
        return _nmap_ok() if params.get("target") else _http_ok()

    http_proposal = _proposal("http_request", {"url": "http://localhost:3000/"}, "h2", "r2")
    proposals = [_proposal("nmap", {"target": "http://localhost:3000"}),
                 _proposal("nmap", {"target": "http://localhost:3000"}),  # repetida identica
                 http_proposal]

    store = EvidenceStore(tmp_path / "runs" / "inv-stag")
    with mock.patch.object(loop, "propose_action", side_effect=proposals) as pa, \
         mock.patch.object(loop, "ask_ollama", return_value="interp"), \
         mock.patch.object(loop, "TOOLS", {"nmap": fake_tool, "http_request": fake_tool}), \
         mock.patch.object(loop, "Prompt") as PromptMock, \
         mock.patch.object(loop, "Confirm") as ConfirmMock:
        PromptMock.ask.side_effect = ["y", "confirmed", "", "y", "confirmed", ""]
        ConfirmMock.ask.side_effect = [True, False]
        loop.run_investigation(store, "http://localhost:11434/api/chat", "qwen3:4b",
                               "objetivo", "inv-stag", max_iter=5, runs_dir=tmp_path / "runs")

    nmap_execs = [p for p in execs if "target" in p]
    assert len(nmap_execs) == 1  # identico nunca rodou duas vezes
    assert pa.call_count == 3  # propose, re-ask, propose final


def test_re_pergunta_carrega_extra_note():
    from agent.ollama_client import build_propose_messages
    msgs = build_propose_messages([], "obj", extra_note="voce ja rodou nmap em localhost; proponha DIFERENTE")
    assert "DIFERENTE" in msgs[1]["content"]


# --- conclude: o agente decide quando parar --------------------------------

def test_action_proposal_aceita_conclude():
    p = ActionProposal(tool="conclude", params={}, hypothesis="agente satisfeito",
                       rationale="evidencia suficiente", risk="baixo",
                       expected_evidence="resumo final")
    assert p.tool == "conclude"


def test_conclude_encerra_sem_executar_e_grava_evidencia(tmp_path):
    execs = []

    def fake_tool(params, **kw):
        execs.append(params)
        return _http_ok()

    conclude = _proposal("conclude", {}, "objetivo alcancado", "nmap mostrou o Juice Shop na 3000")
    store = EvidenceStore(tmp_path / "runs" / "inv-conc")
    with mock.patch.object(loop, "propose_action", return_value=conclude) as pa, \
         mock.patch.object(loop, "ask_ollama", return_value="interp"), \
         mock.patch.object(loop, "TOOLS", {"http_request": fake_tool}), \
         mock.patch.object(loop, "Prompt") as PromptMock, \
         mock.patch.object(loop, "Confirm") as ConfirmMock:
        ConfirmMock.ask.return_value = True  # confirma encerramento
        loop.run_investigation(store, "http://localhost:11434/api/chat", "qwen3:4b",
                               "objetivo", "inv-conc", max_iter=5, runs_dir=tmp_path / "runs")

    assert execs == []  # nada foi executado
    assert pa.call_count == 1
    rows = store.list("inv-conc")
    assert rows[-1][6] == "conclude"


def test_conclude_recusado_continua_a_investigacao(tmp_path):
    http_proposal = _proposal("http_request", {"url": "http://localhost:3000/"}, "h2", "r2")
    conclude = _proposal("conclude", {}, "acho que terminei", "posso parar")

    store = EvidenceStore(tmp_path / "runs" / "inv-conc2")
    with mock.patch.object(loop, "propose_action", side_effect=[conclude, http_proposal]) as pa, \
         mock.patch.object(loop, "ask_ollama", return_value="interp"), \
         mock.patch.object(loop, "TOOLS", {"http_request": lambda p, **kw: _http_ok()}), \
         mock.patch.object(loop, "Prompt") as PromptMock, \
         mock.patch.object(loop, "Confirm") as ConfirmMock:
        PromptMock.ask.side_effect = ["y", "confirmed", ""]
        ConfirmMock.ask.side_effect = [False, False]  # recusa encerrar; depois recusa continuar
        loop.run_investigation(store, "http://localhost:11434/api/chat", "qwen3:4b",
                               "objetivo", "inv-conc2", max_iter=5, runs_dir=tmp_path / "runs")

    assert pa.call_count == 2  # recusar o encerramento leva a outra proposta


# --- veredito como input de direcao -----------------------------------------

def test_veredito_aceita_instrucao_e_grava_na_evidencia(tmp_path):
    def fake_tool(params, **kw):
        return _http_ok()

    store = EvidenceStore(tmp_path / "runs" / "inv-instr")
    with mock.patch.object(loop, "propose_action",
                           return_value=_proposal("http_request", {"url": "http://localhost:3000/"})), \
         mock.patch.object(loop, "ask_ollama", return_value="interp"), \
         mock.patch.object(loop, "TOOLS", {"http_request": fake_tool}), \
         mock.patch.object(loop, "Prompt") as PromptMock, \
         mock.patch.object(loop, "Confirm") as ConfirmMock:
        PromptMock.ask.side_effect = ["y", "confirmed", "nao repita nmap, va de curl"]
        ConfirmMock.ask.return_value = False
        loop.run_investigation(store, "http://localhost:11434/api/chat", "qwen3:4b",
                               "objetivo", "inv-instr", max_iter=1, runs_dir=tmp_path / "runs")

    rows = store.list("inv-instr")
    hv = json.loads(rows[0][10])
    assert hv["verdict"] == "confirmed"
    assert hv["instruction"] == "nao repita nmap, va de curl"


def test_historico_carrega_instrucao_humana(tmp_path):
    def fake_tool(params, **kw):
        return _http_ok()

    store = EvidenceStore(tmp_path / "runs" / "inv-instr2")
    with mock.patch.object(loop, "propose_action",
                           return_value=_proposal("http_request", {"url": "http://localhost:3000/"})), \
         mock.patch.object(loop, "ask_ollama", return_value="interp"), \
         mock.patch.object(loop, "TOOLS", {"http_request": fake_tool}), \
         mock.patch.object(loop, "Prompt") as PromptMock, \
         mock.patch.object(loop, "Confirm") as ConfirmMock:
        PromptMock.ask.side_effect = ["y", "refuted", "troque por gobuster"]
        ConfirmMock.ask.return_value = False
        loop.run_investigation(store, "http://localhost:11434/api/chat", "qwen3:4b",
                               "objetivo", "inv-instr2", max_iter=1, runs_dir=tmp_path / "runs")

    hist = json.loads((tmp_path / "runs" / "inv-instr2" / "history.json").read_text(encoding="utf-8"))
    assert hist[0].get("human_instruction") == "troque por gobuster"


# --- divergencia intencao declarada x proposta ------------------------------

def test_aviso_de_divergencia_quando_proposta_contraria_intencao(tmp_path, capsys):
    execs = []

    def fake_tool(params, **kw):
        execs.append(params)
        return ToolResult(exit_code=0, stdout="ok", stderr="", duration_ms=1,
                          command="cmd", summary="resumo")

    interp = "Analise.\nPROXIMO_PASSO: rodar gobuster na porta 3000"
    proposals = [_proposal("nmap", {"target": "http://localhost:3000"}),   # turno 1: ok
                 _proposal("nmap", {"target": "127.0.0.1"})]                # turno 2: divergente (dito gobuster)

    store = EvidenceStore(tmp_path / "runs" / "inv-div")
    with mock.patch.object(loop, "propose_action", side_effect=proposals), \
         mock.patch.object(loop, "ask_ollama", return_value=interp), \
         mock.patch.object(loop, "TOOLS", {"nmap": fake_tool}), \
         mock.patch.object(loop, "Prompt") as PromptMock, \
         mock.patch.object(loop, "Confirm") as ConfirmMock:
        PromptMock.ask.side_effect = ["y", "confirmed", "", "y", "confirmed", ""]
        ConfirmMock.ask.side_effect = [True, False]
        loop.run_investigation(store, "http://localhost:11434/api/chat", "qwen3:4b",
                               "objetivo", "inv-div", max_iter=5, runs_dir=tmp_path / "runs")

    out = capsys.readouterr().out
    assert "Divergencia" in out
    assert "gobuster" in out


# --- interpretacao: prefill do turno assistant (Resposta:) -------------------

def test_interpretacao_usa_prefill_de_assistant(tmp_path):
    vistas = []

    def fake_ask(endpoint, model, messages, **kwargs):
        vistas.append(messages)
        return "Resposta limpa. PROXIMO_PASSO: rodar gobuster na 3000."

    def fake_tool(params, **kw):
        return _http_ok()

    store = EvidenceStore(tmp_path / "runs" / "inv-prefill")
    with mock.patch.object(loop, "propose_action",
                           return_value=_proposal("http_request", {"url": "http://localhost:3000/"})), \
         mock.patch.object(loop, "ask_ollama", side_effect=fake_ask), \
         mock.patch.object(loop, "TOOLS", {"http_request": fake_tool}), \
         mock.patch.object(loop, "Prompt") as PromptMock, \
         mock.patch.object(loop, "Confirm") as ConfirmMock:
        PromptMock.ask.side_effect = ["y", "confirmed", ""]
        ConfirmMock.ask.return_value = False
        loop.run_investigation(store, "http://localhost:11434/api/chat", "qwen3:4b",
                               "objetivo", "inv-prefill", max_iter=1, runs_dir=tmp_path / "runs")

    assert vistas, "ask_ollama nao foi chamada"
    msgs = vistas[0]
    assert msgs[-1] == {"role": "assistant", "content": "Resposta:"}


def test_interpretacao_envia_stop_para_cortar_fake_turno(tmp_path):
    vistas = []

    def fake_ask(endpoint, model, messages, **kwargs):
        vistas.append(kwargs)
        return "Resposta limpa. PROXIMO_PASSO: x"

    def fake_tool(params, **kw):
        return _http_ok()

    store = EvidenceStore(tmp_path / "runs" / "inv-stop")
    with mock.patch.object(loop, "propose_action",
                           return_value=_proposal("http_request", {"url": "http://localhost:3000/"})), \
         mock.patch.object(loop, "ask_ollama", side_effect=fake_ask), \
         mock.patch.object(loop, "TOOLS", {"http_request": fake_tool}), \
         mock.patch.object(loop, "Prompt") as PromptMock, \
         mock.patch.object(loop, "Confirm") as ConfirmMock:
        PromptMock.ask.side_effect = ["y", "confirmed", ""]
        ConfirmMock.ask.return_value = False
        loop.run_investigation(store, "http://localhost:11434/api/chat", "qwen3:4b",
                               "objetivo", "inv-stop", max_iter=1, runs_dir=tmp_path / "runs")

    assert vistas and vistas[0].get("stop")
    assert "\nuser" in vistas[0]["stop"]


# --- findings_note: fato do codigo injetado no prompt/historico -------------

def test_findings_note_gobuster_vazio_reporta_sem_achados():
    res = ToolResult(exit_code=0, stdout="Starting gobuster...\n(nada)\n", stderr="",
                     duration_ms=1, command="gobuster dir ...", summary="Starting gobuster...\n")
    assert "nenhum achado" in loop.findings_note("gobuster", res)


def test_findings_note_ferramenta_falhou_nao_diz_sem_achados():
    res = ToolResult(exit_code=1, stdout="Starting gobuster in directory enumeration mode\n",
                     stderr="the server returns a status code... => 200 (Length: 9984)",
                     duration_ms=1, command="gobuster dir ...", summary="Starting gobuster...\n")
    note = loop.findings_note("gobuster", res)
    assert "FALHOU" in note
    assert "exit" in note.lower()
    assert "nenhum achado" not in note


def test_findings_note_gobuster_com_achados_conta():
    res = ToolResult(exit_code=0, stdout="/admin (Status: 200) [Size: 1]\n/api (Status: 401) [Size: 2]\n",
                     stderr="", duration_ms=1, command="gobuster ...", summary="/admin (Status: 200)")
    assert "2" in loop.findings_note("gobuster", res)
    assert "achado" in loop.findings_note("gobuster", res)


def test_interpret_prompt_leva_o_fato_do_codigo_quando_vazio(tmp_path):
    vistas = []

    def fake_ask(endpoint, model, messages, **kwargs):
        vistas.append(messages)
        return "Resposta limpa. PROXIMO_PASSO: verificar manualmente."

    def fake_tool(params, **kw):
        return ToolResult(exit_code=0, stdout="Starting gobuster...\n", stderr="",
                          duration_ms=1, command="gobuster ...", summary="Starting gobuster...\n")

    store = EvidenceStore(tmp_path / "runs" / "inv-fato")
    with mock.patch.object(loop, "propose_action",
                           return_value=_proposal("gobuster", {"url": "http://localhost:3000/"})), \
         mock.patch.object(loop, "ask_ollama", side_effect=fake_ask), \
         mock.patch.object(loop, "TOOLS", {"gobuster": fake_tool}), \
         mock.patch.object(loop, "Prompt") as PromptMock, \
         mock.patch.object(loop, "Confirm") as ConfirmMock:
        PromptMock.ask.side_effect = ["y", "inconclusive", ""]
        ConfirmMock.ask.return_value = False
        loop.run_investigation(store, "http://localhost:11434/api/chat", "qwen3:4b",
                               "objetivo", "inv-fato", max_iter=1, runs_dir=tmp_path / "runs")

    mensagens = vistas[0]
    user_msg = next(m for m in mensagens if m["role"] == "user")
    assert "nenhum achado" in user_msg["content"]
    # e tambem no historico, para as proximas propostas verem o fato
    hist = json.loads((tmp_path / "runs" / "inv-fato" / "history.json").read_text(encoding="utf-8"))
    assert any(h.get("findings_note") for h in hist if h.get("tool") == "gobuster")


# --- verificacao de referencias (tripwire de alucinacao) --------------------

def test_tripwire_avisa_quando_interpretacao_cita_ref_ausente(tmp_path, capsys):
    interp = "A hipotese foi confirmada, pois /admin-rotas apareceu. PROXIMO_PASSO: curl /admin-rotas"

    def fake_tool(params, **kw):
        return ToolResult(exit_code=1, stdout="Starting gobuster...\n", stderr="",
                          duration_ms=1, command="gobuster ...", summary="Starting gobuster...\n")

    store = EvidenceStore(tmp_path / "runs" / "inv-trip")
    with mock.patch.object(loop, "propose_action",
                           return_value=_proposal("gobuster", {"url": "http://localhost:3000/"})), \
         mock.patch.object(loop, "ask_ollama", return_value=interp), \
         mock.patch.object(loop, "TOOLS", {"gobuster": fake_tool}), \
         mock.patch.object(loop, "Prompt") as PromptMock, \
         mock.patch.object(loop, "Confirm") as ConfirmMock:
        PromptMock.ask.side_effect = ["y", "confirmed", ""]
        ConfirmMock.ask.return_value = False
        loop.run_investigation(store, "http://localhost:11434/api/chat", "qwen3:4b",
                               "objetivo", "inv-trip", max_iter=1, runs_dir=tmp_path / "runs")

    out = capsys.readouterr().out
    assert "Ausente" in out or "ausente" in out
    assert "/admin-rotas" in out
    # e a evidencia registra a verificacao
    rows = store.list("inv-trip")
    hv = json.loads(rows[0][10])
    assert hv.get("refs_missing") == ["/admin-rotas"]


# --- interpretacao truncada no marcador PROXIMO_PASSO -------------------------

def test_interpretacao_exibe_so_ate_o_proximo_passo(tmp_path):
    interp_com_lixo = ("A hipotese foi confirmada. O servico responde com HTML do Juice Shop.\n"
                       "PROXIMO_PASSO: http_request /api\n"
                       "we are given the result of an http_request tool on http://localhost:3000.\n"
                       "So the hypothesis is confirmed and must be verified again. "
                       "PROXIMO_PASSO: http_request -u /api")
    vistas = {}

    def fake_ask(endpoint, model, messages, **kwargs):
        return interp_com_lixo

    def fake_tool(params, **kw):
        return _http_ok()

    store = EvidenceStore(tmp_path / "runs" / "inv-trunc")
    with mock.patch.object(loop, "propose_action",
                           return_value=_proposal("http_request", {"url": "http://localhost:3000/"})), \
         mock.patch.object(loop, "ask_ollama", side_effect=fake_ask), \
         mock.patch.object(loop, "TOOLS", {"http_request": fake_tool}), \
         mock.patch.object(loop, "Prompt") as PromptMock, \
         mock.patch.object(loop, "Confirm") as ConfirmMock:
        PromptMock.ask.side_effect = ["y", "confirmed", ""]
        ConfirmMock.ask.return_value = False
        loop.run_investigation(store, "http://localhost:11434/api/chat", "qwen3:4b",
                               "objetivo", "inv-trunc", max_iter=1, runs_dir=tmp_path / "runs")

    hist = json.loads((tmp_path / "runs" / "inv-trunc" / "history.json").read_text(encoding="utf-8"))
    dh = next(h for h in hist if h.get("tool") == "http_request")
    assert "we are given" not in dh["interpretation"]
    assert dh["interpretation"].endswith("PROXIMO_PASSO: http_request /api")
    assert dh["findings_note"] is None


# --- liberacao do modelo sobre params do nmap -------------------------------

def test_executed_key_extra_args_diferenciam_nmap():
    base = loop.executed_key("nmap", {"target": "localhost"})
    a = loop.executed_key("nmap", {"target": "localhost", "extra_args": "-sV -p 3000"})
    b = loop.executed_key("nmap", {"target": "localhost", "extra_args": "-sV -p 80"})
    alias = loop.executed_key("nmap", {"target": "localhost", "args": "-sV -p 3000"})
    assert base != a and a != b and a == alias


def test_extra_note_da_re_pergunta_ensina_extra_args(tmp_path):
    notas = []
    proposals = iter([_proposal("nmap", {"target": "http://localhost:3000"}),
                      _proposal("nmap", {"target": "http://localhost:3000"}),
                      _proposal("http_request", {"url": "http://localhost:3000/"}, "h2", "r2")])

    def fake_propose(endpoint, model, history, objective, **kw):
        notas.append(kw.get("extra_note"))
        return next(proposals)

    store = EvidenceStore(tmp_path / "runs" / "inv-note")
    with mock.patch.object(loop, "propose_action", side_effect=fake_propose), \
         mock.patch.object(loop, "ask_ollama",
                           return_value="Resposta. PROXIMO_PASSO: http_request /"), \
         mock.patch.object(loop, "TOOLS", {"nmap": lambda p, **kw: _nmap_ok(),
                                           "http_request": lambda p, **kw: _http_ok()}), \
         mock.patch.object(loop, "Prompt") as PromptMock, \
         mock.patch.object(loop, "Confirm") as ConfirmMock:
        PromptMock.ask.side_effect = ["y", "confirmed", "", "y", "confirmed", ""]
        ConfirmMock.ask.side_effect = [True, False]
        loop.run_investigation(store, "http://localhost:11434/api/chat", "qwen3:4b",
                               "objetivo", "inv-note", max_iter=3, runs_dir=tmp_path / "runs")

    assert any(n and "extra_args" in n for n in notas)
