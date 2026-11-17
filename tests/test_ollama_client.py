import json
from unittest import mock

import pytest

import agent.ollama_client as oc


VALID_ACTION = {
    "tool": "gobuster",
    "params": {"url": "http://localhost:3000"},
    "hypothesis": "ha rotas ocultas",
    "rationale": "analise",
    "risk": "baixo",
    "expected_evidence": "200s",
}


def test_build_payload_tem_campos_criticos():
    p = oc.build_payload("qwen3:4b", [{"role": "user", "content": "oi"}],
                        temperature=0.2, num_ctx=4096, num_predict=64)
    assert p["think"] is False
    assert p["keep_alive"] == "30m"
    assert p["format"] == "json"
    assert p["stream"] is False
    assert p["options"]["repeat_penalty"] == 1.1
    assert p["options"]["num_ctx"] == 4096
    assert p["options"]["num_predict"] == 64


def test_build_prewarm_payload_usa_num_ctx():
    p = oc.build_prewarm_payload("qwen3:4b", 4096)
    assert p["model"] == "qwen3:4b"
    assert p["options"]["num_ctx"] == 4096
    assert p["options"]["num_predict"] == 8


def test_parse_action_ok():
    a = oc.parse_action(json.dumps(VALID_ACTION))
    assert a.tool == "gobuster"
    assert a.params["url"] == "http://localhost:3000"


def test_parse_action_json_invalido_levanta():
    with pytest.raises(Exception):
        oc.parse_action("isto nao e json")


def test_parse_action_schema_invalido_levanta():
    with pytest.raises(Exception):
        oc.parse_action(json.dumps({"tool": "nc"}))


def test_build_propose_messages_sem_reforco():
    msgs = oc.build_propose_messages([{"result_summary": "x" * 5000}], "obj")
    assert msgs[0]["role"] == "system"
    assert "obj" in msgs[1]["content"]
    # historico truncado para nao estourar o contexto
    assert len(msgs[1]["content"]) < 5000


def test_build_propose_messages_com_reforco_adiciona_aviso():
    msgs = oc.build_propose_messages([], "obj", reforco=True)
    assert "APENAS JSON" in msgs[1]["content"]


def test_propose_action_payload_chega_ao_post_correctamente():
    fake_resp = mock.Mock()
    fake_resp.raise_for_status = mock.Mock()
    fake_resp.json = mock.Mock(return_value={"message": {"content": json.dumps(VALID_ACTION)}})

    post = mock.Mock(return_value=fake_resp)
    client = mock.MagicMock()
    client.__enter__.return_value = client
    client.__exit__.return_value = False
    client.post = post

    with mock.patch.object(oc.httpx, "Client", return_value=client):
        a = oc.propose_action("http://localhost:11434/api/chat", "qwen3:4b",
                              [], "enumerar Juice Shop")
    assert a.tool == "gobuster"
    call = post.call_args
    assert call.kwargs["json"]["think"] is False
    assert call.kwargs["json"]["keep_alive"] == "30m"
    assert call.kwargs["json"]["options"]["repeat_penalty"] == 1.1


def test_propose_action_retry_em_json_invalido():
    respostas = iter(["lixo", json.dumps(VALID_ACTION)])

    fake_resp = mock.Mock()
    fake_resp.raise_for_status = mock.Mock()
    fake_resp.json = mock.Mock(side_effect=lambda: {"message": {"content": next(respostas)}})

    client = mock.MagicMock()
    client.__enter__.return_value = client
    client.__exit__.return_value = False
    client.post = mock.Mock(return_value=fake_resp)

    with mock.patch.object(oc.httpx, "Client", return_value=client):
        a = oc.propose_action("http://localhost:11434/api/chat", "qwen3:4b",
                              [], "enumerar")
    assert a.tool == "gobuster"
    assert client.post.call_count == 2


def test_build_payload_sem_format_json_quando_format_json_false():
    p = oc.build_payload("qwen3:4b", [{"role": "user", "content": "oi"}], format_json=False)
    assert "format" not in p
    assert p["think"] is False
    assert p["stream"] is False


def test_strip_think_remove_bloco_completo():
    raw = "<think>\nlinha1\nlinha2\n</think>\n\nA resposta."
    assert oc.strip_think(raw) == "A resposta."


def test_strip_think_sem_abertura_remove_prefacio():
    raw = "raciocinio enorme...\n</think>\n\nResposta limpa."
    assert oc.strip_think(raw) == "Resposta limpa."


def test_strip_think_texto_limpo_permanece():
    assert oc.strip_think("resposta sem think") == "resposta sem think"


def test_propose_action_tolera_bloco_think_antes_do_json():
    respostas = iter(["<think>hmm</think>" + json.dumps(VALID_ACTION)])

    fake_resp = mock.Mock()
    fake_resp.raise_for_status = mock.Mock()
    fake_resp.json = mock.Mock(side_effect=lambda: {"message": {"content": next(respostas)}})

    client = mock.MagicMock()
    client.__enter__.return_value = client
    client.__exit__.return_value = False
    client.post = mock.Mock(return_value=fake_resp)

    with mock.patch.object(oc.httpx, "Client", return_value=client):
        a = oc.propose_action("http://localhost:11434/api/chat", "qwen3:4b", [], "enumerar")
    assert a.tool == "gobuster"


def test_build_propose_messages_destaca_instrucao_humana():
    history = [{"tool": "http_request", "human_instruction": "nao repita nmap, va de curl"}]
    msgs = oc.build_propose_messages(history, "obj")
    assert "nao repita nmap" in msgs[1]["content"]


def test_instrucao_humana_suprime_intencao_declarada_conflitante():
    history = [{"tool": "http_request",
                "params": {"url": "http://localhost:3000"},
                "next_step": "http_request -u \"http://localhost:3000\" --method GET",
                "human_instruction": "enumerate diretorios"}]
    content = oc.build_propose_messages(history, "obj")[1]["content"]
    assert "Sua intencao declarada" not in content
    assert "enumerate diretorios" in content


def test_instrucao_humana_proibe_repetir_acao_anterior():
    history = [{"tool": "http_request",
                "params": {"url": "http://localhost:3000"},
                "human_instruction": "enumerate diretorios"}]
    content = oc.build_propose_messages(history, "obj")[1]["content"]
    assert "PROIBIDO" in content
    assert "http_request" in content
    assert "http://localhost:3000" in content


def test_system_prompt_inclui_cards_de_ferramentas():
    for tool in ("nmap", "http_request", "gobuster", "wfuzz"):
        assert tool in oc.SYSTEM_PROMPT
    assert "conclude" in oc.SYSTEM_PROMPT


def test_extract_next_step():
    assert oc.extract_next_step("blah\nPROXIMO_PASSO: rodar curl na porta 3000") == "rodar curl na porta 3000"
    assert oc.extract_next_step("sem linha alguma") is None


def test_expected_tool_from_text():
    assert oc.expected_tool_from_text("rodar curl na porta 3000") == "http_request"
    assert oc.expected_tool_from_text("varrer com nmap -sV") == "nmap"
    assert oc.expected_tool_from_text("achar diretorios ocultos com gobuster") == "gobuster"
    assert oc.expected_tool_from_text("fuzzing de parametro com wfuzz") == "wfuzz"
    assert oc.expected_tool_from_text("pense sobre o problema") is None


def test_build_propose_messages_destaca_proximo_passo():
    history = [{"tool": "nmap", "next_step": "rodar gobuster na porta 3000"}]
    msgs = oc.build_propose_messages(history, "obj")
    assert "Sua intencao declarada" in msgs[1]["content"]


def test_payload_inclui_stop_quando_informado():
    p = oc.build_payload("qwen3:4b", [{"role": "user", "content": "oi"}], stop=["\nuser"])
    assert p["options"]["stop"] == ["\nuser"]
    p2 = oc.build_payload("qwen3:4b", [{"role": "user", "content": "oi"}])
    assert "stop" not in p2["options"]


def test_extract_refs_encontra_caminhos_e_ignora_urls():
    refs = oc.extract_refs('O gobuster enumerou /admin e /api. Veja http://localhost:3000/fake-path-deve-sair')
    assert "/admin" in refs
    assert "/api" in refs
    assert "/fake-path-deve-sair" not in refs  # URLs sao removidas antes


def test_extract_refs_filtro_de_falsos_positivos_menores():
    # /tcp de '22/tcp open' nao e caminho de app — filtrado
    assert oc.extract_refs("portas 22/tcp e 80/tcp") == []
    assert oc.extract_refs("nao ha caminhos") == []


def test_find_missing_refs():
    refs = ["/admin", "/naoexiste"]
    missing = oc.find_missing_refs(refs, "Gobuster v3 Starting...\n/admin (Status: 200)")
    assert missing == ["/naoexiste"]


# --- truncate_at_next_step: corta tudo depois da 1a linha PROXIMO_PASSO ------

def test_truncate_at_next_step_corta_rambling_pos_resposta():
    raw = ("A hipotese foi confirmada. O servico responde com HTML do Juice Shop.\n"
           "PROXIMO_PASSO: http_request /api\n"
           "we are given the result of an http_request tool on http://localhost:3000.\n"
           "So the hypothesis is confirmed. PROXIMO_PASSO: http_request -u /api")
    out = oc.truncate_at_next_step(raw)
    assert out.endswith("PROXIMO_PASSO: http_request /api")
    assert "we are given" not in out
    assert out.count("PROXIMO_PASSO") == 1


def test_truncate_at_next_step_sem_marcador_retorna_inalterado():
    raw = "Resposta sem marcador nenhum\nsegunda linha"
    assert oc.truncate_at_next_step(raw) == raw


def test_truncate_at_next_step_marcador_inline_na_mesma_linha():
    raw = "Confirmado. PROXIMO_PASSO: nmap -p- 127.0.0.1\nlixo depois que nao deve ficar"
    out = oc.truncate_at_next_step(raw)
    assert out == "Confirmado. PROXIMO_PASSO: nmap -p- 127.0.0.1"


# --- build_history_digest: historico compacto, sem corte no meio do JSON ------

def test_propose_messages_mantem_ultima_entrada_e_nao_vaza_fingerprint():
    sf = "SF:" + "A" * 800
    history = [
        {"tool": "nmap", "params": {"target": "http://localhost:3000"},
         "result_summary": "portas abertas: 3000\n" + sf,
         "interpretation": "porta 3000 aberta, servico ppp?"},
        {"tool": "nmap", "params": {"target": "localhost", "extra_args": "-sV -p 3000"},
         "result_summary": "PORT STATE SERVICE\n3000/tcp open ppp?\n" + sf,
         "interpretation": "fingerprint com HTTP 200"},
        {"tool": "http_request", "params": {"url": "http://localhost:3000"},
         "result_summary": "status=200 body Juice Shop",
         "interpretation": "Juice Shop confirmado na 3000",
         "human_instruction": "enumerate diretorios"},
    ]
    content = oc.build_propose_messages(history, "obj")[1]["content"]
    # a entrada mais recente nao pode sumir do prompt por truncamento
    assert "status=200" in content
    assert "enumerate diretorios" in content
    # blob de fingerprint nmap nao deve ocupar o contexto
    assert "SF:" + "A" * 100 not in content


def test_system_prompt_ensina_extra_args_para_nmap_livre():
    assert "extra_args" in oc.SYSTEM_PROMPT
    assert "NAO passe extra_args" not in oc.SYSTEM_PROMPT
    assert "-sV -p 3000" in oc.SYSTEM_PROMPT
