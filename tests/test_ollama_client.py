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
