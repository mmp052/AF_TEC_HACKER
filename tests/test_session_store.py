import json

import pytest

from tools import session_store


def test_validate_nome_sessao_aceita_nomes_simples():
    assert session_store.validate_session_name("A") == "A"
    assert session_store.validate_session_name("conta-2_b") == "conta-2_b"


def test_validate_nome_sessao_rejeita_traversal_e_vazio():
    with pytest.raises(ValueError):
        session_store.validate_session_name("../etc/passwd")
    with pytest.raises(ValueError):
        session_store.validate_session_name("")
    with pytest.raises(ValueError):
        session_store.validate_session_name("a b")


def test_validate_nome_sessao_mensagem_ensina_exemplo():
    with pytest.raises(ValueError, match="A"):
        session_store.validate_session_name("")


def test_load_sessao_inexistente_retorna_estrutura_vazia(tmp_path):
    s = session_store.load_session("A", base=tmp_path)
    assert s["cookies"] == {}
    assert s["authorization"] is None
    assert s["bid"] is None


def test_save_e_load_roundtrip(tmp_path):
    session_store.save_session(
        "A",
        {"cookies": {"jwt": "abc"}, "authorization": "Bearer tok", "bid": 7, "subject": "a@b.c"},
        base=tmp_path,
    )
    s = session_store.load_session("A", base=tmp_path)
    assert s["cookies"] == {"jwt": "abc"}
    assert s["authorization"] == "Bearer tok"
    assert s["bid"] == 7
    assert s["subject"] == "a@b.c"


def test_save_sessao_grava_arquivo_com_permissao_600(tmp_path):
    p = session_store.save_session("A", {"cookies": {}}, base=tmp_path)
    assert (p.stat().st_mode & 0o777) == 0o600


def test_load_sessao_corrompida_erro_claro(tmp_path):
    (tmp_path / "A.json").write_text("{nao e json", encoding="utf-8")
    with pytest.raises(ValueError, match="corrompida"):
        session_store.load_session("A", base=tmp_path)


def test_extract_credentials_formato_juice_shop():
    body = json.dumps({"authentication": {"token": "tok123", "bid": 7, "email": "a@b.c"},
                       "status": "success"})
    c = session_store.extract_credentials(body)
    assert c["token"] == "tok123"
    assert c["bid"] == 7
    assert c["subject"] == "a@b.c"


def test_extract_credentials_sem_token_ou_json_invalido():
    assert session_store.extract_credentials('{"ok": true}') == {"token": None, "bid": None, "subject": None}
    assert session_store.extract_credentials("nao json")["token"] is None


def test_describe_sessions_lista_mas_nao_vaza_token(tmp_path):
    session_store.save_session(
        "A",
        {"cookies": {}, "authorization": "Bearer SUPER-SECRETO", "bid": 1, "subject": "a@b.c"},
        base=tmp_path,
    )
    session_store.save_session("B", {"cookies": {}}, base=tmp_path)
    out = session_store.describe_sessions(base=tmp_path)
    assert "A" in out and "a@b.c" in out and "bid=1" in out
    assert "B" in out
    assert "SUPER-SECRETO" not in out
    assert "session" in out


def test_describe_sessions_sem_sessoes_retorna_vazio(tmp_path):
    assert session_store.describe_sessions(base=tmp_path / "nao-existe") == ""


def test_apply_session_injeta_authorization_e_cookies(tmp_path):
    session_store.save_session(
        "A", {"cookies": {"c": "1"}, "authorization": "Bearer tok"}, base=tmp_path)
    cookies, headers = session_store.apply_session("A", {}, base=tmp_path)
    assert cookies == {"c": "1"}
    assert headers["Authorization"] == "Bearer tok"


def test_apply_session_header_explicito_prevalece(tmp_path):
    session_store.save_session(
        "A", {"cookies": {"c": "1"}, "authorization": "Bearer tok"}, base=tmp_path)
    _, headers = session_store.apply_session("A", {"authorization": "Bearer explicito"}, base=tmp_path)
    assert headers["authorization"] == "Bearer explicito"
