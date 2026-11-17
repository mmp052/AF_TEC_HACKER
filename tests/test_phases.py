import pytest

from agent import phases


def test_cinco_fases_com_wstg():
    assert [p["id"] for p in phases.PHASES] == [0, 1, 2, 3, 4]
    assert phases.phase(1)["wstg"] == "WSTG-INFO"
    assert "gobuster" in phases.phase(2)["tools"]
    assert "nmap" not in phases.phase(3)["tools"]


def test_fase_invalida_levanta():
    with pytest.raises(ValueError, match="fase"):
        phases.phase(9)


def test_sanitize_flags_separa_validas_desconhecidas():
    validas, desc = phases.sanitize_flags(["http_confirmado", "ROTAS_ENCONTRADAS", "flag_fantasma", "http_confirmado"])
    assert validas == ["http_confirmado", "rotas_encontradas"]
    assert desc == ["flag_fantasma"]


def test_sanitize_flags_vazio():
    assert phases.sanitize_flags(None) == ([], [])
    assert phases.sanitize_flags([]) == ([], [])


def test_suspeita_sqli_vira_flag_e_fase_3():
    flags = phases.initial_flags_from_knowledge({"suspeita": "acho que tem SQLi no parametro q"})
    assert "sqli_suspeita" in flags
    assert phases.fase_inicial_from_knowledge({"suspeita": "sqli"}) == 3


def test_conhecimento_com_endpoints_pula_recon():
    flags = phases.initial_flags_from_knowledge({"endpoints": ["/rest/user"]})
    assert "endpoint_conhecido" in flags
    assert phases.fase_inicial_from_knowledge({"endpoints": ["/x"]}) == 3


def test_conhecimento_vazio_comeca_no_recon():
    assert phases.fase_inicial_from_knowledge(None) == 1
    assert phases.fase_inicial_from_knowledge({}) == 1


def test_fase_inicial_explicita_ganha():
    assert phases.fase_inicial_from_knowledge({"endpoints": ["/x"]}, fase_inicial=1) == 1


def test_merge_flags_sem_duplicar():
    assert phases.merge_flags(["http_confirmado"], ["http_confirmado", "rotas_encontradas"]) == \
        ["http_confirmado", "rotas_encontradas"]


def test_phase_prompt_block_contem_fase_flags_e_tools():
    b = phases.phase_prompt_block(2, ["http_confirmado"])
    assert "Fase atual: 2" in b and "Enumeracao" in b
    assert "http_confirmado" in b
    assert "gobuster" in b


def test_phase_header():
    assert phases.phase_header(1).startswith("Fase 1")
