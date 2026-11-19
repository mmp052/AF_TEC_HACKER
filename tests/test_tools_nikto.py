from unittest import mock

import pytest

import tools.nikto_tool as nikto_tool
from agent_schemas import ToolResult

URL = "http://localhost:3000"


def test_comando_nikto_basico_tem_limite_e_formato_txt():
    cmd = nikto_tool.build_nikto_command(URL, {}, "/tmp/report")
    assert cmd[0] == "nikto"
    assert "-h" in cmd and URL in cmd
    assert "-Format" in cmd and "txt" in cmd
    assert "-maxtime" in cmd
    assert "-nointeractive" in cmd


def test_comando_nao_usa_flags_inexistentes_no_nikto_debian():
    # o nikto do Ubuntu (fork Debian 2.1.5) nao aceita -nocheck: ele imprime
    # 'Unknown option' e sai sem escanear. -ask no eh o equivalente (nada de update).
    cmd = nikto_tool.build_nikto_command(URL, {}, "/tmp/report")
    assert "-nocheck" not in cmd
    i = cmd.index("-ask")
    assert cmd[i + 1] == "no"


def test_comando_nao_usa_nolookup_com_alvo_por_nome():
    # observado no lab (recon-enumeracao-14): '-nolookup' no Debian/Ubuntu nikto
    # aborta com "-skiplookup set, but given name" quando o alvo eh nome
    # (localhost/juice-shop) — justamente nossa allowlist. Removido.
    cmd = nikto_tool.build_nikto_command(URL, {}, "/tmp/report")
    assert "-nolookup" not in cmd


def test_tuning_valido_passa_na_linha_de_comando():
    cmd = nikto_tool.build_nikto_command(URL, {"tuning": "9"}, "/tmp/report")
    i = cmd.index("-Tuning")
    assert cmd[i + 1] == "9"


def test_tuning_multiplo_valido():
    cmd = nikto_tool.build_nikto_command(URL, {"tuning": "149bde"}, "/tmp/report")
    i = cmd.index("-Tuning")
    assert cmd[i + 1] == "149bde"


def test_tuning_invalido_levanta():
    with pytest.raises(ValueError, match="tuning"):
        nikto_tool.build_nikto_command(URL, {"tuning": "9; rm -rf /"}, "/tmp/report")


def test_tuning_com_char_fora_da_allowlist_levanta():
    with pytest.raises(ValueError, match="tuning"):
        nikto_tool.build_nikto_command(URL, {"tuning": "z9"}, "/tmp/report")


def test_param_desconhecido_levanta():
    with pytest.raises(ValueError, match="params"):
        nikto_tool.build_nikto_command(URL, {"tuning": "9", "proxy": "http://127.0.0.1:8080"}, "/tmp/report")


def test_maxtime_fora_da_faixa_levanta():
    with pytest.raises(ValueError, match="maxtime"):
        nikto_tool.build_nikto_command(URL, {"maxtime": 99999}, "/tmp/report")


def test_host_externo_rejeitado():
    with pytest.raises(ValueError):
        nikto_tool.run_nikto({"url": "http://example.com"})


def test_run_nikto_junta_report_na_saida(tmp_path):
    def fake_run_cmd(cmd, timeout=120):
        out = cmd[cmd.index("-o") + 1]
        with open(out, "w", encoding="utf-8") as f:
            f.write("+ /admin: Admin panel detected\n+ OSVDB-3233: /admin/index.php found")
        return ToolResult(exit_code=0, stdout="scan completo", stderr="",
                          duration_ms=10, command=" ".join(cmd), summary="scan")

    with mock.patch.object(nikto_tool, "run_cmd", side_effect=fake_run_cmd):
        r = nikto_tool.run_nikto({"url": URL})
    assert "Admin panel" in (r.stdout + r.summary)
