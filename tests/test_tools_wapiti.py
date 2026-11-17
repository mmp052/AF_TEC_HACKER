from unittest import mock

import pytest

import tools.wapiti_tool as wapiti_tool
from agent_schemas import ToolResult

URL = "http://localhost:3000"


def test_comando_wapiti_basico_tem_limite_e_formato_txt():
    cmd = wapiti_tool.build_wapiti_command(URL, {}, "/tmp/report")
    assert cmd[0] == "wapiti"
    assert "-u" in cmd and URL in cmd
    assert "-f" in cmd and "txt" in cmd
    assert "--max-scan-time" in cmd


def test_modulo_invalido_levanta():
    with pytest.raises(ValueError, match="modulo"):
        wapiti_tool.build_wapiti_command(URL, {"modules": ["http_request_shadow_rce"]}, "/tmp/report")


def test_modulo_valido_passa_na_linha_de_comando():
    cmd = wapiti_tool.build_wapiti_command(URL, {"modules": ["sql", "xss"]}, "/tmp/report")
    i = cmd.index("-m")
    assert cmd[i + 1] == "sql,xss"


def test_modulo_como_string_csv_aceita():
    cmd = wapiti_tool.build_wapiti_command(URL, {"modules": "sql, xss"}, "/tmp/report")
    i = cmd.index("-m")
    assert cmd[i + 1] == "sql,xss"


def test_param_desconhecido_levanta():
    with pytest.raises(ValueError, match="params"):
        wapiti_tool.build_wapiti_command(URL, {"modules": ["sql"], "proxy": "http://127.0.0.1:8080"}, "/tmp/report")


def test_scope_fora_da_allowlist_levanta():
    with pytest.raises(ValueError, match="scope"):
        wapiti_tool.build_wapiti_command(URL, {"scope": "domain"}, "/tmp/report")


def test_level_fora_da_faixa_levanta():
    with pytest.raises(ValueError, match="level"):
        wapiti_tool.build_wapiti_command(URL, {"level": 9}, "/tmp/report")


def test_host_externo_rejeitado():
    with pytest.raises(ValueError):
        wapiti_tool.run_wapiti({"url": "http://example.com"})


def _fake_run_cmd(stdout="done", stderr="", exit_code=0):
    def fake_run_cmd(cmd, timeout=120):
        return ToolResult(exit_code=exit_code, stdout=stdout, stderr=stderr,
                          duration_ms=10, command=" ".join(cmd), summary="summary")
    return fake_run_cmd


def test_run_wapiti_junta_report_na_saida(tmp_path):
    def fake_run_cmd(cmd, timeout=120):
        # o comando usa -o <arquivo>; simula o wapiti criando o txt de report
        out = cmd[cmd.index("-o") + 1]
        with open(out, "w", encoding="utf-8") as f:
            f.write("Vulnerability: SQL injection\n  url: http://localhost:3000/rest")
        return ToolResult(exit_code=0, stdout="scan completo", stderr="",
                          duration_ms=10, command=" ".join(cmd), summary="scan")

    with mock.patch.object(wapiti_tool, "run_cmd", side_effect=fake_run_cmd):
        r = wapiti_tool.run_wapiti({"url": URL})
    assert "SQL injection" in (r.stdout + r.summary)
