from unittest import mock

import pytest

import tools.nmap_tool as nmap_tool
from agent_schemas import ToolResult
from guardrails import ALLOWED_HOSTS


def run_cmd_echo(cmd, timeout=120):
    from agent_schemas import ToolResult
    return ToolResult(exit_code=0, stdout="|".join(cmd), stderr="",
                      duration_ms=1, command=" ".join(cmd), summary="ok")


def test_alias_host_vira_target_e_remove_esquema_e_porta():
    with mock.patch.object(nmap_tool, "has_binary", return_value=True), \
         mock.patch.object(nmap_tool, "run_cmd", side_effect=run_cmd_echo):
        r = nmap_tool.run_nmap({"host": "http://localhost:3000"})
    parts = r.stdout.split("|")
    # a porta do nmap vai no -p; o alvo e sempre o host puro
    assert parts[-1] == "localhost"
    assert "http://" not in r.stdout
    assert "localhost:3000" not in r.command


def test_extra_args_string_vira_lista():
    with mock.patch.object(nmap_tool, "has_binary", return_value=True), \
         mock.patch.object(nmap_tool, "run_cmd", side_effect=run_cmd_echo):
        r = nmap_tool.run_nmap({"target": "localhost", "extra_args": "-sV -p 3000"})
    assert r.command == "nmap -sV -p 3000 localhost"


def test_extra_args_lista_preservada():
    with mock.patch.object(nmap_tool, "has_binary", return_value=True), \
         mock.patch.object(nmap_tool, "run_cmd", side_effect=run_cmd_echo):
        r = nmap_tool.run_nmap({"target": "localhost", "extra_args": ["-sC", "-Pn"]})
    assert r.command == "nmap -sC -Pn localhost"


def test_argumentos_bloqueados_propagam_erro():
    with mock.patch.object(nmap_tool, "has_binary", return_value=True):
        with pytest.raises(ValueError):
            nmap_tool.run_nmap({"target": "localhost", "extra_args": "--script=http-enum"})


def test_fallback_docker_quando_sem_binario():
    def fake_run(cmd, timeout=120):
        joined = " ".join(cmd)
        if "-p-" in joined:  # fase sweep: ninguem aberto -> versao nao roda
            return ToolResult(exit_code=0, stdout="nenhuma porta", stderr="",
                              duration_ms=1, command=joined, summary="sweep")
        return ToolResult(exit_code=0, stdout="ok", stderr="",
                          duration_ms=1, command=joined, summary="versao")

    with mock.patch.object(nmap_tool, "has_binary", return_value=False), \
         mock.patch.object(nmap_tool, "run_cmd", side_effect=fake_run):
        r = nmap_tool.run_nmap({"target": "localhost"})
    cmd = r.command
    assert cmd.startswith("docker run --rm --network host instrumentisto/nmap:latest")
    assert cmd.endswith("-p- --open -Pn localhost")


def test_fallback_docker_duas_fases_usam_mesma_imagem():
    def fake_run(cmd, timeout=120):
        joined = " ".join(cmd)
        if "-p-" in joined:
            return ToolResult(exit_code=0, stdout="22/tcp open ssh\nNmap done",
                              stderr="", duration_ms=1, command=joined, summary="sweep")
        return ToolResult(exit_code=0, stdout="22/tcp open ssh OpenSSH",
                          stderr="", duration_ms=1, command=joined, summary="versao")

    with mock.patch.object(nmap_tool, "has_binary", return_value=False), \
         mock.patch.object(nmap_tool, "run_cmd", side_effect=fake_run):
        r = nmap_tool.run_nmap({"target": "localhost"})
    assert r.command.count("instrumentisto/nmap:latest") == 2
    assert "22" in r.command
    assert "-sV" in r.command


def test_extra_args_padrao_cobre_todas_as_portas():
    with mock.patch.object(nmap_tool, "has_binary", return_value=True), \
         mock.patch.object(nmap_tool, "run_cmd", side_effect=run_cmd_echo):
        r = nmap_tool.run_nmap({"target": "localhost"})
    assert "-p-" in r.command
    assert "-p 3000" not in r.command
