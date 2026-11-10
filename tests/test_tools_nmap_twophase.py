"""Contrato do nmap em duas fases (sweep -> service scan nas portas abertas)."""
from unittest import mock

import pytest

import tools.nmap_tool as nmap_tool
from agent_schemas import ToolResult

SWEEP_OUTPUT = """Starting Nmap ...
PORT     STATE SERVICE
22/tcp   open  ssh
3000/tcp open  http
Service scan ... (not run)
Nmap done: 1 IP address (1 host up) scanned in 3.21 seconds"""

VERSION_OUTPUT = """PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1
3000/tcp open  http    Node.js Express framework (http)
Nmap done: 1 IP address (1 host up) scanned in 5.02 seconds"""


def echo_left(cmd, timeout=120):
    return ToolResult(exit_code=0, stdout="|".join(cmd), stderr="",
                      duration_ms=1, command=" ".join(cmd), summary="")


def test_parse_open_ports_extrai_portas_em_ordem():
    ports = nmap_tool.parse_open_ports(SWEEP_OUTPUT)
    assert ports == ["22", "3000"]


def test_parse_open_ports_sem_nenhuma():
    assert nmap_tool.parse_open_ports("Nenhuma porta aberta") == []
    assert nmap_tool.parse_open_ports("") == []


def test_parse_open_ports_deduplica():
    dup = "22/tcp open ssh\n22/tcp open ssh\n3000/tcp open http"
    assert nmap_tool.parse_open_ports(dup) == ["22", "3000"]


def test_build_sweep_command():
    cmd = nmap_tool.build_nmap_command("localhost", nmap_tool.sweep_args(), use_docker=False)
    assert cmd == ["nmap", "-p-", "--open", "-Pn", "localhost"]
    docker_cmd = nmap_tool.build_nmap_command("localhost", nmap_tool.sweep_args(), use_docker=True)
    assert docker_cmd[:5] == ["docker", "run", "--rm", "--network", "host"]
    assert "instrumentisto/nmap:latest" in docker_cmd
    assert "-p-" in docker_cmd


def test_build_version_command_so_nas_portas_achadas():
    args = nmap_tool.version_args(["22", "3000"])
    assert args == ["-sV", "-p", "22,3000", "--open", "-Pn"]
    cmd = nmap_tool.build_nmap_command("localhost", args, use_docker=False)
    assert cmd == ["nmap", "-sV", "-p", "22,3000", "--open", "-Pn", "localhost"]


def test_run_nmap_executa_duas_fases_e_combina_resultado():
    calls = []

    def fake_run(cmd, timeout=120):
        calls.append(cmd)
        if len(calls) == 1:
            return ToolResult(exit_code=0, stdout=SWEEP_OUTPUT, stderr="",
                              duration_ms=100, command=" ".join(cmd), summary=SWEEP_OUTPUT)
        return ToolResult(exit_code=0, stdout=VERSION_OUTPUT, stderr="",
                          duration_ms=200, command=" ".join(cmd), summary=VERSION_OUTPUT)

    with mock.patch.object(nmap_tool, "has_binary", return_value=True), \
         mock.patch.object(nmap_tool, "run_cmd", side_effect=fake_run):
        r = nmap_tool.run_nmap({"target": "localhost"})

    assert len(calls) == 2
    assert "-p-" in calls[0]  # sweep
    assert "22,3000" in calls[1]  # versao so nas abertas
    assert "-sV" not in " ".join(calls[0])
    assert "-sV" in " ".join(calls[1])
    assert "OpenSSH" in r.stdout
    assert "22,3000" in r.command or "3000" in r.command
    assert r.command.count("nmap") >= 2
    assert r.exit_code == 0


def test_run_nmap_sem_portas_abertas_nao_roda_versao():
    calls = []

    def fake_run(cmd, timeout=120):
        calls.append(cmd)
        return ToolResult(exit_code=0, stdout="Nenhuma porta aberta", stderr="",
                          duration_ms=100, command=" ".join(cmd), summary="nada")

    with mock.patch.object(nmap_tool, "has_binary", return_value=True), \
         mock.patch.object(nmap_tool, "run_cmd", side_effect=fake_run):
        r = nmap_tool.run_nmap({"target": "localhost"})

    assert len(calls) == 1
    assert "nenhuma porta aberta" in r.summary.lower()


def test_extra_args_do_llm_volta_para_modo_single_shot():
    calls = []

    def fake_run(cmd, timeout=120):
        calls.append(cmd)
        return ToolResult(exit_code=0, stdout="out", stderr="",
                          duration_ms=1, command=" ".join(cmd), summary="s")

    with mock.patch.object(nmap_tool, "has_binary", return_value=True), \
         mock.patch.object(nmap_tool, "run_cmd", side_effect=fake_run):
        nmap_tool.run_nmap({"target": "localhost", "extra_args": "--top-ports 100"})

    assert len(calls) == 1
    cmd = " ".join(calls[0])
    assert "--top-ports 100" in cmd
    assert "-sV" not in cmd


def test_run_nmap_timeout_padrao_acomportado_a_uma_varredura_completa():
    # -sV contra 10 portas levou aprox. 1-2 min; o default deve ser maior
    import inspect
    sig = inspect.signature(nmap_tool.run_nmap)
    assert sig.parameters["timeout"].default >= 300


def test_validate_url_continua_aplicado_nas_duas_fases():
    with pytest.raises(ValueError):
        nmap_tool.run_nmap({"target": "example.com"})
