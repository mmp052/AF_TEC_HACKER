from pathlib import Path
from unittest import mock

import pytest

import tools.gobuster_tool as gobuster_tool
from agent_schemas import ToolResult

WORDLIST_OK = "Discovery/Web-Content/common.txt"


def echo_cmd(cmd, timeout=120):
    return ToolResult(exit_code=0, stdout="|".join(cmd), stderr="",
                      duration_ms=1, command=" ".join(cmd), summary="ok")


def test_sem_wordlist_levanta():
    with pytest.raises(ValueError, match="wordlist"):
        gobuster_tool.run_gobuster({"url": "http://localhost:3000"})


def test_wordlist_inexistente_levanta():
    with pytest.raises(ValueError, match="wordlist"):
        gobuster_tool.run_gobuster({"url": "http://localhost:3000",
                                    "wordlist": "Discovery/Web-Content/definitely-not-here.txt"})


def test_host_externo_rejeitado():
    with pytest.raises(ValueError):
        gobuster_tool.run_gobuster({"url": "http://example.com",
                                    "wordlist": WORDLIST_OK})


def test_comando_gobuster_com_binario_no_path():
    with mock.patch.object(gobuster_tool, "has_binary", return_value=True), \
         mock.patch.object(gobuster_tool, "run_cmd", side_effect=echo_cmd):
        r = gobuster_tool.run_gobuster({"url": "http://localhost:3000",
                                        "wordlist": WORDLIST_OK})
    cmd = r.command
    assert cmd.startswith(f"gobuster dir -u http://localhost:3000 -w wordlists/SecLists/{WORDLIST_OK}")
    assert cmd.endswith("-k -t 20")
    assert "--no-error" not in cmd


def test_fallback_docker_monta_seclists_readonly():
    with mock.patch.object(gobuster_tool, "has_binary", return_value=False), \
         mock.patch.object(gobuster_tool, "run_cmd", side_effect=echo_cmd):
        r = gobuster_tool.run_gobuster({"url": "http://localhost:3000",
                                        "wordlist": WORDLIST_OK})
    cmd = r.command
    assert cmd.startswith("docker run --rm --network host -v ")
    assert str(Path("wordlists/SecLists").resolve()) in cmd
    assert "mdiqib/gobuster:latest" in cmd
    assert f"/wl/{WORDLIST_OK}" in cmd
    assert "-t 20" in cmd
    assert "--no-error" not in cmd


def test_gobuster_retenta_com_exclude_length_quando_wildcard():
    calls = []

    def fake_run_cmd(cmd, timeout=120):
        calls.append(cmd)
        if len(calls) == 1:
            return ToolResult(exit_code=1, stdout="banner",
                              stderr="the server returns a status code... => 200 (Length: 9984). Please exclude the response length",
                              duration_ms=1, command=" ".join(cmd), summary="banner")
        return ToolResult(exit_code=0, stdout="/admin (Status: 200)\n", stderr="",
                          duration_ms=1, command=" ".join(cmd), summary="/admin (Status: 200)")

    with mock.patch.object(gobuster_tool, "has_binary", return_value=True), \
         mock.patch.object(gobuster_tool, "run_cmd", side_effect=fake_run_cmd):
        r = gobuster_tool.run_gobuster({"url": "http://localhost:3000",
                                        "wordlist": WORDLIST_OK})
    assert len(calls) == 2
    assert "--exclude-length" in calls[1]
    assert "9984" in calls[1]
    assert "/admin" in r.stdout
    assert "9984" in r.summary


def test_gobuster_erro_sem_wildcard_nao_retenta():
    calls = []

    def fake_run_cmd(cmd, timeout=120):
        calls.append(cmd)
        return ToolResult(exit_code=1, stdout="banner", stderr="outro erro qualquer",
                          duration_ms=1, command=" ".join(cmd), summary="banner")

    with mock.patch.object(gobuster_tool, "has_binary", return_value=True), \
         mock.patch.object(gobuster_tool, "run_cmd", side_effect=fake_run_cmd):
        r = gobuster_tool.run_gobuster({"url": "http://localhost:3000",
                                        "wordlist": WORDLIST_OK})
    assert len(calls) == 1
    assert r.exit_code == 1


def test_seclists_clonado_existe():
    assert (Path("wordlists/SecLists") / WORDLIST_OK).exists()
