from unittest import mock

import pytest

import tools.wfuzz_tool as wfuzz_tool
from agent_schemas import ToolResult

WORDLIST_OK = "Fuzzing/Databases/SQLi/quick-SQLi.txt"


def echo_cmd(cmd, timeout=120):
    return ToolResult(exit_code=0, stdout="|".join(cmd), stderr="",
                      duration_ms=1, command=" ".join(cmd), summary="ok")


def test_url_sem_fuzz_levanta():
    with pytest.raises(ValueError, match="FUZZ"):
        wfuzz_tool.run_wfuzz({"url": "http://localhost:3000/search?q=x",
                              "wordlist": WORDLIST_OK})


def test_sem_wordlist_levanta():
    with pytest.raises(ValueError, match="wordlist"):
        wfuzz_tool.run_wfuzz({"url": "http://localhost:3000/search?q=FUZZ"})


def test_wordlist_inexistente_levanta():
    with pytest.raises(ValueError, match="wordlist"):
        wfuzz_tool.run_wfuzz({"url": "http://localhost:3000/search?q=FUZZ",
                              "wordlist": "Fuzzing/nope-not-here.txt"})


def test_fuzz_na_url_e_verificado_por_host_permitido():
    with mock.patch.object(wfuzz_tool, "has_binary", return_value=True):
        with pytest.raises(ValueError):
            wfuzz_tool.run_wfuzz({"url": "http://example.com/search?q=FUZZ",
                                  "wordlist": WORDLIST_OK})


def test_hc_404_adiciona_por_padrao():
    with mock.patch.object(wfuzz_tool, "has_binary", return_value=True), \
         mock.patch.object(wfuzz_tool, "run_cmd", side_effect=echo_cmd):
        r = wfuzz_tool.run_wfuzz({"url": "http://localhost:3000/search?q=FUZZ",
                                  "wordlist": WORDLIST_OK})
    assert "--hc 404" in r.command
    assert "wfuzz -c -z file," in r.command


def test_extra_args_podem_sobrepor_hc():
    with mock.patch.object(wfuzz_tool, "has_binary", return_value=True), \
         mock.patch.object(wfuzz_tool, "run_cmd", side_effect=echo_cmd):
        r = wfuzz_tool.run_wfuzz({"url": "http://localhost:3000/q=FUZZ",
                                  "wordlist": WORDLIST_OK,
                                  "extra_args": "--hc 500"})
    assert "--hc 500" in r.command
    assert "--hc 404" not in r.command


def test_fallback_docker():
    with mock.patch.object(wfuzz_tool, "has_binary", return_value=False), \
         mock.patch.object(wfuzz_tool, "run_cmd", side_effect=echo_cmd):
        r = wfuzz_tool.run_wfuzz({"url": "http://localhost:3000/q=FUZZ",
                                  "wordlist": WORDLIST_OK})
    assert "huntertier/wfuzz:latest" in r.command
    assert f"/wl/{WORDLIST_OK}" in r.command
