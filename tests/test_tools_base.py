import sys

from tools.base import has_binary, run_cmd


def test_run_cmd_sucesso():
    r = run_cmd([sys.executable, "-c", "print('ola')"], timeout=10)
    assert r.exit_code == 0
    assert "ola" in r.stdout
    assert r.command.startswith(f"{sys.executable} -c")


def test_run_cmd_timeout():
    r = run_cmd([sys.executable, "-c", "import time; time.sleep(5)"], timeout=1)
    assert r.exit_code == 124
    assert "timeout" in r.stderr


def test_run_cmd_binario_inexistente():
    r = run_cmd(["definitely-not-a-real-binary-xyz"], timeout=5)
    assert r.exit_code == 127
    assert "binario nao encontrado" in r.summary


def test_run_cmd_executa_lista_nunca_shell():
    r = run_cmd([sys.executable, "-c", "import os; print(os.getpid() > 0)"], timeout=10)
    assert r.exit_code == 0


def test_has_binary_true_false():
    assert has_binary(sys.executable.rsplit("/", 1)[-1]) or has_binary("python3")
    assert not has_binary("definitely-not-a-real-binary-xyz")
