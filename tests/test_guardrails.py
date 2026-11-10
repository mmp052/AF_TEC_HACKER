import pytest

from guardrails import ALLOWED_HOSTS, validate_nmap_args, validate_url


def test_localhost_http_permitido():
    validate_url("http://localhost:3000")
    validate_url("http://localhost:3000/rest/products")


@pytest.mark.parametrize("url", ["http://127.0.0.1:3000/", "http://juice-shop:3000/"])
def test_hosts_permitidos(url):
    validate_url(url)


@pytest.mark.parametrize("url", ["http://example.com/", "http://localhost.evil.com/", "https://127.0.0.1.evil.com/"])
def test_host_externo_rejeitado(url):
    with pytest.raises(ValueError):
        validate_url(url)


@pytest.mark.parametrize("url", ["ftp://localhost/x", "file:///etc/passwd", "gopher://localhost/"])
def test_esquema_nao_http_rejeitado(url):
    with pytest.raises(ValueError):
        validate_url(url)


def test_hosts_permitidos_padrao():
    assert ALLOWED_HOSTS == {"localhost", "127.0.0.1", "juice-shop"}


def test_override_do_conjunto_de_hosts():
    validate_url("http://app.lab/", {"app.lab"})
    with pytest.raises(ValueError):
        validate_url("http://localhost/", {"app.lab"})


def test_args_banais_sao_aceitos():
    validate_nmap_args(["-sV", "-sC", "-p", "3000", "--open", "-Pn"])


@pytest.mark.parametrize("args", [["-p", "3000", "-oX", "/tmp/out.xml"], ["-oA", "dump"]])
def test_output_para_arquivo_bloqueado(args):
    with pytest.raises(ValueError):
        validate_nmap_args(args)


@pytest.mark.parametrize("args", [["--script=http-enum", "localhost"], ["-iL", "targets.txt"]])
def test_script_e_input_file_bloqueados(args):
    with pytest.raises(ValueError):
        validate_nmap_args(args)
