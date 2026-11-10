import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from tools.http_tool import run_http


class _Handler(BaseHTTPRequestHandler):
    def _respond(self):
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Test", "sim")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _respond
    do_POST = _respond

    def log_message(self, *args):  # silencia logs do servidor de teste
        pass


@pytest.fixture(scope="module")
def server():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://localhost:{port}"
    srv.shutdown()


def test_get_200(server):
    r = run_http({"url": f"{server}/"})
    assert r.exit_code == 0
    assert "status=200" in r.summary
    assert "x-test" in r.summary.lower()
    assert "ok" in r.summary


def test_post_com_body(server):
    r = run_http({"url": f"{server}/submit", "method": "POST",
                  "headers": {"Content-Type": "application/json"},
                  "body": '{"q": "x"}'})
    assert r.exit_code == 0
    assert "POST" in r.command


def test_host_externo_bloqueado_sem_rede():
    with pytest.raises(ValueError):
        run_http({"url": "http://example.com/"})


def test_erro_de_conexao_retorna_exit_1(server):
    # porta fechada: httpx falha, tool converte em exit_code 1 (nao propaga excecao)
    r = run_http({"url": "http://localhost:1/"})
    assert r.exit_code == 1
    assert "erro http" in r.summary
