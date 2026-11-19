import json
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


class _LoginHandler(BaseHTTPRequestHandler):
    """Simula /login (devolve token no formato Juice Shop) e /whoami (eco do Bearer)."""

    def _json(self, obj, status=200, set_cookie=None):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        if self.path == "/login":
            self._json({"authentication": {"token": "tok-abc", "bid": 7, "email": "a@b.c"},
                        "status": "success"},
                       set_cookie="sess=xyz; Path=/")
        elif self.path == "/whoami":
            self._json({"auth": self.headers.get("Authorization"),
                        "cookie": self.headers.get("Cookie")})
        else:
            self._json({}, status=404)

    do_GET = do_POST

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def login_server():
    srv = HTTPServer(("127.0.0.1", 0), _LoginHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://localhost:{port}"
    srv.shutdown()


def test_sessao_captura_token_da_resposta_de_login(monkeypatch, tmp_path, login_server):
    monkeypatch.chdir(tmp_path)
    r = run_http({"url": f"{login_server}/login", "method": "POST",
                  "headers": {"Content-Type": "application/json"},
                  "body": '{"email":"a@b.c","password":"x"}', "session": "A"})
    assert r.exit_code == 0
    assert "tok-abc" in r.summary                      # evidencia registra a resposta
    from tools import session_store
    s = session_store.load_session("A", base=tmp_path / "runs" / ".sessions")
    assert s["authorization"] == "Bearer tok-abc"
    assert s["bid"] == 7 and s["subject"] == "a@b.c"
    assert s["cookies"].get("sess") == "xyz"


def test_sessao_aplica_authorization_automaticamente(monkeypatch, tmp_path, login_server):
    monkeypatch.chdir(tmp_path)
    run_http({"url": f"{login_server}/login", "method": "POST", "body": "{}", "session": "A"})
    r = run_http({"url": f"{login_server}/whoami", "session": "A"})
    assert "Bearer tok-abc" in r.summary


def test_sessao_nao_vaza_token_para_outro_nome(monkeypatch, tmp_path, login_server):
    monkeypatch.chdir(tmp_path)
    run_http({"url": f"{login_server}/login", "method": "POST", "body": "{}", "session": "A"})
    r = run_http({"url": f"{login_server}/whoami", "session": "B"})
    assert "Bearer tok-abc" not in r.summary        # sessao B nao herda o token de A


def test_sessao_nome_invalido_rejeitado(server):
    with pytest.raises(ValueError):
        run_http({"url": f"{server}/", "session": "../escape"})


def test_sessao_vazia_e_erro_claro(server):
    # silencioso viraria "sem sessao" — queremos erro visivel no painel
    with pytest.raises(ValueError, match="sessao"):
        run_http({"url": f"{server}/", "session": ""})


def test_sessao_so_espacos_e_erro_claro(server):
    with pytest.raises(ValueError, match="sessao"):
        run_http({"url": f"{server}/", "session": "   "})


def test_sessao_null_explicita_e_erro_claro(server):
    with pytest.raises(ValueError, match="sessao"):
        run_http({"url": f"{server}/", "session": None})


def test_metodo_fora_da_allowlist_rejeitado(server):
    with pytest.raises(ValueError):
        run_http({"url": f"{server}/", "method": "FOOBAR"})


def test_command_mostra_sessao_e_metodo(monkeypatch, tmp_path, login_server):
    monkeypatch.chdir(tmp_path)
    r = run_http({"url": f"{login_server}/login", "method": "POST", "body": "{}", "session": "A"})
    assert r.command.startswith("POST")
    assert "session=A" in r.command


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
