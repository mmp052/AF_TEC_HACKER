"""HTTP direto via httpx (Juice Shop em localhost)."""
from __future__ import annotations

import time

import httpx

from agent_schemas import ToolResult
from guardrails import validate_url, ALLOWED_HOSTS
from tools import session_store

MAX_BODY = 8000

ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"})


def build_summary(status: int, headers: dict, text: str) -> str:
    lines = [f"status={status}", f"headers={dict(headers)}", f"body_preview={text[:2000]}"]
    return "\n".join(lines)[:4000]


def build_command_str(method: str, url: str, headers: dict, body: str,
                      session: str | None = None) -> str:
    cmd = f"{method} {url} headers={headers} body={body!r}"
    if session:
        cmd += f" session={session}"
    return cmd


def _validate_headers(headers) -> dict:
    if headers is None:
        return {}
    if not isinstance(headers, dict):
        raise ValueError("headers deve ser um objeto JSON (ex.: {\"Content-Type\": \"application/json\"})")
    for k, v in headers.items():
        if "\n" in str(k) or "\r" in str(k) or "\n" in str(v) or "\r" in str(v):
            raise ValueError("header nao pode conter quebra de linha")
    return dict(headers)


def _capture_into_session(session: str, state: dict | None, resp_text: str,
                          client_cookies) -> None:
    new_state = dict(state or {})
    new_state["cookies"] = dict(client_cookies)
    creds = session_store.extract_credentials(resp_text)
    if creds["token"]:
        new_state["authorization"] = "Bearer " + str(creds["token"])
    if creds["bid"] is not None:
        new_state["bid"] = creds["bid"]
    if creds["subject"]:
        new_state["subject"] = str(creds["subject"])
    session_store.save_session(session, new_state)


def run_http(params: dict, timeout: int = 30,
             allowed_hosts: set[str] | None = None) -> ToolResult:
    url = params.get("url", "")
    method = str(params.get("method", "GET")).upper()
    if method not in ALLOWED_METHODS:
        raise ValueError(f"metodo nao suportado: {method} (permitidos: {sorted(ALLOWED_METHODS)})")
    if "session" in params:
        # chave presente, valor inutil ("" / null / espacos) = erro visivel no painel,
        # nao "roda sem sessao silenciosamente"
        session = session_store.validate_session_name(params["session"] or "")
    else:
        session = None
    allowed = allowed_hosts or ALLOWED_HOSTS
    validate_url(url, allowed)
    headers = _validate_headers(params.get("headers"))
    body = params.get("body", "")
    t0 = time.time()
    orig_headers = dict(headers)   # para o comando auditavel (sem o Bearer injetado)

    if session:
        cookies, headers = session_store.apply_session(session, headers)
        state = session_store.load_session(session)
    else:
        cookies, state = {}, None

    with httpx.Client(timeout=15, follow_redirects=False, cookies=cookies) as c:
        try:
            r = c.request(method, url, headers=headers, content=body.encode() if body else None)
            text = r.text[:MAX_BODY]
            if session:
                _capture_into_session(session, state, r.text, c.cookies)
            summary = build_summary(r.status_code, dict(r.headers), text)
            return ToolResult(
                exit_code=0,
                stdout=summary,
                stderr="",
                duration_ms=int((time.time() - t0) * 1000),
                command=build_command_str(method, url, orig_headers, body, session),
                summary=summary,
            )
        except Exception as e:
            return ToolResult(
                exit_code=1,
                stdout="",
                stderr=str(e),
                duration_ms=int((time.time() - t0) * 1000),
                command=build_command_str(method, url, orig_headers, body, session),
                summary=f"erro http: {e}",
            )
