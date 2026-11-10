"""HTTP direto via httpx (Juice Shop em localhost)."""
from __future__ import annotations

import time

import httpx

from agent_schemas import ToolResult
from guardrails import validate_url, ALLOWED_HOSTS

MAX_BODY = 8000


def build_summary(status: int, headers: dict, text: str) -> str:
    lines = [f"status={status}", f"headers={dict(headers)}", f"body_preview={text[:2000]}"]
    return "\n".join(lines)[:4000]


def build_command_str(method: str, url: str, headers: dict, body: str) -> str:
    return f"{method} {url} headers={headers} body={body!r}"


def run_http(params: dict, timeout: int = 30,
             allowed_hosts: set[str] | None = None) -> ToolResult:
    url = params.get("url", "")
    method = params.get("method", "GET").upper()
    allowed = allowed_hosts or ALLOWED_HOSTS
    validate_url(url, allowed)
    headers = params.get("headers", {})
    body = params.get("body", "")
    t0 = time.time()

    with httpx.Client(timeout=15, follow_redirects=False) as c:
        try:
            r = c.request(method, url, headers=headers, content=body.encode() if body else None)
            text = r.text[:MAX_BODY]
            summary = build_summary(r.status_code, dict(r.headers), text)
            return ToolResult(
                exit_code=0,
                stdout=summary,
                stderr="",
                duration_ms=int((time.time() - t0) * 1000),
                command=build_command_str(method, url, headers, body),
                summary=summary,
            )
        except Exception as e:
            return ToolResult(
                exit_code=1,
                stdout="",
                stderr=str(e),
                duration_ms=int((time.time() - t0) * 1000),
                command=f"{method} {url}",
                summary=f"erro http: {e}",
            )
