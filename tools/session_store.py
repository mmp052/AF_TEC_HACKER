"""Registro de sessoes nomeadas para o http_tool (cookies + bearer token).

Um arquivo por sessao em runs/.sessions/<nome>.json (chmod 600). Sobrevive a
Ctrl-C e eh reaproveitado entre chamadas do http_request.

Regras:
- O token NUNCA vai para o prompt do LLM — so um resumo (describe_sessions)
  com nome da sessao, subject e bid. O http_request aplica o Bearer sozinho.
- Arquivos de sessao nao sao evidencia academica: sao estado labeioral efemero.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

SESSIONS_DIR = Path("runs") / ".sessions"

_NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,32}")

# caminhos candidatos (em ordem) para token/bid/subject no JSON de resposta
_TOKEN_PATHS = [("authentication", "token"), ("token",), ("access_token",),
                ("accessToken",), ("data", "token")]
_BID_PATHS = [("authentication", "bid"), ("bid",), ("data", "bid")]
_SUBJECT_PATHS = [("authentication", "email"), ("email",), ("data", "email"),
                  ("user", "email")]


def validate_session_name(name: str) -> str:
    name = str(name or "").strip()
    if not _NAME_RE.fullmatch(name):
        raise ValueError(f"sessao invalida: {name!r} (use [A-Za-z0-9_-], 1-32 chars, ex.: 'A' ou 'B')")
    return name


def session_path(name: str, base: Path = SESSIONS_DIR) -> Path:
    return Path(base) / f"{validate_session_name(name)}.json"


def _empty() -> dict:
    return {"cookies": {}, "authorization": None, "bid": None, "subject": None}


def load_session(name: str, base: Path = SESSIONS_DIR) -> dict:
    validate_session_name(name)
    path = Path(base) / f"{name}.json"
    if not path.exists():
        return _empty()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise ValueError(f"sessao {name!r} corrompida ({path}): {e}") from e
    if not isinstance(data, dict):
        raise ValueError(f"sessao {name!r} corrompida ({path}): conteudo nao e objeto JSON")
    state = _empty()
    cookies = data.get("cookies")
    state["cookies"] = dict(cookies) if isinstance(cookies, dict) else {}
    for key in ("authorization", "subject"):
        if isinstance(data.get(key), str) and data[key]:
            state[key] = data[key]
    if data.get("bid") is not None:
        state["bid"] = data["bid"]
    return state


def save_session(name: str, state: dict, base: Path = SESSIONS_DIR) -> Path:
    validate_session_name(name)
    path = Path(base) / f"{name}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "cookies": dict(state.get("cookies") or {}),
        "authorization": state.get("authorization"),
        "bid": state.get("bid"),
        "subject": state.get("subject"),
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass  # filesystem sem permissoes posix (ex.: testes em FS estranho) — nao abortar
    return path


def _first_at(obj, paths):
    for path in paths:
        cur = obj
        for key in path:
            if not isinstance(cur, dict):
                cur = None
                break
            cur = cur.get(key)
        if cur not in (None, ""):
            return cur
    return None


def extract_credentials(body_text: str) -> dict:
    """Extrai token/bid/subject de um corpo JSON de resposta (puro)."""
    try:
        obj = json.loads(str(body_text or ""))
    except Exception:
        return {"token": None, "bid": None, "subject": None}
    if not isinstance(obj, dict):
        return {"token": None, "bid": None, "subject": None}
    return {
        "token": _first_at(obj, _TOKEN_PATHS),
        "bid": _first_at(obj, _BID_PATHS),
        "subject": _first_at(obj, _SUBJECT_PATHS),
    }


def apply_session(name: str, headers: dict, base: Path = SESSIONS_DIR) -> tuple[dict, dict]:
    """Retorna (cookies, headers) para a chamada httpx.

    O Authorization explicito do chamador prevalece sobre o token da sessao.
    """
    state = load_session(name, base=base)
    merged = dict(headers or {})
    has_auth = any(str(k).lower() == "authorization" for k in merged)
    if state.get("authorization") and not has_auth:
        merged["Authorization"] = state["authorization"]
    return dict(state.get("cookies") or {}), merged


def describe_sessions(base: Path = SESSIONS_DIR) -> str:
    """Bloco curto para o prompt: sessoes existentes (SEM tokens). """
    base = Path(base)
    if not base.is_dir():
        return ""
    rows = []
    for path in sorted(base.glob("*.json")):
        try:
            s = load_session(path.stem, base=base)
        except ValueError:
            rows.append(f"- {path.stem}: (arquivo corrompido — faca login novamente)")
            continue
        if not (s.get("authorization") or s.get("cookies")):
            continue
        subject = s.get("subject") or "?"
        bid = s.get("bid") if s.get("bid") is not None else "?"
        token = "sim" if s.get("authorization") else "nao"
        rows.append(f"- {path.stem}: subject={subject}, bid={bid}, token={token}")
    if not rows:
        return ""
    return ("Sessoes registradas (fonte: codigo; o token eh aplicado automaticamente pelo "
            "http_request — NUNCA copie tokens no prompt):\n" + "\n".join(rows) +
            "\nPara usar uma sessao: \"session\": \"<nome>\" nos params. "
            "Para criar uma: login com \"session\": \"A\" (ou \"B\") — o token da resposta eh capturado sozinho.")
