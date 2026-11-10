"""Cliente Ollama: prompt rigido, parse JSON estrito, timeout generoso (CPU lento)."""
from __future__ import annotations

import json
import re

import httpx

from agent_schemas import ActionProposal
from llm_io_log import append_llm_io


SYSTEM_PROMPT = """Voce e um assistente de testes de seguranca supervisionados.
Alvo permitido: http://localhost:3000 ou http://127.0.0.1:3000 ou http://juice-shop:3000.
Ferramentas permitidas: nmap, http_request, gobuster, wfuzz, conclude.

Como usar cada ferramenta (cards):

Ferramenta: nmap
- Dupla fase automatica: sweep '-p-' e -sV nas portas abertas. NAO passe extra_args — so target/host.
- Exemplo: {"target": "http://localhost:3000"} — o codigo normaliza o alvo e roda as duas fases.

Ferramenta: http_request
- params: {"url": "http://localhost:3000/caminho"} — GET apenas (seguro).
- Bom para confirmar que uma porta/servico responde HTTP com conteudo.

Ferramenta: gobuster
- params: {"url": "http://localhost:3000"} — diretorio/arquivo. Wordlist automatica, NAO informe.
- Bom para achar rotas/diretorios ocultos depois que uma porta web estiver confirmada.

Ferramenta: wfuzz
- params: {"url": "http://localhost:3000/busca?q=FUZZ"} — FUZZ marca o ponto de injecao. Wordlist automatica, NAO informe.
- Bom para fuzzing de parametros (SQLi/XSS/LFI) depois de achar uma entrada.

Ferramenta: conclude
- params: {} — quando a evidencia ja responde ao objetivo; escreva resumo final em hypothesis e rationale.
- Nao use conclude cedo demais: o humano aprova cada passo.

Regras:
- Responda APENAS JSON valido (sem texto extra, sem markdown).
- Campos obrigatorios: tool, params, hypothesis, rationale, expected_evidence.
- Em cada proposta diga POR QUE a ferramenta e os parametros escolhidos resolvem o objetivo agora.
- Nunca repita uma acao identica executada nesta investigacao — o codigo bloqueia e devolve a proposta.
- Nunca proponha host externo.
- Nunca proponha comando shell arbitrario; apenas a ferramenta e params estruturados.
"""


# --- funcoes puras ---------------------------------------------------------

_THINK_BLOCK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_NEXT_STEP_RE = re.compile(r"PROXIMO_PASSO:\s*(.+)", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s\"'<>)]+")
_REF_PATH_RE = re.compile(r"(?<![A-Za-z0-9_.-])/[A-Za-z0-9_\.-]{2,64}(?:/[A-Za-z0-9_\.-]{1,64})*")
_REF_DENYLIST = {"tcp", "udp", "ipp", "icmp"}
_TOOL_KEYWORDS = [
    ("nmap", re.compile(r"\bnmap\b", re.IGNORECASE)),
    ("http_request", re.compile(r"\b(curl|httpx|http_request|request)\b", re.IGNORECASE)),
    ("gobuster", re.compile(r"\b(gobuster|diret\w*)\b", re.IGNORECASE)),
    ("wfuzz", re.compile(r"\b(wfuzz|fuzz)\b", re.IGNORECASE)),
]


def strip_think(text: str) -> str:
    """Remove blocos <think>...</think> que o Qwen3 emite mesmo com think=false.

    Casos: bloco completo (<think>...</think>), fechamento solto sem abertura
    (o modelo descarta tudo antes de </think>), ou abertura sem fechamento
    (descarta ate o fim). Texto limpo passa inalterado.
    """
    if not text:
        return ""
    out = _THINK_BLOCK_RE.sub("", str(text))
    close = out.rfind("</think>")
    if close != -1:
        out = out[close + len("</think>"):]
    open_tag = out.rfind("<think>")
    if open_tag != -1:
        out = out[:open_tag]
    return out.strip()


def build_prewarm_payload(model: str, num_ctx: int) -> dict:
    return build_payload(model, [{"role": "user", "content": "ok"}],
                         temperature=0.0, num_ctx=num_ctx, num_predict=8)


def build_payload(model: str, messages: list[dict], *,
                  temperature: float = 0.2, num_ctx: int = 4096,
                  num_predict: int = 1024, format_json: bool = True,
                  stop: list[str] | None = None) -> dict:
    options = {"temperature": temperature, "num_ctx": num_ctx,
               "repeat_penalty": 1.1, "num_predict": num_predict}
    if stop:
        options["stop"] = stop
    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "think": False,
        "keep_alive": "30m",
        "options": options,
    }
    if format_json:
        payload["format"] = "json"
    return payload


def parse_action(raw: str) -> ActionProposal:
    obj = json.loads(raw)
    return ActionProposal(**obj)


def build_propose_messages(history: list[dict], objective: str, reforco: bool = False,
                             extra_note: str | None = None) -> list[dict]:
    user = f"Objetivo: {objective}\n\nHistorico recente (resumido):\n" + json.dumps(history[-5:], ensure_ascii=False)[:2000]
    if reforco:
        user += "\nATENCAO: responda APENAS JSON, sem markdown, sem texto antes/depois."
    if extra_note:
        user += f"\nATENCAO: {extra_note}"
    instruction = next((h.get("human_instruction") for h in reversed(history)
                        if isinstance(h, dict) and h.get("human_instruction")), None)
    if instruction:
        user += f"\nInstrucao do humano para o proximo passo: {instruction}"
    next_step = next((h.get("next_step") for h in reversed(history)
                      if isinstance(h, dict) and h.get("next_step")), None)
    if next_step:
        user += f"\nSua intencao declarada no passo anterior: {next_step}"
    return [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user}]


# --- I/O -------------------------------------------------------------------

def ask_ollama(endpoint: str, model: str, messages: list[dict],
               temperature: float = 0.2, num_ctx: int = 4096,
               timeout: float = 300.0, num_predict: int = 1024,
               format_json: bool = True,
               stop: list[str] | None = None) -> str:
    payload = build_payload(model, messages, temperature=temperature,
                            num_ctx=num_ctx, num_predict=num_predict,
                            format_json=format_json, stop=stop)
    with httpx.Client(timeout=timeout) as c:
        r = c.post(endpoint, json=payload)
        r.raise_for_status()
        data = r.json()
        return data.get("message", {}).get("content", "")


def propose_action(endpoint: str, model: str, history: list[dict],
                  objective: str, num_ctx: int = 4096,
                  runs_dir=None, investigation_id=None,
                  extra_note: str | None = None) -> ActionProposal:
    msgs = build_propose_messages(history, objective, extra_note=extra_note)

    def _log(stage: str, msgs_, raw_: str) -> None:
        if runs_dir and investigation_id:
            append_llm_io(runs_dir, investigation_id,
                          {"stage": stage, "model": model, "endpoint": endpoint,
                           "objective": objective, "messages": msgs_,
                           "raw_response": raw_})

    raw = ask_ollama(endpoint, model, msgs, num_ctx=num_ctx)
    _log("propose", msgs, raw)
    try:
        return parse_action(strip_think(raw))
    except Exception:
        # retry 1x com reforco
        msgs = build_propose_messages(history, objective, reforco=True)
        raw2 = ask_ollama(endpoint, model, msgs, num_ctx=num_ctx)
        _log("propose_retry", msgs, raw2)
        return parse_action(strip_think(raw2))


def extract_next_step(text: str | None) -> str | None:
    """Extrai a linha 'PROXIMO_PASSO: ...' que a interpretacao e obrigada a terminar."""
    m = _NEXT_STEP_RE.search(str(text or ""))
    return m.group(1).strip() if m else None


def expected_tool_from_text(text: str | None) -> str | None:
    """Mapeia keywords de ferramenta -> tool; None se ausente ou ambiguo."""
    matches = [tool for tool, rx in _TOOL_KEYWORDS if rx.search(str(text or ""))]
    return matches[0] if len(matches) == 1 else None


def extract_refs(text: str | None) -> list[str]:
    """Extrai referencias a caminhos (/...) citados pela saida/interpretacao.

    Remove URLs antes de extrair (evitar paths contidos em links) e descarta
    tokens curtos de contexto (ex.: /tcp de '22/tcp open').
    """
    t_ = _URL_RE.sub(" ", str(text or ""))
    refs, seen = [], set()
    for m in _REF_PATH_RE.findall(t_):
        norm = m.rstrip("/.")
        if not norm:
            continue
        if norm.strip("/") in _REF_DENYLIST:
            continue
        if norm not in seen:
            seen.add(norm)
            refs.append(norm)
    return refs[:20]


def find_missing_refs(refs: list[str], haystack: str | None) -> list[str]:
    hay = str(haystack or "")
    return [r for r in refs if r not in hay]
