"""Cliente Ollama: prompt rigido, parse JSON estrito, timeout generoso (CPU lento)."""
from __future__ import annotations

import json
import re

import httpx

from agent.phases import phase_prompt_block
from agent_schemas import ActionProposal
from llm_io_log import append_llm_io


SYSTEM_PROMPT = """Voce e um assistente de testes de seguranca supervisionados.
Alvo permitido: http://localhost:3000 ou http://127.0.0.1:3000 ou http://juice-shop:3000.
Ferramentas permitidas: nmap, http_request, gobuster, wfuzz, wapiti, nikto, conclude.

Como usar cada ferramenta (cards):

Ferramenta: nmap
- Sem params alem de target/host: o codigo roda em duas fases (sweep '-p- --open -Pn' e depois -sV so nas portas abertas). Exemplo: {"target": "http://localhost:3000"}
- Voce PODE pedir um scan especifico com extra_args. Ex.: para rodar 'nmap -sV -p 3000 localhost', proponha {"target": "localhost", "extra_args": "-sV -p 3000"}
- extra_args vira UM UNICO comando seu no lugar das duas fases. O alvo e normalizado (esquema/porta do target sao descartados).
- Mesmo alvo, scans diferentes = parametros diferentes: varie extra_args (ex.: "-sV -p 3000"), nao so o target.
- Flags bloqueadas no codigo: -oX, -oA, --script=, -iL. Sem scripts NSE.

Ferramenta: http_request
- params: {"url": "http://localhost:3000/caminho", "method": "GET|POST|PUT|PATCH|DELETE"} (default GET), "headers": {...}, "body": "...".
- Ex. login: {"url": "http://localhost:3000/rest/user/login", "method": "POST", "headers": {"Content-Type": "application/json"}, "body": "{\"email\":\"a@b.c\",\"password\":\"x\"}", "session": "A"}
- Sessoes nomeadas: passe "session": "A" (ou "B"). O http_request aplica o Bearer token capturado automaticamente (JSON da resposta com authentication.token) e reutiliza os cookies — voce NAO precisa (e NUNCA deve) copiar o token.
- Use sessoes para registrar/autenticar duas contas de teste: A e B (ex.: POST /api/Users para registrar, POST /rest/user/login com session para autenticar).
- Ex. autenticado: {"url": "http://localhost:3000/rest/user/whoami", "session": "A"}
- Bom para qualquer rota da API (JSON) — preferível a gobuster/wfuzz para interagir com endpoints conhecidos.

Ferramenta: gobuster
- params: {"url": "http://localhost:3000"} — diretorio/arquivo. Wordlist automatica, NAO informe.
- Bom para achar rotas/diretorios ocultos depois que uma porta web estiver confirmada.

Ferramenta: wfuzz
- params: {"url": "http://localhost:3000/busca?q=FUZZ"} — FUZZ marca o ponto de injecao. Wordlist automatica, NAO informe.
- Bom para fuzzing de parametros (SQLi/XSS/LFI) depois de achar uma entrada.

Ferramenta: wapiti
- params: {"url": "http://localhost:3000"} — scan de VULNERABILIDADES web (sqli, xss, file, ssrf, ...), nao de rotas.
- Voce PODE escolher os modulos em "modules" (ex.: ["sql", "xss"]); sem ele, o wapiti roda os modulos default.
- Outros params opcionais (com faixas validadas no codigo): scope (url|page|folder), level (1-4), depth (1-5), max_scan_time, max_attack_time, max_parameters, tasks, timeout, data (POST).
- Pode levar MINUTOS contra a aplicacao inteira; o humano aprova antes e o relatorio completo fica na evidencia.

Ferramenta: nikto
- params: {"url": "http://localhost:3000"} — scan de SERVIDOR/cabecalhos/arquivos default (nao de rotas nem de logica de app).
- Tuning opcional em "tuning" (combinacao de 1-9,0,a-e,x; ex.: "9" so SQLi, "4" so XSS, "x9" tudo exceto SQLi). Sem o param, roda todos os testes.
- maxtime (segundos, padrao 300, faixa 30-900) e timeout por requisicao (1-30) tambem aceitos.
- Complementa o wapiti: nikto = configuracao/cabecalhos/arquivos conhecidos; wapiti = vulnerabilidades da aplicacao. Pode levar MINUTOS; o humano aprova antes.

Ferramenta: conclude
- params: {} — quando a evidencia ja responde ao objetivo; escreva resumo final em hypothesis e rationale.
- Nao use conclude cedo demais: o humano aprova cada passo.

Como decidir o proximo passo (adapte ao OBJETIVO — nao sirva so a recon):
- Confirme algo simples antes de lancar uma ferramenta cara (ex.: http_request antes de wapiti).
- Aproxime do objetivo: superficie/rotas -> gobuster; parametros/injecao -> wfuzz; vulnerabilidades -> wapiti; servidor/cabecalhos/arquivos default -> nikto.
- Se a evidencia ja responde ao objetivo, proponha `conclude` com um resumo — nao repita acoes identicas nem estique o escopo.

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
_NEXT_STEP_LINE_RE = re.compile(r"PROXIMO_PASSO:[^\n]*", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s\"'<>)]+")
_REF_PATH_RE = re.compile(r"(?<![A-Za-z0-9_.-])/[A-Za-z0-9_\.-]{2,64}(?:/[A-Za-z0-9_\.-]{1,64})*")
_REF_DENYLIST = {"tcp", "udp", "ipp", "icmp"}
_TOOL_KEYWORDS = [
    ("nmap", re.compile(r"\bnmap\b", re.IGNORECASE)),
    ("http_request", re.compile(r"\b(curl|httpx|http_request|request)\b", re.IGNORECASE)),
    ("gobuster", re.compile(r"\b(gobuster|diret\w*)\b", re.IGNORECASE)),
    ("wfuzz", re.compile(r"\b(wfuzz|fuzz)\b", re.IGNORECASE)),
    ("wapiti", re.compile(r"\bwapiti\b", re.IGNORECASE)),
    ("nikto", re.compile(r"\bnikto\b", re.IGNORECASE)),
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


def build_history_digest(history: list[dict], max_entries: int = 5,
                         max_chars: int = 1600) -> str:
    """Resumo compacto do historico para o prompt: uma linha por entrada,
    sem corte no meio do JSON e sem blobs de fingerprint (SF:) do nmap.
    Se estourar o orcamento, descarta entradas mais antigas (nunca a ultima)."""
    entries: list[str] = []
    for h in history[-max_entries:]:
        if not isinstance(h, dict):
            continue
        tool = h.get("tool", "?")
        params = h.get("params")
        result = h.get("result_summary") if h.get("result_summary") is not None else h.get("result")
        if isinstance(result, (dict, list)):
            result = json.dumps(result, ensure_ascii=False, default=str)
        # remove blob de fingerprint do nmap e colapsa espacos
        result = " ".join(
            line.strip() for line in str(result or "").splitlines()
            if not line.strip().startswith("SF:")
        ).strip()
        interp = " ".join(str(h.get("interpretation") or "").split())
        parts = [f"- {tool}"]
        if params:
            parts.append("params=" + json.dumps(params, ensure_ascii=False,
                                                separators=(",", ":"), default=str))
        if result:
            parts.append("-> " + result[:300])
        if interp:
            parts.append("| interp: " + interp[:200])
        if h.get("findings_note"):
            parts.append("| fato: " + str(h["findings_note"]))
        if h.get("human_instruction"):
            parts.append("| INSTRUCAO DO HUMANO: " + str(h["human_instruction"]))
        entries.append(" ".join(parts))
    digest = "\n".join(entries)
    while len(digest) > max_chars and len(entries) > 1:
        entries.pop(0)
        digest = "\n".join(entries)
    return digest[:max_chars]


def build_propose_messages(history: list[dict], objective: str, reforco: bool = False,
                             extra_note: str | None = None,
                             fase: int = 1, flags: list[str] | None = None,
                             state_note: str | None = None) -> list[dict]:
    user = (phase_prompt_block(fase, flags or []) +
            f"\nObjetivo: {objective}\n\nHistorico recente (resumido):\n" + build_history_digest(history))
    if state_note:
        user += "\n" + state_note
    if reforco:
        user += "\nATENCAO: responda APENAS JSON, sem markdown, sem texto antes/depois."
    if extra_note:
        user += f"\nATENCAO: {extra_note}"
    instruction_entry = next((h for h in reversed(history)
                              if isinstance(h, dict) and h.get("human_instruction")), None)
    if instruction_entry:
        # instrucao humana tem prioridade: nao ecoar a intencao declarada (pode
        # contradizer o humano e reforca a acao que ele mandou evitar)
        user += ("\nInstrucao do humano para o proximo passo (OBRIGATORIA, tem prioridade "
                 f"sobre qualquer intencao declarada anteriormente): {instruction_entry['human_instruction']}")
        banned_tool = instruction_entry.get("tool")
        if banned_tool:
            user += ("\nPROIBIDO repetir a acao anterior: " + banned_tool + " "
                     + json.dumps(instruction_entry.get("params") or {},
                                  ensure_ascii=False, separators=(",", ":"), default=str)
                     + " — proponha algo DIFERENTE.")
    else:
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
                  extra_note: str | None = None,
                  fase: int = 1, flags: list[str] | None = None,
                  state_note: str | None = None) -> ActionProposal:
    msgs = build_propose_messages(history, objective, extra_note=extra_note, fase=fase, flags=flags,
                                  state_note=state_note)

    def _log(stage: str, msgs_, raw_: str) -> None:
        if runs_dir and investigation_id:
            append_llm_io(runs_dir, investigation_id,
                          {"stage": stage, "model": model, "endpoint": endpoint,
                           "objective": objective, "fase": fase, "flags": flags or [],
                           "messages": msgs_,
                           "raw_response": raw_})

    raw = ask_ollama(endpoint, model, msgs, num_ctx=num_ctx)
    _log("propose", msgs, raw)
    try:
        return parse_action(strip_think(raw))
    except Exception:
        # retry 1x com reforco
        msgs = build_propose_messages(history, objective, reforco=True, fase=fase, flags=flags,
                                       state_note=state_note)
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
    hay = str(haystack or "").lower()
    return [r for r in refs if r.lower() not in hay]


def truncate_at_next_step(text: str | None) -> str:
    """Corta a interpretacao no fim da 1a linha PROXIMO_PASSO.

    O modelo as vezes cumpre a tarefa (resposta + PROXIMO_PASSO) e depois
    continua com raciocinio de verificacao sem nenhum marcador de fim;
    o stop 
user nao pega isso. Tudo apos a linha PROXIMO_PASSO e descarte.
    """
    t_ = str(text or "")
    m = _NEXT_STEP_LINE_RE.search(t_)
    if not m:
        return t_
    return t_[:m.end()].rstrip()
