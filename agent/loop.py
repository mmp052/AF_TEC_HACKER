"""Loop supervisionado: LLM propoe -> humano decide -> executa -> volta pro LLM."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt

from agent.ollama_client import (ask_ollama, extract_next_step, expected_tool_from_text,
                             extract_refs, find_missing_refs, propose_action, strip_think)
from agent_schemas import HumanDecision, ToolResult
from evidence_store import EvidenceStore
from llm_io_log import append_llm_io
from routing.wordlist import choose_wordlist, describe_choice
from tools.gobuster_tool import run_gobuster
from tools.http_tool import run_http
from tools.nmap_tool import run_nmap, normalize_target
from tools.wfuzz_tool import run_wfuzz

console = Console()

TOOLS = {
    "nmap": run_nmap,
    "http_request": run_http,
    "gobuster": run_gobuster,
    "wfuzz": run_wfuzz,
}


# --- funcoes puras ---------------------------------------------------------

def inject_wordlist(proposal, history):
    """Retorna (proposta, note_ou_None). Se gobuster/wfuzz, injeta a wordlist
    escolhida pelo routing por evidencia; se nao existe, retorna note=''."""
    if proposal.tool not in ("gobuster", "wfuzz"):
        return proposal, None
    wl, motivo = choose_wordlist(proposal.tool, history)
    if not wl:
        return proposal, ""
    return proposal.model_copy(update={"params": {**proposal.params, "wordlist": wl}}), \
        describe_choice(proposal.tool, wl, motivo)


def build_evidence_item(investigation_id: str, i: int, proposal, decision,
                        result, interpretation: str, verdict: str,
                        instruction: str = "", refs_missing: list[str] | None = None) -> dict:
    return {
        "id": f"{investigation_id}-{i:03d}",
        "investigation_id": investigation_id,
        "hypothesis": proposal.hypothesis,
        "proposed_action": proposal.model_dump(),
        "human_decision": decision.model_dump(),
        "tool": proposal.tool,
        "command": result.command,
        "result": {"exit_code": result.exit_code, "summary": result.summary,
                   "stdout": result.stdout[:4000]},
        "llm_interpretation": interpretation,
        "human_validation": {"verdict": verdict, "instruction": instruction or None,
                             "refs_missing": refs_missing or []},
    }


_FINDING_RE = re.compile(r"Status:\s*(2\d\d|30[123]|401|403|204)")


def findings_note(tool: str, result) -> str:
    """Fato do codigo sobre a existencia de achados (gobuster/wfuzz).

    Vazio nao eh evidencia de rotas; serve para o LLM nao inventar sucesso.
    """
    if tool not in ("gobuster", "wfuzz"):
        return ""
    # stdout e a fonte (summary duplica o mesmo texto e infla a contagem)
    texto = result.stdout or result.summary or ""
    hits = _FINDING_RE.findall(texto)
    if hits:
        return f"{len(hits)} achado(s) com resposta de sucesso/redirect/auth na saida"
    return "nenhum achado listado na saida (apenas o cabecalho; ex.: gobuster sem linhas de resultado)"


def executed_key(tool: str, params: dict) -> str:
    """Chave canonica da acao: tool + params (nmap: alvo normalizado; wordlist ignorada)."""
    p = dict(params or {})
    if tool == "nmap":
        target = p.pop("target", None)
        host = p.pop("host", None)
        target = normalize_target(target if target is not None else host)
        rest = {k: v for k, v in sorted(p.items()) if k != "wordlist"}
        rest = {"target": target, **rest}
    else:
        rest = {k: v for k, v in p.items() if k != "wordlist"}
    return tool + "|" + json.dumps(rest, sort_keys=True, ensure_ascii=False, default=str)


def _human_decide(proposal) -> HumanDecision:
    console.print(Panel(
        f"tool: {proposal.tool}\nparams: {json.dumps(proposal.params, indent=2, ensure_ascii=False)}\n"
        f"hipotese: {proposal.hypothesis}\nrationale: {proposal.rationale}\n"
        f"evidencia esperada: {proposal.expected_evidence}",
        title="Proposta do LLM",
        border_style="cyan",
    ))
    choice = Prompt.ask("Autorizar?", choices=["y", "n", "edit", "skip"], default="y")
    if choice in ("y",):
        return HumanDecision(action="approved", final_params=proposal.params)
    if choice == "skip" or choice == "n":
        return HumanDecision(action="rejected", final_params=None, note="humano rejeitou")
    # edit
    edited_str = Prompt.ask("Novo params JSON")
    try:
        edited = json.loads(edited_str)
    except json.JSONDecodeError:
        edited = proposal.params
    if proposal.tool in ("gobuster", "wfuzz") and proposal.params.get("wordlist"):
        edited.setdefault("wordlist", proposal.params["wordlist"])  # mantem escolha por evidencia
    return HumanDecision(action="modified", final_params=edited, note="editado pelo humano")


def run_investigation(store: EvidenceStore, endpoint: str, model: str,
                      objective: str, investigation_id: str,
                      max_iter: int = 20,
                      allowed_hosts: set[str] | None = None,
                      runs_dir: str | Path | None = None) -> None:
    history: list[dict[str, Any]] = []
    console.print(Panel(objective, title=f"Investigacao: {investigation_id}", border_style="magenta"))

    executed: set[str] = set()

    last_next_step: str | None = None

    for i in range(max_iter):
        console.print(f"\n[bold cyan]Iteracao {i+1}/{max_iter}[/]")
        try:
            proposal = propose_action(endpoint, model, history, objective,
                                      runs_dir=runs_dir, investigation_id=investigation_id)
        except Exception as e:
            console.print(f"[red]LLM falhou ao propor acao: {e}[/]")
            retry = Confirm.ask("Tentar novamente?", default=True)
            if not retry:
                break
            continue

        # estagnacao: mesma tool+params ja executada -> pede outra proposta (max 2)
        for attempt in range(1, 3):
            key = executed_key(proposal.tool, proposal.params)
            if key not in executed:
                break
            console.print(Panel(
                f"O LLM propos de novo uma acao identica a ja executada:\n  {key}\n"
                f"Pedindo outra proposta ao modelo ({attempt}/2).",
                title="estagnacao", border_style="red"))
            try:
                proposal = propose_action(
                    endpoint, model, history, objective,
                    runs_dir=runs_dir, investigation_id=investigation_id,
                    extra_note="Voce ja executou exatamente esta acao nesta investigacao. "
                               "Proponha uma ferramenta e/ou parametros DIFERENTES que facam progresso.")
            except Exception as e:
                console.print(f"[red]LLM falhou ao re-propor: {e}[/]")
                break
        else:
            console.print(Panel("O LLM insistiu na acao repetida — a decisao fica com voce no painel.",
                                title="estagnacao", border_style="yellow"))

        if proposal.tool == "conclude":
            # o agente decidiu encerrar: nada a executar
            console.print(Panel(
                f"{proposal.hypothesis}\n\n{proposal.rationale}",
                title="O agente concluiu", border_style="green"))
            store.append({
                "id": f"{investigation_id}-{i:03d}",
                "investigation_id": investigation_id,
                "hypothesis": proposal.hypothesis,
                "proposed_action": proposal.model_dump(),
                "human_decision": {"action": "approved", "final_params": {}, "note": "conclusao do agente"},
                "tool": "conclude",
                "command": "",
                "result": {"conclusion": True},
                "llm_interpretation": proposal.rationale,
                "human_validation": {"verdict": "concluded"},
            })
            history.append({"tool": "conclude", "result_summary": proposal.rationale[:800]})
            out = (Path(runs_dir) if runs_dir else Path("runs")) / investigation_id / "history.json"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(history, indent=2, ensure_ascii=False), encoding="utf-8")
            encerrar = Confirm.ask("Confirmar encerramento da investigacao?", default=True)
            if not encerrar:
                history.append({"tool": "human", "result_summary": "humano pediu para continuar a investigacao"})
                continue
            break

        # divergencia entre a intencao declarada e a proposta (apenas avisa)
        expected = expected_tool_from_text(last_next_step) if last_next_step else None
        if expected and proposal.tool != "conclude" and proposal.tool != expected:
            console.print(Panel(
                f"Sua intencao declarada era: '{last_next_step}' (esperado: {expected})\n"
                f"A proposta agora eh '{proposal.tool}' — confira antes de aprovar.",
                title="Divergencia", border_style="yellow"))

        # wordlist e escolhida pelo codigo a partir das evidencias ja coletadas
        old_llm_wl = proposal.params.get("wordlist") if proposal.tool in ("gobuster", "wfuzz") else None
        proposal, wordlist_note = inject_wordlist(proposal, history)
        if wordlist_note:
            if old_llm_wl and old_llm_wl != proposal.params.get("wordlist"):
                console.print(f"[dim]note: wordlist do LLM ({old_llm_wl}) sera substituida pela escolha por evidencia: {proposal.params['wordlist']}[/]")
            console.print(Panel(wordlist_note, title="wordlist", border_style="blue"))
        elif wordlist_note == "":
            console.print("[red]wordlist nao disponivel no SecLists clonado — abortando passo[/]")
            continue

        decision = _human_decide(proposal)
        if decision.action == "rejected":
            store.append({
                "id": f"{investigation_id}-{i:03d}",
                "investigation_id": investigation_id,
                "hypothesis": proposal.hypothesis,
                "proposed_action": proposal.model_dump(),
                "human_decision": decision.model_dump(),
                "tool": proposal.tool,
                "command": "",
                "result": {"rejected": True},
                "llm_interpretation": proposal.rationale,
                "human_validation": {"verdict": "rejected"},
            })
            history.append({"tool": proposal.tool, "result": "rejected pelo humano"})
            break  # termina a investigacao ao rejeitar (evita loop infinito)

        final_params = decision.final_params or proposal.params
        tool_fn = TOOLS.get(proposal.tool)
        if tool_fn is None:
            console.print("[red]tool desconhecida[/]")
            continue

        executed.add(executed_key(proposal.tool, final_params))
        console.print(f"[bold yellow]Executando {proposal.tool}...[/]")
        try:
            result: ToolResult = tool_fn(final_params, allowed_hosts=allowed_hosts)
        except Exception as e:
            result = ToolResult(exit_code=1, stdout="", stderr=str(e), duration_ms=0,
                                command=f"{proposal.tool} {final_params}", summary=f"erro: {e}")

        console.print(Panel(result.summary[:2000], title="resultado", border_style="green"))
        if wordlist_note:
            # registra tambem no historico p/ evidencia auditaveil
            history.append({"tool": "routing", "result_summary": wordlist_note})

        # pede interpretacao ao LLM
        fato = findings_note(proposal.tool, result)
        fato_linha = f"Fato do codigo (fonte da verdade): {fato}\n" if fato else ""
        interp_prompt = (
            f"Resultado da ferramenta {proposal.tool}:\n{result.summary[:3000]}\n\n"
            f"{fato_linha}"
            f"Hipotese: {proposal.hypothesis}\n\n"
            "Interprete tecnicamente e diga se a hipotese foi confirmada, refutada ou inconclusiva, "
            "e qual deve ser o proximo passo. Responda em 3-5 frases, sem alucinar vulnerabilidade sem evidencia. "
            "Se a saida estiver vazia/sem achados, diga isso explicitamente e marque inconclusive — NUNCA invente caminhos ou vulnerabilidades que nao estejam na saida.\n"
            "Termine OBRIGATORIAMENTE com uma linha final no formato exato: PROXIMO_PASSO: <o que fazer agora, citando a ferramenta>."
        )
        try:
            raw_interp = ask_ollama(endpoint, model,
                                    [{"role": "system", "content": "Voce interpreta resultados tecnicos de forma critica. Responda em texto puro, sem JSON. Sem raciocinio visivel."},
                                     {"role": "user", "content": interp_prompt},
                                     {"role": "assistant", "content": "Resposta:"}],
                                    format_json=False,
                                    stop=["\nuser", "\nUser", "\nUSER"])
            interpretation = strip_think(raw_interp)
            if not interpretation:
                interpretation = "falha ao interpretar: resposta vazia"
        except Exception as e:
            raw_interp, interpretation = None, f"falha ao interpretar: {e}"
        if runs_dir and investigation_id:
            append_llm_io(runs_dir, investigation_id,
                          {"stage": "interpret", "model": model, "endpoint": endpoint,
                           "tool": proposal.tool, "hypothesis": proposal.hypothesis,
                           "prompt": interp_prompt,
                           "raw_response": raw_interp if raw_interp is not None else interpretation,
                           "interpretation": interpretation})

        last_next_step = extract_next_step(interpretation)
        # tripwire: a interpretacao cita caminhos que nao constam na saida da tool?
        refs = extract_refs(interpretation)
        missing = find_missing_refs(refs, f"{result.stdout or ''}\n{result.stderr or ''}\n{result.command or ''}")
        if missing:
            console.print(Panel(
                "Interpretacao cita referencias ausentes na saida da ferramenta:\n"
                + "\n".join(f"  - {m}" for m in missing)
                + "\nPossivel alucinacao — confira a saida bruta antes de aprovar.",
                title="Verificacao de referencias", border_style="red"))

        console.print(Panel(interpretation, title="Interpretacao LLM", border_style="yellow"))

        verdict = Prompt.ask("Veredito humano (confirmed/refuted/inconclusive)",
                             choices=["confirmed", "refuted", "inconclusive"], default="inconclusive")
        hint = Prompt.ask("Instrucoes para o proximo passo (Enter = nenhuma)", default="").strip()

        store.append(build_evidence_item(investigation_id, i, proposal, decision,
                                         result, interpretation, verdict, instruction=hint,
                                         refs_missing=missing or None))

        history.append({
            "tool": proposal.tool,
            "params": final_params,
            "result_summary": result.summary[:800],
            "interpretation": interpretation[:400],
            "human_instruction": hint or None,
            "next_step": last_next_step,
            "findings_note": findings_note(proposal.tool, result) or None,
        })
        # grava history a cada turno (sobrevive a Ctrl-C no meio da investigacao)
        out = (Path(runs_dir) if runs_dir else Path("runs")) / investigation_id / "history.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(history, indent=2, ensure_ascii=False), encoding="utf-8")

        cont = Confirm.ask("Continuar investigacao?", default=True)
        if not cont:
            break

    # salva historico no mesmo runs_dir do store (evita poluir cwd)
    out = (Path(runs_dir) if runs_dir else Path("runs")) / investigation_id / "history.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(history, indent=2, ensure_ascii=False), encoding="utf-8")
