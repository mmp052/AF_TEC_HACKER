"""Loop supervisionado: LLM propoe -> humano decide -> executa -> volta pro LLM.

Fases OWASP (agent/phases.py): cada iteracao sabe em que fase esta (0 parceria,
1 reconhecimento, 2 enumeracao/config, 3 validacao de vulnerabilidades,
4 encerramento/relatorio). Flags sao declaradas pelo LLM, saneadas pelo codigo
e aprovadas pelo humano no painel. Fora da fase = painel amarelo, o humano decide.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

from agent.ollama_client import (ask_ollama, extract_next_step, expected_tool_from_text,
                             extract_refs, find_missing_refs, propose_action,
                             strip_think, truncate_at_next_step)
from agent.phases import (phase, sanitize_flags, merge_flags, phase_header,
                          fase_inicial_from_knowledge)
from agent_schemas import HumanDecision, ToolResult
from evidence_store import EvidenceStore
from llm_io_log import append_llm_io
from owasp_report import write_owasp_report
from routing.wordlist import choose_wordlist, describe_choice
from tools import session_store
from tools.cmdparse import parse_command, preview_command
from tools.gobuster_tool import run_gobuster
from tools.http_tool import run_http
from tools.nmap_tool import run_nmap, normalize_target, get_extra_args, parse_extra_args
from tools.nikto_tool import run_nikto
from tools.wapiti_tool import run_wapiti
from tools.wfuzz_tool import run_wfuzz

console = Console()

TOOLS = {
    "nmap": run_nmap,
    "http_request": run_http,
    "gobuster": run_gobuster,
    "wfuzz": run_wfuzz,
    "wapiti": run_wapiti,
    "nikto": run_nikto,
}

_VEREDITO_REGRA = (
    "confirmado  = voce leu a saida bruta e a evidencia verifica a hipotese "
    "(ex.: /admin listado com Status 200)\n"
    "refutado    = a saida contradiz a hipotese com evidencia positiva "
    "(ausencia de achados NAO refuta)\n"
    "inconclusivo= faltou evidencia para os dois lados (tool falhou, saida parcial, "
    "sem conviccao na saida) — na duvida, SEMPRE inconclusivo"
)


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
                        instruction: str = "", refs_missing: list[str] | None = None,
                        fase: int | None = None) -> dict:
    return {
        "id": f"{investigation_id}-{i:03d}",
        "investigation_id": investigation_id,
        "hypothesis": proposal.hypothesis,
        "proposed_action": proposal.model_dump(),
        "human_decision": decision.model_dump(),
        "tool": proposal.tool,
        "command": result.command,
        "result": {"exit_code": result.exit_code, "summary": result.summary,
                   "stdout": result.stdout[:4000], "stderr": result.stderr[:2000],
                   "duration_ms": result.duration_ms},
        "llm_interpretation": interpretation,
        "human_validation": {"verdict": verdict, "instruction": instruction or None,
                             "refs_missing": refs_missing or []},
        "fase": fase,
    }


_FINDING_RE = re.compile(r"Status:\s*(2\d\d|30[123]|401|403|204)")


def findings_note(tool: str, result) -> str:
    """Fato do codigo sobre a existencia de achados (gobuster/wfuzz).

    Vazio nao eh evidencia de rotas; serve para o LLM nao inventar sucesso.
    """
    if tool not in ("gobuster", "wfuzz"):
        return ""
    if result.exit_code != 0:
        return (f"a ferramenta FALHOU (exit code {result.exit_code}): saida vazia/parcial "
                "nao eh evidencia de ausencia de achados — leia o stderr antes de interpretar")
    texto = result.stdout or result.summary or ""
    # stdout e a fonte (summary duplica o mesmo texto e infla a contagem)
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
        extra = get_extra_args(p)
        toks = parse_extra_args(extra, default=None, target=target) if extra is not None else []
        rest = {"target": target}
        if toks:
            rest["extra_args"] = " ".join(toks)
    else:
        rest = {k: v for k, v in p.items() if k != "wordlist"}
    return tool + "|" + json.dumps(rest, sort_keys=True, ensure_ascii=False, default=str)


def _sim_nao(prompt: str, default: bool = True) -> bool:
    """Confirmacao em PT-BR: s/n (no lugar de y/n/yes/no do rich)."""
    return Prompt.ask(f"{prompt} (s/n)", choices=["s", "n"],
                      default="s" if default else "n") == "s"


def _human_decide(proposal, fase: int) -> HumanDecision:
    preview = preview_command(proposal.tool, proposal.params)
    flags_props, flags_desc = sanitize_flags(getattr(proposal, "flags", None))
    corpo = [
        f"tool: {proposal.tool}",
        f"params: {json.dumps(proposal.params, indent=2, ensure_ascii=False)}",
        f"comando: {preview}",
        f"hipotese: {proposal.hypothesis}",
        f"rationale: {proposal.rationale}",
        f"evidencia esperada: {proposal.expected_evidence}",
        f"fase: {phase_header(fase)}",
    ]
    if flags_props:
        corpo.append("flags propostas: " + ", ".join(flags_props))
    if flags_desc:
        corpo.append("flags desconhecidas (ignoradas): " + ", ".join(flags_desc))
    console.print(Panel("\n".join(corpo), title="Proposta do LLM", border_style="cyan"))
    choice = Prompt.ask("Autorizar?", choices=["s", "n", "pular", "editar"], default="s")
    if choice == "s":
        return HumanDecision(action="approved", final_params=proposal.params)
    if choice == "pular":
        return HumanDecision(action="skipped", final_params=None, note="passo pulado pelo humano")
    if choice == "n":
        return HumanDecision(action="rejected", final_params=None, note="humano rejeitou")
    # editar: humano digita o comando que quer rodar
    while True:
        console.print(f"[dim]comando atual: {preview}[/]")
        text = Prompt.ask("comando>", default="").strip()
        if not text:
            return _human_decide(proposal, fase)  # Enter vazio: volta ao menu
        try:
            edited = parse_command(proposal.tool, text)
        except ValueError as e:
            console.print(f"[red]Erro: {e}[/]")
            if not _sim_nao("Tentar de novo?", default=True):
                return _human_decide(proposal, fase)
            continue
        console.print(f"Entendi: {json.dumps(edited, ensure_ascii=False)}")
        if _sim_nao("Rodar este comando?", default=True):
            if proposal.tool in ("gobuster", "wfuzz") and proposal.params.get("wordlist"):
                edited.setdefault("wordlist", proposal.params["wordlist"])  # mantem escolha por evidencia
            return HumanDecision(action="modified", final_params=edited,
                                 note=f"comando digitado: {text}")
        # nao confirmou: volta ao menu
        return _human_decide(proposal, fase)


def run_investigation(store: EvidenceStore, endpoint: str, model: str,
                      objective: str, investigation_id: str,
                      max_iter: int = 20,
                      allowed_hosts: set[str] | None = None,
                      runs_dir: str | Path | None = None,
                      fase_inicial: int | None = None,
                      flags_iniciais: list[str] | None = None) -> None:
    history: list[dict[str, Any]] = []
    console.print(Panel(objective, title=f"Investigacao: {investigation_id}", border_style="magenta"))

    executed: set[str] = set()
    last_next_step: str | None = None

    phase_id: int = fase_inicial_from_knowledge(None, fase_inicial) if fase_inicial is not None else 1
    flags: list[str] = list(dict.fromkeys(flags_iniciais or []))
    if flags:
        console.print(f"[dim]fase inicial pre-semeada: {phase_header(phase_id)} | flags: {', '.join(flags)}[/]")

    for i in range(max_iter):
        console.print(f"\n[bold cyan]Iteracao {i+1}/{max_iter} · {phase_header(phase_id)}[/]")
        try:
            state_note = session_store.describe_sessions() or None
            proposal = propose_action(endpoint, model, history, objective,
                                      runs_dir=runs_dir, investigation_id=investigation_id,
                                      fase=phase_id, flags=flags, state_note=state_note)
        except Exception as e:
            console.print(f"[red]LLM falhou ao propor acao: {e}[/]")
            if not _sim_nao("Tentar novamente?", default=True):
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
                    fase=phase_id, flags=flags, state_note=state_note,
                    extra_note="Voce ja executou exatamente esta acao nesta investigacao. "
                               "Proponha uma ferramenta e/ou parametros DIFERENTES que facam progresso. "
                               "Se o objetivo ja foi cumprido, proponha conclude com um resumo. "
                               "Se quiser um nmap especifico (ex.: 'nmap -sV -p 3000 localhost'), "
                               "passe extra_args, ex.: {\"target\": \"localhost\", \"extra_args\": \"-sV -p 3000\"}.")
            except Exception as e:
                console.print(f"[red]LLM falhou ao re-propor: {e}[/]")
                break
        else:
            console.print(Panel("O LLM insistiu na acao repetida — a decisao fica com voce no painel.",
                                title="estagnacao", border_style="yellow"))

        # conclude nunca executa ferramenta: o agente apenas declara conclusao,
        # a evidencia guarda, e o humano confirma o encerramento
        if proposal.tool == "conclude":
            phase_id = 4  # concluir encerra na fase de relatorio
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
                "human_validation": {"verdict": "concluido"},
                "fase": phase_id,
            })
            history.append({"tool": "conclude", "result_summary": proposal.rationale[:800], "fase": phase_id})
            out = (Path(runs_dir) if runs_dir else Path("runs")) / investigation_id / "history.json"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(history, indent=2, ensure_ascii=False), encoding="utf-8")
            if not _sim_nao("Confirmar encerramento da investigacao?", default=True):
                history.append({"tool": "human", "result_summary": "humano pediu para continuar a investigacao"})
                continue
            break

        # flags declaradas pelo LLM: saneia contra o registro; o humano aprova no painel
        llm_flags, _desc_flags = sanitize_flags(getattr(proposal, "flags", None))
        fase_sugerida = getattr(proposal, "fase_sugerida", None)

        # tool fora da fase = aviso, o humano decide (nunca bloqueia)
        fase_tools = phase(phase_id)["tools"]
        if fase_tools and proposal.tool not in fase_tools:
            console.print(Panel(
                f"Proposta '{proposal.tool}' esta fora da {phase_header(phase_id)} "
                f"(tools recomendadas: {', '.join(fase_tools)}).\n"
                f"Voce decide no painel — s para autorizar, n para recusar, editar para corrigir o comando.",
                title="Fora da fase", border_style="yellow"))

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

        decision = _human_decide(proposal, phase_id)

        # o agente propos avancar de fase? so muda com o sim do humano
        if (decision.action in ("approved", "modified") and fase_sugerida is not None):
            try:
                sugerida = int(fase_sugerida)
            except (TypeError, ValueError):
                sugerida = None
            if sugerida is not None and sugerida in (0, 1, 2, 3, 4) and sugerida != phase_id:
                if _sim_nao(f"O agente propoe avancar para a fase {sugerida} — {phase(sugerida)['nome']}. Avancar?", default=True):
                    phase_id = sugerida

        if decision.action == "skipped":
            store.append({
                "id": f"{investigation_id}-{i:03d}",
                "investigation_id": investigation_id,
                "hypothesis": proposal.hypothesis,
                "proposed_action": proposal.model_dump(),
                "human_decision": decision.model_dump(),
                "tool": proposal.tool,
                "command": "",
                "result": {"skipped": True},
                "llm_interpretation": "(passo pulado pelo humano — nada executado)",
                "human_validation": {"verdict": "pulado"},
                "fase": phase_id,
            })
            history.append({"tool": proposal.tool, "result_summary": "pulado pelo humano (nada executado)",
                            "fase": phase_id})
            out = (Path(runs_dir) if runs_dir else Path("runs")) / investigation_id / "history.json"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(history, indent=2, ensure_ascii=False), encoding="utf-8")
            if _sim_nao("Continuar investigacao?", default=True):
                continue
            break

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
                "human_validation": {"verdict": "rejeitado"},
                "fase": phase_id,
            })
            history.append({"tool": proposal.tool, "result": "rejeitado pelo humano", "fase": phase_id})
            break  # termina a investigacao ao rejeitar (evita loop infinito)

        final_params = decision.final_params or proposal.params
        tool_fn = TOOLS.get(proposal.tool)
        if tool_fn is None:
            console.print("[red]tool desconhecida[/]")
            continue

        executed.add(executed_key(proposal.tool, final_params))
        flags = merge_flags(flags, llm_flags)
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
            interpretation = truncate_at_next_step(strip_think(raw_interp))
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

        # regra do veredito (PT): mostrada antes da pergunta
        console.print(Panel(_VEREDITO_REGRA, title="Regra do veredito", border_style="blue"))
        verdict = Prompt.ask("Veredito humano",
                             choices=["confirmado", "refutado", "inconclusivo"],
                             default="inconclusivo")
        hint = Prompt.ask("Instrucoes para o proximo passo (Enter = nenhuma)", default="").strip()

        store.append(build_evidence_item(investigation_id, i, proposal, decision,
                                         result, interpretation, verdict, instruction=hint,
                                         refs_missing=missing or None, fase=phase_id))

        history.append({
            "tool": proposal.tool,
            "params": final_params,
            "result_summary": result.summary[:800],
            "interpretation": interpretation[:400],
            "human_instruction": hint or None,
            "next_step": last_next_step,
            "findings_note": findings_note(proposal.tool, result) or None,
            "fase": phase_id,
            "flags": list(flags),
        })
        # grava history a cada turno (sobrevive a Ctrl-C no meio da investigacao)
        out = (Path(runs_dir) if runs_dir else Path("runs")) / investigation_id / "history.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(history, indent=2, ensure_ascii=False), encoding="utf-8")

        if not _sim_nao("Continuar investigacao?", default=True):
            break

    # salva historico no mesmo runs_dir do store (evita poluir cwd)
    out = (Path(runs_dir) if runs_dir else Path("runs")) / investigation_id / "history.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(history, indent=2, ensure_ascii=False), encoding="utf-8")

    # fim da investigacao: oferecer relatorio OWASP (WSTG + Top 10) das descobertas
    if _sim_nao("Gerar relatorio OWASP das descobertas?", default=True):
        try:
            rdir = Path(runs_dir) if runs_dir else Path("runs")
            report = write_owasp_report(store.list(investigation_id), investigation_id,
                                        objective, rdir)
            console.print(Panel(f"Relatorio OWASP escrito em {report}",
                                title="relatorio", border_style="green"))
        except Exception as e:
            console.print(f"[red]Falha ao gerar relatorio OWASP: {e}[/]")
