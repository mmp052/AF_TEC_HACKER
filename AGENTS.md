# AGENTS.md — agente_hacker

Agente supervisionado (terminal, Python + Rich) para o laboratório OWASP Juice Shop local, disciplina Tecnologias Hackers — AF. Não é biblioteca; é um CLI que executa `main.py` contra `http://localhost:3000`. Não é git repository.

## Ambiente (verificado)

- Ubuntu 26.04, Python 3.14.4, 14 GiB RAM, Intel UHD 770 (sem CUDA). `docker` e `curl` no PATH; `nmap` 7.98, `gobuster` (v3.8.2) e `wfuzz` em `/usr/bin` (vistos em 2026-11-17 — as tools preferem o binario local, com fallback Docker se ausente); só `bkimminich/juice-shop` está em `docker images`, as outras imagens são baixadas na primeira execução (lento, precisa de rede).
- **Não tente `python3 -m venv .venv`**: fica quebrado (falta `python3.14-venv` e o sistema é "externally-managed"). Dependências reais foram instaladas com `python3 -m pip install --break-system-packages` no user-site (`~/.local/.../site-packages`). Import `rich/httpx/pydantic/yaml` funciona com `python3` direto da raiz do repo.
- Usuário `kit12` está no grupo `docker` — docker funciona sem sudo.
- SecLists já clonado em `wordlists/SecLists` (shallow). Escolha de wordlist é por `routing/wordlist.py` — **não** há catálogo no prompt (`catalog.yaml`/`make_catalog.py` foram removidos).
- Ollama rodando como processo (`/usr/local/bin/ollama serve`, não via systemd do usuário) em `127.0.0.1:11434`, modelo `qwen3:4b` Q4_K_M (~2.5 GB). `config.yaml` usa `num_ctx: 4096`, `timeout_sec: 300`, `keep_alive: "30m"`, `think: false` (o thinking do Qwen3 era a causa principal do timeout em CPU). `python3 main.py check` faz pre-warm (`/api/chat` mínimo, ctx 4096) — medido ~7 s.
- Juice Shop sobe com `bash lab/reset.sh` (`docker compose down -v && up -d` + healthcheck). Container `juice-shop` na porta 3000 quando ativo.

## Comandos (origem da verdade: código/scripts, não o README)

```bash
bash lab/reset.sh                    # restaura estado conhecido do Juice Shop
python3 main.py check                # checa Juice Shop + Ollama (/api/chat pre-warm) + SecLists + binários
python3 main.py run --file exemplo.yaml   # INTERATIVO: executa a investigação com aprovação humana
python3 main.py report --investigation recon-enumeracao
python3 -m pytest -q                 # 168 testes unitarios
```

- Testes com **pytest** em `tests/` — `tests/test_*.py`, todos com mocks/tmpdirs (`monkeypatch.chdir(tmp_path)` para o que escreve em disco) ou servidores locais na fixture `server` (http). **Nenhum teste bate na rede externa nem altera o lab.** Verificação mínima: `python3 -m pytest -q` (testes) ou `python3 -m py_compile main.py agent/*.py tools/*.py routing/*.py`.
- Rode tudo a partir da raiz do repo — todos os imports são planos/top-level (`from tools.x import ...`, `from agent.x import ...`, `import guardrails`), sem package instalável nem cwd switching.
- `main.py run` dispara ferramentas reais de recon/fuzz contra o lab local e pede confirmação humana [y/n/edit/skip] — só execute sob pedido do usuário.

## Arquitetura (fluxo real)

`main.py` → `agent/loop.py::run_investigation` → LLM via Ollama (`agent/ollama_client.py`, prompt rígido + `format: "json"`, `think: false`, `keep_alive: 30m` + parse pydantic com 1 retry) → proposta `ActionProposal` (`agent_schemas.py`) → `routing/wordlist.py` escolhe wordlist por evidência (gobuster/wfuzz, antes do painel de aprovação) → humano decide [y/n/edit/skip] → guardrails (`guardrails.py`, allowlist de hosts: localhost/127.0.0.1/juice-shop; valida params) → tool (`tools/`) → resultado volta pro LLM → interpretação + veredito humano → evidência.

- `tools/` sempre via `subprocess` com lista de args (nunca `shell=True`), output truncado em ~4–8 k chars.
- `evidence_store.py`: JSONL append-only (`runs/<id>/events.jsonl`) + SQLite (`runs/<id>/evidence.db`). `reporter.py` gera `summary.md`/`evidences.html`.
- `routing/wordlist.py`: roteador programático de wordlists por evidências acumuladas (regex sobre `history`; ex. wordpress → `CMS/wordpress.fuzz.txt`). A escolha aparece em painel `wordlist` no terminal e fica no histórico como entrada `tool: "routing"`; o LLM **não** recebe catálogo e **não** informa wordlist (LLM-provided wordlist é ignorada; se o humano editar params, a wordlist roteada é preservada).
- Evidência por turno é gravada **antes** de qualquer decisão humana: `runs/<id>/llm_io.jsonl` (I/O bruto com o modelo — prompt completo + resposta crua, fases `propose`/`propose_retry`/`interpret`; a interpretação também grava `interpretation` limpa de think) e `history.json` a cada turno. Quer Ctrl-C no meio → tudo permanece auditável.
- **Guardas de progressão** (código): `executed_key` (nmap com alvo normalizado, wordlist ignorada) detecta proposta idêntica a já executada → não roda, LLM re-perguntado até 2x via `extra_note` (`propose_action(..., extra_note=...)`); se insistir, cai no humano. `tool="conclude"` encerra o laço (grava evidência `tool: conclude`; humano confirma ou manda continuar).
- **Veredito vira direção**: após confirmed/refuted/inconclusive há um prompt opcional "Instrucoes para o proximo passo (Enter = nenhuma)"; a instrução grava-se em `human_validation.instruction` e é destacada no próximo prompt (`Instrucao do humano para o proximo passo: ...`).
- **PROXIMO_PASSO**: a interpretação é obrigada a terminar com `PROXIMO_PASSO: <...>`; `extract_next_step`/`expected_tool_from_text` (agent/ollama_client.py) detectam a tool citada e o loop avisa (não bloqueia) em painel "Divergencia" se a proposta seguinte usar outra tool. A intenção declarada também é destacada no prompt de proposta (`Sua intencao declarada no passo anterior:`) — **exceto quando há `human_instruction` recente**, caso em que é suprimida em favor da instrução (ver bullet do digest abaixo).
- **Fato do código** (`findings_note`, gobuster/wfuzz): a interpretação/o histórico recebem o número de achados da saída (ex.: "nenhum achado listado na saida") — zero achado NÃO pode virar "encontrou /admin" (alucinação observada em `recon-enumeracao-3`). Se a tool sai com `exit != 0`, o fato vira "a ferramenta FALHOU (exit N): saida vazia/parcial nao eh evidencia de ausencia de achados" — saida vazia com exit 1 NÃO significa "sem achados" (visto em `recon-enumeracao-9`: gobuster morreu no wildcard do SPA).
- **Tripwire de referências** (`extract_refs`/`find_missing_refs`, agent/ollama_client.py): cada `/...` citado na interpretação (URLs fora, segmentos de 2+ chars, denylist /tcp) é exigido na saída/stderr/comando da tool; faltantes viram painel vermelho "Verificacao de referencias" e caem em `human_validation.refs_missing` na evidência.
- **Routing web servers**: Apache/nginx sem evidência de app/CMS → `Discovery/Web-Content/raft-small-directories.txt` (medindo: 358 linhas api/admin vs 10 no Apache.txt — listas Web-Servers rendem ~0 em SPA).
- System prompt tem **usage cards** curados por tool (não `-h` bruto — nmap -h sozinho ≈ 1500 tokens); propose segue `format: "json"`, interpret usa `format_json=False` + `strip_think` (Qwen3 vaza `<think>` mesmo com `think: false`) + **prefill** `{"role": "assistant", "content": "Resposta:"}` (sem ele o 4B entra em rambling "Wait, but..." até estourar `num_predict`) + **stop** `\nuser`/`\nUser`/`\nUSER` (sem ele o modelo fabrica um fake turno de usuário após a resposta — observado no lab) + **`truncate_at_next_step`** (agent/ollama_client.py): corta tudo depois da primeira linha `PROXIMO_PASSO:` — elimina o raciocínio "we are given..." que o 4B emite **depois** da resposta mesmo com prefill (observado em `recon-enumeracao-4`; o stop `\nuser` não cobre esse caso). `raw_response` em `llm_io.jsonl` segue íntegro (auditoria); `interpretation`/histórico/tripwire usam a versão truncada.
- O LLM tende a emitir chaves erradas (`host` em vez de `target` no nmap, wordlists "de cabeça"). O loop ignora wordlist do LLM; `nmap_tool` aceita `host` como alias de `target` e **descarta esquema/caminho/porta do alvo** (nmap nunca aceita `host:porta` — a porta vai no `-p`). Manter esse padrão — não confiar em nomes exatos dos params vindos de um 4B.
- Refatoração em **funções puras** (`build_*_command`, `inject_wordlist`, `build_evidence_item`, `parse_action`, `build_payload`, `render_markdown`, `build_summary_table`) — I/O (subprocess/http/SQLite/Rich) fica numa casca fina; lógica testável fica pura. Manter essa separação ao adicionar código.

## Armadilhas / estado atual

- Correções aplicadas (eram a causa do timeout): `think: false`, `keep_alive: 30m`, `num_ctx 4096`, `timeout_sec 300`, `repeat_penalty: 1.1`, `num_predict` limitado, pre-warm no `check`. Carga inicial ~7 s; quente, pre-warm ~0.4 s e proposta do LLM ~7 s. Não reintroduzir o catálogo no prompt — a seleção de wordlist é por evidência no código.
- Prompt de proposta com **digest compacto do histórico** (`build_history_digest`, `agent/ollama_client.py`, 2026-11-17): substitui o `json.dumps(history[-5:])[:2000]`, que cortava o JSON no meio e escondia a entrada mais recente do modelo (observado em `recon-enumeracao-7`: o modelo nunca viu o resultado do http_request nem a instrução humana de dentro dele). Uma linha por entrada (`- tool params=... -> resumo | interp: ...`), blobs `SF:` do fingerprint nmap removidos, orçamento estourado descarta as entradas mais antigas (nunca a última). Se há `human_instruction` recente, a linha "Sua intencao declarada" é suprimida e a instrução vai como `OBRIGATORIA, tem prioridade`, junto de `PROIBIDO repetir a acao anterior: <tool> <params>` — antes o código ecoava `http_request ...` logo abaixo da instrução do humano (e o check de "Divergencia" nem disparava, pois a intenção declarada batia com a proposta).
- **Gobuster vs SPA do Juice Shop** (observado em `recon-enumeracao-9`): o Juice Shop responde **200 (Length 9984)** para qualquer URL inexistente; o wildcard check do gobuster abortava com `exit 1` antes de fuzzar, e o agente via só o banner — `stderr` era descartado do `summary` (`(out or err)`) e não ia para a evidência → interpretação "inconclusiva" + próximo passo alucinado (`gobuster :3010`). Correções: `--no-error` removido das `FLAGS`; `run_cmd` inclui `[stderr]` no `summary`; evidência persiste `stderr` e `duration_ms` (dentro de `result`, JSONL + SQLite, **sem mudança de schema**); em `exit != 0` com `Length: N` no stderr, `run_gobuster` repete uma vez com `--exclude-length N` (nota `[wildcard detectado...]` no summary; comando final auditável na evidência). Caveat: assume corpo de fallback fixo; SPA com tamanho variável exigiria outra estratégia.
- `nmap` roda em **duas fases** por padrão: sweep `-p- --open -Pn <alvo>` (rápido — achou 10 portas abertas em ~1,4 s neste kit, incluindo 3000 do Juice Shop e 11434 do Ollama) e `-sV -p <abertas>` (version detection **sem scripts NSE** — ainda leva ~110 s aqui, dominado pelos probes nas portas desconhecidas; `--version-light` acelera se aprovado). Default do `run_nmap`: `timeout=300`. Nenhuma porta aberta → fase 2 não roda. O modelo **pode** pedir scan específico: `extra_args` (aliases `args`/`flags`/`options`/`command`) troca as duas fases por single-shot; o código descarta `nmap` inicial e token final igual ao alvo; guardrail bloqueia `-oX`/`-oA`/`--script=`/`-iL` (NSE fora). `executed_key` inclui args normalizados — mesmo alvo com `extra_args` diferente NÃO é estagnação. Re-pergunta de estagnação ensina `extra_args` com exemplo.
- Qwen3 em CPU com `stream=false` + `format:"json"` pode devolver HTTP 500 `prediction aborted, token repeat limit reached` (geração sem fim). Toda chamada Ollama do agente usa `repeat_penalty: 1.1` + `num_predict`; manter esses limites em novos clients.
- `history.json` é gravado no mesmo `runs_dir` passado ao `EvidenceStore` (`run_investigation(..., runs_dir=...)`); não depende mais do cwd. Testes devem passar `runs_dir` sob `tmp_path` — nunca vão criar `runs/inv-*` no repo.
- `routing/wordlist.py`: wordlist roteada é injetada **antes** do painel de aprovação (humano vê a decisão) e preservada em edição humana. Fallbacks validados contra os arquivos existentes no clone do SecLists.
- `README.md` foi atualizado para o roteamento programático; os imports seguem planos, então qualquer novo módulo importado tem que funcionar com cwd = raiz.
- `.exemplo.yaml.swp` é artefato do editor do usuário — não deletar.
- `.venv/` está vazio/quebrado — ignorar; usar `python3` direto. `runs/recon-enumeracao/` contém saída de uma execução anterior.
- Não é repositório git: sem histórico, sem `.gitignore`, sem CI. `wordlists/SecLists`, `__pycache__/`, `.venv/`, `runs/` são artefatos locais (o SecLists pesa muito — não copiar para commits).

## Convenções

- Código e comentários em PT-BR **sem acentos** (ex.: "investigacao", "nao", "Voce") — manter esse estilo em código e mensagens.
- `runs/` e outputs de ferramentas são gerados de execução real, podem conter evidências brutas — não reescrever manualmente.
- Tarefas de curso/projeto acadêmico: `AF - Tecnologias Hackers 26-2.pdf` (enunciado da AF) está na raiz; o código precisa demonstrar loop supervisionado com aprovação humana e evidência reconstrutível.

## Regras gerais de desenvolvimento

- Você não pode escrever nenhum código até que tenha escrito um teste de unidade que falhe.
- Você não pode escrever mais de um teste de unidade do que o necessário para falhar (e não compilar é falhar).
- Você não pode escrever mais código do que o suficiente para fazer o teste de unidade que falhou passar.
- Sempre que achar um bug faça um teste que reproduz o bug e que só passa quando o bug não acontecer.
