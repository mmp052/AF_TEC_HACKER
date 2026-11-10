# agente_hacker — AF Tecnologias Hackers

Agente supervisionado (terminal, Python + Rich) que integra **LLM local (Ollama/qwen3:4b)** a ferramentas de seguranca contra o **OWASP Juice Shop local**.

## Arquitetura

```
agente_hacker/
├── main.py               # CLI: check | run --file hypothesis.yaml | report
├── config.yaml           # alvo, modelo, limites
├── guardrails.py         # allowlist de hosts + validacao de params
├── agent_schemas.py      # pydantic: ActionProposal, HumanDecision, ToolResult
├── evidence_store.py     # JSONL append-only + SQLite
├── reporter.py           # summary.md + HTML (Rich)
├── agent/
│   ├── ollama_client.py  # prompt rigido, JSON estrito, retry 1x
│   └── loop.py           # loop: LLM propoe -> humano [y/n/edit] -> executa -> LLM interpreta
├── tools/
│   ├── nmap_tool.py      # nmap ou Docker fallback
│   ├── http_tool.py      # httpx (curl-like)
│   ├── gobuster_tool.py  # gobuster ou Docker fallback
│   └── wfuzz_tool.py     # wfuzz ou Docker fallback
├── lab/
│   ├── docker-compose.yml
│   └── reset.sh
├── scripts/
│   └── setup.sh
├── tests/                # pytest; tmp_path/monkeypatch/fixture local em `server`
└── runs/<investigation_id>/
    ├── events.jsonl
    ├── evidence.db
    ├── summary.md
    └── evidences.html
```

## Setup (kit de lab)

```bash
bash scripts/setup.sh
python3 main.py check
```

O setup sobe o Juice Shop, clona o **SecLists** (`wordlists/SecLists`) e baixa `qwen3:4b` (se ainda não tiver).

> Máquina alvo: 14 GiB RAM, 20 cores, Intel UHD 770 → `qwen3:4b` (Q4_K_M, ~2,5 GB) roda confortável em CPU.

## Uso

```bash
python3 main.py run --file exemplo.yaml
python3 main.py report --investigation recon-enumeracao
```

O loop supervisionado:
1. LLM propoe `ActionProposal` (tool + params + hipotese + rationale + **por que** esses parametros).
2. Rich mostra `Panel` com a proposta.
3. Humano: `[y] aprovar, [n] rejeitar, [edit] editar params JSON, [skip] rejeitar e parar]`.
4. `guardrails` valida host/params; ferramenta executa (`subprocess` lista, nunca `shell=True`).
5. Resultado volta pro LLM → interpretação obrigatoriamente terminada em `PROXIMO_PASSO: <proximo passo>` → humano dá veredito (`confirmed/refuted/inconclusive`) **e, opcionalmente, instruções livres** para o próximo passo (Enter = nenhuma).
6. Tudo vira `EvidenceItem` em `runs/<id>/events.jsonl` + SQLite; `history.json` é gravado a cada turno.

**Guardas de progressão (código, não LLM):**
- **Estagnação bloqueada**: se o LLM propor a mesma tool+params já executada (nmap com alvo normalizado; wordlist do routing ignorada na comparação), a ação **não executa** — o painel avisa e o LLM é re-perguntado (até 2x) com a instrução explícita; se insistir, a decisão fica com você.
- **Divergência intenção × proposta**: após cada interpretação, a tool citada em `PROXIMO_PASSO:` é comparada com a proposta seguinte; se divergir, painel amarelo "Divergencia" (apenas avisa; você decide).
- **`tool=conclude`**: quando o LLM julga a evidência suficiente, declara conclusão em vez de propor outra ação; o humano confirma (ou manda continuar) e o laço encerra.
- O system prompt traz **usage cards** curados de cada tool (não o `-h` bruto) e destaca a instrução do humano e a intenção declarada no turno anterior.

## Ferramentas

- **nmap** — duas fases (uma única aprovação humana): 1) sweep `-p- --open -Pn` (todas as portas, rápido — achou o Juice Shop e o Ollama em ~1,4 s neste kit); 2) `-sV -p <portas abertas>` (versão/service detection **sem scripts** — os scripts NSE (`-sC`) foram removidos por simplicidade; a fase 2 ainda leva ~110 s neste kit, dominada pelos probes contra as portas desconhecidas `34133`/`49374`; use `--version-light` aprovado no extra_args para acelerar). Se nada aberto aparecer no sweep, a fase 2 não roda. Override single-shot: o LLM pode aprovar `extra_args` próprios (ex.: `--top-ports 100`). Default `timeout` da tool: 300 s.
- **http_request** — `httpx`, com headers/body. Usado p/ Juice Shop direto.
- **gobuster** — `gobuster dir` com wordlist escolhida pelo routing (por evidência).
- **wfuzz** — `wfuzz -c -z file,<wordlist> -u <url com FUZZ>` com wordlist escolhida pelo routing.

Se `nmap/gobuster/wfuzz` não estiverem no `PATH`, o agente usa **fallback Docker** (`instrumentisto/nmap`, `mdiqib/gobuster`, `huntertier/wfuzz`) — sem `sudo`.

## Verificacoes no loop

- **EstagnACAO bloqueada**: proposta identica a ja executada nao roda; o LLM e re-perguntado ate 2x (se insistir, a decisao cai pro humano).
- **Divergencia intencao x proposta**: se a tool citada em `PROXIMO_PASSO:` difere da proposta, painel amarelo avisa (nao bloqueia).
- **`tool=conclude`**: o agente declara conclusao; o humano confirma e o laco encerra.
- **Fato do codigo** (gobuster/wfuzz): a interpretacao recebe explicitamente quantos achados a tool reportou (ex.: "nenhum achado listado na saida") — zero-achado nao pode virar "encontrou /admin".
- **Tripwire de referencias** (`Verificacao de referencias`): a interpretacao nao pode citar caminhos que nao constem na saida/stderr/comando da tool (URLs sao ignoradas); qualquer referencia ausente gera painel vermelho e fica registrada em `human_validation.refs_missing` na evidencia.

## Wordlists — escolhidas por codigo a partir da evidencia

O LLM **nao** recebe catalogo e **nao** informa wordlist. Ele decide apenas ferramenta + url; `routing/wordlist.py` escolhe a wordlist com base nas evidencias acumuladas em `history`:

- **Tecnologia especifica detectada** (wordpress, joomla, drupal, magento, django, php, express/SPA, graphql, swagger/openapi) → wordlist CMS/server correspondente (gobuster enumerate). **Apache/nginx sem evidencia de app/CMS** → `raft-small-directories.txt` (lista genérica de app; medir 358 linhas api/admin vs 10 no Apache.txt — listas de servidor rendem ~0 numa SPA).
- **Tipo de falha detectada** (erro SQL, NoSQL, reflexao XSS, SSTI, path traversal/LFI, blind/time-based) → payload correspondente (wfuzz).
- **Sem evidencia** → `Discovery/Web-Content/common.txt` (gobuster) / `Fuzzing/Databases/SQLi/quick-SQLi.txt` (wfuzz).

A escolha aparece em um `Panel("wordlist ...")` no terminal e e registrada no historico (`routing`) para auditoria.

## Modelos

- **Base:** `qwen3:4b` (Q4_K_M)
- **Comparativo:** `llama3.1:8b` — troque com `--model llama3.1:8b` (não rode os dois ao mesmo tempo em 14 GiB).

Config (`config.yaml`): temperatura `0.2`, `num_ctx: 4096`, `timeout_sec: 300`, `keep_alive: "30m"`, `format=json`, `think: false` (desliga raciocínio do Qwen3 — em CPU, o thinking longo era a causa do timeout), parse com `pydantic` + retry de 1x (limitação assumida — modelos 4B-8B não fazem tool-calling nativo confiável). `main.py check` faz um pre-warm (`/api/chat` mínimo) para carregar o modelo com o contexto certo antes da investigação — a primeira chamada fica rápida, não 120 s de carga.

## Evidências

Cada turno vira `EvidenceItem` com: `proposed_action`, `human_decision` (approved/modified/rejected), `tool`, `command`, `result`, `llm_interpretation`, `human_validation` (confirmed/refuted/inconclusive). O `summary.md` gerado responde às 6 perguntas do PDF por investigação.

Adicionalmente, `runs/<id>/llm_io.jsonl` registra **por turno, imediatamente**, o I/O bruto com o LLM (`stage`: `propose` | `propose_retry` | `interpret`) — prompt completo e resposta crua — e `history.json` é gravado a cada turno. Ou seja: mesmo que o programa morra no meio (Ctrl-C), ficam registros de tudo o que entrou e saiu do modelo.

## Testes

```bash
python3 -m pytest -q
```

93 testes unitários em `tests/` (pytest). Nenhum teste bate na rede externa nem altera o laboratório: são usados mocks (`unittest.mock`), `tmp_path`/`monkeypatch.chdir` para quem escreve em disco e um `HTTPServer` local na fixture `server` (`tests/test_tools_http.py`). O código foi refatorado para funções puras (`build_*_command`, `inject_wordlist`, `parse_action`, `render_markdown`...) — I/O é uma casca fina ao redor delas.

## Restauracao

```bash
bash lab/reset.sh
```

`docker compose down -v && up -d` + healthcheck em `http://localhost:3000` — estado conhecido antes de cada investigação.
