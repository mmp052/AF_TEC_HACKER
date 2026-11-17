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
├── owasp_report.py       # relatorio OWASP (WSTG + Top 10) gerado no fim, com confirmacao humana
├── agent/
│   ├── ollama_client.py  # prompt rigido, JSON estrito, retry 1x
│   ├── phases.py         # fases OWASP (WSTG) + registro de flags — puro, testavel
│   └── loop.py           # loop: LLM propoe -> humano [s/n/pular/editar] -> executa -> LLM interpreta
├── tools/
│   ├── nmap_tool.py      # nmap ou Docker fallback
│   ├── http_tool.py      # httpx (curl-like)
│   ├── gobuster_tool.py  # gobuster (ou Docker fallback) — retry com --exclude-length em wildcard SPA
│   ├── wapiti_tool.py    # wapiti: scan de vulnerabilidades web (via pip; LLM escolhe os módulos)
│   ├── nikto_tool.py     # nikto: scan de servidor/cabecalhos/arquivos default (sudo apt install nikto)
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

`python3 main.py` (sem argumentos, em terminal interativo) inicia o modo de **parceria**: `check` do lab, intake conversacional (situacao, suspeita, endpoints conhecidos, evidencias) e o loop — o agente propoe a fase inicial (ou voce escolhe) e a investigacao anda com voce confirmando cada passo. Em pipe/sem TTY, cai no help com subcomandos.

`python3 main.py run --file exemplo.yaml` aceita tambem campos opcionais para pular o recon:

```yaml
conhecimento:
  endpoints: ["/rest/user?q="]
  suspeita: "sqli no parametro q"
# fase_inicial: 3   # opcional; padrao: pular recon se houver endpoints/suspeita
```

O loop supervisionado:
1. LLM propoe `ActionProposal` (tool + params + hipotese + rationale + **por que** esses parametros, alem de **fase sugerida** e **flags** declaradas — saneadas pelo codigo contra um registro fixo; voce aprova/edita no painel).
2. Rich mostra `Panel` com a proposta: **fase atual**, comando exato que vai rodar, flags propostas e acumuladas.
3. Humano: `[s] aprovar, [n] negar e recusar o passo (encerra a investigacao), [pular] pula este passo, [editar] digita o comando que quer rodar — sem JSON`.
   - No `editar`, o `cmd>` exibe o comando atual; o comando digitado eh parseado de volta para `(tool, params)` e **sempre revalidado pelos mesmos guardrails** (hosts permitidos, allowlist de params/flags/tuning/modulos, wordlist confinada ao `wordlists/SecLists/`). Simples: `nmap -sV -p 3000 localhost` no lugar do comando proposto.
   - Comando que o parser nao entende ou que viola um guarda → `Erro: ...` e volta ao menu (nada executa sem passar pelos guardrails). A confirmacao `[s/n]` mostra o parametro entendido antes de rodar.
4. `guardrails` valida host/params; ferramenta executa (`subprocess` lista, nunca `shell=True`).
5. Resultado volta pro LLM → interpretação obrigatoriamente terminada em `PROXIMO_PASSO: <proximo passo>` → humano dá veredito (`confirmado`/`refutado`/`inconclusivo`, ver regra abaixo) **e, opcionalmente, instruções livres** para o próximo passo (Enter = nenhuma).
6. Tudo vira `EvidenceItem` em `runs/<id>/events.jsonl` + SQLite; `history.json` é gravado a cada turno.

**Fases OWASP (WSTG):** o agente sabe em que fase esta e quais ferramentas aquela fase recomenda. Entrada pelo intake (ou por `conhecimento:` no YAML) pode pular o recon direto para a fase de validacao.

| Fase | WSTG | Ferramentas recomendadas |
|---|---|---|
| 0 — Parceria/intake | — | (o humano descreve; o agente propoe a fase inicial) |
| 1 — Reconhecimento | WSTG-INFO | `nmap`, `http_request` |
| 2 — Enumeracao/Config | WSTG-CONF-05 + INFO | `gobuster`, `wfuzz`, `nikto` |
| 3 — Validacao de vulnerabilidades | WSTG-INPVAL | `wapiti`, `wfuzz`, `nikto` |
| 4 — Encerramento/Relatorio | — | `conclude` + `owasp_report.md` |

Transicao entre fases: o agente propoe no `ActionProposal` (`fase_sugerida`) — so muda com o seu sim no painel. Ferramenta fora da fase vira aviso amarelo (voce decide), nunca trava. Flags (`http_confirmado`, `rotas_encontradas`, `sqli_suspeita`, `vuln_confirmada`, ...) acumulam ao longo da investigacao, sao saneadas contra um registro fixo e ficam gravadas no `history.json`.

**Regra do veredito** (tambem exibida no painel antes da pergunta):
- **confirmado** — voce leu a saida bruta e a evidencia verifica a hipotese (ex.: `/admin (Status: 200)` listado). Só isso vira achado no relatorio OWASP.
- **refutado** — a saida contradiz a hipotese com evidencia positiva (todos os payloads sem efeito; scan limpo). **Ausencia de achados nao refuta.**
- **inconclusivo** — faltou evidencia para os dois lados (tool falhou, saida parcial, sem conviccao). **Na duvida, sempre inconclusivo.**
- `rejeitado` (proposta negada) continua um caso a parte.

**Guardas de progressão (código, não LLM):**
- **Estagnação bloqueada**: se o LLM propor a mesma tool+params já executada (nmap com alvo normalizado; wordlist do routing ignorada na comparação), a ação **não executa** — o painel avisa e o LLM é re-perguntado (até 2x) com a instrução explícita; se insistir, a decisão fica com você.
- **Divergência intenção × proposta**: após cada interpretação, a tool citada em `PROXIMO_PASSO:` é comparada com a proposta seguinte; se divergir, painel amarelo "Divergencia" (apenas avisa; você decide).
- **`tool=conclude`**: quando o LLM julga a evidência suficiente, declara conclusão em vez de propor outra ação; o humano confirma (ou manda continuar) e o laço encerra.
- O system prompt traz **usage cards** curados de cada tool (não o `-h` bruto) e destaca a instrução do humano e a intenção declarada no turno anterior.

## Ferramentas

- **nmap** — duas fases (uma única aprovação humana): 1) sweep `-p- --open -Pn` (todas as portas, rápido — achou o Juice Shop e o Ollama em ~1,4 s neste kit); 2) `-sV -p <portas abertas>` (versão/service detection **sem scripts** — os scripts NSE (`-sC`) foram removidos por simplicidade; a fase 2 ainda leva ~110 s neste kit, dominada pelos probes contra as portas desconhecidas `34133`/`49374`; use `--version-light` aprovado no extra_args para acelerar). Se nada aberto aparecer no sweep, a fase 2 não roda. O LLM **pode pedir um scan específico**: `extra_args` (aliases aceitos: `args`/`flags`/`options`/`command`) substituem as duas fases por um único comando (ex.: `{"target": "localhost", "extra_args": "-sV -p 3000"}`); `nmap` inicial e token final igual ao alvo são descartados. Flags de escrita/script (`-oX`, `-oA`, `--script=`, `-iL`) são bloqueadas pelo guardrail; NSE segue fora. Default `timeout` da tool: 300 s.
- **http_request** — `httpx`, com headers/body. Usado p/ Juice Shop direto.
- **gobuster** — `gobuster dir` com wordlist escolhida pelo routing (por evidência). Em SPA que devolve `200` para toda rota inexistente (Juice Shop responde `Length: 9984`), um `exit 1` com `Length: N` no stderr dispara um retry automático com `--exclude-length N`.
- **wfuzz** — `wfuzz -c -z file,<wordlist> -u <url com FUZZ>` com wordlist escolhida pelo routing.
- **wapiti** — scan de **vulnerabilidades** web (sqli, xss, file, ssrf, ...). O LLM escolhe o alvo e **quais módulos** usar (`"modules": ["sql", "xss"]`; sem o param, roda os defaults). Params opcionais validados por allowlist no código (`scope url|page|folder`, `level` 1-4, `depth`, `max_scan_time` padrão 300 s, `max_parameters`, `tasks`, `timeout`, `data`): flag ou param fora da allowlist → `ValueError` e o humano vê o erro no painel. O relatório (`-f txt`) é lido e anexado ao `stdout`/`summary` da evidência; `--max-scan-time` limita a duração.

- **nikto** — scan de **servidor/cabecalhos/arquivos default** (nao de rotas nem de logica de app; complementa o wapiti). Params: `"tuning"` opcional (combinacao de `1-9,0,a-e,x`; ex.: `"9"` so SQLi, `"4"` so XSS, `"x9"` tudo exceto SQLi — ver `nikto -Help`), `"maxtime"` em segundos (padrao 300, faixa 30-900) e `"timeout"` por requisicao (1-30). Params fora da allowlist → `ValueError` no painel. O relatorio (`-Format txt`) e lido e anexado ao `stdout`/`summary` da evidencia; o comando roda com `-nointeractive -nolookup -ask no` (o nikto do Ubuntu/fork Debian 2.1.5 nao tem `-nocheck` — ele imprime "Unknown option" e sai sem escanear; `-ask no` eh o equivalente).

Se `nmap/gobuster/wfuzz` não estiverem no `PATH`, o agente usa **fallback Docker** (`instrumentisto/nmap`, `mdiqib/gobuster`, `huntertier/wfuzz`) — sem `sudo`. O `wapiti` foi instalado via `pip` (user-site): `python3 -m pip install --break-system-packages wapiti3`. O `nikto` esta no Ubuntu como pacote `nikto` (`sudo apt install nikto`), sem fallback Docker.

## Verificacoes no loop

- **EstagnACAO bloqueada**: proposta identica a ja executada nao roda; o LLM e re-perguntado ate 2x (se insistir, a decisao cai pro humano).
- **Divergencia intencao x proposta**: se a tool citada em `PROXIMO_PASSO:` difere da proposta, painel amarelo avisa (nao bloqueia).
- **`tool=conclude`**: o agente declara conclusao; o humano confirma e o laco encerra.
- **Fato do codigo** (gobuster/wfuzz): a interpretacao recebe explicitamente quantos achados a tool reportou (ex.: "nenhum achado listado na saida") — zero-achado nao pode virar "encontrou /admin".
- **Tripwire de referencias** (`Verificacao de referencias`): a interpretacao nao pode citar caminhos que nao constem na saida/stderr/comando da tool (URLs sao ignoradas); qualquer referencia ausente gera painel vermelho e fica registrada em `human_validation.refs_missing` na evidencia.
- **Interpretacao truncada em `PROXIMO_PASSO:`**: tudo que o modelo emite depois da linha `PROXIMO_PASSO:` (re-raciocinio "we are given...", segunda resposta, fake turno) e descartado no codigo (`truncate_at_next_step`) — o painel, a evidencia e o tripwire veem so a conclusao; `llm_io.jsonl` preserva a resposta bruta integra para auditoria.
- **Relatorio OWASP no fim**: ao encerrar a investigacao o humano e perguntado `Gerar relatorio OWASP das descobertas? [s/n]` se quer gerar `owasp_report.md` em `runs/<id>/`. O relatorio (OWASP WSTG como metodologia; OWASP Top 10 2021 por achado; CWE e severidade **indicativos**; so entra como achado aquilo que o humano marcou `confirmado`; refs faltantes aparecem destacadas; trilha completa com todos os vereditos) eh gerado a partir de `evidence.db`/`events.jsonl` — nada eh inventado pelo modelo. Leitura normaliza vereditos legados (`confirmed`→`confirmado`); evidencia antiga nao eh reescrita.

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

Cada turno vira `EvidenceItem` com: `proposed_action`, `human_decision` (approved/modified/rejected/skipped), `tool`, `command`, `result`, `llm_interpretation`, `human_validation` (confirmado/refutado/inconclusivo/rejeitado/pulado; legados EN normalizados na leitura), `fase` (no events.jsonl) e `fase`/`flags` no history.json. O `summary.md` gerado responde às 6 perguntas do PDF por investigação.

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
