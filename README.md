# Northwind Retail — Secure RAG Application (security lab)

A deliberately dual-mode RAG assistant over fictional company documents, built to demonstrate
and then close the trust-boundary failures specific to retrieval-augmented generation.

Every component runs in one of two postures, switched by `SECURITY_MODE`:

| Mode | Retrieval filter | Prompt separation | Output validation |
|---|---|---|---|
| `vulnerable` | none | none | none |
| `secure` | role/classification scoped | structural | on |

That switch is what makes the before/after evidence credible: the same corpus, the same
model, the same query — one control changed at a time.

> All companies, people, policies and figures in `corpus/` are fictional.

---

## Architecture & trust boundaries

```mermaid
flowchart TB
    subgraph Untrusted["Untrusted zone"]
        Emp([Employee User])
        HR([HR User])
        Docs[/Ingested Documents
        incl. possibly poisoned/]
    end
    subgraph App["RAG Application"]
        Auth[AuthN/AuthZ
        role check]
        Query[Query Handler]
        Retriever[Retriever]
        PromptBuilder[Prompt Builder
        separates instructions
        from retrieved data]
        Ingest[Ingestion Pipeline]
        Embed[Embedding Step]
    end
    subgraph Data["Data Stores"]
        VDB[(Vector DB - Chroma)]
    end
    Model[(LLM via OpenRouter)]
    Emp -->|query| Auth
    HR -->|query| Auth
    Auth -->|authorized query| Query
    Query --> Retriever
    Retriever -->|role-filtered search| VDB
    VDB -->|top-k chunks| Retriever
    Retriever --> PromptBuilder
    PromptBuilder -->|prompt + labeled context| Model
    Model -->|response| Query
    Query -->|response, output-validated| Emp
    Query -->|response, output-validated| HR
    Docs -->|ingest| Ingest
    Ingest --> Embed
    Embed -->|vectors| VDB
```

| # | Boundary | Where in code | Failure mode tested |
|---|---|---|---|
| 1 | user → app | `app/config.py` roles, `app/rag.py` | role spoofing, privilege confusion |
| 2 | document → ingestion | `app/ingest.py` | data poisoning, unlabelled untrusted content |
| 3 | retriever → vector DB | `app/retriever.py` | cross-tenant leakage |
| 4 | model output → user | `app/guard.py` | context exfiltration, restricted data in the answer |

---

## Roles

| Role | Entitled classifications | Documents |
|---|---|---|
| `employee` | `internal` | 5 general policy documents |
| `hr` | `internal`, `hr-confidential` | all 10, including comp bands, PIPs, ER cases |

---

## Build phases

- [x] **Phase 1 — Foundations.** Repo, corpus with classification labels, ingestion pipeline,
      embedding step, Chroma store, role model, and a raw retrieval CLI. Ends with
      cross-tenant leakage demonstrated *at the retrieval layer, before any LLM is involved*.
- [x] **Phase 2 — Generation, mitigations and attack surface.** OpenRouter client (+ offline
      stub), prompt builder (naive concatenation vs. structural separation), output guard,
      the query handler wiring all four trust boundaries together. Poisoned corpus (4
      documents: indirect injection, context exfiltration, pure data poisoning, embedding-space
      pollution). Attack scripts for all five catalogue items, each run against both
      `vulnerable` and `secure` mode in one pass, with every prompt/response captured to
      `evidence/*.json`. Built the mitigations alongside the attacks (both modes share one
      mode-switched codebase) rather than bolting them on afterward, since `security_mode`
      already gated retrieval in Phase 1 - the query handler follows the same pattern.
- [ ] **Phase 3 — Retest & harden.** Run the full attack suite against real OpenRouter output,
      not just the offline stub (see "Getting real evidence" below); tune the prompt/guard
      against whatever the real model actually does; note where a mitigation only reduces
      risk rather than closing it (data poisoning and embedding weaknesses, see below, are
      expected to land here).
- [ ] **Phase 4 — Deliverables.** Findings mapped to LLM01 / LLM02 / LLM08 and MITRE ATLAS,
      full report, one-page executive summary, demo script.

---

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env      # then put your OpenRouter key in .env
```

`EMBEDDING_BACKEND` in `.env`:

- `minilm` — real semantic embeddings (all-MiniLM-L6-v2, ~80MB downloaded once). Use this.
- `hashed` — offline deterministic bag-of-words. No network needed. Plumbing only; retrieval
  is lexical, so do not draw conclusions about embedding-space behaviour from it.

## Usage (Phase 1)

```bash
python -m app.cli roles                  # show the two roles and their entitlements
python -m app.cli ingest                 # build the vector store from corpus/clean
python -m app.cli stats                  # what actually landed in Chroma

# raw retrieval, no LLM in the loop
python -m app.cli search "compensation bands merit budget" --role employee --mode vulnerable
python -m app.cli search "compensation bands merit budget" --role employee --mode secure
python -m app.cli search "compensation bands merit budget" --role hr       --mode secure
```

`search` exits `2` when a role receives a document it is not entitled to, so it can be
driven from a test harness in Phase 4.

### Phase 1 finding (retrieval layer)

```
employee / vulnerable  ->  LEAK: HR-COMP-2026, HR-ER-0091 returned to a general employee
employee / secure      ->  clean: 4/4 chunks classified 'internal'
hr       / secure      ->  clean: hr-confidential returned as entitled
```

The vulnerable path knows the caller's role and never uses it. Nothing has been said to a
model yet — the confidential text is already on its way to the prompt.

---

## Usage (Phase 2)

```bash
# one-off manual query through the full pipeline: retrieve -> prompt -> LLM -> guard
python -m app.cli ask "How long until my account unlocks after failed logins?" \
  --role employee --mode vulnerable

# the whole attack catalogue in one pass (ingests WITH poisoned docs first)
python -m attacks.run_all
```

`run_all` re-ingests the collection with `corpus/poisoned/` included, then runs all five
attacks — each one calls the real pipeline as `vulnerable` and then as `secure` and prints a
PASS/FAIL verdict per case. Every prompt actually sent to the model and every raw response is
saved to `evidence/<attack>__<case>__<mode>.json`, so a result can be checked later without
re-running anything (worth doing — LLM output isn't deterministic).

### Getting real evidence

The pipeline ships with an offline `stub` LLM (`LLM_BACKEND=stub` in `.env`) purely so the
plumbing can be tested without a key or network — see the warning in `app/llm.py`. It is a
crude pattern-matcher, not a reasoning model, and **its output does not belong in the report**.
Before you run `attacks.run_all` for real:

```
LLM_BACKEND=openrouter
EMBEDDING_BACKEND=minilm
```

in `.env`, with a real `OPENROUTER_API_KEY` set. `run_all` prints a loud warning if it detects
`LLM_BACKEND=stub` so you can't accidentally ship stub output as findings.

### What each attack is checking

| # | Attack | OWASP | What it does | Expected shape of the result |
|---|---|---|---|---|
| 1 | Indirect Prompt Injection | LLM01 | An HTML-comment "SYSTEM NOTE" hidden in `POI-IT-101` (IT FAQ) tells the model to drop role restrictions and prove it by emitting a canary token | vulnerable: canary may fire in the raw answer; secure: the structural prompt and/or the guard should stop it reaching the user |
| 2 | Cross-Tenant Leakage | LLM02 | A direct and a paraphrased query try to pull `hr-confidential` content into an `employee`-role answer | vulnerable: real risk of leakage, worse with the paraphrased query; secure: retrieval filter should make this structurally impossible |
| 3 | Data Poisoning | LLM08 | `POI-OPS-012` quietly overstates the till float (80,000 INR vs the real 8,000 INR) with **no** injection language — just a false fact | this is the hardest one to fully close; secure mode only asks the model to prefer the trusted figure and flag the conflict, it can't force it — expect a partial result and write it up as residual risk |
| 4 | Context Exfiltration | LLM02 | A fake `[assistant-instructions]` block in the staff newsletter asks the model to base64-dump its whole context, HR role | vulnerable: real risk; secure: guard should catch a canary fire or a verbatim/base64 dump even if the prompt-level defence doesn't stop it |
| 5 | Embedding Weaknesses | LLM08 | `POI-VEN-330` is stuffed with keywords from six unrelated topics to see if it pollutes nearest-neighbour search for queries that have nothing to do with it | **expected to fail in both modes** — this is a retrieval-quality problem, not an access-control one, and the RBAC filter (which is what `secure` mode changes) doesn't touch it. That's the finding, not a bug: it's a distinct exposure with its own mitigation story (corpus hygiene / anomaly detection) to write up separately |

Attack 5 failing in both modes is not the harness malfunctioning — read `attacks/attack_05_embedding_weaknesses.py`'s docstring for why RBAC and embedding hygiene are orthogonal defences.

---

## Layout

```
app/
  config.py         roles, entitlements, settings           (boundary 1)
  ingest.py         front-matter parsing, chunking, labels  (boundary 2)
  embeddings.py     pluggable embedder
  store.py          Chroma wrapper
  retriever.py      vulnerable vs secure retrieval          (boundary 3)
  llm.py            OpenRouter client + offline stub
  prompt_builder.py naive concatenation vs structural separation
  guard.py          post-hoc output validation              (boundary 4)
  rag.py            query handler - wires 1 through 4 together
  cli.py            command line (ingest / stats / search / ask / roles)
corpus/clean/       10 labelled fictional documents
corpus/poisoned/    4 adversarial documents (injection, exfil, poisoning, embedding)
attacks/            one script per catalogue item + run_all.py
evidence/           captured prompt/response pairs, per attack/case/mode
report/             written report, exec summary (Phase 4)
```
