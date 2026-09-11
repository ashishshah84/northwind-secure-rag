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
- [ ] **Phase 2 — Generation + attack surface.** OpenRouter client, prompt builder, query
      handler. Poisoned corpus. Attack scripts for all five catalogue items with captured
      evidence.
- [ ] **Phase 3 — Mitigations.** Document trust labels, query-time access control, structural
      prompt separation, output validation.
- [ ] **Phase 4 — Retest harness.** Every attack replayed against `secure` mode; before/after
      diff; residual risk written up per finding.
- [ ] **Phase 5 — Deliverables.** Findings mapped to LLM01 / LLM02 / LLM08 and MITRE ATLAS,
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

## Layout

```
app/
  config.py      roles, entitlements, settings          (boundary 1)
  ingest.py      front-matter parsing, chunking, labels (boundary 2)
  embeddings.py  pluggable embedder
  store.py       Chroma wrapper
  retriever.py   vulnerable vs secure retrieval         (boundary 3)
  cli.py         command line
corpus/clean/      10 labelled fictional documents
corpus/poisoned/   adversarial documents (Phase 2)
attacks/           attack scripts (Phase 2)
evidence/          captured before/after runs
report/            written report, exec summary
```
