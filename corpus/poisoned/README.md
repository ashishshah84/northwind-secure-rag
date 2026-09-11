# Poisoned corpus (Phase 2)

This folder holds adversarial documents used to demonstrate indirect prompt injection and
data poisoning. It is deliberately **not** ingested by `ingest.py` in Phase 1.

In Phase 2 these are ingested with an explicit flag (`--include-poisoned`) so the
before/after evidence is unambiguous: the same corpus, plus a hostile document.

Nothing here is real. All names, policies and companies are fictional.
