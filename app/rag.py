"""Query Handler - wires AuthN/AuthZ -> Retriever -> Prompt Builder -> LLM -> Guard.

This is the "Query" box in the architecture diagram. It is the single place that
knows about every trust boundary at once, which is exactly why attack scripts
call this module rather than poking retriever/prompt_builder/llm individually -
end_to_end() is what a real user's request would actually go through.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from .config import ROLES, settings
from .guard import GuardResult, check_output
from .llm import get_llm
from .prompt_builder import Prompt, build_prompt
from .retriever import Retriever, RetrievalResult


class AuthError(PermissionError):
    pass


@dataclass
class AnswerResult:
    query: str
    role: str
    mode: str
    retrieval: RetrievalResult
    prompt: Prompt
    raw_answer: str
    guard: GuardResult
    final_answer: str
    latency_s: float
    llm_backend: str

    @property
    def leaked_doc_ids(self) -> list[str]:
        return self.retrieval.leaked_doc_ids

    def to_evidence(self) -> dict[str, Any]:
        """JSON-serialisable snapshot for evidence/*.json - everything an auditor
        would need to reconstruct what happened, without re-running anything."""
        return {
            "query": self.query,
            "role": self.role,
            "mode": self.mode,
            "llm_backend": self.llm_backend,
            "retrieved_doc_ids": [c["metadata"]["doc_id"] for c in self.retrieval.chunks],
            "retrieved_classifications": [
                c["metadata"]["classification"] for c in self.retrieval.chunks
            ],
            "retrieved_trust": [c["metadata"]["trust"] for c in self.retrieval.chunks],
            "leaked_doc_ids": self.leaked_doc_ids,
            "prompt_system": self.prompt.system,
            "prompt_user": self.prompt.user,
            "raw_answer": self.raw_answer,
            "guard_safe": self.guard.safe,
            "guard_findings": self.guard.findings,
            "final_answer": self.final_answer,
            "latency_s": round(self.latency_s, 3),
        }


def authenticate(role: str) -> str:
    """Boundary #1. In this lab a 'session' is just a role string typed on the
    CLI, but the check itself - reject anything not in ROLES before it touches
    the rest of the pipeline - is exactly what a real AuthN/AuthZ layer enforces."""
    if role not in ROLES:
        raise AuthError(f"unknown role {role!r}; expected one of {sorted(ROLES)}")
    return role


def answer(
    query: str,
    role: str,
    mode: str | None = None,
    k: int | None = None,
    retriever: Retriever | None = None,
) -> AnswerResult:
    mode = (mode or settings.security_mode).lower()
    role = authenticate(role)

    retriever = retriever or Retriever()
    retrieval = retriever.retrieve(query, role=role, mode=mode, k=k)

    prompt = build_prompt(query, role=role, chunks=retrieval.chunks, mode=mode)

    llm = get_llm()
    start = time.monotonic()
    raw_answer = llm.chat(prompt.system, prompt.user)
    latency = time.monotonic() - start

    guard = check_output(raw_answer, role=role, retrieved=retrieval.chunks, mode=mode)
    final_answer = raw_answer if guard.safe else (guard.redacted_text or raw_answer)

    return AnswerResult(
        query=query,
        role=role,
        mode=mode,
        retrieval=retrieval,
        prompt=prompt,
        raw_answer=raw_answer,
        guard=guard,
        final_answer=final_answer,
        latency_s=latency,
        llm_backend=llm.name,
    )
