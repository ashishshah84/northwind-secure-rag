"""Retriever - trust boundary #3.

The only difference between the two modes is whether a metadata filter is applied
at query time. That single `where` clause is the entire cross-tenant control, which
is exactly why it is worth attacking.

  vulnerable: search the whole collection, then hand the top-k to the prompt builder.
              The role is known but never used. This is the classic "we filter in
              the UI" bug, moved into a RAG pipeline.
  secure:     constrain the search to classifications the role is entitled to, and
              then re-check every returned chunk before it leaves this function
              (defence in depth - never trust the store to have honoured the filter).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .config import ROLES, settings
from .store import VectorStore


@dataclass
class RetrievalResult:
    role: str
    mode: str
    query: str
    chunks: list[dict[str, Any]] = field(default_factory=list)
    # Chunks the store returned that the role was NOT entitled to. In secure mode
    # this should always be empty; if it is not, the filter failed and we caught it.
    blocked: list[dict[str, Any]] = field(default_factory=list)

    @property
    def leaked_doc_ids(self) -> list[str]:
        return sorted({c["metadata"]["doc_id"] for c in self.chunks
                       if c["metadata"]["classification"] not in
                       settings.entitlements_for(self.role)})


class Retriever:
    def __init__(self, store: VectorStore | None = None) -> None:
        self.store = store or VectorStore()

    def retrieve(self, query: str, role: str, mode: str | None = None,
                 k: int | None = None) -> RetrievalResult:
        if role not in ROLES:
            raise ValueError(f"unknown role {role!r}")
        mode = (mode or settings.security_mode).lower()
        k = k or settings.top_k
        entitlements = settings.entitlements_for(role)

        if mode == "secure":
            where = {"classification": {"$in": sorted(entitlements)}}
        else:
            where = None  # <-- the vulnerability

        hits = self.store.query(query, k=k, where=where)

        result = RetrievalResult(role=role, mode=mode, query=query)
        for hit in hits:
            allowed = hit["metadata"]["classification"] in entitlements
            if mode == "secure" and not allowed:
                # Should be unreachable. If it fires, the store filter is broken.
                result.blocked.append(hit)
            else:
                result.chunks.append(hit)
        return result
