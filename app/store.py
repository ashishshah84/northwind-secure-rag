"""Vector store wrapper (Chroma).

Trust boundary #3 lives here: everything that reaches the collection carries the
metadata the retriever will later filter on. If a chunk is written without a
correct `classification` / `allowed_roles`, no amount of query-time filtering
saves you - the label is the control.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import chromadb
from chromadb.config import Settings as ChromaSettings

from .config import settings
from .embeddings import get_embedder


@dataclass
class Chunk:
    chunk_id: str
    text: str
    metadata: dict[str, Any]


class VectorStore:
    def __init__(self, path=None, collection=None) -> None:
        self.path = path or settings.chroma_path
        self.collection_name = collection or settings.chroma_collection
        self.path.mkdir(parents=True, exist_ok=True)
        self._client = chromadb.PersistentClient(
            path=str(self.path),
            settings=ChromaSettings(anonymized_telemetry=False, allow_reset=True),
        )
        self.embedder = get_embedder()
        # embedding_function=None: we embed explicitly so the embedding step stays
        # visible as its own trust boundary rather than an implicit side effect.
        self._col = self._client.get_or_create_collection(
            name=self.collection_name,
            metadata={"hnsw:space": "cosine"},
            embedding_function=None,
        )

    # --- writes --------------------------------------------------------------
    def reset(self) -> None:
        try:
            self._client.delete_collection(self.collection_name)
        except Exception:  # noqa: BLE001 - collection may not exist yet
            pass
        self._col = self._client.get_or_create_collection(
            name=self.collection_name,
            metadata={"hnsw:space": "cosine"},
            embedding_function=None,
        )

    def add(self, chunks: list[Chunk]) -> int:
        if not chunks:
            return 0
        vectors = self.embedder.embed([c.text for c in chunks])
        self._col.add(
            ids=[c.chunk_id for c in chunks],
            documents=[c.text for c in chunks],
            metadatas=[c.metadata for c in chunks],
            embeddings=vectors,
        )
        return len(chunks)

    # --- reads ---------------------------------------------------------------
    def query(
        self,
        text: str,
        k: int = 4,
        where: dict | None = None,
    ) -> list[dict[str, Any]]:
        """Similarity search. `where` is the Chroma metadata filter.

        Passing where=None is the *vulnerable* path: it searches every chunk in
        the collection regardless of who is asking.
        """
        qvec = self.embedder.embed([text])
        res = self._col.query(
            query_embeddings=qvec,
            n_results=k,
            where=where,
            include=["documents", "metadatas", "distances"],
        )
        out: list[dict[str, Any]] = []
        for i in range(len(res["ids"][0])):
            out.append(
                {
                    "chunk_id": res["ids"][0][i],
                    "text": res["documents"][0][i],
                    "metadata": res["metadatas"][0][i],
                    "distance": res["distances"][0][i],
                }
            )
        return out

    def count(self) -> int:
        return self._col.count()

    def stats(self) -> dict[str, Any]:
        got = self._col.get(include=["metadatas"])
        by_class: dict[str, int] = {}
        by_doc: dict[str, int] = {}
        by_trust: dict[str, int] = {}
        for m in got["metadatas"]:
            by_class[m.get("classification", "?")] = by_class.get(m.get("classification", "?"), 0) + 1
            by_doc[m.get("doc_id", "?")] = by_doc.get(m.get("doc_id", "?"), 0) + 1
            by_trust[m.get("trust", "?")] = by_trust.get(m.get("trust", "?"), 0) + 1
        return {
            "chunks": self._col.count(),
            "documents": len(by_doc),
            "by_classification": by_class,
            "by_trust": by_trust,
            "embedder": self.embedder.name,
        }
