"""Embedding backends.

Two backends, chosen by EMBEDDING_BACKEND:

  minilm  - all-MiniLM-L6-v2 via chromadb's bundled ONNX runtime. Real semantic
            embeddings. Downloads ~80MB on first use. Use this in the VM.
  hashed  - a deterministic hashed bag-of-words vector. No network, no model.
            Lexical similarity only. Use this for CI or an offline box; it is
            good enough to prove the plumbing works, not to draw conclusions
            about embedding-space attacks.

Why this module exists at all: Phase 5 (embedding weaknesses) needs to call the
embedder directly to probe nearest neighbours, so the embedding step is a named
component rather than something hidden inside the vector store.
"""
from __future__ import annotations

import hashlib
import math
import re
from typing import Protocol

from .config import settings

HASHED_DIM = 384  # match MiniLM's dimensionality so the two are swappable


class Embedder(Protocol):
    name: str
    dim: int

    def embed(self, texts: list[str]) -> list[list[float]]: ...


class HashedEmbedder:
    """Offline fallback: hash each token into a fixed-width vector, L2-normalise."""

    name = "hashed-bow"
    dim = HASHED_DIM

    _token_re = re.compile(r"[a-z0-9]+")

    def _one(self, text: str) -> list[float]:
        vec = [0.0] * self.dim
        for tok in self._token_re.findall(text.lower()):
            h = int(hashlib.md5(tok.encode()).hexdigest(), 16)
            vec[h % self.dim] += 1.0
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._one(t) for t in texts]


class MiniLMEmbedder:
    """all-MiniLM-L6-v2 through chromadb's default embedding function."""

    name = "all-MiniLM-L6-v2"
    dim = 384

    def __init__(self) -> None:
        from chromadb.utils import embedding_functions

        self._fn = embedding_functions.DefaultEmbeddingFunction()

    def embed(self, texts: list[str]) -> list[list[float]]:
        # .tolist() on a numpy array gives native Python floats. list(v) on a
        # numpy array instead yields a list of np.float32 *objects*, which
        # newer chromadb versions reject at the validation step (their type
        # check wants a plain float/int list, a numpy array, or a list of
        # numpy arrays - not a Python list containing numpy scalars).
        return [v.tolist() if hasattr(v, "tolist") else list(v) for v in self._fn(texts)]


_cached: Embedder | None = None


def get_embedder(backend: str | None = None) -> Embedder:
    """Return the configured embedder, falling back loudly if the model is unreachable."""
    global _cached
    if _cached is not None and backend is None:
        return _cached

    choice = (backend or settings.embedding_backend).lower()
    if choice == "hashed":
        emb: Embedder = HashedEmbedder()
    else:
        try:
            emb = MiniLMEmbedder()
            # Force the model download / load now so failures surface here.
            emb.embed(["warmup"])
        except Exception as exc:  # noqa: BLE001 - we genuinely want any failure
            print(
                f"[embeddings] WARNING: could not load '{choice}' ({type(exc).__name__}: {exc}).\n"
                f"[embeddings] Falling back to 'hashed'. Retrieval quality will be lexical only."
            )
            emb = HashedEmbedder()

    if backend is None:
        _cached = emb
    return emb
