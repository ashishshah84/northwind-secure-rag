"""Ingestion pipeline - trust boundary #2.

Untrusted content enters the system here. Everything this module writes into the
vector store is later fed to an LLM, so this is the last place where you can
attach a label that the rest of the system can act on.

Labels attached to every chunk:
  doc_id, title, classification, allowed_roles, owner, source, path
  trust      - "trusted" for corpus/clean, "untrusted" for corpus/poisoned
  ingested_at

Note what ingestion deliberately does NOT do: it does not sanitise, rewrite or
strip instructions out of document text. Filtering the content is a losing game;
labelling it and handling it structurally downstream is the defence. Phase 3
shows the difference.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import re
from pathlib import Path
from typing import Any

from .config import settings
from .store import Chunk, VectorStore

FRONT_MATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n", re.DOTALL)

REQUIRED_FIELDS = {"doc_id", "title", "classification", "allowed_roles"}
VALID_CLASSIFICATIONS = {"internal", "hr-confidential"}


class IngestError(ValueError):
    pass


def parse_front_matter(raw: str, path: Path) -> tuple[dict[str, str], str]:
    """Minimal YAML-ish front matter parser (key: value only - no nesting, no deps)."""
    m = FRONT_MATTER_RE.match(raw)
    if not m:
        raise IngestError(f"{path.name}: missing '---' front matter block")

    meta: dict[str, str] = {}
    for line in m.group(1).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise IngestError(f"{path.name}: bad front-matter line {line!r}")
        key, _, value = line.partition(":")
        meta[key.strip()] = value.strip()

    missing = REQUIRED_FIELDS - meta.keys()
    if missing:
        raise IngestError(f"{path.name}: front matter missing {sorted(missing)}")

    if meta["classification"] not in VALID_CLASSIFICATIONS:
        raise IngestError(
            f"{path.name}: classification {meta['classification']!r} not in {VALID_CLASSIFICATIONS}"
        )

    roles = {r.strip() for r in meta["allowed_roles"].split(",") if r.strip()}
    if not roles:
        raise IngestError(f"{path.name}: allowed_roles is empty")
    meta["allowed_roles"] = ",".join(sorted(roles))

    body = raw[m.end():].strip()
    if not body:
        raise IngestError(f"{path.name}: document body is empty")
    return meta, body


def chunk_text(body: str, size: int, overlap: int) -> list[str]:
    """Paragraph-aware chunking with character overlap.

    Kept simple on purpose: an attacker's payload should survive chunking intact
    so the injection tests are testing the model, not the splitter.
    """
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", body) if p.strip()]
    chunks: list[str] = []
    current = ""

    for para in paragraphs:
        if not current:
            current = para
        elif len(current) + 2 + len(para) <= size:
            current = f"{current}\n\n{para}"
        else:
            chunks.append(current)
            tail = current[-overlap:] if overlap else ""
            current = f"{tail}\n\n{para}".strip() if tail else para

    if current:
        chunks.append(current)

    # A single paragraph longer than `size` is hard-split so nothing is dropped.
    final: list[str] = []
    for c in chunks:
        if len(c) <= size * 1.5:
            final.append(c)
        else:
            step = size - overlap
            final.extend(c[i : i + size] for i in range(0, len(c), step))
    return final


def load_document(path: Path, trust: str) -> list[Chunk]:
    raw = path.read_text(encoding="utf-8")
    meta, body = parse_front_matter(raw, path)

    base: dict[str, Any] = {
        "doc_id": meta["doc_id"],
        "title": meta["title"],
        "classification": meta["classification"],
        "allowed_roles": meta["allowed_roles"],
        "owner": meta.get("owner", "unknown"),
        "source": meta.get("source", "unknown"),
        "path": str(path.relative_to(settings.corpus_clean.parent.parent)),
        "trust": trust,
        "ingested_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
    }

    chunks: list[Chunk] = []
    for idx, text in enumerate(chunk_text(body, settings.chunk_chars, settings.chunk_overlap)):
        digest = hashlib.sha1(f"{meta['doc_id']}:{idx}:{text}".encode()).hexdigest()[:12]
        chunks.append(
            Chunk(
                chunk_id=f"{meta['doc_id']}::{idx:03d}::{digest}",
                text=text,
                metadata={**base, "chunk_index": idx},
            )
        )
    return chunks


def ingest(include_poisoned: bool = False, reset: bool = True, verbose: bool = True) -> dict:
    store = VectorStore()
    if reset:
        store.reset()

    sources: list[tuple[Path, str]] = [(settings.corpus_clean, "trusted")]
    if include_poisoned:
        sources.append((settings.corpus_poisoned, "untrusted"))

    total_docs = 0
    total_chunks = 0
    errors: list[str] = []

    for folder, trust in sources:
        for path in sorted(folder.glob("*.md")):
            if path.name.lower() == "readme.md":
                continue
            try:
                chunks = load_document(path, trust)
            except IngestError as exc:
                errors.append(str(exc))
                if verbose:
                    print(f"  SKIP {path.name}: {exc}")
                continue
            store.add(chunks)
            total_docs += 1
            total_chunks += len(chunks)
            if verbose:
                meta = chunks[0].metadata
                print(
                    f"  + {meta['doc_id']:<14} {meta['classification']:<16} "
                    f"roles={meta['allowed_roles']:<12} trust={trust:<9} "
                    f"{len(chunks)} chunk(s)  {path.name}"
                )

    return {
        "documents": total_docs,
        "chunks": total_chunks,
        "errors": errors,
        "stats": store.stats(),
    }
