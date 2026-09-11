"""Central configuration. Everything tunable lives here, read from .env.

Security note: config is loaded once at process start. Nothing in this file is
influenced by user input or by retrieved document content - that separation is
deliberate and is one of the trust boundaries the project is testing.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")


def _env(key: str, default: str) -> str:
    return os.getenv(key, default).strip()


# --- Roles -------------------------------------------------------------------
# The whole access-control story of this project rests on these two roles.
ROLES: dict[str, dict] = {
    "employee": {
        "label": "General Employee",
        # Classifications this role is entitled to see.
        "entitlements": {"internal"},
    },
    "hr": {
        "label": "HR User",
        "entitlements": {"internal", "hr-confidential"},
    },
}


@dataclass(frozen=True)
class Settings:
    # OpenRouter
    openrouter_api_key: str = field(default_factory=lambda: _env("OPENROUTER_API_KEY", ""))
    openrouter_model: str = field(
        default_factory=lambda: _env("OPENROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct")
    )
    openrouter_base_url: str = field(
        default_factory=lambda: _env("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
    )

    # Embeddings
    embedding_backend: str = field(default_factory=lambda: _env("EMBEDDING_BACKEND", "minilm"))

    # Vector store
    chroma_path: Path = field(
        default_factory=lambda: (PROJECT_ROOT / _env("CHROMA_PATH", "./data/chroma")).resolve()
    )
    chroma_collection: str = field(default_factory=lambda: _env("CHROMA_COLLECTION", "northwind"))

    # Security posture: "vulnerable" or "secure"
    security_mode: str = field(default_factory=lambda: _env("SECURITY_MODE", "vulnerable"))

    # Retrieval
    top_k: int = 4
    chunk_chars: int = 600
    chunk_overlap: int = 100

    # Paths
    corpus_clean: Path = PROJECT_ROOT / "corpus" / "clean"
    corpus_poisoned: Path = PROJECT_ROOT / "corpus" / "poisoned"
    evidence_dir: Path = PROJECT_ROOT / "evidence"

    def entitlements_for(self, role: str) -> set[str]:
        if role not in ROLES:
            raise ValueError(f"unknown role {role!r}; expected one of {sorted(ROLES)}")
        return ROLES[role]["entitlements"]


settings = Settings()
