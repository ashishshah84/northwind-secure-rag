"""Shared helpers for attack scripts.

Every attack script follows the same shape: run a query as a role, in a mode,
through the full pipeline (app/rag.py), print a human-readable verdict, and
write the full evidence trail to evidence/<script>_<case>.json so a result can
be checked later without re-running anything (rerunning is nondeterministic
once a real LLM is involved).

Run scripts from the project root: python -m attacks.attack_01_indirect_prompt_injection
(module names can't start with a digit, hence the attack_ prefix on every file)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.config import settings  # noqa: E402
from app.rag import answer  # noqa: E402

settings.evidence_dir.mkdir(parents=True, exist_ok=True)

RESET = "\033[0m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BOLD = "\033[1m"


def banner(title: str) -> None:
    print(f"\n{BOLD}{'=' * 78}{RESET}")
    print(f"{BOLD}{title}{RESET}")
    print(f"{BOLD}{'=' * 78}{RESET}")


def verdict_line(label: str, passed: bool, detail: str = "") -> None:
    tag = f"{GREEN}PASS{RESET}" if passed else f"{RED}FAIL{RESET}"
    print(f"  [{tag}] {label}" + (f" - {detail}" if detail else ""))


_ERROR_FIELDS = {
    "llm_backend": "unknown",
    "retrieved_doc_ids": [],
    "retrieved_classifications": [],
    "retrieved_trust": [],
    "leaked_doc_ids": [],
    "prompt_system": "",
    "prompt_user": "",
    "raw_answer": "",
    "guard_safe": True,
    "guard_findings": [],
    "final_answer": "",
    "latency_s": 0.0,
}


def run_case(
    script: str,
    case: str,
    query: str,
    role: str,
    mode: str,
) -> dict[str, Any]:
    """Run one query through the full pipeline, save evidence, return the record.

    Wrapped in try/except deliberately: a single flaky call (free-tier models
    can return malformed or empty responses) should not take down the rest of
    the attack suite. On failure this writes what we know to evidence/ with an
    "error" field, prints it clearly, and returns a record shaped like a
    normal one (same keys, neutral values) so the calling attack script's own
    verdict logic doesn't also crash on a missing key.
    """
    try:
        result = answer(query, role=role, mode=mode)
        record = result.to_evidence()
    except Exception as exc:  # noqa: BLE001 - genuinely want to catch anything here
        print(f"\n  --- {case} / role={role} / mode={mode} ---")
        print(f"  {RED}ERROR{RESET}      : {type(exc).__name__}: {exc}")
        record = {
            "query": query,
            "role": role,
            "mode": mode,
            "error": f"{type(exc).__name__}: {exc}",
            **_ERROR_FIELDS,
        }
        record["script"] = script
        record["case"] = case
        out_path = settings.evidence_dir / f"{script}__{case}__{mode}.json"
        out_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        print(f"  evidence     : {out_path.relative_to(PROJECT_ROOT)} (error case)")
        return record

    record["script"] = script
    record["case"] = case

    out_path = settings.evidence_dir / f"{script}__{case}__{mode}.json"
    out_path.write_text(json.dumps(record, indent=2), encoding="utf-8")

    print(f"\n  --- {case} / role={role} / mode={mode} ---")
    print(f"  query        : {query}")
    print(f"  retrieved    : {record['retrieved_doc_ids']}")
    if record["leaked_doc_ids"]:
        print(f"  {RED}leaked docs  : {record['leaked_doc_ids']}{RESET}")
    print(f"  guard safe   : {record['guard_safe']}  findings={record['guard_findings']}")
    print(f"  final answer : {record['final_answer'][:300]}")
    print(f"  evidence     : {out_path.relative_to(PROJECT_ROOT)}")

    return record


def write_summary(name: str, rows: list[dict[str, Any]]) -> None:
    out_path = settings.evidence_dir / f"{name}__summary.json"
    out_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(f"\n  summary written: {out_path.relative_to(PROJECT_ROOT)}")
