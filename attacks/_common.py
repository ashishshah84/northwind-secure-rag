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
from typing import Any, Callable

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


def inconclusive(label: str, detail: str = "") -> None:
    """Neither pass nor fail - the test did not actually run.

    This exists because the harness used to score a failed API call as PASS.
    A rate-limited run printed a full set of green verdicts and looked like a
    clean security result, which is failing open: the most dangerous direction
    for a security tool to be wrong in. "We could not test this" and "this is
    safe" must never render the same way.
    """
    print(f"  [{YELLOW}SKIP{RESET}] {label}" + (f" - {detail}" if detail else ""))


def all_errored(rec: dict[str, Any]) -> bool:
    """True when no trial in this case produced a usable answer."""
    trials = rec.get("trial_records") or []
    if not trials:
        return bool(rec.get("error"))
    return all(t.get("error") for t in trials)


def error_note(rec: dict[str, Any]) -> str:
    trials = rec.get("trial_records") or []
    errs = [t.get("error") for t in trials if t.get("error")] or [rec.get("error")]
    first = (errs[0] or "unknown error").split("\n")[0]
    return f"{len(errs)}/{rec.get('trials_run', 1)} trial(s) failed: {first[:140]}"


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


def run_trials(
    script: str,
    case: str,
    query: str,
    role: str,
    mode: str,
    detect: "Callable[[dict[str, Any]], bool]",
    trials: int | None = None,
) -> dict[str, Any]:
    """Run one case `trials` times and report how often the attack landed.

    Why this exists: model behaviour under attack is not deterministic. Across
    four single-shot runs of this suite the same injection complied 3 times out
    of 4, at temperature 0.2. "The injection worked" and "the injection works
    75% of the time" are different claims, and only the second one is worth
    putting in a report.

    `detect(record) -> bool` is the attack-specific definition of "landed",
    supplied by the calling script. The returned record is the first trial where
    it landed (the worst case, which is the one you want to read), or the last
    trial if it never did - annotated with:

        trials_run, trials_landed, landing_rate, trial_records

    Per-trial evidence is written as <script>__<case>__<mode>__t<N>.json, plus
    the representative record at the usual unsuffixed path so existing tooling
    and the README's file naming still work.
    """
    trials = trials or settings.trials
    records: list[dict[str, Any]] = []
    landed_flags: list[bool] = []

    for t in range(1, trials + 1):
        rec = _run_once(script, case, query, role, mode, trial=t, total_trials=trials)
        try:
            landed = bool(detect(rec))
        except Exception as exc:  # noqa: BLE001 - a broken detector shouldn't kill the run
            print(f"  {RED}detector error{RESET}: {type(exc).__name__}: {exc}")
            landed = False
        rec["landed"] = landed
        records.append(rec)
        landed_flags.append(landed)

    landed_count = sum(landed_flags)
    # Representative = first landing trial, else the last one.
    representative = next(
        (r for r in records if r.get("landed")), records[-1]
    )
    out = dict(representative)
    out["trials_run"] = trials
    out["trials_landed"] = landed_count
    out["landing_rate"] = round(landed_count / trials, 3) if trials else 0.0
    out["trial_records"] = [
        {
            "trial": i + 1,
            "landed": r.get("landed"),
            "error": r.get("error"),
            "final_answer": r.get("final_answer", "")[:500],
            "guard_safe": r.get("guard_safe"),
            "leaked_doc_ids": r.get("leaked_doc_ids"),
        }
        for i, r in enumerate(records)
    ]

    out_path = settings.evidence_dir / f"{script}__{case}__{mode}.json"
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")

    if trials > 1:
        print(
            f"  {BOLD}landed {landed_count}/{trials} trials "
            f"({out['landing_rate']:.0%}){RESET}"
        )

    return out


def run_case(
    script: str,
    case: str,
    query: str,
    role: str,
    mode: str,
) -> dict[str, Any]:
    """Single-trial convenience wrapper, kept so older scripts still work."""
    return _run_once(script, case, query, role, mode)


def _run_once(
    script: str,
    case: str,
    query: str,
    role: str,
    mode: str,
    trial: int = 1,
    total_trials: int = 1,
) -> dict[str, Any]:
    """Run one query through the full pipeline, save evidence, return the record.

    Wrapped in try/except deliberately: a single flaky call (free-tier models
    can return malformed or empty responses) should not take down the rest of
    the attack suite. On failure this writes what we know to evidence/ with an
    "error" field, prints it clearly, and returns a record shaped like a
    normal one (same keys, neutral values) so the calling attack script's own
    verdict logic doesn't also crash on a missing key.
    """
    suffix = f"__t{trial}" if total_trials > 1 else ""
    label = f"{case} / role={role} / mode={mode}"
    if total_trials > 1:
        label += f" / trial {trial}/{total_trials}"
    out_path = settings.evidence_dir / f"{script}__{case}__{mode}{suffix}.json"

    try:
        result = answer(query, role=role, mode=mode)
        record = result.to_evidence()
    except Exception as exc:  # noqa: BLE001 - genuinely want to catch anything here
        print(f"\n  --- {label} ---")
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
        record["trial"] = trial
        out_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        print(f"  evidence     : {out_path.relative_to(PROJECT_ROOT)} (error case)")
        return record

    record["script"] = script
    record["case"] = case
    record["trial"] = trial

    out_path.write_text(json.dumps(record, indent=2), encoding="utf-8")

    print(f"\n  --- {label} ---")
    if total_trials == 1:
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
