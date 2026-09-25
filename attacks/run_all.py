"""Run the full attack catalogue and print a before/after summary.

Ingests the corpus WITH the poisoned documents included first (the whole
catalogue depends on them being present), then runs all five attacks against
whatever LLM backend is configured in .env, saving every prompt/response pair
to evidence/ along the way.

    python -m attacks.run_all

Requires OPENROUTER_API_KEY set and LLM_BACKEND=openrouter in .env for
meaningful results - see app/llm.py for why the stub backend doesn't count as
evidence.
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.config import settings  # noqa: E402
from app.ingest import ingest  # noqa: E402
from app.llm import get_llm  # noqa: E402

from attacks import (  # noqa: E402
    attack_01_indirect_prompt_injection as a1,
    attack_02_cross_tenant_leakage as a2,
    attack_03_data_poisoning as a3,
    attack_04_context_exfiltration as a4,
    attack_05_embedding_weaknesses as a5,
    attack_06_system_prompt_leakage as a6,
    attack_07_role_escalation as a7,
    attack_08_chunk_split_injection as a8,
    attack_09_retrieval_crowding as a9,
)


def main() -> None:
    llm = get_llm()
    print(f"LLM backend : {llm.name}")
    print(f"Model       : {settings.openrouter_model if llm.name == 'openrouter' else 'n/a'}")
    print(f"Trials/case : {settings.trials}")
    if settings.trials == 1:
        print(
            "\n  NOTE: TRIALS=1. Model behaviour under attack is not deterministic -\n"
            "  a single run tells you what happened once, not whether a mitigation\n"
            "  works. Set TRIALS=10 in .env before collecting evidence for the\n"
            "  report."
        )
    est = settings.trials * 2 * 13  # 13 LLM-backed cases across attacks 1,2,3,4,6,7,8
    print(
        f"\n  Budget: roughly {est} API calls at TRIALS={settings.trials}. The free tier\n"
        f"  allows 50/day. Above that, run attacks individually - attacks 5 and 9\n"
        f"  are retrieval-only and cost nothing."
    )
    if llm.name == "stub":
        print(
            "\n  WARNING: LLM_BACKEND=stub - results below exercise the pipeline "
            "only and are NOT evidence of real model behaviour. Set "
            "LLM_BACKEND=openrouter in .env before this run counts for the report.\n"
        )

    print("\nIngesting corpus WITH poisoned documents...")
    result = ingest(include_poisoned=True, reset=True, verbose=True)
    print(f"documents={result['documents']} chunks={result['chunks']} "
          f"embedder={result['stats']['embedder']}\n")

    for module in (a1, a2, a3, a4, a5, a6, a7, a8, a9):
        module.main()

    print("\n" + "=" * 78)
    print(f"All evidence written under {settings.evidence_dir.relative_to(PROJECT_ROOT)}/")
    print("=" * 78)


if __name__ == "__main__":
    main()
