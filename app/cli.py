"""Command line entry point.

  python -m app.cli ingest [--include-poisoned] [--no-reset]
  python -m app.cli stats
  python -m app.cli search "<query>" --role employee|hr [--mode vulnerable|secure] [-k N]
  python -m app.cli roles
"""
from __future__ import annotations

import argparse
import json
import sys

from .config import ROLES, settings


def cmd_ingest(args) -> int:
    from .ingest import ingest

    print(f"Ingesting corpus (poisoned={'yes' if args.include_poisoned else 'no'})")
    result = ingest(include_poisoned=args.include_poisoned, reset=not args.no_reset)
    print()
    print(f"  documents : {result['documents']}")
    print(f"  chunks    : {result['chunks']}")
    print(f"  embedder  : {result['stats']['embedder']}")
    print(f"  by class  : {result['stats']['by_classification']}")
    print(f"  by trust  : {result['stats']['by_trust']}")
    if result["errors"]:
        print(f"\n  {len(result['errors'])} document(s) rejected:")
        for e in result["errors"]:
            print(f"    - {e}")
        return 1
    return 0


def cmd_stats(args) -> int:
    from .store import VectorStore

    print(json.dumps(VectorStore().stats(), indent=2))
    return 0


def cmd_roles(args) -> int:
    for name, spec in ROLES.items():
        print(f"{name:<10} {spec['label']:<20} entitlements={sorted(spec['entitlements'])}")
    return 0


def cmd_search(args) -> int:
    from .retriever import Retriever

    res = Retriever().retrieve(args.query, role=args.role, mode=args.mode, k=args.k)
    ent = settings.entitlements_for(args.role)

    print(f"query : {res.query!r}")
    print(f"role  : {res.role}  (entitled to {sorted(ent)})")
    print(f"mode  : {res.mode}")
    print(f"top-k : {args.k or settings.top_k}")
    print("-" * 78)

    if not res.chunks:
        print("  (no chunks returned)")

    for i, c in enumerate(res.chunks, 1):
        m = c["metadata"]
        flag = "  " if m["classification"] in ent else ">>"
        print(f"{flag} [{i}] {m['doc_id']}  {m['title']}")
        print(f"      classification={m['classification']}  trust={m['trust']}  "
              f"distance={c['distance']:.4f}")
        snippet = " ".join(c["text"].split())[:160]
        print(f"      {snippet}...")
        print()

    if res.blocked:
        print(f"!! secure mode caught {len(res.blocked)} chunk(s) the store should not have returned")

    leaked = res.leaked_doc_ids
    print("-" * 78)
    if leaked:
        print(f"RESULT: LEAK - role '{res.role}' received {len(leaked)} unauthorised "
              f"document(s): {', '.join(leaked)}")
        return 2
    print(f"RESULT: clean - no unauthorised documents returned to role '{res.role}'")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="northwind-rag", description="Secure RAG lab")
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("ingest", help="build the vector store from corpus/")
    pi.add_argument("--include-poisoned", action="store_true",
                    help="also ingest corpus/poisoned/ (Phase 2)")
    pi.add_argument("--no-reset", action="store_true", help="append instead of rebuilding")
    pi.set_defaults(func=cmd_ingest)

    ps = sub.add_parser("stats", help="show what is in the vector store")
    ps.set_defaults(func=cmd_stats)

    pr = sub.add_parser("roles", help="list roles and entitlements")
    pr.set_defaults(func=cmd_roles)

    pq = sub.add_parser("search", help="raw retrieval, no LLM")
    pq.add_argument("query")
    pq.add_argument("--role", default="employee", choices=sorted(ROLES))
    pq.add_argument("--mode", default=None, choices=["vulnerable", "secure"])
    pq.add_argument("-k", type=int, default=None)
    pq.set_defaults(func=cmd_search)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
