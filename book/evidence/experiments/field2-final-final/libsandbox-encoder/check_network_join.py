#!/usr/bin/env python3
"""
Experiment-local guardrail for the network matrix join candidates.

This script fails if any candidate reports violations. It is not wired
into book/graph/concepts validation or the shared test harness.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api.path_utils import find_repo_root, to_repo_relative

ROOT = find_repo_root(Path(__file__))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    path = ROOT / "book/evidence/experiments/field2-final-final/libsandbox-encoder/out/network_matrix/join_hypotheses.json"
    if not path.exists():
        print(f"[!] missing {to_repo_relative(path, ROOT)}; run analyze_network_join.py first")
        return 2
    data = json.loads(path.read_text())
    failures = []
    for candidate in data.get("hypotheses", []):
        violations = candidate.get("violations") or []
        if violations:
            failures.append({"id": candidate.get("id"), "violations": violations})
    if failures:
        print("[!] join candidate violations detected")
        for fail in failures:
            print(f"  - {fail['id']}: {len(fail['violations'])} violations")
        return 1
    print("[+] join candidates: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
