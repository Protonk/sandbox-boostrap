#!/usr/bin/env python3
"""
Progress-gate ratchet driver.

If the progress gate is green, widen the milestone and immediately report the
next missing claim key to force the loop back to red.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List

import sys

REPO_ROOT = Path(__file__).resolve()
for parent in REPO_ROOT.parents:
    if (parent / "book").is_dir():
        REPO_ROOT = parent
        break
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils

DEFAULT_MILESTONE = (
    REPO_ROOT
    / "book"
    / "evidence"
    / "experiments"
    / "field2-final-final"
    / "active_milestone.json"
)
DEFAULT_DECISIONS = (
    REPO_ROOT
    / "book"
    / "evidence"
    / "experiments"
    / "field2-final-final"
    / "decisions.jsonl"
)
DEFAULT_FRONTIER = (
    REPO_ROOT
    / "book"
    / "evidence"
    / "experiments"
    / "field2-final-final"
    / "out"
    / "frontier.json"
)


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def missing_claims(milestone_path: Path, decisions_path: Path) -> List[str]:
    milestone = load_json(milestone_path)
    candidates = milestone.get("candidates") or []
    expected = [entry.get("claim_key") for entry in candidates if entry.get("claim_key")]
    decided = {rec.get("claim_key") for rec in load_jsonl(decisions_path) if rec.get("claim_key")}
    return [key for key in expected if key not in decided]


def widen_milestone(
    *,
    frontier_path: Path,
    milestone_path: Path,
    decisions_path: Path,
    delta: int,
    require_runtime_candidate: bool,
    include_retired: bool,
    require_fresh_packet: bool,
) -> None:
    milestone = load_json(milestone_path)
    current_count = len(milestone.get("candidates") or [])
    new_count = current_count + delta
    cmd = [
        sys.executable,
        str(REPO_ROOT / "book" / "evidence" / "experiments" / "field2-final-final" / "milestone_freeze.py"),
        "--frontier",
        str(frontier_path),
        "--out",
        str(milestone_path),
        "--decisions",
        str(decisions_path),
        "--count",
        str(new_count),
        "--milestone-id",
        milestone.get("milestone_id", "field2-frontier") + f"+{delta}",
    ]
    if require_runtime_candidate:
        cmd.append("--require-runtime-candidate")
    if include_retired:
        cmd.append("--include-retired")
    if require_fresh_packet:
        cmd.append("--require-fresh-packet")
    subprocess.check_call(cmd, cwd=REPO_ROOT)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--milestone", type=Path, default=DEFAULT_MILESTONE)
    parser.add_argument("--decisions", type=Path, default=DEFAULT_DECISIONS)
    parser.add_argument("--frontier", type=Path, default=DEFAULT_FRONTIER)
    parser.add_argument("--delta", type=int, default=5)
    parser.add_argument("--require-runtime-candidate", action="store_true")
    parser.add_argument("--include-retired", action="store_true")
    parser.add_argument("--require-fresh-packet", action="store_true")
    args = parser.parse_args()

    repo_root = path_utils.find_repo_root(Path(__file__).resolve())
    missing = missing_claims(args.milestone, args.decisions)
    if not missing:
        widen_milestone(
            frontier_path=args.frontier,
            milestone_path=args.milestone,
            decisions_path=args.decisions,
            delta=args.delta,
            require_runtime_candidate=args.require_runtime_candidate,
            include_retired=args.include_retired,
            require_fresh_packet=args.require_fresh_packet,
        )
        missing = missing_claims(args.milestone, args.decisions)

    if not missing:
        print("no eligible claims after widening; frontier is exhausted")
        raise SystemExit(2)

    print(f"next_claim={missing[0]}")
    raise SystemExit(1)


if __name__ == "__main__":
    main()
