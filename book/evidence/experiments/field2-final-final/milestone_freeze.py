#!/usr/bin/env python3
"""
Freeze a finite milestone from the field2 frontier ranking.
"""

from __future__ import annotations

import argparse
import json
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

SCHEMA_VERSION = "field2-milestone.v0"
DEFAULT_FRONTIER = (
    REPO_ROOT
    / "book"
    / "evidence"
    / "experiments"
    / "field2-final-final"
    / "out"
    / "frontier.json"
)
DEFAULT_OUT = (
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


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _load_decisions(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frontier", type=Path, default=DEFAULT_FRONTIER)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--decisions", type=Path, default=DEFAULT_DECISIONS)
    parser.add_argument("--milestone-id", type=str, default="field2-frontier-1")
    parser.add_argument("--count", type=int, default=5)
    parser.add_argument("--field2", type=int, action="append", default=[])
    parser.add_argument("--require-runtime-candidate", action="store_true")
    parser.add_argument("--include-decided", action="store_true")
    parser.add_argument("--include-retired", action="store_true")
    parser.add_argument("--require-fresh-packet", action="store_true")
    args = parser.parse_args()

    repo_root = path_utils.find_repo_root(Path(__file__).resolve())
    frontier = load_json(args.frontier)
    candidates: List[Dict[str, Any]] = frontier.get("candidates") or []

    decisions = _load_decisions(args.decisions)
    decided = {}
    for rec in decisions:
        key = rec.get("claim_key")
        decision = rec.get("decision")
        if key and decision:
            decided[key] = decision

    if decided and not args.include_decided:
        filtered = []
        for cand in candidates:
            key = f"field2={cand.get('field2')}"
            decision = decided.get(key)
            if decision is None:
                filtered.append(cand)
                continue
            if args.include_retired and decision == "retired":
                filtered.append(cand)
        candidates = filtered

    if args.require_runtime_candidate:
        candidates = [c for c in candidates if c.get("runtime_candidate")]

    if args.field2:
        selected = []
        missing = []
        for fid in args.field2:
            match = next((cand for cand in candidates if cand.get("field2") == fid), None)
            if match is None:
                missing.append(fid)
                continue
            selected.append(match)
        if missing:
            raise ValueError(f"field2 values not found in frontier: {missing}")
    else:
        candidates.sort(key=lambda c: (c.get("score", 0), c.get("anchor_count", 0)), reverse=True)
        selected = candidates[: args.count]

    payload = {
        "schema_version": SCHEMA_VERSION,
        "milestone_id": args.milestone_id,
        "world_id": frontier.get("world_id"),
        "source": path_utils.to_repo_relative(args.frontier, repo_root=repo_root),
        "requirements": {
            "require_packet": True,
            "require_lane_attribution": True,
            "require_mapping_delta_or_retire": True,
            "require_fresh_packet": bool(args.require_fresh_packet),
        },
        "candidates": [
            {
                "claim_key": f"field2={entry.get('field2')}",
                "field2": entry.get("field2"),
                "filter_name": entry.get("filter_name"),
                "status": entry.get("status"),
                "score": entry.get("score"),
                "runtime_candidate": entry.get("runtime_candidate"),
            }
            for entry in selected
        ],
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"[+] wrote {path_utils.to_repo_relative(args.out, repo_root=repo_root)}")


if __name__ == "__main__":
    main()
