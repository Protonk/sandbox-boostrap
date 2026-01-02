#!/usr/bin/env python3
"""
Select the next field2 tranche from a frontier file.

The output is a small, checkable tranche record that drives the next cycle.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import sys

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils

SCHEMA_VERSION = "field2-tranche.v0"
DEFAULT_FRONTIER = (
    REPO_ROOT
    / "book"
    / "experiments"
    / "field2-final-final"
    / "out"
    / "frontier.json"
)
DEFAULT_OUT = (
    REPO_ROOT
    / "book"
    / "experiments"
    / "field2-final-final"
    / "out"
    / "tranche.json"
)


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _eligible(candidate: Dict[str, Any]) -> bool:
    status = candidate.get("status")
    if status in {"runtime_backed", "runtime_backed_historical"}:
        return False
    return True


def _pick_candidate(candidates: List[Dict[str, Any]], *, field2: Optional[int], filter_name: Optional[str]) -> Dict[str, Any]:
    if field2 is not None:
        for cand in candidates:
            if cand.get("field2") == field2:
                return cand
        raise ValueError(f"field2 {field2} not found in frontier")
    if filter_name:
        for cand in candidates:
            if cand.get("filter_name") == filter_name:
                return cand
        raise ValueError(f"filter name {filter_name} not found in frontier")

    eligible = [cand for cand in candidates if _eligible(cand)]
    if not eligible:
        raise ValueError("no eligible frontier candidates")

    eligible.sort(key=lambda c: (c.get("score", 0), c.get("anchor_count", 0)), reverse=True)
    return eligible[0]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frontier", type=Path, default=DEFAULT_FRONTIER)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--field2", type=int, default=None)
    parser.add_argument("--filter-name", type=str, default=None)
    args = parser.parse_args()

    repo_root = path_utils.find_repo_root(Path(__file__).resolve())
    frontier = load_json(args.frontier)
    candidates = frontier.get("candidates") or []
    selected = _pick_candidate(candidates, field2=args.field2, filter_name=args.filter_name)

    anchors = selected.get("anchors_sample") or []
    target_ops = selected.get("target_ops") or []

    tranche = {
        "schema_version": SCHEMA_VERSION,
        "world_id": frontier.get("world_id"),
        "frontier": path_utils.to_repo_relative(args.frontier, repo_root=repo_root),
        "selected": selected,
        "decision_needed": "Define one discriminating micro-suite and either promote a mapping delta or retire this field2 as opaque/blocked.",
        "fast_discriminator": {
            "tool": "sandbox_check",
            "operation": target_ops[0] if target_ops else None,
            "filter_name": selected.get("filter_name"),
            "argument": anchors[0] if anchors else None,
            "notes": "Use sandbox_check as a preflight discriminator; operation-stage confirmation is still required.",
        },
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(tranche, indent=2) + "\n")
    print(f"[+] wrote {path_utils.to_repo_relative(args.out, repo_root=repo_root)}")


if __name__ == "__main__":
    main()
