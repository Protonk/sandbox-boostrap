#!/usr/bin/env python3
"""
Compare one or more blob-apply-matrix runs to detect:
- global apply gating contexts (control_ok=false), and
- digest-level outcome flips across contexts.

This helps prevent misreading “apply-stage EPERM” as a profile-specific signal
when the execution environment is globally gated.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.path_utils import to_repo_relative  # type: ignore
from book.api.profile_tools import identity as identity_mod  # type: ignore


SCHEMA_VERSION = 1


def _rel(path: Path) -> str:
    return to_repo_relative(path, REPO_ROOT)


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text())


def _index_matrix(matrix: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for row in matrix.get("rows") or []:
        if isinstance(row, dict) and isinstance(row.get("blob_sha256"), str):
            out[row["blob_sha256"]] = str(row.get("classification"))
    return out


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="compare_apply_matrices")
    ap.add_argument("--matrix", action="append", default=[], help="blob_apply_matrix.json path (repeatable)")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)

    if not args.matrix:
        raise SystemExit("provide at least one --matrix")

    world_id = identity_mod.baseline_world_id()
    matrices: List[Dict[str, Any]] = []
    for p in args.matrix:
        path = Path(p)
        m = _load_json(path)
        if m.get("world_id") != world_id:
            raise ValueError(f"world_id mismatch in {p}")
        matrices.append({"path": _rel(path), "label": m.get("label"), "control_ok": bool(m.get("control_ok")), "raw": m})

    digest_labels: Dict[str, Dict[str, str]] = {}
    for m in matrices:
        label = str(m.get("label") or m["path"])
        idx = _index_matrix(m["raw"])
        for sha, cls in idx.items():
            digest_labels.setdefault(sha, {})[label] = cls

    # Any digest that has both apply_gated_eperm and not_apply_gated across runs is a flip.
    flips: List[Dict[str, Any]] = []
    for sha, per_label in sorted(digest_labels.items()):
        classes = set(per_label.values())
        if "apply_gated_eperm" in classes and "not_apply_gated" in classes:
            flips.append({"blob_sha256": sha, "by_label": per_label})

    payload = {
        "tool": "book/experiments/preflight-blob-digests",
        "schema_version": SCHEMA_VERSION,
        "world_id": world_id,
        "inputs": {"matrices": [m["path"] for m in matrices]},
        "matrices": [
            {
                "path": m["path"],
                "label": m.get("label"),
                "control_ok": m.get("control_ok"),
                "control_classification": (m["raw"].get("control") or {}).get("classification"),
            }
            for m in matrices
        ],
        "flips": flips,
        "metrics": {
            "matrices": len(matrices),
            "digests_seen": len(digest_labels),
            "flips": len(flips),
            "contexts_control_ok": sum(1 for m in matrices if m.get("control_ok")),
            "contexts_control_blocked": sum(1 for m in matrices if not m.get("control_ok")),
        },
        "notes": [
            "If a context has control_ok=false, its apply_gated_eperm rows are treated as global apply gating (harness/environment), not profile-specific evidence.",
            "Only apply_gated_eperm observed in control_ok=true contexts is treated as a profile-specific apply gate witness.",
        ],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

