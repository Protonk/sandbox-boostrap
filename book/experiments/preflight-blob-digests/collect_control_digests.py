#!/usr/bin/env python3
"""
Collect a small set of "known not apply-gated" control digests.

These are useful for detecting global apply gating in an execution context:
if a control digest that previously applied successfully now fails at apply-stage
EPERM, treat the run as blocked (environment/harness), not profile-specific.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.path_utils import to_repo_relative  # type: ignore
from book.api.profile_tools import identity as identity_mod  # type: ignore


SCHEMA_VERSION = 1

DEFAULT_WITNESSES = (
    REPO_ROOT
    / "book"
    / "graph"
    / "concepts"
    / "validation"
    / "out"
    / "experiments"
    / "gate-witnesses"
    / "witness_results.json"
)


def _rel(path: Path) -> str:
    return to_repo_relative(path, REPO_ROOT)


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text())


def _apply_ok(apply_report: Dict[str, Any] | None) -> bool:
    if not isinstance(apply_report, dict):
        return False
    return apply_report.get("rc") == 0


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="collect_control_digests")
    ap.add_argument("--gate-witnesses", type=Path, default=DEFAULT_WITNESSES)
    ap.add_argument("--apply-matrix", action="append", default=[], help="blob_apply_matrix.json path (repeatable)")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)

    world_id = identity_mod.baseline_world_id()
    combined: Dict[str, Dict[str, Any]] = {}

    if args.gate_witnesses.exists():
        w = _load_json(args.gate_witnesses)
        if w.get("world_id") != world_id:
            raise ValueError("gate-witnesses world_id mismatch")
        for witness in w.get("witnesses") or []:
            if not isinstance(witness, dict):
                continue
            target = witness.get("target")
            forensics = witness.get("forensics") or {}
            blob_apply = forensics.get("blob_apply") or {}
            for kind in ("minimal_failing", "passing_neighbor"):
                entry = blob_apply.get(kind) or {}
                sha = entry.get("blob_sha256")
                report = entry.get("apply_report")
                if not isinstance(sha, str) or not _apply_ok(report):
                    continue
                combined.setdefault(
                    sha,
                    {"blob_sha256": sha, "classification": "known_not_apply_gated_control", "evidence": []},
                )["evidence"].append(
                    {
                        "source": "gate-witnesses",
                        "witness_target": target,
                        "kind": kind,
                        "apply_report": report,
                    }
                )

    for path_str in args.apply_matrix:
        p = Path(path_str)
        m = _load_json(p)
        if m.get("world_id") != world_id:
            raise ValueError("apply matrix world_id mismatch")

        # Control digest can be a control even if other rows are gated.
        ctrl = m.get("control") or {}
        if isinstance(ctrl, dict):
            ctrl_sha = ctrl.get("blob_sha256")
            ctrl_res = (ctrl.get("result") or {}).get("apply_report") if isinstance(ctrl.get("result"), dict) else None
            if isinstance(ctrl_sha, str) and _apply_ok(ctrl_res):
                combined.setdefault(
                    ctrl_sha,
                    {"blob_sha256": ctrl_sha, "classification": "known_not_apply_gated_control", "evidence": []},
                )["evidence"].append(
                    {"source": "preflight-blob-digests", "label": m.get("label"), "blob": ctrl.get("blob"), "apply_report": ctrl_res}
                )

        for row in m.get("rows") or []:
            if not isinstance(row, dict):
                continue
            sha = row.get("blob_sha256")
            result = row.get("result") or {}
            report = result.get("apply_report") if isinstance(result, dict) else None
            if not isinstance(sha, str) or not _apply_ok(report):
                continue
            combined.setdefault(
                sha,
                {"blob_sha256": sha, "classification": "known_not_apply_gated_control", "evidence": []},
            )["evidence"].append(
                {
                    "source": "preflight-blob-digests",
                    "label": m.get("label"),
                    "blob": row.get("blob"),
                    "apply_report": report,
                    "failure_stage": result.get("failure_stage") if isinstance(result, dict) else None,
                    "failure_kind": result.get("failure_kind") if isinstance(result, dict) else None,
                }
            )

    controls = [combined[sha] for sha in sorted(combined.keys())]
    payload = {
        "tool": "book/experiments/preflight-blob-digests",
        "schema_version": SCHEMA_VERSION,
        "world_id": world_id,
        "inputs": {
            "gate_witnesses": _rel(args.gate_witnesses),
            "apply_matrices": [_rel(Path(p)) for p in args.apply_matrix],
        },
        "metrics": {"controls": len(controls)},
        "controls": controls,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

