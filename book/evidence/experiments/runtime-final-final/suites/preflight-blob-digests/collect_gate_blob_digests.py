#!/usr/bin/env python3
"""
Harvest a small corpus of *known apply-gated* compiled blobs (`.sb.bin`)
from:

- the gate-witnesses validation output (minimized witnesses), plus
- optional direct blob-apply measurements from this experiment (e.g., sys:* fixtures).

This is intentionally static: it does not compile or apply profiles.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple


def _find_repo_root(start: Path) -> Path:
    cur = start.resolve()
    agents_root: Path | None = None
    for candidate in [cur] + list(cur.parents):
        if (candidate / ".git").exists():
            return candidate
        if (candidate / "AGENTS.md").exists():
            agents_root = candidate
    if agents_root:
        return agents_root
    raise RuntimeError("Unable to locate repository root")


REPO_ROOT = _find_repo_root(Path(__file__))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.path_utils import to_repo_relative  # type: ignore
from book.api.profile import identity as identity_mod  # type: ignore


SCHEMA_VERSION = 1

DEFAULT_SOURCE = (
    REPO_ROOT
    / "book"
    / "evidence"
    / "syncretic"
    / "validation"
    / "out"
    / "experiments"
    / "gate-witnesses"
    / "witness_results.json"
)
FORENSICS_ROOT = (
    REPO_ROOT
    / "book"
    / "evidence"
    / "syncretic"
    / "validation"
    / "out"
    / "experiments"
    / "gate-witnesses"
    / "forensics"
)
PATH_REWRITES: Tuple[Tuple[str, str], ...] = (
    ("book/evidence/graph/concepts/validation/", "book/evidence/syncretic/validation/"),
)


def _rel(path: Path) -> str:
    return to_repo_relative(path, REPO_ROOT)


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text())


def _rewrite_repo_path(path: str) -> str:
    for source, target in PATH_REWRITES:
        if path.startswith(source):
            return f"{target}{path[len(source):]}"
    return path


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_apply_gate_report(apply_report: Dict[str, Any] | None) -> bool:
    if not isinstance(apply_report, dict):
        return False
    # Contract layer normalizes this; prefer err_class to avoid relying on errbuf text.
    if apply_report.get("err_class") == "errno_eperm":
        return True
    return apply_report.get("rc") == -1 and apply_report.get("errno") == 1


def _collect_apply_gated_digests(witness_results: Dict[str, Any]) -> List[Dict[str, Any]]:
    digests: Dict[str, List[Dict[str, Any]]] = {}

    witnesses = witness_results.get("witnesses") or []
    for w in witnesses:
        target = w.get("target")
        if not isinstance(target, str):
            continue
        forensics = w.get("forensics") or {}
        blob_apply = forensics.get("blob_apply") or {}
        for kind in ("minimal_failing", "passing_neighbor"):
            entry = blob_apply.get(kind) or {}
            blob_sha = entry.get("blob_sha256")
            apply_report = entry.get("apply_report")
            if not isinstance(blob_sha, str):
                continue
            if not _is_apply_gate_report(apply_report):
                continue

            blob_path = (
                REPO_ROOT
                / "book"
                / "evidence"
                / "syncretic"
                / "validation"
                / "out"
                / "experiments"
                / "gate-witnesses"
                / "forensics"
                / target
                / f"{kind}.sb.bin"
            )
            evidence = {
                "source": "gate-witnesses",
                "witness_target": target,
                "kind": kind,
                "blob_path": _rel(blob_path),
                "apply_report": apply_report,
            }
            digests.setdefault(blob_sha, []).append(evidence)

    out: List[Dict[str, Any]] = []
    for sha, evidence_list in sorted(digests.items()):
        out.append(
            {
                "blob_sha256": sha,
                "classification": "apply_gated_for_harness_identity",
                "evidence": sorted(
                    evidence_list,
                    key=lambda e: (str(e.get("witness_target")), str(e.get("kind")), str(e.get("blob_path"))),
                ),
            }
        )
    return out


def _collect_forensics_minimal_failing() -> List[Dict[str, Any]]:
    digests: Dict[str, List[Dict[str, Any]]] = {}
    if not FORENSICS_ROOT.exists():
        return []

    for target_dir in sorted(FORENSICS_ROOT.iterdir()):
        if not target_dir.is_dir():
            continue
        blob_path = target_dir / "minimal_failing.sb.bin"
        if not blob_path.exists():
            continue
        blob_sha = _sha256_file(blob_path)
        evidence = {
            "source": "gate-witnesses-forensics",
            "witness_target": target_dir.name,
            "kind": "minimal_failing",
            "blob_path": _rel(blob_path),
            "note": "derived from forensics blob; witness_results empty or blocked",
        }
        digests.setdefault(blob_sha, []).append(evidence)

    out: List[Dict[str, Any]] = []
    for sha, evidence_list in sorted(digests.items()):
        out.append(
            {
                "blob_sha256": sha,
                "classification": "apply_gated_for_harness_identity",
                "evidence": sorted(
                    evidence_list,
                    key=lambda e: (str(e.get("witness_target")), str(e.get("kind")), str(e.get("blob_path"))),
                ),
            }
        )
    return out


def _merge_apply_matrix(
    existing: Dict[str, Dict[str, Any]],
    apply_matrix: Dict[str, Any],
) -> None:
    baseline_world = identity_mod.baseline_world_id()
    if apply_matrix.get("world_id") != baseline_world:
        raise ValueError("apply matrix world_id mismatch")
    if not apply_matrix.get("control_ok"):
        raise ValueError("apply matrix control_ok is false; refusing to treat results as profile-specific")

    label = apply_matrix.get("label")
    rows = apply_matrix.get("rows") or []
    if not isinstance(rows, list):
        raise ValueError("apply matrix rows must be a list")
    for row in rows:
        if not isinstance(row, dict):
            continue
        if row.get("classification") != "apply_gated_eperm":
            continue
        sha = row.get("blob_sha256")
        blob_path = row.get("blob")
        result = row.get("result") or {}
        if not isinstance(sha, str) or not isinstance(blob_path, str):
            continue
        blob_path = _rewrite_repo_path(blob_path)
        evidence = {
            "source": "preflight-blob-digests",
            "label": label,
            "blob_path": blob_path,
            "apply_report": (result.get("apply_report") if isinstance(result, dict) else None),
            "failure_stage": result.get("failure_stage") if isinstance(result, dict) else None,
            "failure_kind": result.get("failure_kind") if isinstance(result, dict) else None,
        }
        if sha not in existing:
            existing[sha] = {
                "blob_sha256": sha,
                "classification": "apply_gated_for_harness_identity",
                "evidence": [],
            }
        existing[sha]["evidence"].append(evidence)


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="collect_gate_blob_digests")
    ap.add_argument("--source", type=Path, default=DEFAULT_SOURCE, help="gate-witnesses witness_results.json path")
    ap.add_argument(
        "--apply-matrix",
        action="append",
        default=[],
        help="optional blob_apply_matrix.json (control_ok context) to fold in additional apply-gated digests (repeatable)",
    )
    ap.add_argument("--out", type=Path, required=True, help="output JSON path")
    args = ap.parse_args(argv)

    baseline_world = identity_mod.baseline_world_id()
    witness_results = _load_json(args.source)
    source_world = witness_results.get("world_id")
    if source_world != baseline_world:
        raise ValueError(f"world_id mismatch: source={source_world!r} baseline={baseline_world!r}")

    combined: Dict[str, Dict[str, Any]] = {}
    forensics_used = False
    witness_entries = _collect_apply_gated_digests(witness_results)
    if witness_entries:
        for entry in witness_entries:
            combined[entry["blob_sha256"]] = entry
    else:
        for entry in _collect_forensics_minimal_failing():
            combined[entry["blob_sha256"]] = entry
        forensics_used = bool(combined)

    apply_matrices: List[str] = []
    for apply_matrix_path in args.apply_matrix:
        p = Path(apply_matrix_path)
        if not p.exists():
            continue
        apply_matrix = _load_json(p)
        _merge_apply_matrix(combined, apply_matrix)
        apply_matrices.append(_rel(p))

    payload = {
        "tool": "book/evidence/experiments/runtime-final-final/suites/preflight-blob-digests",
        "schema_version": SCHEMA_VERSION,
        "world_id": baseline_world,
        "inputs": {
            "gate_witnesses_witness_results": _rel(args.source),
            "gate_witnesses_forensics": _rel(FORENSICS_ROOT) if forensics_used else None,
            "apply_matrices": apply_matrices or None,
        },
        "apply_gate_digests": [combined[sha] for sha in sorted(combined.keys())],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
