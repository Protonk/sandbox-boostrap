#!/usr/bin/env python3
"""
Scan the in-repo `.sb.bin` digest corpus for matches to candidate structural signatures.

This consumes:
- `out/blob_structural_features.json` (decoded structure per digest)
- `out/structural_signature_candidates.json` (candidate signatures + labeled metrics)

and produces a scan artifact suitable for picking unknown digests to validate via apply.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.path_utils import to_repo_relative  # type: ignore
from book.api.profile import identity as identity_mod  # type: ignore

SCHEMA_VERSION = 2

DEFAULT_FEATURES = REPO_ROOT / "book/experiments/preflight-blob-digests/out/blob_structural_features.json"


def _rel(path: Path) -> str:
    return to_repo_relative(path, REPO_ROOT)


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text())


def _tags(features: Dict[str, Any]) -> Set[int]:
    raw = features.get("tags_present") or []
    out: Set[int] = set()
    if isinstance(raw, list):
        for v in raw:
            try:
                out.add(int(v))
            except Exception:
                continue
    return out


def _int_field(features: Dict[str, Any], field: str) -> Optional[int]:
    v = features.get(field)
    if isinstance(v, int):
        return v
    return None


def _derived_float(features: Dict[str, Any], key: str) -> Optional[float]:
    derived = features.get("derived")
    if not isinstance(derived, dict):
        return None
    v = derived.get(key)
    if isinstance(v, (int, float)):
        return float(v)
    return None


def _eval_candidate(cand: Dict[str, Any], row: Dict[str, Any]) -> bool:
    feats = row.get("features")
    if not isinstance(feats, dict):
        return False

    kind = cand.get("kind")
    if kind == "tag_present":
        tag = cand.get("tag")
        if not isinstance(tag, int):
            return False
        return tag in _tags(feats)
    if kind == "tag_or":
        tags = cand.get("tags")
        if not isinstance(tags, list):
            return False
        present = _tags(feats)
        return any(int(t) in present for t in tags)
    if kind == "tag_and":
        tags = cand.get("tags")
        if not isinstance(tags, list):
            return False
        present = _tags(feats)
        return all(int(t) in present for t in tags)
    if kind == "tags_present_count_eq":
        n = cand.get("n")
        if not isinstance(n, int):
            return False
        return _int_field(feats, "tags_present_count") == n
    if kind == "node_count_eq_op_count":
        node_count = _int_field(feats, "node_count")
        op_count = _int_field(feats, "op_count")
        return node_count is not None and op_count is not None and node_count == op_count
    if kind == "literal_pool_bytes_ratio_ge":
        threshold = cand.get("threshold")
        if not isinstance(threshold, (int, float)):
            return False
        ratio = _derived_float(feats, "literal_pool_bytes_ratio")
        return ratio is not None and ratio >= float(threshold)
    if kind == "op_table_unique_ratio_le":
        threshold = cand.get("threshold")
        if not isinstance(threshold, (int, float)):
            return False
        ratio = _derived_float(feats, "op_table_unique_ratio")
        return ratio is not None and ratio <= float(threshold)

    return False


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="scan_structural_signatures")
    ap.add_argument("--features", type=Path, default=DEFAULT_FEATURES)
    ap.add_argument("--candidates", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument(
        "--high-precision-threshold",
        type=float,
        default=1.0,
        help="threshold on labeled precision for inclusion in the unknown-hit shortlist",
    )
    args = ap.parse_args(argv)

    world_id = identity_mod.baseline_world_id()
    features_doc = _load_json(args.features)
    if features_doc.get("world_id") != world_id:
        raise ValueError("features world_id mismatch")
    cand_doc = _load_json(args.candidates)
    if cand_doc.get("world_id") != world_id:
        raise ValueError("candidates world_id mismatch")

    rows = features_doc.get("rows") or []
    if not isinstance(rows, list):
        raise ValueError("features rows must be a list")
    digest_to_row: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        if isinstance(r, dict) and isinstance(r.get("blob_sha256"), str):
            digest_to_row[r["blob_sha256"]] = r

    candidates = cand_doc.get("candidates") or []
    if not isinstance(candidates, list):
        raise ValueError("candidates list missing")

    label_counts = {"apply_gated": 0, "control": 0, "unknown": 0}
    for r in digest_to_row.values():
        label = r.get("label")
        if label in label_counts:
            label_counts[label] += 1

    scan_rows: List[Dict[str, Any]] = []
    unknown_hits: Dict[str, List[str]] = {}
    unknown_hit_best_precision: Dict[str, float] = {}

    for cand in candidates:
        if not isinstance(cand, dict):
            continue
        cid = cand.get("id")
        if not isinstance(cid, str):
            continue

        matched: Dict[str, List[str]] = {"apply_gated": [], "control": [], "unknown": []}
        for sha, row in digest_to_row.items():
            if not _eval_candidate(cand, row):
                continue
            label = row.get("label")
            if label not in matched:
                continue
            matched[label].append(sha)

        labeled_metrics = cand.get("labeled_metrics") if isinstance(cand.get("labeled_metrics"), dict) else {}
        precision = labeled_metrics.get("precision")
        precision_f = float(precision) if isinstance(precision, (float, int)) else None

        scan_rows.append(
            {
                "id": cid,
                "kind": cand.get("kind"),
                "expr": {k: v for k, v in cand.items() if k not in {"id", "labeled_metrics"}},
                "labeled_metrics": labeled_metrics,
                "matches": {k: len(v) for k, v in matched.items()},
                "matched_digests": matched,
            }
        )

        if precision_f is not None and precision_f >= float(args.high_precision_threshold):
            for sha in matched["unknown"]:
                unknown_hits.setdefault(sha, []).append(cid)
                unknown_hit_best_precision[sha] = max(unknown_hit_best_precision.get(sha, 0.0), precision_f)

    unknown_shortlist: List[Dict[str, Any]] = []
    for sha, cids in unknown_hits.items():
        row = digest_to_row.get(sha) or {}
        unknown_shortlist.append(
            {
                "blob_sha256": sha,
                "representative_path": row.get("representative_path"),
                "paths_count": row.get("paths_count"),
                "matches": sorted(set(cids)),
                "best_precision": unknown_hit_best_precision.get(sha),
            }
        )
    unknown_shortlist.sort(key=lambda r: (-len(r.get("matches") or []), str(r.get("blob_sha256"))))

    payload = {
        "tool": "book/experiments/preflight-blob-digests",
        "schema_version": SCHEMA_VERSION,
        "world_id": world_id,
        "inputs": {"features": _rel(args.features), "candidates": _rel(args.candidates)},
        "metrics": {
            "digests": len(digest_to_row),
            "labels": label_counts,
            "candidates": len(scan_rows),
            "unknown_shortlist": len(unknown_shortlist),
            "high_precision_threshold": args.high_precision_threshold,
        },
        "candidates": scan_rows,
        "unknown_shortlist": unknown_shortlist,
        "notes": [
            "This scan lists matches against candidate structural signatures; it does not upgrade them into a classifier.",
            "Use `unknown_shortlist` as a starting point for apply-validation in a control_ok context.",
        ],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
