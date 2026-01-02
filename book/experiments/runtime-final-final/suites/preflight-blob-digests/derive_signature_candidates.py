#!/usr/bin/env python3
"""
Derive candidate *structural signatures* for apply gating from decoded blob features.

This script is intentionally conservative about meaning:
- It operates only on static, decoded structure from `.sb.bin` blobs.
- It produces *candidates* for later validation, not a classifier.
- Any correlation is **partial/brittle** until expanded and regression-checked.
"""

from __future__ import annotations

import argparse
import itertools
import json
import sys
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.path_utils import to_repo_relative  # type: ignore
from book.api.profile import identity as identity_mod  # type: ignore

SCHEMA_VERSION = 2

DEFAULT_FEATURES = REPO_ROOT / "book/experiments/runtime-final-final/suites/preflight-blob-digests/out/blob_structural_features.json"


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


def _metrics(
    positives: Sequence[Dict[str, Any]],
    negatives: Sequence[Dict[str, Any]],
    predicate: Callable[[Dict[str, Any]], bool],
) -> Dict[str, Any]:
    tp = sum(1 for r in positives if predicate(r))
    fp = sum(1 for r in negatives if predicate(r))
    fn = len(positives) - tp
    tn = len(negatives) - fp

    precision: Optional[float]
    recall: Optional[float]
    if tp + fp == 0:
        precision = None
    else:
        precision = tp / (tp + fp)
    recall = (tp / len(positives)) if positives else None

    f1: Optional[float]
    if precision is None or recall is None or (precision + recall) == 0:
        f1 = None if precision is None or recall is None else 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "pos_total": len(positives),
        "neg_total": len(negatives),
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def _candidate_tag_present(tag: int) -> Tuple[Dict[str, Any], Callable[[Dict[str, Any]], bool]]:
    cand = {"kind": "tag_present", "tag": tag}

    def pred(row: Dict[str, Any]) -> bool:
        feats = row.get("features") or {}
        return tag in _tags(feats if isinstance(feats, dict) else {})

    return cand, pred


def _candidate_tag_or(tags: Sequence[int]) -> Tuple[Dict[str, Any], Callable[[Dict[str, Any]], bool]]:
    tag_list = sorted({int(t) for t in tags})
    cand = {"kind": "tag_or", "tags": tag_list}

    def pred(row: Dict[str, Any]) -> bool:
        feats = row.get("features") or {}
        present = _tags(feats if isinstance(feats, dict) else {})
        return any(t in present for t in tag_list)

    return cand, pred


def _candidate_tag_and(tags: Sequence[int]) -> Tuple[Dict[str, Any], Callable[[Dict[str, Any]], bool]]:
    tag_list = sorted({int(t) for t in tags})
    cand = {"kind": "tag_and", "tags": tag_list}

    def pred(row: Dict[str, Any]) -> bool:
        feats = row.get("features") or {}
        present = _tags(feats if isinstance(feats, dict) else {})
        return all(t in present for t in tag_list)

    return cand, pred


def _candidate_tags_present_count_eq(n: int) -> Tuple[Dict[str, Any], Callable[[Dict[str, Any]], bool]]:
    cand = {"kind": "tags_present_count_eq", "n": n}

    def pred(row: Dict[str, Any]) -> bool:
        feats = row.get("features") or {}
        v = _int_field(feats if isinstance(feats, dict) else {}, "tags_present_count")
        return v == n

    return cand, pred


def _candidate_node_count_eq_op_count() -> Tuple[Dict[str, Any], Callable[[Dict[str, Any]], bool]]:
    cand = {"kind": "node_count_eq_op_count"}

    def pred(row: Dict[str, Any]) -> bool:
        feats = row.get("features") or {}
        if not isinstance(feats, dict):
            return False
        node_count = _int_field(feats, "node_count")
        op_count = _int_field(feats, "op_count")
        return node_count is not None and op_count is not None and node_count == op_count

    return cand, pred


def _candidate_literal_pool_ratio_ge(threshold: float) -> Tuple[Dict[str, Any], Callable[[Dict[str, Any]], bool]]:
    cand = {"kind": "literal_pool_bytes_ratio_ge", "threshold": float(threshold)}

    def pred(row: Dict[str, Any]) -> bool:
        feats = row.get("features") or {}
        if not isinstance(feats, dict):
            return False
        ratio = _derived_float(feats, "literal_pool_bytes_ratio")
        return ratio is not None and ratio >= float(threshold)

    return cand, pred


def _candidate_op_table_unique_ratio_le(threshold: float) -> Tuple[Dict[str, Any], Callable[[Dict[str, Any]], bool]]:
    cand = {"kind": "op_table_unique_ratio_le", "threshold": float(threshold)}

    def pred(row: Dict[str, Any]) -> bool:
        feats = row.get("features") or {}
        if not isinstance(feats, dict):
            return False
        ratio = _derived_float(feats, "op_table_unique_ratio")
        return ratio is not None and ratio <= float(threshold)

    return cand, pred


def _candidate_id(cand: Dict[str, Any]) -> str:
    kind = str(cand.get("kind"))
    if kind == "tag_present":
        return f"tag_present:{cand.get('tag')}"
    if kind in {"tag_or", "tag_and"}:
        tags = cand.get("tags") or []
        return f"{kind}:{','.join(str(int(t)) for t in tags)}"
    if kind == "tags_present_count_eq":
        return f"tags_present_count_eq:{cand.get('n')}"
    if kind == "node_count_eq_op_count":
        return "node_count_eq_op_count"
    if kind == "literal_pool_bytes_ratio_ge":
        return f"literal_pool_bytes_ratio_ge:{cand.get('threshold')}"
    if kind == "op_table_unique_ratio_le":
        return f"op_table_unique_ratio_le:{cand.get('threshold')}"
    return kind


def _sorted_candidate_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    def key(r: Dict[str, Any]) -> Tuple:
        m = r.get("labeled_metrics") or {}
        tp = int(m.get("tp", 0))
        fp = int(m.get("fp", 0))
        precision = m.get("precision")
        recall = m.get("recall")
        # Prefer zero false positives, then higher recall, then higher tp.
        precision_key = -1.0 if precision is None else float(precision)
        recall_key = -1.0 if recall is None else float(recall)
        return (fp, -recall_key, -precision_key, -tp, str(r.get("id")))

    return sorted(rows, key=key)


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="derive_signature_candidates")
    ap.add_argument("--features", type=Path, default=DEFAULT_FEATURES)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)

    world_id = identity_mod.baseline_world_id()
    features_doc = _load_json(args.features)
    if features_doc.get("world_id") != world_id:
        raise ValueError("features world_id mismatch")

    rows = features_doc.get("rows") or []
    if not isinstance(rows, list):
        raise ValueError("features rows must be a list")

    positives = [r for r in rows if isinstance(r, dict) and r.get("label") == "apply_gated" and isinstance(r.get("features"), dict)]
    negatives = [r for r in rows if isinstance(r, dict) and r.get("label") == "control" and isinstance(r.get("features"), dict)]
    if not positives or not negatives:
        raise ValueError("need at least one apply_gated and one control row to derive candidates")

    # "Core" tags for small OR/AND exploration:
    # - tags that appear in >=2 apply-gated digests, plus
    # - tags from any apply-gated digest with very small tag sets (to avoid airlock-sized unions dominating).
    pos_tag_support: Dict[int, int] = {}
    small_pos_tags: Set[int] = set()
    for r in positives:
        feats = r["features"]
        tags = _tags(feats)
        for t in tags:
            pos_tag_support[t] = pos_tag_support.get(t, 0) + 1
        tpc = _int_field(feats, "tags_present_count")
        if tpc is not None and tpc <= 2:
            small_pos_tags |= tags

    core_tags = sorted({t for t, c in pos_tag_support.items() if c >= 2} | small_pos_tags)

    candidates: List[Dict[str, Any]] = []

    # Scalar candidates (very small set).
    cand, pred = _candidate_node_count_eq_op_count()
    candidates.append({"id": _candidate_id(cand), **cand, "labeled_metrics": _metrics(positives, negatives, pred)})

    observed_counts: Set[int] = set()
    for r in positives + negatives:
        tpc = _int_field(r["features"], "tags_present_count")
        if tpc is not None:
            observed_counts.add(tpc)
    for n in sorted(observed_counts):
        cand, pred = _candidate_tags_present_count_eq(n)
        candidates.append({"id": _candidate_id(cand), **cand, "labeled_metrics": _metrics(positives, negatives, pred)})

    # Derived "density/ratio" candidates (new; still structural-only).
    literal_pool_ratio_thresholds = [0.05, 0.1, 0.25, 0.5, 0.75]
    for t in literal_pool_ratio_thresholds:
        cand, pred = _candidate_literal_pool_ratio_ge(t)
        candidates.append({"id": _candidate_id(cand), **cand, "labeled_metrics": _metrics(positives, negatives, pred)})

    op_table_unique_ratio_thresholds = [0.1, 0.2, 0.25, 0.5]
    for t in op_table_unique_ratio_thresholds:
        cand, pred = _candidate_op_table_unique_ratio_le(t)
        candidates.append({"id": _candidate_id(cand), **cand, "labeled_metrics": _metrics(positives, negatives, pred)})

    # Single-tag predicates on core_tags.
    for t in core_tags:
        cand, pred = _candidate_tag_present(t)
        candidates.append({"id": _candidate_id(cand), **cand, "labeled_metrics": _metrics(positives, negatives, pred)})

    # Small OR/AND combinations on core_tags.
    for k in (2, 3):
        for tags in itertools.combinations(core_tags, k):
            cand, pred = _candidate_tag_or(tags)
            candidates.append({"id": _candidate_id(cand), **cand, "labeled_metrics": _metrics(positives, negatives, pred)})
    for k in (2,):
        for tags in itertools.combinations(core_tags, k):
            cand, pred = _candidate_tag_and(tags)
            candidates.append({"id": _candidate_id(cand), **cand, "labeled_metrics": _metrics(positives, negatives, pred)})

    payload = {
        "tool": "book/experiments/runtime-final-final/suites/preflight-blob-digests",
        "schema_version": SCHEMA_VERSION,
        "world_id": world_id,
        "inputs": {"features": _rel(args.features)},
        "labels": {"positive": "apply_gated", "negative": "control"},
        "core_tags": core_tags,
        "metrics": {
            "positives": len(positives),
            "negatives": len(negatives),
            "candidates": len(candidates),
        },
        "candidates": _sorted_candidate_rows(candidates),
        "notes": [
            "These are *candidate* structural signatures derived from a very small labeled set.",
            "Treat any correlation as partial/brittle until expanded and regression-checked.",
            "The derived ratio candidates (literal-pool density, op-table uniqueness ratio) are structural-only and do not imply anything about semantics.",
        ],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
