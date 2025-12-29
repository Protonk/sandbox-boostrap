#!/usr/bin/env python3
"""
Extract compact, stable structural features from compiled blobs (`.sb.bin`).

This is intended for *structural signal listening* only:
- it does not run sandbox apply
- it does not claim semantics
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.path_utils import to_repo_relative  # type: ignore
from book.api.profile import decoder as pt_decoder  # type: ignore
from book.api.profile import identity as identity_mod  # type: ignore
from book.api.profile import ingestion as pt_ingestion  # type: ignore


SCHEMA_VERSION = 2


def _ratio(numer: Optional[int], denom: Optional[int]) -> Optional[float]:
    if not isinstance(numer, int) or not isinstance(denom, int) or denom <= 0:
        return None
    # Keep a small, stable precision so JSON artifacts are diff-friendly.
    return round(numer / denom, 6)


def _rel(path: Path) -> str:
    return to_repo_relative(path, REPO_ROOT)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text())


def _inventory_digest_to_paths(inventory: Dict[str, Any]) -> Dict[str, List[str]]:
    digest_to_paths: Dict[str, List[str]] = {}
    for row in inventory.get("rows") or []:
        if not isinstance(row, dict):
            continue
        sha = row.get("sha256")
        p = row.get("path")
        if isinstance(sha, str) and isinstance(p, str):
            digest_to_paths.setdefault(sha, []).append(p)
    for sha in list(digest_to_paths.keys()):
        digest_to_paths[sha] = sorted(set(digest_to_paths[sha]))
    return digest_to_paths


def _representative_path(paths: List[str]) -> Optional[str]:
    return sorted(paths)[0] if paths else None


def _decode_features(blob: bytes) -> Dict[str, Any]:
    decoded = pt_decoder.decode_profile_dict(blob)
    tag_counts_raw = decoded.get("tag_counts") or {}
    tag_counts: Dict[int, int] = {}
    if isinstance(tag_counts_raw, dict):
        for k, v in tag_counts_raw.items():
            try:
                tag_counts[int(k)] = int(v)
            except Exception:
                continue

    op_table = decoded.get("op_table") or []
    op_table_list: List[int] = []
    if isinstance(op_table, list):
        for v in op_table:
            if isinstance(v, int):
                op_table_list.append(v)

    tags_present = sorted(tag_counts.keys())
    literal_strings = decoded.get("literal_strings") or []
    literal_string_count = len(literal_strings) if isinstance(literal_strings, list) else None

    sections = decoded.get("sections") if isinstance(decoded.get("sections"), dict) else {}
    validation = decoded.get("validation") if isinstance(decoded.get("validation"), dict) else {}

    blob_size = len(blob)
    nodes_bytes = sections.get("nodes") if isinstance(sections, dict) else None
    literal_pool_bytes = sections.get("literal_pool") if isinstance(sections, dict) else None

    derived = {
        "op_table_unique_ratio": _ratio(len(set(op_table_list)), len(op_table_list)) if op_table_list else None,
        "nodes_bytes_ratio": _ratio(nodes_bytes, blob_size),
        "literal_pool_bytes_ratio": _ratio(literal_pool_bytes, blob_size),
        "literal_pool_bytes_per_node": _ratio(literal_pool_bytes, decoded.get("node_count") if isinstance(decoded.get("node_count"), int) else None),
        "literal_strings_per_node": _ratio(
            (literal_string_count if isinstance(literal_string_count, int) else None),
            (decoded.get("node_count") if isinstance(decoded.get("node_count"), int) else None),
        ),
    }

    return {
        "format_variant": decoded.get("format_variant"),
        "op_count": decoded.get("op_count"),
        "node_count": decoded.get("node_count"),
        "op_table_offset": decoded.get("op_table_offset"),
        "op_table_len": len(op_table_list),
        "op_table_unique": len(set(op_table_list)),
        "op_table_min": min(op_table_list) if op_table_list else None,
        "op_table_max": max(op_table_list) if op_table_list else None,
        "tag_counts": {str(k): tag_counts[k] for k in tags_present},
        "tags_present": tags_present,
        "tags_present_count": len(tags_present),
        "tag_total_count": sum(tag_counts.values()),
        "literal_string_count": literal_string_count,
        "derived": derived,
        "sections": {
            "op_table": sections.get("op_table"),
            "nodes": sections.get("nodes"),
            "literal_pool": sections.get("literal_pool"),
            "nodes_start": sections.get("nodes_start"),
            "literal_start": sections.get("literal_start"),
        },
        "validation": {
            "node_stride_bytes": validation.get("node_stride_bytes"),
            "node_remainder_bytes": validation.get("node_remainder_bytes"),
            "edge_fields_in_bounds": validation.get("edge_fields_in_bounds"),
            "edge_fields_total": validation.get("edge_fields_total"),
        },
    }


def _fallback_header_features(blob: bytes) -> Dict[str, Any]:
    header = pt_ingestion.parse_header(pt_ingestion.ProfileBlob(bytes=blob, source="structural_features"))
    return {
        "format_variant": header.format_variant,
        "op_count_guess": header.operation_count,
        "raw_length": header.raw_length,
    }


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="extract_structural_features")
    ap.add_argument("--inventory", type=Path, required=True, help="repo_sb_bin_inventory.json")
    ap.add_argument("--sets", type=Path, required=True, help="structural_signal_sets.json")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--only-labeled", action="store_true", help="only process apply-gated and control digests")
    args = ap.parse_args(argv)

    world_id = identity_mod.baseline_world_id()
    inv = _load_json(args.inventory)
    sets = _load_json(args.sets)
    if inv.get("world_id") != world_id:
        raise ValueError("inventory world_id mismatch")
    if sets.get("world_id") != world_id:
        raise ValueError("sets world_id mismatch")

    digest_to_paths = _inventory_digest_to_paths(inv)

    apply_gated_set = {d["blob_sha256"] for d in (sets.get("apply_gated_digests") or []) if isinstance(d, dict)}
    control_set = {d["blob_sha256"] for d in (sets.get("control_digests") or []) if isinstance(d, dict)}

    digests = sorted(digest_to_paths.keys())
    if args.only_labeled:
        digests = sorted(apply_gated_set | control_set)

    rows: List[Dict[str, Any]] = []
    decode_ok = 0
    decode_err = 0
    for sha in digests:
        paths = digest_to_paths.get(sha) or []
        rep = _representative_path(paths)
        if rep is None:
            rows.append(
                {
                    "blob_sha256": sha,
                    "label": "unknown",
                    "representative_path": None,
                    "paths_count": 0,
                    "error": "missing_paths",
                }
            )
            decode_err += 1
            continue

        label = "unknown"
        if sha in apply_gated_set:
            label = "apply_gated"
        elif sha in control_set:
            label = "control"

        abs_path = REPO_ROOT / rep
        try:
            blob = abs_path.read_bytes()
        except Exception as exc:
            rows.append(
                {
                    "blob_sha256": sha,
                    "label": label,
                    "representative_path": rep,
                    "paths_count": len(paths),
                    "error": f"read_failed:{exc}",
                }
            )
            decode_err += 1
            continue

        computed = _sha256_bytes(blob)
        if computed != sha:
            rows.append(
                {
                    "blob_sha256": sha,
                    "label": label,
                    "representative_path": rep,
                    "paths_count": len(paths),
                    "size": len(blob),
                    "error": "sha256_mismatch",
                    "computed_sha256": computed,
                }
            )
            decode_err += 1
            continue

        try:
            features = _decode_features(blob)
            decode_ok += 1
            rows.append(
                {
                    "blob_sha256": sha,
                    "label": label,
                    "representative_path": rep,
                    "paths_count": len(paths),
                    "paths_sample": paths[:5],
                    "size": len(blob),
                    "features": features,
                }
            )
        except Exception as exc:
            decode_err += 1
            rows.append(
                {
                    "blob_sha256": sha,
                    "label": label,
                    "representative_path": rep,
                    "paths_count": len(paths),
                    "paths_sample": paths[:5],
                    "size": len(blob),
                    "error": f"decode_failed:{exc}",
                    "fallback": _fallback_header_features(blob),
                }
            )

    payload = {
        "tool": "book/experiments/preflight-blob-digests",
        "schema_version": SCHEMA_VERSION,
        "world_id": world_id,
        "inputs": {"inventory": _rel(args.inventory), "sets": _rel(args.sets)},
        "metrics": {"digests": len(digests), "decode_ok": decode_ok, "decode_err": decode_err},
        "rows": rows,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
