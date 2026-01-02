#!/usr/bin/env python3
"""
Summarize join evidence for the libsandbox-encoder network matrix.

This is an experiment-local analyzer that scores simple join hypotheses using
the diff-anchored join artifacts. It does not alter shared mappings.

Output: out/network_matrix/join_hypotheses.json
"""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api.path_utils import find_repo_root, to_repo_relative

ROOT = find_repo_root(Path(__file__))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


OUT_DIR = ROOT / "book/experiments/field2-final-final/libsandbox-encoder/out/network_matrix"
JOIN_RECORDS_PATH = OUT_DIR / "join_records.jsonl"
JOIN_SUMMARY_PATH = OUT_DIR / "join_summary.json"
OUT_PATH = OUT_DIR / "join_hypotheses.json"


def rel(path: Path) -> str:
    return to_repo_relative(path, ROOT)


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text())


def load_join_records(path: Path) -> Dict[str, List[Dict[str, Any]]]:
    by_pair: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        pair_id = row.get("pair_id")
        if pair_id:
            by_pair[pair_id].append(row)
    return by_pair


def classify_pair(pair_id: str, diff_byte_count: int) -> Optional[str]:
    if diff_byte_count <= 0 or diff_byte_count > 2:
        return None
    if pair_id.startswith(("domain_", "type_", "proto_")):
        return "single_arg"
    if pair_id.startswith("pair_"):
        return "pairwise"
    if pair_id.startswith("triple_"):
        return "triple"
    return None


def record_role(row: Dict[str, Any]) -> Optional[str]:
    role = row.get("diff", {}).get("role", {})
    return role.get("kind")


def record_u16_index(row: Dict[str, Any]) -> Optional[int]:
    role = row.get("diff", {}).get("role", {})
    return role.get("u16_index")


def record_header_byte(row: Dict[str, Any]) -> Optional[str]:
    role = row.get("diff", {}).get("role", {})
    return role.get("header_byte")


def record_tag_kind(row: Dict[str, Any]) -> Optional[Dict[str, int]]:
    rec = row.get("record8") or {}
    rec_a = rec.get("a") or {}
    if "tag" not in rec_a or "kind" not in rec_a:
        return None
    return {"tag": int(rec_a["tag"]), "kind": int(rec_a["kind"])}


def main() -> None:
    join_summary = load_json(JOIN_SUMMARY_PATH)
    join_records = load_join_records(JOIN_RECORDS_PATH)

    by_pair = join_summary.get("by_pair", {})
    world_id = join_summary.get("world_id")

    hypotheses: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []

    categories = {
        "single_arg": {
            "expected": {"role": "u16_field_byte", "u16_index": 1},
            "pairs": [],
        },
        "pairwise": {
            "expected": {"role": "u16_field_byte", "u16_index": 0, "tag": 0, "kind_set": [11, 12, 13]},
            "pairs": [],
        },
        "triple": {
            "expected": {"role": "record_header_byte"},
            "pairs": [],
        },
    }

    for pair_id, summary in by_pair.items():
        diff_byte_count = int(summary.get("diff_byte_count", 0))
        category = classify_pair(pair_id, diff_byte_count)
        if category is None:
            skipped.append({"pair_id": pair_id, "diff_byte_count": diff_byte_count})
            continue
        categories[category]["pairs"].append(pair_id)

    for category, meta in categories.items():
        pairs = meta["pairs"]
        expected = meta["expected"]
        role_counts = Counter()
        u16_index_counts = Counter()
        header_byte_counts = Counter()
        tag_counts = Counter()
        kind_counts = Counter()
        violations: List[Dict[str, Any]] = []
        pair_summaries: List[Dict[str, Any]] = []
        total_diff_bytes = 0

        for pair_id in pairs:
            summary = by_pair.get(pair_id, {})
            diff_byte_count = int(summary.get("diff_byte_count", 0))
            total_diff_bytes += diff_byte_count
            rows = join_records.get(pair_id, [])

            pair_role_counts = Counter()
            pair_u16_index_counts = Counter()
            pair_header_byte_counts = Counter()
            pair_tag_counts = Counter()
            pair_kind_counts = Counter()

            for row in rows:
                role = record_role(row)
                if role:
                    pair_role_counts[role] += 1
                u16_index = record_u16_index(row)
                if u16_index is not None:
                    pair_u16_index_counts[str(u16_index)] += 1
                header_byte = record_header_byte(row)
                if header_byte:
                    pair_header_byte_counts[header_byte] += 1
                tag_kind = record_tag_kind(row)
                if tag_kind:
                    pair_tag_counts[str(tag_kind["tag"])] += 1
                    pair_kind_counts[str(tag_kind["kind"])] += 1

            if expected.get("role") and (pair_role_counts.get(expected["role"], 0) != diff_byte_count):
                violations.append(
                    {
                        "pair_id": pair_id,
                        "reason": "unexpected_role_mix",
                        "expected_role": expected["role"],
                        "diff_byte_count": diff_byte_count,
                        "role_counts": dict(pair_role_counts),
                    }
                )

            if expected.get("u16_index") is not None:
                expected_index = str(expected["u16_index"])
                if pair_u16_index_counts.get(expected_index, 0) != diff_byte_count:
                    violations.append(
                        {
                            "pair_id": pair_id,
                            "reason": "unexpected_u16_index",
                            "expected_u16_index": expected_index,
                            "diff_byte_count": diff_byte_count,
                            "u16_index_counts": dict(pair_u16_index_counts),
                        }
                    )

            if category == "pairwise":
                if pair_tag_counts.get("0", 0) != diff_byte_count:
                    violations.append(
                        {
                            "pair_id": pair_id,
                            "reason": "unexpected_tag",
                            "expected_tag": 0,
                            "diff_byte_count": diff_byte_count,
                            "tag_counts": dict(pair_tag_counts),
                        }
                    )
                kind_set = set(str(k) for k in expected.get("kind_set", []))
                unexpected_kinds = [k for k in pair_kind_counts.keys() if k not in kind_set]
                if unexpected_kinds:
                    violations.append(
                        {
                            "pair_id": pair_id,
                            "reason": "unexpected_kind",
                            "expected_kinds": sorted(kind_set),
                            "unexpected_kinds": unexpected_kinds,
                            "kind_counts": dict(pair_kind_counts),
                        }
                    )

            role_counts.update(pair_role_counts)
            u16_index_counts.update(pair_u16_index_counts)
            header_byte_counts.update(pair_header_byte_counts)
            tag_counts.update(pair_tag_counts)
            kind_counts.update(pair_kind_counts)
            pair_summaries.append(
                {
                    "pair_id": pair_id,
                    "diff_byte_count": diff_byte_count,
                    "role_counts": dict(pair_role_counts),
                    "u16_index_counts": dict(pair_u16_index_counts),
                    "header_byte_counts": dict(pair_header_byte_counts),
                    "tag_counts": dict(pair_tag_counts),
                    "kind_counts": dict(pair_kind_counts),
                }
            )

        hypotheses.append(
            {
                "id": f"{category}_join_pattern",
                "category": category,
                "expected": expected,
                "pairs": pairs,
                "total_diff_bytes": total_diff_bytes,
                "role_counts": dict(role_counts),
                "u16_index_counts": dict(u16_index_counts),
                "header_byte_counts": dict(header_byte_counts),
                "tag_counts": dict(tag_counts),
                "kind_counts": dict(kind_counts),
                "pair_summaries": pair_summaries,
                "violations": violations,
                "status": "ok" if not violations else "partial",
            }
        )

    payload = {
        "world_id": world_id,
        "inputs": {
            "join_summary": rel(JOIN_SUMMARY_PATH),
            "join_records": rel(JOIN_RECORDS_PATH),
        },
        "outputs": {"join_hypotheses": rel(OUT_PATH)},
        "hypotheses": hypotheses,
        "skipped_pairs": skipped,
        "notes": "Experiment-local hypothesis scoring; do not promote without additional evidence.",
    }
    OUT_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True))
    print(f"[+] wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
