#!/usr/bin/env python3
"""
Summarize per-tag field roles (candidate filter_id vs payload) from existing artifacts.

Inputs:
- Local tag layout overrides (out/tag_layout_overrides.json)
- Field2 encoder matrix (out/field2_encoder_matrix.json)
- Optional extra blobs (tiny profiles) to observe field variability across runs

Output:
- Prints a small table per tag with:
  - candidate filter_id field (values matching filters.json)
  - candidate payload field (values that vary across probes)
  - literal_refs presence
  - supporting profiles
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Dict, Any, List

ROOT = Path(__file__).resolve().parents[3]

def load_filters() -> Dict[int, str]:
    data = json.loads((ROOT / "book/integration/carton/bundle/relationships/mappings/vocab/filters.json").read_text())
    return {entry["id"]: entry["name"] for entry in data.get("filters", [])}

def load_matrix(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text())


def main() -> None:
    filters = load_filters()
    matrix_paths = sorted((ROOT / "book/evidence/experiments/field2-final-final/libsandbox-encoder/out").glob("matrix_v*_field2_encoder_matrix.json"))
    matrices = {p.stem.replace("_field2_encoder_matrix", ""): load_matrix(p) for p in matrix_paths}

    # Aggregate by tag
    agg_by_matrix: Dict[str, Dict[int, Dict[str, Any]]] = {}

    for mname, matrix in matrices.items():
        agg: Dict[int, Dict[str, Any]] = defaultdict(lambda: {"filter_values": set(), "rows": [], "field_variability": defaultdict(set), "by_filter_arg": defaultdict(list)})
        for row in matrix.get("rows", []):
            tag = row.get("tag")
            raw = row.get("field2_raw")
            filter_name = row.get("filter_name")
            agg[tag]["filter_values"].add((raw, filter_name))
            agg[tag]["rows"].append(row)
            # capture per-field variability
            fields: List[int] = row.get("fields", [])
            for idx, val in enumerate(fields):
                agg[tag]["field_variability"][idx].add(val)
            key = (row.get("filter_name"), row.get("op_hint"), tuple(sorted(row.get("literal_refs", []))), row.get("field2_raw"))
            agg[tag]["by_filter_arg"][key].append(fields)
        agg_by_matrix[mname] = agg

    # Build a simple table: for each tag, list filter_id candidates and variability
    out = {}
    for mname, agg in agg_by_matrix.items():
        rows = []
        for tag, info in sorted(agg.items()):
            filter_vals = sorted(info["filter_values"])
            literals = sum(1 for r in info["rows"] if r.get("literal_refs"))
            field_var = {str(idx): sorted(vals) for idx, vals in info["field_variability"].items()}
            # payload candidates: for each (filter_name/op/literals/field2) bucket, note variability of other fields
            payload_candidates: Dict[str, Any] = {}
            for key, rows_list in info["by_filter_arg"].items():
                fname, op_hint, lits, field2_val = key
                per_field = defaultdict(set)
                for f in rows_list:
                    for i, v in enumerate(f):
                        per_field[i].add(v)
                payload_candidates[str(key)] = {str(i): sorted(vs) for i, vs in per_field.items()}
            rows.append(
                {
                    "tag": tag,
                    "filter_vals": filter_vals,
                    "field_variability": field_var,
                    "payload_candidates": payload_candidates,
                    "literal_rows": literals,
                    "row_count": len(info["rows"]),
                }
            )
        out[mname] = rows

    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
