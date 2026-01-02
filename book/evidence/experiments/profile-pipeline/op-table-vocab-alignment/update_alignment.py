#!/usr/bin/env python3
"""
Regenerate op_table_vocab_alignment.json using the harvested Operation Vocabulary.

Inputs:
- book/evidence/experiments/profile-pipeline/op-table-operation/out/summary.json
- book/evidence/graph/mappings/vocab/ops.json
- book/evidence/graph/mappings/vocab/filters.json

Outputs:
- book/evidence/experiments/profile-pipeline/op-table-vocab-alignment/out/op_table_vocab_alignment.json
"""

from __future__ import annotations

import json
import hashlib
from pathlib import Path
import sys


def _find_repo_root(start: Path) -> Path:
    cur = start.resolve()
    for candidate in [cur] + list(cur.parents):
        if (candidate / ".git").exists():
            return candidate
    raise RuntimeError("Unable to locate repo root")


ROOT = _find_repo_root(Path(__file__))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api.path_utils import to_repo_relative  # type: ignore

SUMMARY_PATH = ROOT / "book/evidence/experiments/profile-pipeline/op-table-operation/out/summary.json"
OPS_VOCAB_PATH = ROOT / "book/evidence/graph/mappings/vocab/ops.json"
FILTERS_VOCAB_PATH = ROOT / "book/evidence/graph/mappings/vocab/filters.json"
OUT_PATH = ROOT / "book/evidence/experiments/profile-pipeline/op-table-vocab-alignment/out/op_table_vocab_alignment.json"


def main() -> None:
    summary = json.loads(SUMMARY_PATH.read_text())
    ops_vocab_json = json.loads(OPS_VOCAB_PATH.read_text())
    ops_entries = ops_vocab_json.get("ops", [])
    vocab_version = hashlib.sha256(json.dumps(ops_entries, sort_keys=True).encode()).hexdigest() if ops_entries else None
    ops_map = {entry["name"]: entry["id"] for entry in ops_vocab_json.get("ops", [])}
    filters_map = {entry["name"]: entry["id"] for entry in json.loads(FILTERS_VOCAB_PATH.read_text()).get("filters", [])} if FILTERS_VOCAB_PATH.exists() else {}

    records = []
    for s in summary:
        op_ids = [ops_map.get(op) for op in s.get("ops", [])]
        filter_ids = [filters_map.get(f) for f in s.get("filters", [])]
        records.append(
            {
                "profile": s["name"],
                "ops": s.get("ops", []),
                "filters": s.get("filters", []),
                "operation_ids": op_ids,
                "filter_ids": filter_ids,
                "op_entries": s.get("op_entries", []),
                "op_count": len(s.get("op_entries", [])),
                "vocab_version": vocab_version,
            }
        )

    alignment = {
        "records": records,
        "source_summary": to_repo_relative(SUMMARY_PATH, ROOT),
        "vocab_present": bool(ops_map),
        "vocab_status": "ok" if ops_map else "missing",
        "vocab_version": vocab_version,
        "filter_vocab_present": bool(filters_map),
    }
    OUT_PATH.parent.mkdir(exist_ok=True)
    OUT_PATH.write_text(json.dumps(alignment, indent=2, sort_keys=True))
    print(f"[+] wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
