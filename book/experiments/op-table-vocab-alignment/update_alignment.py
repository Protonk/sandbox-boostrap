#!/usr/bin/env python3
"""
Regenerate op_table_vocab_alignment.json using the harvested Operation Vocabulary.

Inputs:
- book/experiments/op-table-operation/out/summary.json
- book/graph/concepts/validation/out/vocab/ops.json

Outputs:
- book/experiments/op-table-vocab-alignment/out/op_table_vocab_alignment.json
"""

from __future__ import annotations

import json
from pathlib import Path


SUMMARY_PATH = Path("book/experiments/op-table-operation/out/summary.json")
OPS_VOCAB_PATH = Path("book/graph/concepts/validation/out/vocab/ops.json")
OUT_PATH = Path("book/experiments/op-table-vocab-alignment/out/op_table_vocab_alignment.json")


def main() -> None:
    summary = json.loads(SUMMARY_PATH.read_text())
    ops_vocab_json = json.loads(OPS_VOCAB_PATH.read_text())
    vocab_version = ops_vocab_json.get("generated_at")
    ops_map = {entry["name"]: entry["id"] for entry in ops_vocab_json.get("ops", [])}

    records = []
    for s in summary:
        op_ids = [ops_map.get(op) for op in s.get("ops", [])]
        records.append(
            {
                "profile": s["name"],
                "ops": s.get("ops", []),
                "operation_ids": op_ids,
                "op_entries": s.get("op_entries", []),
                "op_count": len(s.get("op_entries", [])),
                "vocab_version": vocab_version,
            }
        )

    alignment = {
        "records": records,
        "source_summary": str(SUMMARY_PATH),
        "vocab_present": bool(ops_map),
        "vocab_status": "ok" if ops_map else "missing",
        "vocab_version": vocab_version,
    }
    OUT_PATH.parent.mkdir(exist_ok=True)
    OUT_PATH.write_text(json.dumps(alignment, indent=2, sort_keys=True))
    print(f"[+] wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
