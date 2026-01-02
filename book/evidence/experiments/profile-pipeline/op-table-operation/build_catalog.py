"""
Build a join-ready catalog for op-table-operation.

Inputs:
- out/summary.json (decoder + ops/filters)
- out/op_table_map.json (op_entries/unique_entries)
- out/op_table_signatures.json (per-entry decoder signatures)
- out/runtime_signatures.json (optional, provisional runtime hints)

Output:
- out/op_table_catalog_v1.json with one record per profile:
  - profile_id
  - bucket_pattern (sorted unique op-table entries)
  - op_count / op_entries
  - sbpl_ops / filters
  - decoder_signatures
  - runtime_signature (if present) marked provisional
"""

from __future__ import annotations

import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
OUT = BASE / "out"
REPO_ROOT = Path(__file__).resolve().parents[6]


def load_json(path: Path):
    if not path.exists():
        return None
    return json.loads(path.read_text())


def main() -> None:
    summary = load_json(OUT / "summary.json") or []
    op_map = load_json(OUT / "op_table_map.json") or {}
    sig_list = load_json(OUT / "op_table_signatures.json") or []
    runtime = load_json(OUT / "runtime_signatures.json") or {}
    vocab_ops_path = REPO_ROOT / "book" / "evidence" / "graph" / "mappings" / "vocab" / "ops.json"
    vocab_ops = load_json(vocab_ops_path) or {}
    ops_index = {entry["name"]: entry["id"] for entry in vocab_ops.get("ops", []) if isinstance(entry, dict)}

    map_profiles = op_map.get("profiles", {})
    runtime_profiles = runtime.get("profiles", {}) if isinstance(runtime, dict) else {}
    sig_map = {entry.get("name"): entry.get("entry_signatures") for entry in sig_list if isinstance(entry, dict)}

    records = []
    for rec in summary:
        name = rec.get("name")
        if not name:
            continue
        map_rec = map_profiles.get(name, {})
        unique_entries = sorted(set(map_rec.get("unique_entries") or []))
        op_entries = map_rec.get("op_entries") or rec.get("op_entries") or []
        decoder_signatures = sig_map.get(name)
        runtime_entry = runtime_profiles.get(name)
        op_ids = [ops_index.get(op) for op in rec.get("ops") or []]

        record = {
            "profile_id": name,
            "bucket_pattern": unique_entries,
            "op_count": rec.get("op_count"),
            "op_entries": op_entries,
            "sbpl_ops": rec.get("ops") or [],
            "op_ids": op_ids,
            "filters": rec.get("filters") or [],
            "decoder_signatures": decoder_signatures,
            "profile_path": f"sb/{name}.sb",
        }
        if runtime_entry:
            record["runtime_signature"] = runtime_entry.get("runtime_signature")
            record["runtime_provisional"] = True

        records.append(record)

    catalog = {
        "schema": "op_table_catalog_v1",
        "records": records,
    }
    out_path = OUT / "op_table_catalog_v1.json"
    out_path.write_text(json.dumps(catalog, indent=2, sort_keys=True))
    print(f"[+] wrote {out_path}")


if __name__ == "__main__":
    main()
