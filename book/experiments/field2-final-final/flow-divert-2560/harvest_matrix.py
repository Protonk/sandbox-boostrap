#!/usr/bin/env python3
"""
Decode compiled probes for flow-divert field2 analysis and emit joinable records.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import sys

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api.profile import decoder  # type: ignore
from book.api import path_utils  # type: ignore


def decode_profile(path: Path) -> List[Dict[str, Any]]:
    prof = decoder.decode_profile_dict(path.read_bytes())
    records: List[Dict[str, Any]] = []
    for idx, node in enumerate(prof.get("nodes") or []):
        fields = node.get("fields") or []
        field2_raw: Optional[int] = None
        field2_hi: Optional[int] = None
        field2_lo: Optional[int] = None
        if len(fields) > 2:
            field2_raw = fields[2]
            field2_hi = field2_raw & 0xC000
            field2_lo = field2_raw & 0x3FFF
        records.append(
            {
                "spec_id": path.stem,
                "profile_path": path_utils.to_repo_relative(path),
                "node_index": idx,
                "tag": node.get("tag"),
                "fields": fields,
                "field2_raw": field2_raw,
                "field2_hi": field2_hi,
                "field2_lo": field2_lo,
                "u16_role": node.get("u16_role"),
                "successors": node.get("successors", []),
                "literal_refs": node.get("literal_refs", []),
            }
        )
    return records


def summarize(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    # Aggregate field2 payloads per spec
    per_spec: Dict[str, Dict[str, Any]] = {}
    for rec in records:
        spec = rec["spec_id"]
        spec_entry = per_spec.setdefault(
            spec,
            {
                "spec_id": spec,
                "profile_path": rec["profile_path"],
                "field2_payloads": {},
            },
        )
        raw = rec["field2_raw"]
        if raw is None:
            continue
        payload_entry = spec_entry["field2_payloads"].setdefault(
            str(raw),
            {
                "raw": raw,
                "raw_hex": hex(raw),
                "hi": rec["field2_hi"],
                "lo": rec["field2_lo"],
                "count": 0,
                "tags": {},
            },
        )
        payload_entry["count"] += 1
        tag = rec["tag"]
        if tag is not None:
            payload_entry["tags"][tag] = payload_entry["tags"].get(tag, 0) + 1
    # Normalize payload lists sorted by descending count
    for spec_entry in per_spec.values():
        payloads = spec_entry["field2_payloads"]
        spec_entry["field2_payloads"] = [
            payloads[key] for key in sorted(payloads, key=lambda k: -payloads[k]["count"])
        ]
    return per_spec


def main() -> None:
    sb_dir = Path("book/experiments/field2-final-final/flow-divert-2560/sb/build")
    blobs = sorted(sb_dir.glob("*.sb.bin"))
    if not blobs:
        raise SystemExit("No compiled probes found under sb/build")

    all_records: List[Dict[str, Any]] = []
    for blob in blobs:
        all_records.extend(decode_profile(blob))

    out_dir = Path("book/experiments/field2-final-final/flow-divert-2560/out")
    out_dir.mkdir(exist_ok=True)

    records_path = out_dir / "matrix_records.jsonl"
    with records_path.open("w") as f:
        for rec in all_records:
            f.write(json.dumps(rec) + "\n")

    summary = summarize(all_records)
    summary_path = out_dir / "field2_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2))

    print(f"[+] wrote {records_path}")
    print(f"[+] wrote {summary_path}")


if __name__ == "__main__":
    main()
