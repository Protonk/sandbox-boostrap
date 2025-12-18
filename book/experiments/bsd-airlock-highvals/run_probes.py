#!/usr/bin/env python3
"""
Compile and decode probes for bsd/airlock high field2 payload exploration.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import sys

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api import decoder, path_utils, profile_tools  # type: ignore


def compile_probes(sb_dir: Path, build_dir: Path) -> List[Path]:
    build_dir.mkdir(exist_ok=True)
    compiled: List[Path] = []
    for sb in sorted(sb_dir.glob("*.sb")):
        if sb.name == ".gitkeep":
            continue
        out = build_dir / f"{sb.stem}.sb.bin"
        profile_tools.compile_sbpl_file(sb, out)
        compiled.append(out)
    return compiled


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
    for spec_entry in per_spec.values():
        payloads = spec_entry["field2_payloads"]
        spec_entry["field2_payloads"] = [
            payloads[key] for key in sorted(payloads, key=lambda k: -payloads[k]["count"])
        ]
    return per_spec


def main() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    sb_dir = repo_root / "book/experiments/bsd-airlock-highvals/sb"
    build_dir = sb_dir / "build"
    out_dir = repo_root / "book/experiments/bsd-airlock-highvals/out"
    out_dir.mkdir(exist_ok=True)

    blobs = compile_probes(sb_dir, build_dir)
    if not blobs:
        raise SystemExit("No SBPL probes found")

    all_records: List[Dict[str, Any]] = []
    for blob in blobs:
        all_records.extend(decode_profile(blob))

    records_path = out_dir / "decode_records.jsonl"
    with records_path.open("w") as f:
        for rec in all_records:
            f.write(json.dumps(rec) + "\n")

    summary = summarize(all_records)
    summary_path = out_dir / "field2_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2))

    print(f"[+] compiled {len(blobs)} probes")
    print(f"[+] wrote {records_path}")
    print(f"[+] wrote {summary_path}")


if __name__ == "__main__":
    main()
