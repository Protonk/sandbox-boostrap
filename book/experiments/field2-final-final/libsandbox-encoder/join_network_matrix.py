#!/usr/bin/env python3
"""
Diff-anchored join analysis for the libsandbox-encoder Phase A network matrix.

Goal: map SBPL deltas -> compiled blob byte deltas -> local 8-byte record context,
without assuming that all 8-byte records are PolicyGraph nodes.

Outputs (under `out/network_matrix/`):
- `join_records.jsonl`: one row per (pair_id, diff_offset) with record+window context.
- `join_summary.json`: small rollups to compare structural roles across pairs.
"""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api.path_utils import find_repo_root, to_repo_relative

ROOT = find_repo_root(Path(__file__))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


NETWORK_OUT_DIR = ROOT / "book/experiments/field2-final-final/libsandbox-encoder/out/network_matrix"
INDEX_PATH = NETWORK_OUT_DIR / "index.json"
DIFFS_PATH = NETWORK_OUT_DIR / "blob_diffs.json"
JOIN_RECORDS_PATH = NETWORK_OUT_DIR / "join_records.jsonl"
JOIN_SUMMARY_PATH = NETWORK_OUT_DIR / "join_summary.json"


def rel(path: Path) -> str:
    return to_repo_relative(path, ROOT)


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text())


def write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True))


def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True))
            f.write("\n")


def u16le(buf: bytes, off: int) -> int:
    return int.from_bytes(buf[off : off + 2], "little")


def parse_record8(buf: bytes, start: int) -> Optional[Dict[str, Any]]:
    if start < 0 or start + 8 > len(buf):
        return None
    chunk = buf[start : start + 8]
    return {
        "start": start,
        "tag": chunk[0],
        "kind": chunk[1],
        "u16": [u16le(chunk, 2), u16le(chunk, 4), u16le(chunk, 6)],
        "hex": chunk.hex(),
    }


def window_hex(buf: bytes, center: int, radius: int = 16) -> Dict[str, Any]:
    start = max(0, center - radius)
    end = min(len(buf), center + radius)
    chunk = buf[start:end]
    return {"start": start, "end": end, "len": len(chunk), "hex": chunk.hex()}


@dataclass(frozen=True)
class CaseInfo:
    spec_id: str
    blob_path: Path
    nodes_start: int
    nodes_end: int
    literal_start: int


def load_cases(index: Dict[str, Any]) -> Dict[str, CaseInfo]:
    cases: Dict[str, CaseInfo] = {}
    for entry in index.get("cases", []):
        spec_id = entry["spec_id"]
        sections = entry["sections"]
        nodes = sections["nodes"]
        blob_path = ROOT / entry["blob"]
        cases[spec_id] = CaseInfo(
            spec_id=spec_id,
            blob_path=blob_path,
            nodes_start=int(nodes["start"]),
            nodes_end=int(nodes["end"]),
            literal_start=int(sections["literal_pool"]["start"]),
        )
    return cases


def load_known_tags() -> set[int]:
    tag_layouts_path = ROOT / "book/graph/mappings/tag_layouts/tag_layouts.json"
    data = load_json(tag_layouts_path)
    return {int(t["tag"]) for t in data.get("tags", []) if "tag" in t}


def classify_structural_role(nodes_start: int, nodes_end: int, offset: int) -> Dict[str, Any]:
    within_nodes = nodes_start <= offset < nodes_end
    role: Dict[str, Any] = {"within_nodes": within_nodes}
    if not within_nodes:
        role["kind"] = "outside_nodes"
        if offset < nodes_start:
            role["outside_reason"] = "before_nodes"
        else:
            role["outside_reason"] = "after_nodes"
        return role
    within = (offset - nodes_start) % 8
    role["within_record_offset"] = within
    if within == 0:
        role["kind"] = "record_header_byte"
        role["header_byte"] = "tag"
        return role
    if within == 1:
        role["kind"] = "record_header_byte"
        role["header_byte"] = "kind"
        return role
    if 2 <= within <= 7:
        role["kind"] = "u16_field_byte"
        u16_index = (within - 2) // 2
        role["u16_index"] = u16_index
        role["u16_byte"] = "lo" if (within % 2 == 0) else "hi"
        return role
    role["kind"] = "unknown"
    return role


def main() -> None:
    index = load_json(INDEX_PATH)
    diffs = load_json(DIFFS_PATH)
    cases = load_cases(index)
    known_tags = load_known_tags()

    rows: List[Dict[str, Any]] = []
    summary_by_pair: Dict[str, Dict[str, Any]] = {}
    totals = Counter()

    diffs_by_pair_id = {p["pair_id"]: p for p in diffs.get("pairs", [])}

    for pair in index.get("diff_pairs", []):
        pair_id = pair["pair_id"]
        a_id = pair["a"]
        b_id = pair["b"]
        if a_id not in cases or b_id not in cases:
            continue
        a_case = cases[a_id]
        b_case = cases[b_id]
        a_blob = a_case.blob_path.read_bytes()
        b_blob = b_case.blob_path.read_bytes()

        pair_diffs = diffs_by_pair_id.get(pair_id, {})
        annotated_diffs = pair_diffs.get("diffs", [])

        role_counts = Counter()
        section_counts = Counter()
        tag_known_counts = Counter()
        u16_index_counts = Counter()

        for d in annotated_diffs:
            off = int(d["offset"])
            sec = d.get("section", "unknown")
            section_counts[sec] += 1

            # normalize record start under stride=8 regardless of tag layout.
            if sec.startswith("nodes:"):
                rec_start = a_case.nodes_start + ((off - a_case.nodes_start) // 8) * 8
            else:
                rec_start = None

            role = classify_structural_role(a_case.nodes_start, a_case.nodes_end, off)
            role_counts[role["kind"]] += 1
            if role.get("kind") == "u16_field_byte":
                u16_index_counts[str(role["u16_index"])] += 1

            rec_a = parse_record8(a_blob, rec_start) if rec_start is not None else None
            rec_b = parse_record8(b_blob, rec_start) if rec_start is not None else None

            if rec_a is not None:
                tag_known_counts["a_known" if rec_a["tag"] in known_tags else "a_unknown"] += 1
            if rec_b is not None:
                tag_known_counts["b_known" if rec_b["tag"] in known_tags else "b_unknown"] += 1

            rows.append(
                {
                    "pair_id": pair_id,
                    "intent": pair.get("intent"),
                    "a": {
                        "spec_id": a_id,
                        "blob": rel(a_case.blob_path),
                        "nodes_start": a_case.nodes_start,
                        "nodes_end": a_case.nodes_end,
                        "literal_start": a_case.literal_start,
                    },
                    "b": {
                        "spec_id": b_id,
                        "blob": rel(b_case.blob_path),
                        "nodes_start": b_case.nodes_start,
                        "nodes_end": b_case.nodes_end,
                        "literal_start": b_case.literal_start,
                    },
                    "diff": {
                        "offset": off,
                        "a_byte": d.get("a_byte"),
                        "b_byte": d.get("b_byte"),
                        "section": sec,
                        "role": role,
                    },
                    "record8": {
                        "start": rec_start,
                        "a": rec_a,
                        "b": rec_b,
                        "tag_known": {
                            "a": (rec_a["tag"] in known_tags) if rec_a else None,
                            "b": (rec_b["tag"] in known_tags) if rec_b else None,
                        },
                    }
                    if rec_start is not None
                    else None,
                    "window": {
                        "a": window_hex(a_blob, off),
                        "b": window_hex(b_blob, off),
                    },
                }
            )

        summary_by_pair[pair_id] = {
            "pair_id": pair_id,
            "a": a_id,
            "b": b_id,
            "intent": pair.get("intent"),
            "diff_byte_count": int(pair_diffs.get("diff_byte_count", 0)),
            "diff_counts_by_section": dict(section_counts),
            "structural_role_counts": dict(role_counts),
            "u16_index_counts": dict(u16_index_counts),
            "tag_known_counts": dict(tag_known_counts),
        }
        totals.update(role_counts)

    write_jsonl(JOIN_RECORDS_PATH, rows)
    write_json(
        JOIN_SUMMARY_PATH,
        {
            "world_id": index.get("world_id"),
            "manifest": index.get("manifest"),
            "inputs": {
                "index": rel(INDEX_PATH),
                "blob_diffs": rel(DIFFS_PATH),
            },
            "outputs": {
                "join_records": rel(JOIN_RECORDS_PATH),
                "join_summary": rel(JOIN_SUMMARY_PATH),
            },
            "totals": dict(totals),
            "by_pair": summary_by_pair,
        },
    )
    print(f"[+] wrote {JOIN_RECORDS_PATH} ({len(rows)} rows)")
    print(f"[+] wrote {JOIN_SUMMARY_PATH}")


if __name__ == "__main__":
    main()
