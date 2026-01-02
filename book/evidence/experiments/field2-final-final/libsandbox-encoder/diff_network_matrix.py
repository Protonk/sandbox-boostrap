#!/usr/bin/env python3
"""
Compute byte diffs across the libsandbox-encoder Phase A network matrix blobs.

This produces a small, joinable witness artifact that answers:
- Which byte offsets change when only a network arg changes?
- Do those changes land in the node record stream, its tail, or the literal pool?

Output: `out/network_matrix/blob_diffs.json`
"""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api.path_utils import find_repo_root, to_repo_relative

ROOT = find_repo_root(Path(__file__))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def rel(path: Path) -> str:
    return to_repo_relative(path, ROOT)


def load_index(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text())


def load_node_records(path: Path) -> Dict[str, List[Dict[str, Any]]]:
    by_spec: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        by_spec[rec["spec_id"]].append(rec)
    # stable ordering by blob offset
    for spec_id in list(by_spec.keys()):
        by_spec[spec_id].sort(key=lambda r: r.get("blob_offset", 0))
    return by_spec


def classify_offset(off: int, sections: Dict[str, Any]) -> str:
    pre = sections["preamble_len"]
    op_end = sections["op_table"]["end"]
    node_end = sections["nodes"]["end"]
    lit_end = sections["literal_pool"]["end"]
    if off < pre:
        return "preamble"
    if off < op_end:
        return "op_table"
    if off < node_end:
        # further split node records vs remainder
        nodes_start = sections["nodes"]["start"]
        nodes_len = sections["nodes"]["len"]
        remainder = sections["nodes"].get("remainder_after_parse") or 0
        parsed_len = max(0, nodes_len - remainder)
        if off < nodes_start + parsed_len:
            return "nodes:records"
        return "nodes:remainder"
    if off < lit_end:
        return "literal_pool"
    return "out_of_range"


def find_record_for_offset(records: List[Dict[str, Any]], off: int) -> Optional[Dict[str, Any]]:
    # records are small; linear scan is fine and stable.
    for r in records:
        start = r["blob_offset"]
        size = r["record_size"]
        if start <= off < start + size:
            return r
    return None


def compute_byte_diffs(a: bytes, b: bytes) -> List[Tuple[int, Optional[int], Optional[int]]]:
    diffs: List[Tuple[int, Optional[int], Optional[int]]] = []
    n = max(len(a), len(b))
    for i in range(n):
        ba = a[i] if i < len(a) else None
        bb = b[i] if i < len(b) else None
        if ba != bb:
            diffs.append((i, ba, bb))
    return diffs


def spans_from_offsets(offsets: List[int]) -> List[Dict[str, int]]:
    if not offsets:
        return []
    offsets = sorted(offsets)
    spans: List[Dict[str, int]] = []
    start = prev = offsets[0]
    for off in offsets[1:]:
        if off == prev + 1:
            prev = off
            continue
        spans.append({"start": start, "end_exclusive": prev + 1, "len": prev + 1 - start})
        start = prev = off
    spans.append({"start": start, "end_exclusive": prev + 1, "len": prev + 1 - start})
    return spans


def main() -> None:
    out_dir = ROOT / "book/evidence/experiments/field2-final-final/libsandbox-encoder/out/network_matrix"
    index_path = out_dir / "index.json"
    node_records_path = out_dir / "node_records.jsonl"
    out_path = out_dir / "blob_diffs.json"

    index = load_index(index_path)
    by_spec_id = {c["spec_id"]: c for c in index["cases"]}
    node_records = load_node_records(node_records_path)

    pair_reports: List[Dict[str, Any]] = []
    offsets_by_pair: Dict[str, List[int]] = {}

    for pair in index.get("diff_pairs", []):
        pair_id = pair["pair_id"]
        a_id = pair["a"]
        b_id = pair["b"]
        a_case = by_spec_id[a_id]
        b_case = by_spec_id[b_id]
        a_blob = ROOT / a_case["blob"]
        b_blob = ROOT / b_case["blob"]
        a_bytes = a_blob.read_bytes()
        b_bytes = b_blob.read_bytes()

        diffs = compute_byte_diffs(a_bytes, b_bytes)
        offsets = [d[0] for d in diffs]
        offsets_by_pair[pair_id] = offsets

        # annotate diffs with section + record information (from the "a" specimen)
        sections = a_case["sections"]
        annotated: List[Dict[str, Any]] = []
        for off, ba, bb in diffs:
            sec = classify_offset(off, sections)
            entry: Dict[str, Any] = {"offset": off, "a_byte": ba, "b_byte": bb, "section": sec}
            if sec.startswith("nodes:"):
                rec = find_record_for_offset(node_records.get(a_id, []), off)
                if rec:
                    within = off - rec["blob_offset"]
                    entry["record"] = {
                        "tag": rec["tag"],
                        "kind": rec["kind"],
                        "record_start": rec["blob_offset"],
                        "within_record_offset": within,
                        "fields_u16": rec["fields_u16"],
                        "layout": rec["layout"],
                    }
                    if within in (2, 4, 6):
                        entry["record"]["u16_index"] = (within - 2) // 2
            annotated.append(entry)

        section_counts = Counter(a["section"] for a in annotated)
        pair_reports.append(
            {
                "pair_id": pair_id,
                "a": a_id,
                "b": b_id,
                "intent": pair.get("intent"),
                "lengths": {"a": len(a_bytes), "b": len(b_bytes)},
                "diff_byte_count": len(diffs),
                "diff_spans": spans_from_offsets(offsets),
                "diff_counts_by_section": dict(section_counts),
                "diffs": annotated,
            }
        )

    # cross-pair helper: identify offsets shared between the "single-arg" pairs
    shared = None
    for pid in ["domain_af_inet_vs_af_system", "type_sock_stream_vs_sock_dgram", "proto_tcp_vs_udp"]:
        offs = set(offsets_by_pair.get(pid, []))
        shared = offs if shared is None else shared.intersection(offs)
    cross = {
        "single_arg_pairs": ["domain_af_inet_vs_af_system", "type_sock_stream_vs_sock_dgram", "proto_tcp_vs_udp"],
        "shared_diff_offsets": sorted(shared) if shared is not None else [],
    }

    out = {
        "world_id": index.get("world_id"),
        "manifest": index.get("manifest"),
        "outputs": {"blob_diffs": rel(out_path)},
        "cross_pair": cross,
        "pairs": pair_reports,
    }
    out_path.write_text(json.dumps(out, indent=2, sort_keys=True))
    print(f"[+] wrote {out_path}")


if __name__ == "__main__":
    main()

