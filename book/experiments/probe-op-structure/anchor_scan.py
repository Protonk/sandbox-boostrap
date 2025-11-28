#!/usr/bin/env python3
"""
Anchor-based scan: map known anchor literals to nodes and field2 values.

Given:
- Probes/system profiles (.sb.bin)
- A map of anchor strings per profile (JSON)

This script:
- Decodes profiles with decoder
- Finds literal occurrences of anchor strings
- Collects node indices whose byte ranges overlap the anchor strings
- Reports field2/tag values for those nodes

Outputs:
- out/anchor_hits.json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Any, List, Tuple

import sys
sys.path.append("book/graph/concepts/validation")
import decoder  # type: ignore
import profile_ingestion as pi  # type: ignore


def load_filter_names() -> Dict[int, str]:
    filters = json.loads(Path("book/graph/concepts/validation/out/vocab/filters.json").read_text())
    return {e["id"]: e["name"] for e in filters.get("filters", [])}


def find_anchor_offsets(buf: bytes, anchor: bytes) -> List[int]:
    """Return all offsets where anchor appears in a buffer."""
    offsets: List[int] = []
    start = 0
    while True:
        idx = buf.find(anchor, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + 1
    return offsets


def nodes_touching_bytes(nodes_bytes: bytes, anchor_offsets: List[int], literal_start: int, strides: List[int]) -> List[int]:
    """Search raw node bytes for little-endian representations of anchor offsets."""
    hits: List[int] = []
    patterns: List[Tuple[int, bytes]] = []
    for off in anchor_offsets:
        # relative offset into literal pool
        patterns.append((off, off.to_bytes(2, "little")))
        # absolute offset into blob (literal_start + off)
        abs_off = literal_start + off
        patterns.append((abs_off, abs_off.to_bytes(2, "little")))
    for stride in strides:
        for idx in range(0, len(nodes_bytes), stride):
            chunk = nodes_bytes[idx : idx + stride]
            for _, pat in patterns:
                if pat in chunk:
                    hits.append(idx // stride)
                    break
    return sorted(set(hits))


def extract_strings(buf: bytes, min_len: int = 4) -> List[Tuple[int, str]]:
    """Extract printable runs from a buffer with their offsets."""
    out: List[Tuple[int, str]] = []
    start = None
    cur: List[int] = []
    for idx, b in enumerate(buf):
        if 32 <= b <= 126:
            if start is None:
                start = idx
            cur.append(b)
        else:
            if cur and len(cur) >= min_len and start is not None:
                out.append((start, bytes(cur).decode("ascii", errors="ignore")))
            start = None
            cur = []
    if cur and len(cur) >= min_len and start is not None:
        out.append((start, bytes(cur).decode("ascii", errors="ignore")))
    return out


def summarize(profile_path: Path, anchors: List[str], filter_names: Dict[int, str]) -> Dict[str, Any]:
    blob = profile_path.read_bytes()
    # Decode for high-level counts/strings
    dec = decoder.decode_profile_dict(blob)
    literal_strings = dec.get("literal_strings") or []
    nodes_decoded = dec.get("nodes") or []

    # Slice raw sections for byte-level scans
    pb = pi.ProfileBlob(bytes=blob, source=profile_path.name)
    header = pi.parse_header(pb)
    sections = pi.slice_sections(pb, header)
    literal_pool = sections.regex_literals
    literal_start = len(blob) - len(literal_pool)
    nodes_bytes = sections.nodes
    literal_strings = extract_strings(literal_pool)

    anchor_hits = []
    for anchor in anchors:
        a_bytes = anchor.encode()
        offsets_lit = find_anchor_offsets(literal_pool, a_bytes)
        node_idxs = nodes_touching_bytes(nodes_bytes, offsets_lit, literal_start, strides=[12, 16])
        # also try matching by string index in literal_strings list
        string_index = None
        for idx, (off, s) in enumerate(literal_strings):
            if anchor in s or s in anchor:
                string_index = idx
                break
        field2_vals = []
        for idx in node_idxs:
            if idx < len(nodes_decoded):
                fields = nodes_decoded[idx].get("fields", [])
                if len(fields) > 2:
                    field2_vals.append(fields[2])
        anchor_hits.append(
            {
                "anchor": anchor,
                "offsets": offsets_lit,
                "literal_offsets": offsets_lit,
                "literal_string_index": string_index,
                "node_indices": node_idxs,
                "field2_values": field2_vals,
                "field2_names": [filter_names.get(v) for v in field2_vals],
            }
        )

    return {
        "op_count": dec.get("op_count"),
        "node_count": dec.get("node_count"),
        "anchors": anchor_hits,
        "literal_strings_sample": literal_strings[:10],
    }


def main() -> None:
    filter_names = load_filter_names()
    anchors_map = json.loads(Path("book/experiments/probe-op-structure/anchor_map.json").read_text())
    profiles_dir = Path("book/experiments/probe-op-structure/sb/build")
    sys_profiles = {
        "sys:airlock": Path("book/examples/extract_sbs/build/profiles/airlock.sb.bin"),
        "sys:bsd": Path("book/examples/extract_sbs/build/profiles/bsd.sb.bin"),
        "sys:sample": Path("book/examples/sb/build/sample.sb.bin"),
    }
    outputs: Dict[str, Any] = {}

    for name, anchors in anchors_map.items():
        p = profiles_dir / f"{name}.sb.bin"
        if not p.exists():
            continue
        outputs[f"probe:{name}"] = summarize(p, anchors, filter_names)

    for name, p in sys_profiles.items():
        if not p.exists():
            continue
        outputs[name] = summarize(p, anchors_map.get(name, []), filter_names)

    out_dir = Path("book/experiments/probe-op-structure/out")
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / "anchor_hits.json"
    out_path.write_text(json.dumps(outputs, indent=2))
    print(f"[+] wrote {out_path}")


if __name__ == "__main__":
    main()
