#!/usr/bin/env python3
"""
Scan node bytes for potential literal references.

For each profile and anchor:
- locate anchor offsets in the literal pool
- scan node bytes as 16-bit words to find matches to offsets (relative/absolute)
- report any hits
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Any, List

import sys
ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api.profile_tools import ingestion as pi  # type: ignore
from book.graph.concepts.validation import node_decoder  # type: ignore


def find_anchor_offsets(buf: bytes, anchor: bytes) -> List[int]:
    offs = []
    start = 0
    while True:
        idx = buf.find(anchor, start)
        if idx == -1:
            break
        offs.append(idx)
        start = idx + 1
    return offs


def scan_for_offsets(nodes: bytes, offsets: List[int], literal_start: int) -> List[int]:
    hits = []
    patterns = []
    for off in offsets:
        patterns.append(off.to_bytes(2, "little"))
        patterns.append((literal_start + off).to_bytes(2, "little"))
    for idx in range(0, len(nodes) - 1, 2):
        word = nodes[idx : idx + 2]
        if word in patterns:
            hits.append(idx // 2)
    return sorted(set(hits))


def process(profile: Path, anchors: List[str]) -> Dict[str, Any]:
    blob = profile.read_bytes()
    pb = pi.ProfileBlob(bytes=blob, source=profile.name)
    header = pi.parse_header(pb)
    sections = pi.slice_sections(pb, header)
    literal_pool = sections.regex_literals
    literal_start = len(blob) - len(literal_pool)
    nodes = sections.nodes
    results = []
    for anchor in anchors:
        offs = find_anchor_offsets(literal_pool, anchor.encode())
        hits = scan_for_offsets(nodes, offs, literal_start)
        results.append({"anchor": anchor, "offsets": offs, "hits": hits})
    decoded_nodes = node_decoder.decode_nodes(nodes)
    return {
        "op_count": header.operation_count,
        "nodes_len": len(nodes),
        "literal_len": len(literal_pool),
        "literal_start": literal_start,
        "anchors": results,
        "tag_counts": {n.tag: sum(1 for nn in decoded_nodes if nn.tag == n.tag) for n in decoded_nodes},
    }


def main() -> None:
    anchors_map = json.loads(Path("book/experiments/probe-op-structure/anchor_map.json").read_text())
    profiles_dir = Path("book/experiments/probe-op-structure/sb/build")
    out = {}
    for name, anchors in anchors_map.items():
        path = profiles_dir / f"{name}.sb.bin"
        if not path.exists():
            continue
        out[name] = process(path, anchors)
    out_path = Path("book/experiments/probe-op-structure/out/literal_scan.json")
    out_path.write_text(json.dumps(out, indent=2))
    print(f"[+] wrote {out_path}")


if __name__ == "__main__":
    main()
