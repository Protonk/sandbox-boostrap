"""
Tag-aware node decoder scaffold for modern sandbox profiles.

This is exploratory: interpret nodes as variable-layout records keyed by a tag
byte, attempting to recover operands (edges, filter ID, literal/regex index).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Dict, Any, Optional


@dataclass
class DecodedNode:
    offset: int
    tag: int
    operands: List[int]
    raw: bytes


# Known tags observed in heuristics; this is a placeholder mapping.
TAG_LAYOUTS = {
    # tag: (size, operand_count)
    # Common observed tags in heuristic decoder: 0,1,2,3,4,5,6
    0: (12, 5),  # decision?
    1: (12, 5),
    2: (12, 5),
    3: (12, 5),
    4: (12, 5),
    5: (12, 5),
    6: (12, 5),
}


def decode_nodes(data: bytes, stride_fallback: int = 12) -> List[DecodedNode]:
    nodes: List[DecodedNode] = []
    offset = 0
    while offset + stride_fallback <= len(data):
        tag = data[offset]
        layout = TAG_LAYOUTS.get(tag)
        size = layout[0] if layout else stride_fallback
        if offset + size > len(data):
            break
        chunk = data[offset : offset + size]
        # interpret as little-endian u16 operands after the tag byte
        operands: List[int] = []
        for i in range(1, size, 2):
            operands.append(int.from_bytes(chunk[i : i + 2], "little"))
        nodes.append(DecodedNode(offset=offset, tag=tag, operands=operands, raw=chunk))
        offset += size
    return nodes


def decode_profile_nodes(blob: bytes, node_bytes: bytes) -> Dict[str, Any]:
    decoded = decode_nodes(node_bytes)
    tag_counts: Dict[int, int] = {}
    for n in decoded:
        tag_counts[n.tag] = tag_counts.get(n.tag, 0) + 1
    return {
        "node_count": len(decoded),
        "tag_counts": tag_counts,
        "nodes": [
            {"offset": n.offset, "tag": n.tag, "operands": n.operands, "raw": n.raw.hex()}
            for n in decoded
        ],
    }
