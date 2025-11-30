"""
Best-effort decoder for modern sandbox profile blobs.

Focuses on structure: header preamble, op-table entries, node chunks (stride 12),
and literal/regex pool slices. This is heuristic and intended to be version-tolerant.
"""

from __future__ import annotations

import json
import string
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple


PRINTABLE = set(bytes(string.printable, "ascii"))
# tag: (record_size_bytes, edge_field_indices, payload_field_indices)
DEFAULT_TAG_LAYOUTS: Dict[int, Tuple[int, Tuple[int, ...], Tuple[int, ...]]] = {
    # Tentative assumptions; a richer decoder should update these.
    5: (12, (0, 1), (2,)),
    6: (12, (0, 1), (2,)),
}


@dataclass
class DecodedProfile:
    format_variant: str
    preamble_words: List[int]
    preamble_words_full: List[int]
    header_bytes: bytes
    op_count: Optional[int]
    op_table_offset: int
    op_table: List[int]
    nodes: List[Dict[str, Any]]
    node_count: int
    tag_counts: Dict[str, int]
    literal_pool: bytes
    literal_strings: List[str]
    sections: Dict[str, int]
    validation: Dict[str, Any]
    header_fields: Dict[str, Any]


def _read_words(data: bytes, byte_len: int) -> List[int]:
    words = []
    for i in range(0, min(len(data), byte_len), 2):
        words.append(int.from_bytes(data[i : i + 2], "little"))
    return words


def _guess_op_count(words: List[int]) -> Optional[int]:
    if len(words) < 2:
        return None
    maybe = words[1]
    if 0 < maybe < 4096:
        return maybe
    return None


def _scan_literal_start(data: bytes, start: int) -> int:
    """Find onset of mostly-printable tail; conservative if none found."""
    window = 64
    threshold = 0.7
    for i in range(start, len(data)):
        chunk = data[i : min(len(data), i + window)]
        if not chunk:
            continue
        printable = sum(1 for b in chunk if b in PRINTABLE or b == 0x00)
        if printable / len(chunk) >= threshold:
            return i
    return len(data)


def _parse_op_table(data: bytes) -> List[int]:
    return [int.from_bytes(data[i : i + 2], "little") for i in range(0, len(data), 2)]


def _load_external_tag_layouts() -> Dict[int, Tuple[int, Tuple[int, ...], Tuple[int, ...]]]:
    """
    Optionally merge in tag layout hints from stable mappings or experiments.

    Priority: published mapping under book/graph/mappings/tag_layouts/tag_layouts.json,
    then experimental assumptions under probe-op-structure. If none found, fall
    back to the built-in defaults. Keys are tag ints; values mirror DEFAULT_TAG_LAYOUTS.
    """
    candidates = [
        Path("book/graph/mappings/tag_layouts/tag_layouts.json"),
        Path("book/experiments/probe-op-structure/out/tag_layout_assumptions.json"),
    ]
    data = None
    for path in candidates:
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text())
            break
        except Exception:
            continue
    if not data:
        return {}
    out: Dict[int, Tuple[int, Tuple[int, ...], Tuple[int, ...]]] = {}
    for entry in data.get("tags", []):
        try:
            tag = int(entry["tag"])
        except Exception:
            continue
        rec_size = int(entry.get("record_size_bytes", 12))
        edges = tuple(entry.get("edge_fields", []))
        payloads = tuple(entry.get("payload_fields", []))
        out[tag] = (rec_size, edges, payloads)
    return out


def _parse_nodes_tagged(data: bytes) -> Tuple[List[Dict[str, Any]], Dict[int, int], int]:
    """
    Parse nodes using per-tag record sizes when available, defaulting to 12-byte
    records. Returns (nodes, tag_counts, remainder_bytes).
    """
    tag_layouts = {**DEFAULT_TAG_LAYOUTS, **_load_external_tag_layouts()}
    nodes: List[Dict[str, Any]] = []
    tag_counts: Dict[int, int] = {}

    offset = 0
    while offset + 2 <= len(data):
        tag = data[offset]
        rec_size, _, _ = tag_layouts.get(tag, (12, (0, 1), (2,)))
        chunk = data[offset : offset + rec_size]
        if len(chunk) < rec_size:
            break
        fields = [int.from_bytes(chunk[i : i + 2], "little") for i in range(2, rec_size, 2)]
        tag_counts[tag] = tag_counts.get(tag, 0) + 1
        nodes.append(
            {
                "offset": offset,
                "tag": tag,
                "fields": fields,
                "record_size": rec_size,
                "hex": chunk.hex(),
            }
        )
        offset += rec_size

    remainder = len(data) - offset
    return nodes, tag_counts, remainder


def _extract_strings_with_offsets(buf: bytes, min_len: int = 4) -> List[Tuple[int, str]]:
    """Pull out printable runs with offsets; simple heuristic to aid orientation."""
    out: List[Tuple[int, str]] = []
    cur: List[int] = []
    start = None
    for idx, b in enumerate(buf):
        if b in PRINTABLE and b != 0x00:
            if start is None:
                start = idx
            cur.append(b)
        else:
            if len(cur) >= min_len and start is not None:
                out.append((start, bytes(cur).decode("ascii", errors="ignore")))
            cur = []
            start = None
    if len(cur) >= min_len and start is not None:
        out.append((start, bytes(cur).decode("ascii", errors="ignore")))
    return out


def decode_profile(data: bytes, header_window: int = 128) -> DecodedProfile:
    preamble = _read_words(data, 16)
    preamble_full = _read_words(data, header_window)
    header_bytes = data[:header_window]
    op_count = _guess_op_count(preamble)
    op_table_len = (op_count or 0) * 2
    op_table_start = 16
    op_table_end = min(len(data), op_table_start + op_table_len)
    op_table_bytes = data[op_table_start:op_table_end]

    nodes_start = op_table_end
    literal_start = _scan_literal_start(data, nodes_start)
    nodes_bytes = data[nodes_start:literal_start]
    literal_pool = data[literal_start:]

    nodes, tag_counts, node_remainder = _parse_nodes_tagged(nodes_bytes)

    # Sanity: treat first two fields as edges and count in-bounds hits.
    edge_total = 0
    edge_in_bounds = 0
    for node in nodes:
        edges = node.get("fields", [])[:2]
        edge_total += len(edges)
        edge_in_bounds += sum(1 for e in edges if 0 <= e < len(nodes))

    # Tag-aware validation: check candidate layouts for selected tags.
    literal_strings_with_offsets = _extract_strings_with_offsets(literal_pool)
    literal_count = len(literal_strings_with_offsets)
    tag_validation: Dict[str, Any] = {}
    # Tag-aware validation based on merged layouts
    merged_layouts = {**DEFAULT_TAG_LAYOUTS, **_load_external_tag_layouts()}
    for node in nodes:
        tag = node.get("tag")
        if tag not in merged_layouts:
            continue
        rec_size, edge_idx, payload_idx = merged_layouts[tag]
        if node.get("record_size") != rec_size:
            continue
        fields = node.get("fields", [])
        edges = [fields[i] for i in edge_idx if i < len(fields)]
        payloads = [fields[i] for i in payload_idx if i < len(fields)]
        tv = tag_validation.setdefault(
            str(tag), {"edge_in_bounds": 0, "edge_total": 0, "payloads": {}, "record_size": rec_size}
        )
        tv["edge_total"] += len(edges)
        tv["edge_in_bounds"] += sum(1 for e in edges if 0 <= e < len(nodes))
        for p in payloads:
            tv["payloads"][str(p)] = tv["payloads"].get(str(p), 0) + 1

    # Heuristic literal references: match node fields to literal offsets, absolute offsets, or string indices.
    literal_refs_per_node: List[List[str]] = []
    literal_candidates: List[Tuple[str, List[bytes]]] = []
    for idx, (off, val) in enumerate(literal_strings_with_offsets):
        abs_off = literal_start + off
        patterns = [
            off.to_bytes(2, "little"),
            abs_off.to_bytes(2, "little"),
            off.to_bytes(4, "little"),
            abs_off.to_bytes(4, "little"),
            idx.to_bytes(2, "little"),
            idx.to_bytes(4, "little"),
        ]
        literal_candidates.append((val, patterns))
    for node in nodes:
        matches: List[str] = []
        fields = node.get("fields", [])
        # field-based matching (u16 payloads)
        for off, val in literal_strings_with_offsets:
            abs_off = literal_start + off
            if any((f == off or f == abs_off) for f in fields):
                matches.append(val)
        # byte-scan matching inside the record
        try:
            rec_size = node.get("record_size", 0) or 0
            chunk = nodes_bytes[node["offset"] : node["offset"] + rec_size]
        except Exception:
            chunk = b""
        if chunk:
            for val, pats in literal_candidates:
                for pat in pats:
                    if pat in chunk:
                        matches.append(val)
                        break
        literal_refs_per_node.append(sorted(set(matches)))
    for node, refs in zip(nodes, literal_refs_per_node):
        node["literal_refs"] = refs

    header_fields: Dict[str, Any] = {}
    try:
        # Basic header fields
        header_fields = {
            "magic": preamble_full[2] if len(preamble_full) > 2 else None,
            "op_count_word": preamble_full[1] if len(preamble_full) > 1 else None,
            "maybe_flags": preamble_full[0] if preamble_full else None,
            "unknown_words": [
                {"index": i, "value": w} for i, w in enumerate(preamble_full[3:], start=3)
            ]
            if len(preamble_full) > 3
            else [],
        }
        # Heuristic profile_class: look for small ints near the start of the header and within the first header_window.
        profile_class = None
        for idx in range(0, min(len(preamble_full), header_window // 2)):
            val = preamble_full[idx]
            if val in (0, 1, 2, 3):
                profile_class = val
                header_fields["profile_class_word_index"] = idx
                break
        header_fields["profile_class"] = profile_class
    except Exception:
        header_fields = {}

    decoded = DecodedProfile(
        format_variant="modern-heuristic",
        preamble_words=preamble,
        preamble_words_full=preamble_full,
        header_bytes=header_bytes,
        op_count=op_count,
        op_table_offset=op_table_start,
        op_table=_parse_op_table(op_table_bytes),
        nodes=nodes,
        node_count=len(nodes),
        tag_counts={str(k): v for k, v in tag_counts.items()},
        literal_pool=literal_pool,
        literal_strings=[s for _, s in literal_strings_with_offsets],
        sections={
            "op_table": len(op_table_bytes),
            "nodes": len(nodes_bytes),
            "literal_pool": len(literal_pool),
            "nodes_start": nodes_start,
            "literal_start": literal_start,
        },
        validation={
            "node_remainder_bytes": node_remainder,
            "edge_fields_in_bounds": edge_in_bounds,
            "edge_fields_total": edge_total,
            "nodes_start": nodes_start,
            "literal_start": literal_start,
            "tag_validation": tag_validation,
        },
        header_fields=header_fields,
    )
    decoded.literal_strings_with_offsets = literal_strings_with_offsets  # type: ignore[attr-defined]

    return decoded


def decode_profile_dict(data: bytes) -> Dict[str, Any]:
    """Dict wrapper for JSON serialization."""
    d = decode_profile(data)
    return {
        "format_variant": d.format_variant,
        "preamble_words": d.preamble_words,
        "preamble_words_full": d.preamble_words_full,
        "header_bytes": d.header_bytes.hex(),
        "op_count": d.op_count,
        "op_table_offset": d.op_table_offset,
        "op_table": d.op_table,
        "nodes": d.nodes,
        "node_count": d.node_count,
        "tag_counts": d.tag_counts,
        "literal_strings": d.literal_strings,
        "literal_strings_with_offsets": getattr(
            d, "literal_strings_with_offsets", [(i, s) for i, s in enumerate(d.literal_strings)]
        ),
        "sections": d.sections,
        "validation": getattr(d, "validation", {}),
        "header_fields": getattr(d, "header_fields", {}),
    }
