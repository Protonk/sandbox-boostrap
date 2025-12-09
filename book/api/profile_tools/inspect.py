"""
Read-only inspection helpers for compiled sandbox blobs (Sonoma baseline).

This is the consolidated home for the former `inspect_profile` helpers.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Sequence

import book.api.decoder as decoder
from book.graph.concepts.validation import profile_ingestion as pi


@dataclass
class Summary:
    format_variant: str | None
    op_count: int | None
    length: int
    op_entries: List[int]
    section_lengths: Dict[str, int]
    stride_stats: List[Dict[str, Any]]
    tag_counts_stride12: Dict[int, int]
    remainder_stride12_hex: str
    literal_strings: List[Dict[str, Any]]
    decoder: Dict[str, Any]
    nodes_raw: List[Dict[str, Any]] | None = None


def load_blob(path: Path) -> bytes:
    return path.read_bytes()


def _op_entries(blob: bytes, op_count: int) -> List[int]:
    ops = blob[16 : 16 + op_count * 2]
    return [int.from_bytes(ops[i : i + 2], "little") for i in range(0, len(ops), 2)]


def _stride_stats(nodes: bytes, stride: int) -> Dict[str, Any]:
    recs = len(nodes) // stride
    rem = len(nodes) % stride
    tags = set()
    edge_in_bounds = 0
    edges_total = 0
    for i in range(0, recs * stride, stride):
        rec = nodes[i : i + stride]
        if not rec:
            continue
        tags.add(rec[0])
        if stride >= 6:
            e1 = int.from_bytes(rec[2:4], "little")
            e2 = int.from_bytes(rec[4:6], "little")
            edges_total += 2
            if e1 * stride < len(nodes):
                edge_in_bounds += 1
            if e2 * stride < len(nodes):
                edge_in_bounds += 1
    return {
        "stride": stride,
        "records": recs,
        "remainder": rem,
        "tags": sorted(tags),
        "edges_in_bounds": edge_in_bounds,
        "edges_total": edges_total,
    }


def _tag_counts(nodes: bytes, stride: int = 12) -> Dict[int, int]:
    counts: Dict[int, int] = {}
    recs = len(nodes) // stride
    for idx in range(recs):
        rec = nodes[idx * stride : (idx + 1) * stride]
        tag = rec[0]
        counts[tag] = counts.get(tag, 0) + 1
    return counts


def _ascii_strings(buf: bytes, min_len: int = 4) -> List[Dict[str, Any]]:
    runs: List[Dict[str, Any]] = []
    start = None
    current: List[str] = []
    for idx, byte in enumerate(buf):
        if 0x20 <= byte < 0x7F:
            if start is None:
                start = idx
            current.append(chr(byte))
        else:
            if current and len(current) >= min_len and start is not None:
                runs.append({"offset": start, "string": "".join(current)})
            start = None
            current = []
    if current and len(current) >= min_len and start is not None:
        runs.append({"offset": start, "string": "".join(current)})
    return runs


def summarize_blob(blob: bytes, strides: Sequence[int] = (8, 12, 16)) -> Summary:
    header = pi.parse_header(pi.ProfileBlob(bytes=blob, source="inspect_profile"))
    sections = pi.slice_sections(pi.ProfileBlob(bytes=blob, source="inspect_profile"), header)
    op_count = header.operation_count or 0
    op_entries = _op_entries(blob, op_count) if op_count else []
    decoded = decoder.decode_profile_dict(blob)
    # Guarded fallback: if decoder emitted empty nodes, but slice_sections found a nonzero nodes range, overwrite.
    dec_sections = decoded.get("sections") or {}
    nodes_len_dec = dec_sections.get("nodes")
    nodes_len_dec = nodes_len_dec.get("length") if isinstance(nodes_len_dec, dict) else nodes_len_dec
    if nodes_len_dec in (None, 0) and sections.nodes:
        dec_sections = dict(dec_sections)
        dec_sections["nodes_start"] = 16 + (header.operation_count or 0) * 2
        dec_sections["nodes"] = len(sections.nodes)
        decoded["sections"] = dec_sections
    nodes_raw: List[Dict[str, Any]] | None = None
    if sections.nodes:
        stride = 12  # default modern stride for Sonoma baseline
        recs = len(sections.nodes) // stride
        nodes_raw = []
        for idx in range(recs):
            rec = sections.nodes[idx * stride : (idx + 1) * stride]
            nodes_raw.append(
                {
                    "offset": idx * stride,
                    "tag": rec[0],
                    "bytes": rec.hex(),
                    "halfwords": [int.from_bytes(rec[i : i + 2], "little") for i in range(0, stride, 2)],
                }
            )
        if recs > 0:
            canonical_len = recs * stride
            if len(sections.nodes) - canonical_len == 3:
                sections = pi.Sections(op_table=sections.op_table, nodes=sections.nodes[:canonical_len], regex_literals=sections.regex_literals)
                dec_sections = decoded.get("sections") or {}
                dec_sections = dict(dec_sections)
                dec_sections["nodes"] = canonical_len
                dec_sections["literal_start"] = dec_sections.get("nodes_start", 16 + (header.operation_count or 0) * 2) + canonical_len
                decoded["sections"] = dec_sections
    stride_stats = [_stride_stats(sections.nodes, s) for s in strides]
    return Summary(
        format_variant=header.format_variant,
        op_count=op_count,
        length=len(blob),
        op_entries=op_entries,
        section_lengths={
            "op_table": len(sections.op_table),
            "nodes": len(sections.nodes),
            "literals": len(sections.regex_literals),
        },
        stride_stats=stride_stats,
        tag_counts_stride12=_tag_counts(sections.nodes),
        remainder_stride12_hex=sections.nodes[(len(sections.nodes) // 12) * 12 :].hex(),
        literal_strings=_ascii_strings(sections.regex_literals),
        decoder={
            "format_variant": decoded.get("format_variant"),
            "op_count": decoded.get("op_count"),
            "op_table_offset": decoded.get("op_table_offset"),
            "node_count": decoded.get("node_count"),
            "tag_counts": decoded.get("tag_counts"),
            "literal_strings": decoded.get("literal_strings"),
            "sections": decoded.get("sections"),
        },
        nodes_raw=nodes_raw,
    )
