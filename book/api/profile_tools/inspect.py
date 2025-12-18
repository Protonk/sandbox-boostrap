"""
Read-only inspection helpers for compiled sandbox blobs (Sonoma baseline).

This is the consolidated home for the former `inspect_profile` helpers.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Sequence

from . import bytes_util as bu
from . import decoder as decoder
from . import ingestion as pi


@dataclass
class Summary:
    format_variant: str | None
    op_count: int | None
    length: int
    header_words: List[int] | None
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
    return bu.tag_counts(nodes, stride=stride)


def summarize_blob(blob: bytes, strides: Sequence[int] = (8, 12, 16)) -> Summary:
    header_words = [int.from_bytes(blob[i : i + 2], "little") for i in range(0, min(len(blob), 16), 2)]
    header = pi.parse_header(pi.ProfileBlob(bytes=blob, source="inspect_profile"))
    sections = pi.slice_sections(pi.ProfileBlob(bytes=blob, source="inspect_profile"), header)
    op_count = header.operation_count or 0
    op_entries = bu.op_entries(blob, op_count) if op_count else []
    decoded = decoder.decode_profile_dict(blob)
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
    stride_stats = [_stride_stats(sections.nodes, s) for s in strides]
    return Summary(
        format_variant=header.format_variant,
        op_count=op_count,
        length=len(blob),
        header_words=header_words if header_words else None,
        op_entries=op_entries,
        section_lengths={
            "op_table": len(sections.op_table),
            "nodes": len(sections.nodes),
            "literals": len(sections.regex_literals),
        },
        stride_stats=stride_stats,
        tag_counts_stride12=_tag_counts(sections.nodes),
        remainder_stride12_hex=sections.nodes[(len(sections.nodes) // 12) * 12 :].hex(),
        literal_strings=bu.ascii_strings(sections.regex_literals),
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
