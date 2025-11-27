"""
Minimal, version-tolerant profile ingestion helpers.

This is intentionally light: it provides a stable interface (`parse_header`,
`slice_sections`) that the examples can call without depending on a specific
format variant. Where possible, it recognizes the early decision-tree layout;
otherwise it treats the blob as an opaque modern/unknown format and returns
placeholder counts while still letting callers inspect byte ranges.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class ProfileBlob:
    bytes: bytes
    source: str


@dataclass
class Header:
    format_variant: str
    operation_count: Optional[int]
    node_count: Optional[int]
    regex_count: Optional[int]
    raw_length: int


@dataclass
class Sections:
    op_table: bytes
    nodes: bytes
    regex_literals: bytes


def _is_legacy_decision_tree(blob: bytes) -> bool:
    """Heuristic: early format uses u16 re_table_offset (8-byte words) + u8 count."""
    if len(blob) < 4:
        return False
    re_offset_words = int.from_bytes(blob[0:2], "little")
    re_offset_bytes = re_offset_words * 8
    if re_offset_bytes <= 4 or re_offset_bytes > len(blob):
        return False
    # op_table fills the gap between header (4 bytes) and regex table
    return (re_offset_bytes - 4) % 2 == 0


def parse_header(blob: ProfileBlob) -> Header:
    data = blob.bytes
    if _is_legacy_decision_tree(data):
        re_offset_words = int.from_bytes(data[0:2], "little")
        re_offset_bytes = re_offset_words * 8
        re_count = data[2]
        op_table_len = re_offset_bytes - 4
        op_count = op_table_len // 2 if op_table_len >= 0 else None
        return Header(
            format_variant="legacy-decision-tree",
            operation_count=op_count,
            node_count=None,
            regex_count=re_count,
            raw_length=len(data),
        )
    # Fallback for unknown/modern formats: report length and unknown counts.
    return Header(
        format_variant="unknown-modern",
        operation_count=None,
        node_count=None,
        regex_count=None,
        raw_length=len(data),
    )


def slice_sections(blob: ProfileBlob, header: Header) -> Sections:
    data = blob.bytes
    if header.format_variant == "legacy-decision-tree":
        re_offset_bytes = int.from_bytes(data[0:2], "little") * 8
        op_table = data[4:re_offset_bytes]
        nodes = b""  # legacy handlers are embedded; keep them in regex_literals below
        regex_literals = data[re_offset_bytes:]
        return Sections(op_table=op_table, nodes=nodes, regex_literals=regex_literals)
    # Unknown/modern: expose the whole blob as regex_literals for inspection.
    return Sections(op_table=b"", nodes=b"", regex_literals=data)
