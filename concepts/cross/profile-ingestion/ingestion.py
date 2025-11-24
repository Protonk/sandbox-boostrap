"""
Axis 4.1 – Profile Ingestion Layer

Parses compiled sandbox profiles into header/section slices to support later graph
construction. Supports:
- `graph-v1`: modern graph-based blobs produced by `sandbox_compile_*` (`examples/sb/`, `examples/sbsnarf/`).
- `legacy-tree-v1`: early/decision-tree format parsed by `examples/sbdis/`.

Concept linkage: Binary Profile Header (§3.10), Operation Pointer Table (§3.11),
Regex/Literal Table (§3.14), Profile Format Variant (§3.15), Compiled Profile Source (§3.19).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


class UnsupportedProfileFormat(RuntimeError):
    """Raised when the blob does not look like the supported modern graph format."""


HEADER_SIZE_BYTES = 12  # graph-v1 header size (6 * uint16)
NODE_STRUCT_SIZE_BYTES = 8  # graph-v1 node struct size
FORMAT_GRAPH_V1 = "graph-v1"
FORMAT_LEGACY_V1 = "legacy-tree-v1"


@dataclass
class ProfileBlob:
    """Raw compiled profile bytes plus provenance metadata (Compiled Profile Source §3.19)."""

    bytes: bytes
    source: str = "unknown"

    @classmethod
    def from_path(cls, path: str | Path, source: Optional[str] = None) -> "ProfileBlob":
        data = Path(path).read_bytes()
        return cls(bytes=data, source=source or str(path))


@dataclass
class ProfileHeader:
    """
    Parsed header/section info for supported formats.

    Fields track the Binary Profile Header (§3.10) and section offsets used by both
    modern graph and legacy decision-tree layouts.
    """

    format_variant: str
    profile_type: int
    version: int
    operation_count: int
    node_count: int
    op_table_offset: int
    op_table_size: int
    node_array_offset: int
    node_array_size: int
    regex_literals_offset: int
    regex_literals_size: int
    regex_count: int = 0  # legacy: number of regex pointers (re_table_count)


@dataclass
class ProfileSections:
    """Typed views over the parsed sections."""

    op_table: memoryview
    nodes: memoryview
    regex_literals: memoryview


def detect_format(blob: ProfileBlob) -> str:
    """
    Return a format tag for supported blobs (graph-v1 or legacy-tree-v1).

    Detection heuristic:
    - re_table_offset == 0 → graph-v1 (modern)
    - re_table_offset > 0 → legacy-tree-v1 (early decision-tree)
    """
    data = blob.bytes
    if len(data) < 4:
        raise UnsupportedProfileFormat("blob too small for any supported header")
    re_table_offset_words, _ = struct.unpack_from("<HH", data, 0)
    if re_table_offset_words == 0:
        return FORMAT_GRAPH_V1
    return FORMAT_LEGACY_V1


def parse_header(blob: ProfileBlob) -> ProfileHeader:
    """
    Parse a compiled profile header into a ProfileHeader for the supported formats.
    """
    fmt = detect_format(blob)
    data = blob.bytes

    if fmt == FORMAT_GRAPH_V1:
        if len(data) < HEADER_SIZE_BYTES:
            raise UnsupportedProfileFormat("blob too small for graph-v1 header parsing")

        profile_type, version, operation_count = struct.unpack_from("<HHH", data, 0)
        op_table_offset = HEADER_SIZE_BYTES
        op_table_size = operation_count * 2
        if op_table_offset + op_table_size > len(data):
            raise UnsupportedProfileFormat("operation table exceeds blob length")

        if operation_count:
            op_entries = struct.unpack_from(f"<{operation_count}H", data, op_table_offset)
            node_count = max(op_entries) + 1
        else:
            op_entries = ()
            node_count = 0

        node_array_offset = op_table_offset + op_table_size
        node_array_size = node_count * NODE_STRUCT_SIZE_BYTES
        regex_literals_offset = node_array_offset + node_array_size

        if regex_literals_offset > len(data):
            raise UnsupportedProfileFormat(
                "computed regex/literal offset beyond blob length; unsupported variant?"
            )

        regex_literals_size = len(data) - regex_literals_offset

        return ProfileHeader(
            format_variant=fmt,
            profile_type=profile_type,
            version=version,
            operation_count=operation_count,
            node_count=node_count,
            op_table_offset=op_table_offset,
            op_table_size=op_table_size,
            node_array_offset=node_array_offset,
            node_array_size=node_array_size,
            regex_literals_offset=regex_literals_offset,
            regex_literals_size=regex_literals_size,
            regex_count=0,
        )

    # legacy-tree-v1 (decision-tree style, as parsed by sbdis)
    re_table_offset_words, re_table_count = struct.unpack_from("<HH", data, 0)
    regex_literals_offset = re_table_offset_words * 8
    if regex_literals_offset > len(data):
        raise UnsupportedProfileFormat("legacy regex table offset beyond blob length")

    op_table_offset = 4
    op_table_size = regex_literals_offset - op_table_offset
    if op_table_size < 0:
        raise UnsupportedProfileFormat("invalid op-table size for legacy format")
    operation_count = op_table_size // 2

    # For legacy blobs, handlers/nodes live in the pre-regex portion; keep a broad view.
    node_array_offset = 0
    node_array_size = regex_literals_offset
    node_count = node_array_size // NODE_STRUCT_SIZE_BYTES if NODE_STRUCT_SIZE_BYTES else 0
    regex_literals_size = len(data) - regex_literals_offset

    return ProfileHeader(
        format_variant=fmt,
        profile_type=0,
        version=0,
        operation_count=operation_count,
        node_count=node_count,
        op_table_offset=op_table_offset,
        op_table_size=op_table_size,
        node_array_offset=node_array_offset,
        node_array_size=node_array_size,
        regex_literals_offset=regex_literals_offset,
        regex_literals_size=regex_literals_size,
        regex_count=re_table_count,
    )


def slice_sections(blob: ProfileBlob, header: ProfileHeader) -> ProfileSections:
    """Return memoryviews over the key sections using offsets from ProfileHeader."""
    mv = memoryview(blob.bytes)
    op_mv = mv[header.op_table_offset : header.op_table_offset + header.op_table_size]
    node_mv = mv[header.node_array_offset : header.node_array_offset + header.node_array_size]
    regex_mv = mv[
        header.regex_literals_offset : header.regex_literals_offset + header.regex_literals_size
    ]
    return ProfileSections(op_table=op_mv, nodes=node_mv, regex_literals=regex_mv)
