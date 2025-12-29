"""
Profile ingestion helpers (Sonoma baseline).

This module is a copy of the canonical ingestion helpers under:
- `book/graph/concepts/validation/profile_ingestion.py`

It exists so that callers outside the validation layer (examples, experiments,
API tooling) have a stable import path under `book.api.profile_tools` without
reaching into `book/graph/concepts/validation/`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, List, Dict, Any
import struct
import string

PRINTABLE = set(bytes(string.printable, "ascii"))

# Minimal Mach-O segment parser for slicing fallbacks
def _parse_macho_segments(data: bytes) -> List[Dict[str, Any]]:
    # Expect 64-bit Mach-O magic 0xfeedfacf
    if len(data) < 32 or data[0:4] not in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
        return []
    # mach_header_64: uint32 magic, cpu_type, cpu_subtype, filetype, ncmds, sizeofcmds, flags, reserved
    _, _, _, _, ncmds, _, _, _ = struct.unpack_from("<IIIIIIII", data, 0)
    offset = 32
    segments = []
    for _ in range(ncmds):
        if offset + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from("<II", data, offset)
        if cmd == 0x19:  # LC_SEGMENT_64
            if offset + 72 > len(data):
                break
            segname = data[offset + 8 : offset + 24].split(b"\x00", 1)[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, offset + 24)
            segments.append(
                {
                    "name": segname,
                    "vmaddr": vmaddr,
                    "vmsize": vmsize,
                    "fileoff": fileoff,
                    "filesize": filesize,
                }
            )
        offset += cmdsize
    return segments


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


@dataclass(frozen=True)
class SectionOffsets:
    op_table_start: int
    op_table_end: int
    nodes_start: int
    nodes_end: int
    literal_start: int
    literal_end: int


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
    # Heuristic for modern graph-based blobs compiled by libsandbox:
    # - first 16 bytes often contain small u16 fields; the second word usually
    #   matches the number of operations (count of op-table entries).
    # - op table appears immediately after this 16-byte preamble as u16
    #   indices into the node array.
    op_count: Optional[int] = None
    if len(data) >= 18:
        words = [int.from_bytes(data[i : i + 2], "little") for i in range(0, 16, 2)]
        maybe_op = words[1]
        if 0 < maybe_op < 2048:
            op_count = maybe_op
    return Header(
        format_variant="modern-heuristic",
        operation_count=op_count,
        node_count=None,
        regex_count=None,
        raw_length=len(data),
    )


def slice_sections(blob: ProfileBlob, header: Header) -> Sections:
    sections, _offsets = slice_sections_with_offsets(blob, header)
    return sections


def slice_sections_with_offsets(blob: ProfileBlob, header: Header) -> tuple[Sections, SectionOffsets]:
    data = blob.bytes
    if header.format_variant == "legacy-decision-tree":
        re_offset_bytes = int.from_bytes(data[0:2], "little") * 8
        op_table_start = 4
        op_table_end = re_offset_bytes
        literal_start = re_offset_bytes
        literal_end = len(data)
        op_table = data[op_table_start:op_table_end]
        nodes = b""  # legacy handlers are embedded; keep them in regex_literals below
        regex_literals = data[literal_start:]
        return (
            Sections(op_table=op_table, nodes=nodes, regex_literals=regex_literals),
            SectionOffsets(
                op_table_start=op_table_start,
                op_table_end=op_table_end,
                nodes_start=literal_start,
                nodes_end=literal_start,
                literal_start=literal_start,
                literal_end=literal_end,
            ),
        )
    # Modern heuristic: treat bytes 0x10..(0x10 + op_count*2) as op-table.
    op_table_len = 0
    if header.operation_count:
        op_table_len = header.operation_count * 2
    op_table_start = 16
    op_table_end = min(len(data), op_table_start + op_table_len)
    op_table = data[op_table_start:op_table_end]

    # Attempt to split node area vs literal/regex pool.
    #
    # For this Sonoma baseline, op_table entries behave like u16 word offsets
    # (8-byte units) into the node stream. Use the maximum op_table target as a
    # hard lower bound for where the literal pool may begin, to avoid the common
    # failure mode where printable-run heuristics "find" ASCII-looking bytes
    # inside the node stream and truncate the node region.
    nodes_start = op_table_end
    op_entries = [int.from_bytes(op_table[i : i + 2], "little") for i in range(0, len(op_table), 2)]
    lower_bound = nodes_start
    if op_entries:
        lower_bound = nodes_start + (max(op_entries) + 1) * 8
        if lower_bound < nodes_start:
            lower_bound = nodes_start
        if lower_bound > len(data):
            lower_bound = len(data)

    def find_literal_start(buf: bytes, start: int) -> int:
        segments = _parse_macho_segments(buf)
        for seg in segments:
            if seg["name"] == "__TEXT":
                cstring = seg["fileoff"] + seg["filesize"]  # crude upper bound
                if cstring >= start:
                    return cstring
        # Prefer a short run of non-NUL printable characters starting at the lower bound.
        min_run = 4
        for i in range(start, len(buf) - min_run):
            j = i
            while j < len(buf) and buf[j] != 0x00 and buf[j] in PRINTABLE:
                j += 1
            if j - i >= min_run:
                return i
        # Fallback: ratio-based scan, still starting at the lower bound.
        window = 64
        threshold = 0.7
        for i in range(start, len(buf)):
            chunk = buf[i : min(len(buf), i + window)]
            if not chunk:
                continue
            printable = sum(1 for b in chunk if b == 0x00 or b in PRINTABLE)
            if printable / len(chunk) >= threshold:
                return i
        return len(buf)

    literal_start = find_literal_start(data, lower_bound)
    literal_end = len(data)
    nodes_end = literal_start
    nodes = data[nodes_start:nodes_end]
    regex_literals = data[literal_start:literal_end]
    return (
        Sections(op_table=op_table, nodes=nodes, regex_literals=regex_literals),
        SectionOffsets(
            op_table_start=op_table_start,
            op_table_end=op_table_end,
            nodes_start=nodes_start,
            nodes_end=nodes_end,
            literal_start=literal_start,
            literal_end=literal_end,
        ),
    )
