"""
Profile ingestion helpers (Sonoma baseline).

This module defines the *shared slice contract* for compiled sandbox profile blobs:
- Parse a minimal header (including format-variant detection).
- Slice the blob into the op-table region, node stream region, and literal/regex pool.

Why this lives under `book.api.profile`:
- The canonical ingestion logic was developed inside the validation pipeline.
- Experiments, examples, and ad-hoc tooling need the same slicing behavior
  without importing from `book/graph/concepts/validation/`.

It exists so that callers outside the validation layer (examples, experiments,
API tooling) have a stable import path under `book.api.profile` without
reaching into `book/graph/concepts/validation/`.

Evidence / tiering:
- Header/section boundaries are treated as *structural* evidence.
- Heuristics here are baseline-specific; if they fail for a blob, that is
  valuable information and should be captured as a witness rather than patched
  into a more “clever” guess.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, List, Dict, Any
import struct
import string

PRINTABLE = set(bytes(string.printable, "ascii"))


# Minimal Mach-O segment parser for slicing fallbacks.
#
# Why this exists in a “profile blob” slicer:
# Some inputs in this repo are not raw `.sb.bin` blobs but are embedded inside
# other containers. When the input *is* a Mach-O, we can use segment metadata as
# a more principled bound than purely printable-run heuristics.
def _parse_macho_segments(data: bytes) -> List[Dict[str, Any]]:
    """
    Parse Mach-O LC_SEGMENT_64 commands and return a list of segment records.

    Returns an empty list when `data` does not look like a 64-bit Mach-O.
    This is intentionally minimal: it is only used as a slicing hint.
    """
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
    """A compiled blob with a human-friendly source label (for logs/errors)."""

    bytes: bytes
    source: str


@dataclass
class Header:
    """
    Minimal header interpretation.

    The ingestion layer keeps this intentionally small: it is primarily a
    carrier for `format_variant` and an optional `operation_count` hint used to
    slice the op-table region.
    """

    format_variant: str
    operation_count: Optional[int]
    node_count: Optional[int]
    regex_count: Optional[int]
    raw_length: int


@dataclass
class Sections:
    """Byte slices for the major blob regions."""

    op_table: bytes
    nodes: bytes
    regex_literals: bytes


@dataclass(frozen=True)
class SectionOffsets:
    """Absolute byte offsets for `Sections` slices (useful for cross-checks)."""

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
    """
    Parse a minimal header from a compiled profile blob.

    This function only chooses a format variant and (for modern blobs) attempts
    to guess the operation count from the first 16 bytes. If the blob is not
    recognized, we still return a `Header` and let slicing continue — failures
    are surfaced via downstream validation and guardrails.
    """
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
    """
    Slice a blob into sections (op_table, nodes, literal pool).

    This is a convenience wrapper around `slice_sections_with_offsets` when the
    caller doesn't need absolute offsets.
    """
    sections, _offsets = slice_sections_with_offsets(blob, header)
    return sections


def slice_sections_with_offsets(blob: ProfileBlob, header: Header) -> tuple[Sections, SectionOffsets]:
    """
    Slice a blob into sections and return both byte ranges and absolute offsets.

    The modern heuristic path uses:
    - A 16-byte preamble.
    - An op-table length derived from `header.operation_count` when available.
    - A literal-pool start heuristic that is *bounded* by op-table targets to
      avoid truncating the node stream due to printable data inside nodes.
    """
    data = blob.bytes
    if header.format_variant == "legacy-decision-tree":
        # Legacy layout:
        # - header is 4 bytes: u16 re_table_offset_words + u8 regex_count + padding
        # - op_table spans [4, re_table_offset_bytes)
        # - "nodes" are embedded in the regex program region; we treat the tail
        #   as `regex_literals` and leave `nodes` empty.
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
    # Key wrinkle (Sonoma baseline):
    # op_table entries behave like u16 *word offsets* into the node stream, with
    # WORD = 8 bytes on this world (see `book.api.profile.decoder.WORD_OFFSET_BYTES`).
    # We use the maximum referenced node offset as a hard lower bound for the
    # literal pool start so that "printable-run" heuristics don't accidentally
    # treat ASCII-like bytes inside the node stream as the start of literals.
    nodes_start = op_table_end
    op_entries = [int.from_bytes(op_table[i : i + 2], "little") for i in range(0, len(op_table), 2)]
    lower_bound = nodes_start
    if op_entries:
        # `+1` keeps the lower bound past the record referred to by `max(op_entries)`.
        lower_bound = nodes_start + (max(op_entries) + 1) * 8
        if lower_bound < nodes_start:
            lower_bound = nodes_start
        if lower_bound > len(data):
            lower_bound = len(data)

    def find_literal_start(buf: bytes, start: int) -> int:
        """
        Find a plausible start for the literal pool / regex program.

        This is best-effort; callers should treat `literal_start` as heuristic
        evidence and cross-check it (for example with the decoder's node
        remainder and literal string extraction).
        """
        segments = _parse_macho_segments(buf)
        for seg in segments:
            if seg["name"] == "__TEXT":
                # Crude bound: treat the end of __TEXT as the earliest plausible
                # location for a string pool.
                cstring = seg["fileoff"] + seg["filesize"]  # crude upper bound
                if cstring >= start:
                    return cstring
        # Prefer a short run of non-NUL printable characters starting at the lower bound.
        # This catches the common pattern of embedded regex/literal tables that
        # begin with printable tokens.
        min_run = 4
        for i in range(start, len(buf) - min_run):
            j = i
            while j < len(buf) and buf[j] != 0x00 and buf[j] in PRINTABLE:
                j += 1
            if j - i >= min_run:
                return i
        # Fallback: ratio-based scan, still starting at the lower bound.
        # This is intentionally conservative: it is better to return "end of
        # buffer" than to split the node stream incorrectly.
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
