"""
Small byte/record helpers shared across profile modules (Sonoma baseline).

These helpers are intentionally low-level and format-structural. They do not
assert kernel semantics.

If you need higher-level slicing (header/op-table/nodes/literal pool), prefer:
- `book.api.profile.ingestion` (section slicing)
- `book.api.profile.decoder` (best-effort annotation)
"""

from __future__ import annotations

from typing import Any


def u16le(buf: bytes, off: int) -> int:
    """Read a little-endian u16 at byte offset `off`."""
    return int.from_bytes(buf[off : off + 2], "little")


def op_entries(blob: bytes, op_count: int, *, op_table_offset: int = 16) -> list[int]:
    """
    Read u16 op-table entries from a compiled blob (modern layout).

    Notes:
    - On this world baseline, “modern” compiled blobs typically place a 16-byte
      preamble at the start of the blob, followed immediately by the u16 op-table.
    - This helper does not validate the header; it is meant for quick inspection.
      For robust slicing, call `book.api.profile.ingestion.parse_header` and
      `slice_sections*` first.
    """
    ops = blob[op_table_offset : op_table_offset + op_count * 2]
    return [u16le(ops, i) for i in range(0, len(ops), 2)]


def tag_counts(nodes: bytes, *, stride: int = 12) -> dict[int, int]:
    """
    Count node tags using a fixed record stride (best-effort).

    This is intentionally “dumb”: it assumes the first byte of each record is a
    tag, and it does not attempt to infer framing. For framing inference, use
    `book.api.profile.decoder.decode_profile`.
    """
    counts: dict[int, int] = {}
    if stride <= 0:
        return counts
    recs = len(nodes) // stride
    for idx in range(recs):
        tag = nodes[idx * stride]
        counts[tag] = counts.get(tag, 0) + 1
    return counts


def ascii_strings(buf: bytes, *, min_len: int = 4) -> list[dict[str, Any]]:
    """
    Extract printable ASCII runs with offsets (best-effort).

    Output shape matches the historical helpers used by inspect/op_table:
    `{"offset": <byte_offset>, "string": <ascii>}`.

    This is not a full literal pool decoder; it exists to provide human
    orientation when inspecting blobs.
    """
    runs: list[dict[str, Any]] = []
    start: int | None = None
    current: list[str] = []
    for idx, byte in enumerate(buf):
        if 0x20 <= byte < 0x7F:
            if start is None:
                start = idx
            current.append(chr(byte))
            continue
        if current and len(current) >= min_len and start is not None:
            runs.append({"offset": start, "string": "".join(current)})
        start = None
        current = []
    if current and len(current) >= min_len and start is not None:
        runs.append({"offset": start, "string": "".join(current)})
    return runs
