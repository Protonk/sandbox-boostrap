"""
Small byte/record helpers shared across profile_tools modules (Sonoma baseline).

These helpers are intentionally low-level and format-structural. They do not
assert kernel semantics.
"""

from __future__ import annotations

from typing import Any


def u16le(buf: bytes, off: int) -> int:
    return int.from_bytes(buf[off : off + 2], "little")


def op_entries(blob: bytes, op_count: int, *, op_table_offset: int = 16) -> list[int]:
    """Read u16 op-table entries from a compiled blob (modern layout)."""
    ops = blob[op_table_offset : op_table_offset + op_count * 2]
    return [u16le(ops, i) for i in range(0, len(ops), 2)]


def tag_counts(nodes: bytes, *, stride: int = 12) -> dict[int, int]:
    """Count node tags using a fixed record stride (best-effort)."""
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

    Output shape matches the historical helpers used by inspect/op_table.
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

