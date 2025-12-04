#!/usr/bin/env python3
"""
Quick-and-dirty helper to eyeball raw 12-byte node records in a compiled profile.

This is purposely heuristic and scoped to the libsandbox-encoder experiment:
- Finds the first plausible literal/string run to guess the start of the literal pool.
- Walks backwards in 12-byte strides from that point to locate the contiguous node block.
- Dumps halfword values for each record so we can spot payload bytes (e.g., socket domain/type/proto)
  before we go spelunking in the libsandbox serializer.

This is not a general decoder; it is a debug aid for Phase B to align `_emit_*` writes with
tag10 layouts in `matrix_v1.sb.bin`.
"""

import argparse
import re
from pathlib import Path


def find_literal_start(blob: bytes) -> int:
    """Return the offset of the first ASCII-ish run (len>=8), used as a literal pool heuristic."""
    m = re.search(rb"[\x20-\x7e]{8,}", blob)
    return m.start() if m else len(blob)


def find_node_block(blob: bytes, literal_start: int, stride: int = 12) -> tuple[int, int]:
    """
    Heuristically locate the contiguous node block immediately before the literal pool.
    We walk backward from literal_start in stride-sized chunks until we see two consecutive
    all-zero records, then treat everything after that as the node block.
    """
    end = literal_start - (literal_start % stride)  # align to stride
    zero_run = 0
    pos = end
    while pos >= stride:
        chunk = blob[pos - stride : pos]
        if all(b == 0 for b in chunk):
            zero_run += 1
            if zero_run >= 2:
                break
        else:
            zero_run = 0
        pos -= stride
    start = pos + (2 * stride if zero_run >= 2 else 0)
    return start, end


def dump_records(blob: bytes, start: int, end: int, stride: int = 12) -> list[dict]:
    records = []
    for off in range(start, end, stride):
        chunk = blob[off : off + stride]
        hw = [int.from_bytes(chunk[i : i + 2], "little") for i in range(0, stride, 2)]
        records.append({"offset": off, "halfwords": hw})
    return records


def main() -> None:
    ap = argparse.ArgumentParser(description="Dump raw 12-byte node records for a compiled profile blob")
    ap.add_argument("blob", type=Path, help="Path to .sb.bin blob")
    args = ap.parse_args()

    blob = args.blob.read_bytes()
    literal_start = find_literal_start(blob)
    node_start, node_end = find_node_block(blob, literal_start)
    if not (0 <= node_start < node_end <= literal_start <= len(blob)):
        raise SystemExit(f"[error] bad slice: nodes [{node_start},{node_end}), literal_start={literal_start}, blob_len={len(blob)}")
    if (node_end - node_start) % 12 != 0:
        raise SystemExit(f"[error] node block size {(node_end - node_start)} not divisible by 12 (start={node_start}, end={node_end})")

    recs = dump_records(blob, node_start, node_end)

    print(f"blob: {args.blob} (len={len(blob)})")
    print(f"literal_start guess: {literal_start}")
    print(f"node block: [{node_start}, {node_end}) stride=12 -> {len(recs)} records")
    for r in recs:
        hw = " ".join(f"{x:04x}" for x in r["halfwords"])
        print(f"{r['offset']:4d}: {hw}")


if __name__ == "__main__":
    main()
