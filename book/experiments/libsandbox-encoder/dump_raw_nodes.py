#!/usr/bin/env python3
"""
Quick-and-dirty helper to eyeball raw node records in a compiled profile.

This is purposely heuristic and scoped to the libsandbox-encoder experiment:
- Finds the first plausible literal/string run to guess the start of the literal pool.
- Walks backwards in stride-sized chunks (default stride=8 for this world baseline) from that point to locate the contiguous node block.
- Dumps halfword values for each record so we can spot payload bytes (e.g., socket domain/type/proto)
  before we go spelunking in the libsandbox serializer.

This is not a general decoder; it is a debug aid for Phase B to align `_emit_*` writes with
tag10 layouts in `matrix_v1.sb.bin`.
"""

import argparse
import re
import json
from pathlib import Path


def find_literal_start(blob: bytes) -> int:
    """Return the offset of the first ASCII-ish run (len>=8), used as a literal pool heuristic."""
    m = re.search(rb"[\x20-\x7e]{8,}", blob)
    return m.start() if m else len(blob)


def find_node_block(blob: bytes, literal_start: int, stride: int = 8) -> tuple[int, int]:
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


def dump_records(blob: bytes, start: int, end: int, stride: int = 8) -> list[dict]:
    records = []
    for off in range(start, end, stride):
        chunk = blob[off : off + stride]
        hw = [int.from_bytes(chunk[i : i + 2], "little") for i in range(0, stride, 2)]
        records.append({"offset": off, "halfwords": hw})
    return records


def main() -> None:
    ap = argparse.ArgumentParser(description="Dump raw node records for a compiled profile blob")
    ap.add_argument("blob", type=Path, help="Path to .sb.bin blob")
    ap.add_argument("--header", action="store_true", help="Use header-derived nodes_start/nodes_len from inspect_profile summary")
    ap.add_argument("--stride", type=int, help="Override stride (bytes) instead of assuming 8 or inferring")
    args = ap.parse_args()

    blob = args.blob.read_bytes()
    if args.header:
        # load inspect_profile JSON sitting next to blob if present
        insp_path = args.blob.with_suffix(".inspect.json")
        if not insp_path.exists():
            raise SystemExit(f"[error] --header set but no {insp_path} found")
        data = json.loads(insp_path.read_text())
        sections = data.get("decoder", {}).get("sections", {})
        nodes_start = sections.get("nodes_start")
        nodes_raw = data.get("nodes_raw") or []
        if nodes_start is None or not nodes_raw:
            raise SystemExit(f"[error] missing nodes_start or nodes_raw in {insp_path}; re-run inspect_profile first")
        record_size = len(bytes.fromhex(nodes_raw[0]["bytes"]))
        node_count = len(nodes_raw)
        nodes_len = record_size * node_count
        node_start, node_end = nodes_start, nodes_start + nodes_len
        args.stride = args.stride or record_size
    else:
        literal_start = find_literal_start(blob)
        node_start, node_end = find_node_block(blob, literal_start)
        if not (0 <= node_start < node_end <= literal_start <= len(blob)):
            raise SystemExit(f"[error] bad slice: nodes [{node_start},{node_end}), literal_start={literal_start}, blob_len={len(blob)}")
    stride = args.stride or 8
    if (node_end - node_start) % stride != 0:
        raise SystemExit(f"[error] node block size {(node_end - node_start)} not divisible by stride {stride} (start={node_start}, end={node_end})")

    recs = dump_records(blob, node_start, node_end, stride=stride)

    print(f"blob: {args.blob} (len={len(blob)})")
    print(f"node block: [{node_start}, {node_end}) stride={stride} -> {len(recs)} records")
    for r in recs:
        hw = " ".join(f"{x:04x}" for x in r["halfwords"])
        print(f"{r['offset']:4d}: {hw}")


if __name__ == "__main__":
    main()
