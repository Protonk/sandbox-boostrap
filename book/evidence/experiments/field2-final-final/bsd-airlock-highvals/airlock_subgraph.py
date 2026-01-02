#!/usr/bin/env python3
"""
Recompute a reachability slice for sys:airlock under candidate record strides.

This script is intentionally simple: it treats (tag,u8) + u16 fields as fixed-size
records and treats the first two u16 fields as branch targets (record indices).
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

import sys

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api import path_utils  # type: ignore
from book.api.profile import digests as digests_mod  # type: ignore


TAGS_FOCUS = {0, 1, 26, 27, 166}


@dataclass(frozen=True)
class Record:
    idx: int
    abs_off: int
    tag: int
    b1: int
    fields: List[int]


def _u16(blob: bytes, off: int) -> int:
    return struct.unpack_from("<H", blob, off)[0]


def _op_table_u16(blob: bytes, op_count: int) -> List[int]:
    out: List[int] = []
    base = 16
    for i in range(op_count):
        off = base + i * 2
        out.append(_u16(blob, off))
    return out


def _ascii_tag(tag: int) -> bool:
    return 32 <= tag <= 126


def _records(blob: bytes, base: int, stride: int) -> List[Record]:
    rec_count = (len(blob) - base) // stride
    out: List[Record] = []
    for idx in range(rec_count):
        abs_off = base + idx * stride
        tag = blob[abs_off]
        b1 = blob[abs_off + 1]
        fields = [_u16(blob, abs_off + 2 + 2 * j) for j in range((stride - 2) // 2)]
        out.append(Record(idx=idx, abs_off=abs_off, tag=tag, b1=b1, fields=fields))
    return out


def _bfs(records: Sequence[Record], roots: Iterable[int]) -> List[int]:
    rec_count = len(records)
    visited: set[int] = set()
    stack: List[int] = [r for r in roots if 0 <= r < rec_count]
    while stack:
        idx = stack.pop()
        if idx in visited:
            continue
        visited.add(idx)
        rec = records[idx]
        if len(rec.fields) < 2:
            continue
        for t in (rec.fields[0], rec.fields[1]):
            if 0 <= t < rec_count and t not in visited:
                stack.append(t)
    return sorted(visited)


def summarize(records: Sequence[Record], reachable: Sequence[int]) -> Dict[str, object]:
    tag_hist: Dict[str, int] = {}
    b1_hist: Dict[str, int] = {}
    plausible = 0
    focus = 0
    for idx in reachable:
        rec = records[idx]
        tag_hist[str(rec.tag)] = tag_hist.get(str(rec.tag), 0) + 1
        b1_hist[str(rec.b1)] = b1_hist.get(str(rec.b1), 0) + 1
        if rec.b1 == 0 and not _ascii_tag(rec.tag):
            plausible += 1
        if rec.tag in TAGS_FOCUS:
            focus += 1
    sample_nodes: List[Dict[str, object]] = []
    for idx in reachable[:25]:
        rec = records[idx]
        sample_nodes.append(
            {
                "idx": rec.idx,
                "abs_off": rec.abs_off,
                "tag": rec.tag,
                "b1": rec.b1,
                "fields": rec.fields,
                "ascii_tag": _ascii_tag(rec.tag),
                "focus_tag": rec.tag in TAGS_FOCUS,
            }
        )
    return {
        "reachable_count": len(reachable),
        "reachable_focus_count": focus,
        "reachable_plausible_non_ascii_b1_0": plausible,
        "reachable_tag_histogram": tag_hist,
        "reachable_b1_histogram": b1_hist,
        "sample_nodes": sample_nodes,
    }


def main(argv: Sequence[str]) -> None:
    repo_root = ROOT
    path = digests_mod.canonical_system_profile_blobs(repo_root)["airlock"]
    blob = path.read_bytes()

    op_count = _u16(blob, 2)
    op_table = _op_table_u16(blob, op_count)
    base = 16 + op_count * 2

    # Treat op-table entry index 162 as system-fcntl on this truncated op-range (0..166).
    system_fcntl_index = 162
    system_root = op_table[system_fcntl_index] if system_fcntl_index < len(op_table) else None

    out_dir = repo_root / "book/evidence/experiments/field2-final-final/bsd-airlock-highvals/out"
    out_dir.mkdir(exist_ok=True)

    outputs: Dict[str, object] = {
        "source": path_utils.to_repo_relative(path),
        "length": len(blob),
        "op_count": op_count,
        "nodes_base": base,
        "system_fcntl_op_index": system_fcntl_index,
        "system_fcntl_op_table_value": system_root,
    }

    for stride in (8, 10, 12):
        recs = _records(blob, base, stride)
        roots_all = sorted(set(op_table))
        roots_system = [system_root] if system_root is not None else []
        reach_all = _bfs(recs, roots_all)
        reach_sys = _bfs(recs, roots_system)
        outputs[str(stride)] = {
            "stride": stride,
            "record_count": len(recs),
            "reach_from_all_op_table": summarize(recs, reach_all),
            "reach_from_system_fcntl_root": summarize(recs, reach_sys),
        }

    out_path = out_dir / "airlock_subgraph.json"
    out_path.write_text(json.dumps(outputs, indent=2))
    print(f"[+] wrote {out_path}")


if __name__ == "__main__":
    main(sys.argv)
