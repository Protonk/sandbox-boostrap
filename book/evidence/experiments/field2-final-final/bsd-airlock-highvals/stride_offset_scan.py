#!/usr/bin/env python3
"""
Brute-test whether u16 "edge" fields behave like branch offsets (scaled by stride)
instead of node indices for tags {0,1,26,27,166}.

This is an experiment-local analyzer; it does not mutate shared mappings.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import sys

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api import path_utils  # type: ignore
from book.api.profile import digests as digests_mod  # type: ignore


TAGS_FOCUS: Tuple[int, ...] = (0, 1, 26, 27, 166)
STRIDES: Tuple[int, ...] = (8, 10, 12)


@dataclass(frozen=True)
class Record:
    idx: int
    abs_off: int
    tag: int
    b1: int
    fields: List[int]


def _u16(blob: bytes, off: int) -> int:
    return struct.unpack_from("<H", blob, off)[0]


def _read_header_words(blob: bytes, count: int = 8) -> List[int]:
    words: List[int] = []
    for i in range(count):
        if i * 2 + 2 > len(blob):
            break
        words.append(_u16(blob, i * 2))
    return words


def _op_count(blob: bytes) -> Optional[int]:
    if len(blob) < 4:
        return None
    maybe = _u16(blob, 2)
    if 0 < maybe < 4096:
        return maybe
    return None


def _op_table_u16(blob: bytes, op_count: int) -> List[int]:
    out: List[int] = []
    base = 16
    for i in range(op_count):
        off = base + i * 2
        if off + 2 > len(blob):
            break
        out.append(_u16(blob, off))
    return out


def _records_from_base(blob: bytes, base: int, stride: int) -> List[Record]:
    count = (len(blob) - base) // stride
    out: List[Record] = []
    for idx in range(count):
        abs_off = base + idx * stride
        tag = blob[abs_off]
        b1 = blob[abs_off + 1]
        fields = [_u16(blob, abs_off + 2 + 2 * j) for j in range((stride - 2) // 2)]
        out.append(Record(idx=idx, abs_off=abs_off, tag=tag, b1=b1, fields=fields))
    return out


def _ascii_tag(tag: int) -> bool:
    return 32 <= tag <= 126


def _score_offsets(
    records: Sequence[Record],
    stride: int,
    tags_focus: Sequence[int] = TAGS_FOCUS,
    b1_allowed: Sequence[int] = (0,),
) -> Dict[str, object]:
    by_idx = list(records)
    rec_count = len(by_idx)
    tags_focus_set = set(tags_focus)
    b1_allowed_set = set(b1_allowed)

    def target_info(target_idx: int) -> Dict[str, object]:
        if not (0 <= target_idx < rec_count):
            return {"in_range": False}
        rec = by_idx[target_idx]
        return {
            "in_range": True,
            "tag": rec.tag,
            "b1": rec.b1,
            "tag_in_focus": rec.tag in tags_focus_set,
            "b1_allowed": rec.b1 in b1_allowed_set,
            "tag_ascii": _ascii_tag(rec.tag),
        }

    # Edge offsets: for focus-tag records, treat fields[0]/fields[1] as target record indices.
    edges_total = 0
    edges_in_range = 0
    edges_to_focus = 0
    edges_to_focus_b1 = 0
    edges_to_non_ascii_b1 = 0
    per_source_tag: Dict[str, Dict[str, object]] = {}

    for rec in by_idx:
        if rec.tag not in tags_focus_set:
            continue
        if len(rec.fields) < 2:
            continue
        for edge_val in (rec.fields[0], rec.fields[1]):
            edges_total += 1
            st = per_source_tag.setdefault(
                str(rec.tag),
                {
                    "edges_total": 0,
                    "edges_in_range": 0,
                    "targets_tag_b1_histogram": {},
                    "targets_focus_b1": 0,
                    "targets_non_ascii_b1": 0,
                },
            )
            st["edges_total"] = int(st["edges_total"]) + 1
            t = target_info(edge_val)
            if not t["in_range"]:
                continue
            edges_in_range += 1
            st["edges_in_range"] = int(st["edges_in_range"]) + 1
            key = str((t.get("tag"), t.get("b1")))
            hist = st["targets_tag_b1_histogram"]
            if isinstance(hist, dict):
                hist[key] = int(hist.get(key, 0)) + 1
            if t["tag_in_focus"]:
                edges_to_focus += 1
                if t["b1_allowed"]:
                    edges_to_focus_b1 += 1
                    st["targets_focus_b1"] = int(st["targets_focus_b1"]) + 1
            if (not t["tag_ascii"]) and t["b1_allowed"]:
                edges_to_non_ascii_b1 += 1
                st["targets_non_ascii_b1"] = int(st["targets_non_ascii_b1"]) + 1

    # Op-table offsets: treat op-table entries as target record indices.
    # Caller should provide the op_table separately; here we only provide helper structure.
    return {
        "stride": stride,
        "record_count": rec_count,
        "focus_tag_record_count": sum(1 for r in by_idx if r.tag in tags_focus_set),
        "edges_total": edges_total,
        "edges_in_range": edges_in_range,
        "edges_to_focus": edges_to_focus,
        "edges_to_focus_b1": edges_to_focus_b1,
        "edges_to_non_ascii_b1": edges_to_non_ascii_b1,
        "per_source_tag": per_source_tag,
        "tags_focus": list(tags_focus),
        "b1_allowed": list(b1_allowed),
    }


def _score_op_table(
    records: Sequence[Record],
    op_table: Sequence[int],
    tags_focus: Sequence[int] = TAGS_FOCUS,
    b1_allowed: Sequence[int] = (0,),
) -> Dict[str, object]:
    by_idx = list(records)
    rec_count = len(by_idx)
    tags_focus_set = set(tags_focus)
    b1_allowed_set = set(b1_allowed)

    total = len(op_table)
    in_range = 0
    to_focus = 0
    to_focus_b1 = 0
    to_non_ascii_b1 = 0
    targets: Dict[str, int] = {}

    for v in op_table:
        if not (0 <= v < rec_count):
            continue
        in_range += 1
        rec = by_idx[v]
        targets[str((rec.tag, rec.b1))] = targets.get(str((rec.tag, rec.b1)), 0) + 1
        if rec.tag in tags_focus_set:
            to_focus += 1
            if rec.b1 in b1_allowed_set:
                to_focus_b1 += 1
        if (not _ascii_tag(rec.tag)) and rec.b1 in b1_allowed_set:
            to_non_ascii_b1 += 1

    return {
        "op_table_len": total,
        "op_targets_in_range": in_range,
        "op_targets_to_focus": to_focus,
        "op_targets_to_focus_b1": to_focus_b1,
        "op_targets_to_non_ascii_b1": to_non_ascii_b1,
        "op_target_tag_b1_histogram": targets,
    }


def _reachable_focus_subgraph(records: Sequence[Record], op_table: Sequence[int]) -> Dict[str, object]:
    by_idx = list(records)
    rec_count = len(by_idx)
    tags_focus = set(TAGS_FOCUS)

    roots = [v for v in op_table if 0 <= v < rec_count]
    visited: set[int] = set()
    stack = list(roots)
    while stack:
        idx = stack.pop()
        if idx in visited:
            continue
        rec = by_idx[idx]
        if rec.tag not in tags_focus:
            continue
        visited.add(idx)
        if len(rec.fields) < 2:
            continue
        for edge_val in (rec.fields[0], rec.fields[1]):
            if 0 <= edge_val < rec_count and edge_val not in visited:
                stack.append(edge_val)

    tag_hist: Dict[int, int] = {}
    for idx in visited:
        t = by_idx[idx].tag
        tag_hist[t] = tag_hist.get(t, 0) + 1
    return {
        "reachable_focus_nodes": len(visited),
        "reachable_focus_tag_histogram": {str(k): v for k, v in sorted(tag_hist.items())},
    }


def analyze_blob(blob: bytes, source_path: Path) -> Dict[str, object]:
    header_words = _read_header_words(blob, 8)
    op_count = _op_count(blob) or 0
    op_table = _op_table_u16(blob, op_count) if op_count else []
    base = 16 + op_count * 2

    out: Dict[str, object] = {
        "source": path_utils.to_repo_relative(source_path),
        "length": len(blob),
        "header_words": header_words,
        "op_count": op_count,
        "nodes_base": base,
        "strides_tested": list(STRIDES),
        "tags_focus": list(TAGS_FOCUS),
    }

    per_stride: Dict[str, object] = {}
    for stride in STRIDES:
        records = _records_from_base(blob, base, stride)
        score_edges = _score_offsets(records, stride)
        score_ops = _score_op_table(records, op_table)
        reachable = _reachable_focus_subgraph(records, op_table)
        # Histogram of slots 3/4 for focus tags when present.
        # second pass to count distinct values
        field3: Dict[int, Dict[int, int]] = {}
        field4: Dict[int, Dict[int, int]] = {}
        for rec in records:
            if rec.tag not in TAGS_FOCUS or len(rec.fields) < 5:
                continue
            field3.setdefault(rec.tag, {})[rec.fields[3]] = field3.setdefault(rec.tag, {}).get(rec.fields[3], 0) + 1
            field4.setdefault(rec.tag, {})[rec.fields[4]] = field4.setdefault(rec.tag, {}).get(rec.fields[4], 0) + 1
        slot_summary: Dict[str, object] = {}
        for tag in sorted(field3):
            slot_summary[str(tag)] = {
                "field3_top": sorted(
                    [{"value": k, "count": v} for k, v in field3[tag].items()],
                    key=lambda x: (-x["count"], x["value"]),
                )[:10],
                "field4_top": sorted(
                    [{"value": k, "count": v} for k, v in field4[tag].items()],
                    key=lambda x: (-x["count"], x["value"]),
                )[:10],
                "field3_distinct": len(field3[tag]),
                "field4_distinct": len(field4[tag]),
            }

        per_stride[str(stride)] = {
            "edges": score_edges,
            "op_table": score_ops,
            "reachable_focus": reachable,
            "slots34": slot_summary,
        }

    out["per_stride"] = per_stride
    return out


def main(argv: Sequence[str]) -> None:
    repo_root = ROOT
    canonical = digests_mod.canonical_system_profile_blobs(repo_root)
    blobs = [canonical["bsd"], canonical["airlock"]]
    out_dir = repo_root / "book/evidence/experiments/field2-final-final/bsd-airlock-highvals/out"
    out_dir.mkdir(exist_ok=True)

    results: Dict[str, object] = {}
    for path in blobs:
        blob = path.read_bytes()
        results[path.stem] = analyze_blob(blob, path)

    out_path = out_dir / "stride_offset_scan.json"
    out_path.write_text(json.dumps(results, indent=2))
    print(f"[+] wrote {out_path}")


if __name__ == "__main__":
    main(sys.argv)
