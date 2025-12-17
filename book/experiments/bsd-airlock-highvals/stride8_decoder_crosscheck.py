#!/usr/bin/env python3
"""
Stride=8 cross-check for canonical sys:bsd/sys:airlock compiled blobs.

This is an experiment-local analyzer. It is intended to produce byte-level
evidence for (or against) the hypothesis that:

  - node records are 8 bytes (tag,u8 + 3*u16), and
  - op-table entries and branch targets are u16 offsets in 8-byte words.

In particular, this script tries to produce witnesses for:
  - "fields[3]/fields[4]" in the 12-byte decode view are spillover from the next
    8-byte record.
  - op_table[i] * 8 lands on plausible record headers (and *12 often does not).
  - edge targets (fields[0]/fields[1]) * 8 land on plausible record headers and
    the ASCII-like misalignments largely disappear under scale=8.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import sys

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api import path_utils  # type: ignore


FOCUS_TAGS: Tuple[int, ...] = (0, 1, 26, 27, 166)


def _u16(blob: bytes, off: int) -> int:
    return struct.unpack_from("<H", blob, off)[0]


def _ascii_byte(b: int) -> bool:
    return 32 <= b <= 126


def _load_known_tags() -> set[int]:
    path = ROOT / "book/graph/mappings/tag_layouts/tag_layouts.json"
    if not path.exists():
        return set()
    data = json.loads(path.read_text())
    tags: set[int] = set()
    for entry in data.get("tags", []):
        try:
            tags.add(int(entry["tag"]))
        except Exception:
            continue
    return tags


@dataclass(frozen=True)
class Record8:
    idx: int
    abs_off: int
    tag: int
    kind: int
    fields: Tuple[int, int, int]


def _parse_op_table(blob: bytes, op_count: int) -> List[int]:
    base = 16
    return [_u16(blob, base + i * 2) for i in range(op_count)]


def _nodes_base(op_count: int) -> int:
    return 16 + op_count * 2


def _record8_at(blob: bytes, base: int, idx: int) -> Optional[Record8]:
    abs_off = base + idx * 8
    if abs_off + 8 > len(blob):
        return None
    tag = blob[abs_off]
    kind = blob[abs_off + 1]
    fields = (_u16(blob, abs_off + 2), _u16(blob, abs_off + 4), _u16(blob, abs_off + 6))
    return Record8(idx=idx, abs_off=abs_off, tag=tag, kind=kind, fields=fields)


def _header_info(tag: int, kind: int, known_tags: set[int]) -> Dict[str, Any]:
    ascii_tag = _ascii_byte(tag)
    ascii_kind = _ascii_byte(kind)
    return {
        "tag": tag,
        "kind": kind,
        "tag_ascii": ascii_tag,
        "kind_ascii": ascii_kind,
        "ascii_pair": ascii_tag and ascii_kind,
        "kind_zero": kind == 0,
        "tag_in_tag_layouts": tag in known_tags,
        "plausible_non_ascii_kind0": (kind == 0) and (not ascii_tag),
        "plausible_known_kind0": (kind == 0) and (tag in known_tags),
    }


def _target_header(blob: bytes, abs_off: int, known_tags: set[int]) -> Dict[str, Any]:
    if abs_off + 2 > len(blob):
        return {"in_range": False}
    return {"in_range": True, **_header_info(blob[abs_off], blob[abs_off + 1], known_tags)}


def _score_targets(
    blob: bytes,
    base: int,
    offsets_u16: Iterable[int],
    known_tags: set[int],
    scale_bytes: int,
) -> Dict[str, Any]:
    total = 0
    in_range = 0
    ascii_pairs = 0
    kind0 = 0
    plausible_non_ascii_kind0 = 0
    plausible_known_kind0 = 0
    tag_hist: Dict[str, int] = {}
    pair_hist: Dict[str, int] = {}
    sample: List[Dict[str, Any]] = []

    for v in offsets_u16:
        total += 1
        abs_off = base + int(v) * scale_bytes
        info = _target_header(blob, abs_off, known_tags)
        if not info.get("in_range"):
            continue
        in_range += 1
        tag_hist[str(info["tag"])] = tag_hist.get(str(info["tag"]), 0) + 1
        pair_key = str((info["tag"], info["kind"]))
        pair_hist[pair_key] = pair_hist.get(pair_key, 0) + 1
        if info["ascii_pair"]:
            ascii_pairs += 1
        if info["kind_zero"]:
            kind0 += 1
        if info["plausible_non_ascii_kind0"]:
            plausible_non_ascii_kind0 += 1
        if info["plausible_known_kind0"]:
            plausible_known_kind0 += 1
        if len(sample) < 15:
            sample.append(
                {
                    "v": int(v),
                    "abs_off": abs_off,
                    "tag": info["tag"],
                    "kind": info["kind"],
                    "ascii_pair": info["ascii_pair"],
                    "tag_in_tag_layouts": info["tag_in_tag_layouts"],
                }
            )

    def _top(d: Dict[str, int], limit: int = 12) -> List[Dict[str, Any]]:
        return [{"key": k, "count": v} for k, v in sorted(d.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]]

    return {
        "scale_bytes": scale_bytes,
        "total": total,
        "in_range": in_range,
        "ascii_pair_count": ascii_pairs,
        "kind0_count": kind0,
        "plausible_non_ascii_kind0_count": plausible_non_ascii_kind0,
        "plausible_known_kind0_count": plausible_known_kind0,
        "top_tags": _top(tag_hist),
        "top_tag_kind_pairs": _top(pair_hist),
        "sample_targets": sample,
    }


def _bfs_record_indices(blob: bytes, base: int, roots: Sequence[int], max_records: int) -> List[int]:
    visited: set[int] = set()
    stack: List[int] = [r for r in roots if 0 <= r < max_records]
    while stack:
        idx = stack.pop()
        if idx in visited:
            continue
        visited.add(idx)
        rec = _record8_at(blob, base, idx)
        if rec is None:
            continue
        f0, f1, _ = rec.fields
        for t in (f0, f1):
            if 0 <= t < max_records and t not in visited:
                stack.append(t)
    return sorted(visited)


def _spillover_witness_aligned(blob: bytes, base: int) -> Optional[Dict[str, Any]]:
    """
    Find a byte-level witness that a 12-byte record view is consuming 4 bytes
    from the following 8-byte record (spillover).

    We look for offsets that are aligned under both framings (LCM(8,12)=24),
    so that the first 8 bytes of the 12-byte view correspond to a whole 8-byte
    record and the final 4 bytes must necessarily come from the next record.
    """
    tail_len = len(blob) - base
    if tail_len < 24:
        return None
    max_off = tail_len - 24

    # Prefer witnesses where spillover looks like tag values (26/27), then fall
    # back to simpler "tag-looking" spillover.
    preferred_pairs: Tuple[Tuple[int, Optional[int]], ...] = (
        (26, 27),  # most illustrative: next record tag=26, first u16=27
        (26, None),
        (166, None),
        (27, None),
    )

    for preferred_field3, preferred_field4 in preferred_pairs:
        for rel_off in range(0, max_off + 1, 24):
            off = base + rel_off
            r0 = _record8_at(blob, base, rel_off // 8)
            r1 = _record8_at(blob, base, (rel_off // 8) + 1)
            if r0 is None or r1 is None:
                continue
            if off + 12 > len(blob):
                continue

            # 12-byte interpretation starting at the same offset.
            tag12 = blob[off]
            kind12 = blob[off + 1]
            fields12 = [_u16(blob, off + 2 + 2 * j) for j in range(5)]

            # Expected relationship if the real record size is 8 bytes.
            next_tag_kind_u16 = (r1.tag & 0xFF) | ((r1.kind & 0xFF) << 8)
            if fields12[3] != next_tag_kind_u16:
                continue
            if fields12[3] != preferred_field3:
                continue
            if preferred_field4 is not None and fields12[4] != preferred_field4:
                continue

            win = blob[off : off + 24]
            return {
            "offsets": {
                "nodes_base": base,
                "record8_index": r0.idx,
                "abs_off": off,
                "rel_off": rel_off,
                "alignment_note": "rel_off is a multiple of 24 (aligned under both 8- and 12-byte framings)",
            },
            "record8_current": {
                "idx": r0.idx,
                "abs_off": r0.abs_off,
                "tag": r0.tag,
                "kind": r0.kind,
                "fields_u16": list(r0.fields),
            },
            "record8_next": {
                "idx": r1.idx,
                "abs_off": r1.abs_off,
                "tag": r1.tag,
                "kind": r1.kind,
                "fields_u16": list(r1.fields),
            },
            "record12_view_starting_same_offset": {
                "tag": tag12,
                "kind": kind12,
                "fields_u16": fields12,
                "derived": {
                    "expected_field3_next_tag_kind_u16": next_tag_kind_u16,
                    "expected_field4_next_u16_0": r1.fields[0],
                },
                "note": "fields_u16[3] reads next record's (tag,kind) as a u16; fields_u16[4] reads next record's first u16",
            },
            "bytes_window_hex": win.hex(),
            }

    return None


def _analyze_profile(path: Path, known_tags: set[int], system_fcntl_op_index: Optional[int] = None) -> Dict[str, Any]:
    blob = path.read_bytes()
    op_count = _u16(blob, 2)
    op_table = _parse_op_table(blob, op_count)
    base = _nodes_base(op_count)
    rec_count = (len(blob) - base) // 8

    # Score op-table targets as offsets in 8-byte words vs the common mis-scaling by 12.
    op_table_score = {
        "by_scale": {
            "8": _score_targets(blob, base, op_table, known_tags, 8),
            "12": _score_targets(blob, base, op_table, known_tags, 12),
        }
    }

    # Reachability starting at all op roots (treating roots as record indices).
    roots = sorted(set(op_table))
    reachable = _bfs_record_indices(blob, base, roots, rec_count)

    # Score edge targets encountered within the reachable set, focusing on tags likely to carry branch targets.
    edge_targets_focus: List[int] = []
    edge_targets_all: List[int] = []
    sample_nodes: List[Dict[str, Any]] = []
    for idx in reachable:
        rec = _record8_at(blob, base, idx)
        if rec is None:
            continue
        f0, f1, f2 = rec.fields
        edge_targets_all.extend([f0, f1])
        if rec.tag in FOCUS_TAGS:
            edge_targets_focus.extend([f0, f1])
        if len(sample_nodes) < 25:
            sample_nodes.append(
                {
                    "idx": rec.idx,
                    "abs_off": rec.abs_off,
                    "tag": rec.tag,
                    "kind": rec.kind,
                    "fields_u16": [f0, f1, f2],
                }
            )

    edge_score_focus = {
        "tags_focus": list(FOCUS_TAGS),
        "reachable_count": len(reachable),
        "by_scale": {
            "8": _score_targets(blob, base, edge_targets_focus, known_tags, 8),
            "12": _score_targets(blob, base, edge_targets_focus, known_tags, 12),
        },
    }

    edge_score_all = {
        "reachable_count": len(reachable),
        "by_scale": {
            "8": _score_targets(blob, base, edge_targets_all, known_tags, 8),
            "12": _score_targets(blob, base, edge_targets_all, known_tags, 12),
        },
    }

    # Optionally capture a specific op root witness (system-fcntl for airlock).
    op_root_witness: Optional[Dict[str, Any]] = None
    if system_fcntl_op_index is not None and system_fcntl_op_index < len(op_table):
        root = op_table[system_fcntl_op_index]
        rec = _record8_at(blob, base, root)
        op_root_witness = {
            "op_index": system_fcntl_op_index,
            "op_table_value": root,
            "abs_off_scale8": base + root * 8,
            "abs_off_scale12": base + root * 12,
            "record8_at_scale8": None if rec is None else {"tag": rec.tag, "kind": rec.kind, "fields_u16": list(rec.fields)},
            "header_at_scale12": _target_header(blob, base + root * 12, known_tags),
        }

    return {
        "source": path_utils.to_repo_relative(path),
        "length": len(blob),
        "op_count": op_count,
        "nodes_base": base,
        "record_count_tail_div8": rec_count,
        "op_table_score": op_table_score,
        "reachability": {
            "root_count_distinct": len(roots),
            "reachable_count": len(reachable),
            "reachable_sample_nodes": sample_nodes,
        },
        "edge_target_scores": {
            "focus_tags_only": edge_score_focus,
            "all_reached_nodes": edge_score_all,
        },
        "op_root_witness": op_root_witness,
    }


def main(argv: Sequence[str]) -> None:
    known_tags = _load_known_tags()
    out_dir = ROOT / "book/experiments/bsd-airlock-highvals/out"
    out_dir.mkdir(exist_ok=True)

    bsd = ROOT / "book/examples/extract_sbs/build/profiles/bsd.sb.bin"
    airlock = ROOT / "book/examples/extract_sbs/build/profiles/airlock.sb.bin"

    payload: Dict[str, Any] = {
        "notes": "Experiment-local stride=8 framing cross-check; does not mutate mappings.",
        "known_tags_source": "book/graph/mappings/tag_layouts/tag_layouts.json",
        "known_tag_count": len(known_tags),
        "bsd": _analyze_profile(bsd, known_tags),
        "airlock": _analyze_profile(airlock, known_tags, system_fcntl_op_index=162),
    }

    # Add a byte-level spillover witness (aligned under both framings) for bsd if present.
    bsd_blob = bsd.read_bytes()
    payload["bsd_spillover_witness"] = _spillover_witness_aligned(bsd_blob, _nodes_base(_u16(bsd_blob, 2)))

    out_path = out_dir / "stride8_decoder_crosscheck.json"
    out_path.write_text(json.dumps(payload, indent=2))
    print(f"[+] wrote {out_path}")


if __name__ == "__main__":
    main(sys.argv)
