#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.path_utils import ensure_absolute, find_repo_root, to_repo_relative  # type: ignore
from book.api.profile.identity import baseline_world_id  # type: ignore


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def _load_jsonl(path: Path) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    if not path.exists():
        return records
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        records.append(json.loads(line))
    return records


def _count_offsets(offsets: Iterable[int]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for off in offsets:
        key = str(off)
        counts[key] = counts.get(key, 0) + 1
    return counts


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="encoder-write-record-map")
    ap.add_argument(
        "--join",
        type=Path,
        default=Path("book/experiments/field2-final-final/libsandbox-encoder/out/network_matrix/encoder_write_join.json"),
        help="Encoder write join summary",
    )
    ap.add_argument(
        "--events",
        type=Path,
        default=Path("book/experiments/field2-final-final/libsandbox-encoder/out/network_matrix/encoder_write_events.jsonl"),
        help="Encoder write event mapping",
    )
    ap.add_argument(
        "--index",
        type=Path,
        default=Path("book/experiments/field2-final-final/libsandbox-encoder/out/network_matrix/index.json"),
        help="Network matrix index JSON (for section offsets)",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=Path("book/experiments/field2-final-final/libsandbox-encoder/out/network_matrix/encoder_write_record_map.json"),
        help="Output JSON path",
    )
    args = ap.parse_args(argv)

    repo_root = find_repo_root()
    join_path = ensure_absolute(args.join, repo_root)
    events_path = ensure_absolute(args.events, repo_root)
    index_path = ensure_absolute(args.index, repo_root)
    out_path = ensure_absolute(args.out, repo_root)

    join = _load_json(join_path)
    expected_world = baseline_world_id(repo_root)
    if join.get("world_id") != expected_world:
        raise ValueError(f"join world_id mismatch: {join.get('world_id')} != {expected_world}")

    index = _load_json(index_path)
    if index.get("world_id") != expected_world:
        raise ValueError(f"index world_id mismatch: {index.get('world_id')} != {expected_world}")

    cases_by_id: Dict[str, Mapping[str, Any]] = {}
    for case in index.get("cases", []):
        if not isinstance(case, Mapping):
            continue
        spec_id = case.get("spec_id")
        if isinstance(spec_id, str):
            cases_by_id[spec_id] = case

    events = _load_jsonl(events_path)
    events_by_spec: Dict[str, List[Mapping[str, Any]]] = {}
    for event in events:
        spec_id = event.get("spec_id")
        if isinstance(spec_id, str):
            events_by_spec.setdefault(spec_id, []).append(event)

    specs_out: List[Dict[str, Any]] = []

    for spec in join.get("specs", []):
        if not isinstance(spec, Mapping):
            continue
        spec_id = spec.get("spec_id")
        if not isinstance(spec_id, str):
            continue
        case = cases_by_id.get(spec_id)
        sections = case.get("sections") if isinstance(case, Mapping) else {}
        nodes = sections.get("nodes") if isinstance(sections, Mapping) else {}
        nodes_start = nodes.get("start") if isinstance(nodes, Mapping) else None
        nodes_end = nodes.get("end") if isinstance(nodes, Mapping) else None

        base_offset = spec.get("base_offset")
        window_len = spec.get("window_len")
        window_start = base_offset if isinstance(base_offset, int) else None
        window_end = (base_offset + window_len) if isinstance(base_offset, int) and isinstance(window_len, int) else None

        event_list = events_by_spec.get(spec_id, [])
        within_offsets: List[int] = []
        record_offsets: List[int] = []
        total_events = 0
        within_nodes = 0
        outside_nodes = 0
        if isinstance(nodes_start, int) and isinstance(nodes_end, int):
            for event in event_list:
                blob_offset = event.get("blob_offset")
                length = event.get("length")
                if not isinstance(blob_offset, int) or not isinstance(length, int):
                    continue
                total_events += 1
                span_start = blob_offset
                span_end = blob_offset + length
                if span_end <= nodes_start or span_start >= nodes_end:
                    outside_nodes += 1
                    continue
                within_nodes += 1
                for off in range(span_start, span_end):
                    if off < nodes_start or off >= nodes_end:
                        continue
                    rel = off - nodes_start
                    within_offsets.append(rel % 8)
                    record_offsets.append(rel // 8)

        record_range = None
        if isinstance(window_start, int) and isinstance(window_end, int) and isinstance(nodes_start, int):
            rel_start = window_start - nodes_start
            rel_end = window_end - nodes_start
            record_range = {
                "start": rel_start // 8,
                "end_exclusive": (rel_end + 7) // 8 if rel_end > 0 else 0,
            }

        specs_out.append(
            {
                "spec_id": spec_id,
                "nodes_start": nodes_start,
                "nodes_end": nodes_end,
                "window": {"start": window_start, "end_exclusive": window_end},
                "record_range": record_range,
                "event_counts": {
                    "total": total_events,
                    "within_nodes": within_nodes,
                    "outside_nodes": outside_nodes,
                },
                "within_record_offset_counts": _count_offsets(within_offsets),
                "record_index_counts": _count_offsets(record_offsets),
            }
        )

    payload = {
        "world_id": expected_world,
        "join": to_repo_relative(join_path, repo_root),
        "events": to_repo_relative(events_path, repo_root),
        "index": to_repo_relative(index_path, repo_root),
        "specs": specs_out,
        "notes": [
            "Offsets are mapped to 8-byte record indices relative to the nodes section start.",
            "within_record_offset_counts describe which byte positions inside 8-byte records are touched by traced writes.",
        ],
    }

    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
