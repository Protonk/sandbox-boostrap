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


def _range_contains(ranges: Iterable[Tuple[int, int]], start: int, end: int) -> str:
    for r_start, r_end in ranges:
        if start >= r_start and end <= r_end:
            return "witnessed"
    for r_start, r_end in ranges:
        if end <= r_start or start >= r_end:
            continue
        return "spans_boundary"
    return "unknown"


def _extract_join_window(best: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    match = best.get("match")
    kind = match.get("kind") if isinstance(match, Mapping) else None
    reconstructed_len = best.get("reconstructed_len")
    if kind in {"full", "subset"} and isinstance(reconstructed_len, int):
        blob_offset = match.get("blob_offset") if isinstance(match, Mapping) else None
        if isinstance(blob_offset, int):
            return {
                "base_offset": blob_offset,
                "window_len": reconstructed_len,
                "witnessed_ranges": [[0, reconstructed_len]],
                "hole_ranges": [],
                "join_source": "best_match",
            }
    if kind == "gapped":
        alignment = best.get("alignment")
        if isinstance(alignment, Mapping):
            base = alignment.get("base_offset")
            length = alignment.get("window_len")
            ranges = alignment.get("witnessed_ranges")
            holes = alignment.get("hole_ranges")
            if isinstance(base, int) and isinstance(length, int) and isinstance(ranges, list):
                return {
                    "base_offset": base,
                    "window_len": length,
                    "witnessed_ranges": ranges,
                    "hole_ranges": holes if isinstance(holes, list) else [],
                    "join_source": "gapped_alignment",
                }
    return None


def _select_join_window(entry: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    best = entry.get("best")
    best_candidate = _extract_join_window(best) if isinstance(best, Mapping) else None

    gapped_best: Optional[Dict[str, Any]] = None
    for buf in entry.get("buffers", []):
        if not isinstance(buf, Mapping):
            continue
        alignment = buf.get("alignment")
        if not isinstance(alignment, Mapping):
            continue
        base = alignment.get("base_offset")
        length = alignment.get("window_len")
        ranges = alignment.get("witnessed_ranges")
        holes = alignment.get("hole_ranges")
        witnessed = alignment.get("witnessed_bytes", 0)
        if not isinstance(base, int) or not isinstance(length, int) or not isinstance(ranges, list):
            continue
        candidate = {
            "base_offset": base,
            "window_len": length,
            "witnessed_ranges": ranges,
            "hole_ranges": holes if isinstance(holes, list) else [],
            "join_source": "gapped_alignment",
            "witnessed_bytes": int(witnessed) if isinstance(witnessed, int) else 0,
        }
        if gapped_best is None:
            gapped_best = candidate
        else:
            best_witnessed = int(gapped_best.get("witnessed_bytes", 0))
            if candidate["witnessed_bytes"] > best_witnessed:
                gapped_best = candidate
            elif candidate["witnessed_bytes"] == best_witnessed:
                if candidate["window_len"] > gapped_best.get("window_len", 0):
                    gapped_best = candidate

    join_candidate = best_candidate
    if gapped_best:
        if not join_candidate:
            join_candidate = gapped_best
        else:
            join_len = int(join_candidate.get("window_len", 0))
            if gapped_best["window_len"] > join_len:
                join_candidate = gapped_best
    if join_candidate:
        join_candidate.pop("witnessed_bytes", None)
    return join_candidate


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="trace-join-encoder-write")
    ap.add_argument(
        "--analysis",
        type=Path,
        default=Path("book/experiments/encoder-write-trace/out/trace_analysis.json"),
        help="Encoder write trace analysis JSON",
    )
    ap.add_argument(
        "--manifest",
        type=Path,
        default=Path("book/experiments/libsandbox-encoder/sb/network_matrix/MANIFEST.json"),
        help="Network matrix manifest",
    )
    ap.add_argument(
        "--subset-inputs",
        type=Path,
        default=None,
        help="Optional encoder-write-trace inputs JSON to restrict spec IDs",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=Path("book/experiments/libsandbox-encoder/out/network_matrix/encoder_write_join.json"),
        help="Output join summary JSON",
    )
    ap.add_argument(
        "--events-out",
        type=Path,
        default=Path("book/experiments/libsandbox-encoder/out/network_matrix/encoder_write_events.jsonl"),
        help="Output write-event join JSONL",
    )
    args = ap.parse_args(argv)

    repo_root = find_repo_root()
    analysis_path = ensure_absolute(args.analysis, repo_root)
    manifest_path = ensure_absolute(args.manifest, repo_root)
    out_path = ensure_absolute(args.out, repo_root)
    events_path = ensure_absolute(args.events_out, repo_root)

    analysis = _load_json(analysis_path)
    expected_world = baseline_world_id(repo_root)
    if analysis.get("world_id") != expected_world:
        raise ValueError(f"analysis world_id mismatch: {analysis.get('world_id')} != {expected_world}")

    manifest = _load_json(manifest_path)
    if manifest.get("world_id") != expected_world:
        raise ValueError(f"manifest world_id mismatch: {manifest.get('world_id')} != {expected_world}")

    manifest_cases = manifest.get("cases", [])
    manifest_spec_ids = [case.get("spec_id") for case in manifest_cases if isinstance(case, Mapping)]
    manifest_spec_ids = [sid for sid in manifest_spec_ids if isinstance(sid, str)]

    subset_ids: Optional[List[str]] = None
    subset_path = None
    if args.subset_inputs:
        subset_path = ensure_absolute(args.subset_inputs, repo_root)
        subset = _load_json(subset_path)
        subset_inputs = subset.get("inputs", [])
        subset_ids = []
        for entry in subset_inputs:
            if not isinstance(entry, Mapping):
                continue
            entry_id = entry.get("id")
            if isinstance(entry_id, str):
                subset_ids.append(entry_id)
        if subset.get("world_id") != expected_world:
            raise ValueError(f"subset world_id mismatch: {subset.get('world_id')} != {expected_world}")

    spec_ids = subset_ids if subset_ids is not None else manifest_spec_ids

    analysis_by_id: Dict[str, Mapping[str, Any]] = {}
    for entry in analysis.get("entries", []):
        if not isinstance(entry, Mapping):
            continue
        entry_id = entry.get("id")
        if isinstance(entry_id, str):
            analysis_by_id[entry_id] = entry

    missing_specs: List[str] = []
    specs_out: List[Dict[str, Any]] = []
    events_lines: List[str] = []

    for spec_id in spec_ids:
        entry = analysis_by_id.get(spec_id)
        if not entry:
            missing_specs.append(spec_id)
            continue
        trace_rel = entry.get("trace")
        blob_rel = entry.get("blob")
        best = entry.get("best") if isinstance(entry.get("best"), Mapping) else {}
        join_window = _select_join_window(entry)
        cursor_mode = best.get("cursor_mode") if isinstance(best.get("cursor_mode"), str) else None
        base_cursor = None
        join_status = "ok" if join_window else "missing_alignment"
        trace_path = ensure_absolute(trace_rel, repo_root) if isinstance(trace_rel, str) else None
        trace_records = _load_jsonl(trace_path) if isinstance(trace_path, Path) else []
        if cursor_mode == "cursor_as_ptr" and trace_records:
            cursors = [rec.get("cursor") for rec in trace_records if isinstance(rec, Mapping)]
            cursors = [c for c in cursors if isinstance(c, int)]
            if cursors:
                base_cursor = min(cursors)

        base_offset = join_window.get("base_offset") if join_window else None
        window_len = join_window.get("window_len") if join_window else None
        witnessed_ranges = join_window.get("witnessed_ranges") if join_window else []
        hole_ranges = join_window.get("hole_ranges") if join_window else []
        join_source = join_window.get("join_source") if join_window else None

        if trace_records and join_window:
            base = base_cursor or 0
            ranges = [(int(a), int(b)) for a, b in witnessed_ranges] if isinstance(witnessed_ranges, list) else []
            for rec in trace_records:
                if not isinstance(rec, Mapping):
                    continue
                cursor = rec.get("cursor")
                if not isinstance(cursor, int):
                    continue
                chunk_offset = rec.get("chunk_offset", 0)
                if not isinstance(chunk_offset, int):
                    chunk_offset = 0
                length = rec.get("len")
                if not isinstance(length, int):
                    bytes_hex = rec.get("bytes_hex", "")
                    if isinstance(bytes_hex, str):
                        length = len(bytes_hex) // 2
                    else:
                        length = 0
                cursor_effective = cursor + chunk_offset
                offset = cursor_effective - base if cursor_mode == "cursor_as_ptr" else cursor_effective
                blob_offset = base_offset + offset if isinstance(base_offset, int) else None
                span_end = offset + length
                span_class = _range_contains(ranges, offset, span_end) if ranges else "unknown"
                event = {
                    "spec_id": spec_id,
                    "seq": rec.get("seq"),
                    "cursor": cursor,
                    "chunk_offset": chunk_offset,
                    "offset": offset,
                    "length": length,
                    "blob_offset": blob_offset,
                    "blob_span": [blob_offset, blob_offset + length] if isinstance(blob_offset, int) else None,
                    "cursor_mode": cursor_mode,
                    "base_cursor": base_cursor,
                    "span_class": span_class,
                }
                events_lines.append(json.dumps(event, sort_keys=True))

        specs_out.append(
            {
                "spec_id": spec_id,
                "in_manifest": spec_id in manifest_spec_ids,
                "trace": trace_rel,
                "blob": blob_rel,
                "cursor_mode": cursor_mode,
                "base_cursor": base_cursor,
                "join_status": join_status,
                "join_source": join_source,
                "base_offset": base_offset,
                "window_len": window_len,
                "witnessed_ranges": witnessed_ranges,
                "hole_ranges": hole_ranges,
                "trace_records": len(trace_records),
            }
        )

    payload = {
        "world_id": expected_world,
        "analysis": to_repo_relative(analysis_path, repo_root),
        "manifest": to_repo_relative(manifest_path, repo_root),
        "subset_inputs": to_repo_relative(subset_path, repo_root) if subset_path else None,
        "specs": specs_out,
        "missing_specs": missing_specs,
        "events": {
            "path": to_repo_relative(events_path, repo_root),
            "count": len(events_lines),
            "span_class_notes": {
                "witnessed": "write span fully inside witnessed_ranges",
                "spans_boundary": "write span crosses a witnessed/hole boundary",
                "unknown": "no witnessed ranges available for this spec",
            },
        },
        "notes": [
            "Blob offsets are derived from encoder-write-trace alignment; base_offset + cursor_offset.",
            "Holes indicate missing coverage in the reconstructed byte stream and should be treated as inferred if reading bytes from the blob.",
        ],
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    events_path.parent.mkdir(parents=True, exist_ok=True)
    events_path.write_text("\n".join(events_lines) + ("\n" if events_lines else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
