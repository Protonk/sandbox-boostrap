#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.path_utils import ensure_absolute, find_repo_root, to_repo_relative  # type: ignore
from book.api.profile.identity import baseline_world_id  # type: ignore


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _range_contains(ranges: List[List[int]], offset: int) -> bool:
    for start, end in ranges:
        if start <= offset < end:
            return True
    return False


def _best_trace_map(analysis: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for entry in analysis.get("entries", []):
        if not isinstance(entry, Mapping):
            continue
        entry_id = entry.get("id")
        best = entry.get("best")
        if not isinstance(entry_id, str) or not isinstance(best, Mapping):
            continue
        match = best.get("match")
        kind = match.get("kind") if isinstance(match, Mapping) else None
        best_blob_offset = match.get("blob_offset", 0) if isinstance(match, Mapping) else 0
        best_length = best.get("reconstructed_len")
        best_candidate: Optional[Dict[str, Any]] = None
        if isinstance(best_length, int) and isinstance(best_blob_offset, int):
            if kind in {"full", "subset"}:
                best_candidate = {
                    "blob_offset": best_blob_offset,
                    "length": best_length,
                    "witnessed_ranges": [[0, best_length]],
                    "coverage_kind": kind,
                    "join_source": "best_match",
                }
            elif kind == "gapped":
                alignment = best.get("alignment")
                if isinstance(alignment, Mapping):
                    base = alignment.get("base_offset")
                    length = alignment.get("window_len")
                    ranges = alignment.get("witnessed_ranges")
                    if isinstance(base, int) and isinstance(length, int) and isinstance(ranges, list):
                        best_candidate = {
                            "blob_offset": base,
                            "length": length,
                            "witnessed_ranges": ranges,
                            "coverage_kind": kind,
                            "join_source": "best_match",
                        }

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
            witnessed = alignment.get("witnessed_bytes", 0)
            if not isinstance(base, int) or not isinstance(length, int) or not isinstance(ranges, list):
                continue
            candidate = {
                "blob_offset": base,
                "length": length,
                "witnessed_ranges": ranges,
                "coverage_kind": "gapped",
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
                    if candidate["length"] > gapped_best.get("length", 0):
                        gapped_best = candidate

        join_candidate = best_candidate
        if gapped_best:
            if not join_candidate:
                join_candidate = gapped_best
            else:
                join_len = int(join_candidate.get("length", 0))
                if gapped_best["length"] > join_len:
                    join_candidate = gapped_best

        if join_candidate:
            join_candidate.pop("witnessed_bytes", None)
            out[entry_id] = join_candidate
    return out


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="check-trace-join")
    ap.add_argument(
        "--analysis",
        type=Path,
        default=Path("book/evidence/experiments/encoder-write-trace/out/trace_analysis.json"),
        help="Trace analysis JSON",
    )
    ap.add_argument(
        "--network-diffs",
        type=Path,
        default=Path("book/evidence/experiments/field2-final-final/libsandbox-encoder/out/network_matrix/blob_diffs.json"),
        help="Network matrix diff JSON",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=Path("book/evidence/experiments/encoder-write-trace/out/trace_join_check.json"),
        help="Output JSON path",
    )
    args = ap.parse_args(argv)

    repo_root = find_repo_root()
    analysis_path = ensure_absolute(args.analysis, repo_root)
    network_path = ensure_absolute(args.network_diffs, repo_root)
    out_path = ensure_absolute(args.out, repo_root)

    analysis = _load_json(analysis_path)
    expected_world = baseline_world_id(repo_root)
    if analysis.get("world_id") != expected_world:
        raise ValueError(f"analysis world_id mismatch: {analysis.get('world_id')} != {expected_world}")

    trace_map = _best_trace_map(analysis)
    network_diffs = _load_json(network_path)

    missing: List[Dict[str, Any]] = []
    hits: List[Dict[str, Any]] = []
    checked_pairs = 0
    checked_diffs = 0
    witnessed_diffs = 0
    inferred_diffs = 0
    skipped_pairs: List[str] = []

    for pair in network_diffs.get("pairs", []):
        if not isinstance(pair, Mapping):
            continue
        pair_id = pair.get("pair_id")
        a_id = pair.get("a")
        b_id = pair.get("b")
        if not isinstance(pair_id, str) or not isinstance(a_id, str) or not isinstance(b_id, str):
            continue
        if a_id not in trace_map or b_id not in trace_map:
            skipped_pairs.append(pair_id)
            continue
        checked_pairs += 1
        a_trace = trace_map[a_id]
        b_trace = trace_map[b_id]

        diffs = pair.get("diffs", [])
        if not isinstance(diffs, list):
            continue
        for diff in diffs:
            if not isinstance(diff, Mapping):
                continue
            offset = diff.get("offset")
            if not isinstance(offset, int):
                continue
            checked_diffs += 1
            for side, trace in (("a", a_trace), ("b", b_trace)):
                start = trace["blob_offset"]
                end = start + trace["length"]
                if not (start <= offset < end):
                    missing.append(
                        {
                            "pair_id": pair_id,
                            "side": side,
                            "offset": offset,
                            "trace_window": {"start": start, "end_exclusive": end},
                        }
                    )
                    continue
                cursor = offset - start
                coverage = "inferred"
                ranges = trace.get("witnessed_ranges", [])
                if isinstance(ranges, list) and ranges:
                    if _range_contains(ranges, cursor):
                        coverage = "witnessed"
                hits.append(
                    {
                        "pair_id": pair_id,
                        "side": side,
                        "offset": offset,
                        "coverage": coverage,
                        "trace_window": {"start": start, "end_exclusive": end},
                    }
                )
                if coverage == "witnessed":
                    witnessed_diffs += 1
                else:
                    inferred_diffs += 1

    status = "ok" if not missing else "partial"
    payload = {
        "world_id": expected_world,
        "analysis": to_repo_relative(analysis_path, repo_root),
        "network_diffs": to_repo_relative(network_path, repo_root),
        "status": status,
        "counts": {
            "pairs_checked": checked_pairs,
            "diffs_checked": checked_diffs,
            "diffs_witnessed": witnessed_diffs,
            "diffs_inferred": inferred_diffs,
            "missing": len(missing),
            "pairs_skipped": len(skipped_pairs),
        },
        "hits": hits,
        "missing": missing,
        "pairs_skipped": skipped_pairs,
        "notes": [
            "This guardrail only checks offsets for inputs present in the trace manifest.",
            "Offsets are evaluated against the traced buffer window chosen by the analysis step.",
            "Coverage is labeled witnessed when the offset falls inside a traced byte range; inferred when it falls inside the aligned window but outside the traced ranges.",
            "When a gapped alignment offers wider coverage than the best subset/full match, the join window is taken from the gapped alignment.",
        ],
    }
    _write_json(out_path, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
