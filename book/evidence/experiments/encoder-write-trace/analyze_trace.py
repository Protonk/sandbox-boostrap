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


def _hex_to_bytes(value: str) -> bytes:
    if not value:
        return b""
    return bytes.fromhex(value)


def _merge_ranges(ranges: Iterable[Tuple[int, int]]) -> List[Tuple[int, int]]:
    merged: List[Tuple[int, int]] = []
    for start, end in sorted(ranges):
        if not merged:
            merged.append((start, end))
            continue
        last_start, last_end = merged[-1]
        if start <= last_end:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    return merged


def _ranges_complement(ranges: Iterable[Tuple[int, int]], window_len: int) -> List[Tuple[int, int]]:
    holes: List[Tuple[int, int]] = []
    pos = 0
    for start, end in _merge_ranges(ranges):
        if start > pos:
            holes.append((pos, start))
        pos = max(pos, end)
    if pos < window_len:
        holes.append((pos, window_len))
    return holes


def _normalize_writes(
    writes: Iterable[Tuple[int, bytes]],
    *,
    cursor_mode: str,
) -> Tuple[int, List[Tuple[int, bytes]]]:
    writes_list = list(writes)
    cursors = [cursor for cursor, _ in writes_list]
    base = 0
    if cursor_mode == "cursor_as_ptr" and cursors:
        base = min(cursors)
    normalized = [(cursor - base, data) for cursor, data in writes_list]
    return base, normalized


def _find_all(haystack: bytes, needle: bytes) -> Iterable[int]:
    if not needle:
        return []
    start = 0
    out: List[int] = []
    while True:
        pos = haystack.find(needle, start)
        if pos == -1:
            break
        out.append(pos)
        start = pos + 1
    return out


def _align_gapped(
    writes: Iterable[Tuple[int, bytes]],
    *,
    cursor_mode: str,
    blob: bytes,
    window_len: int,
) -> Optional[Dict[str, Any]]:
    if not blob or window_len <= 0:
        return None
    _, normalized = _normalize_writes(writes, cursor_mode=cursor_mode)
    if not normalized:
        return None

    candidates: Dict[int, Dict[str, int]] = {}
    min_len_used: Optional[int] = None
    for min_len in (4, 3, 2, 1):
        candidates.clear()
        for cursor, data in normalized:
            if len(data) < min_len:
                continue
            bases_for_write = set()
            for pos in _find_all(blob, data):
                base = pos - cursor
                if base < 0:
                    continue
                if base + window_len > len(blob):
                    continue
                bases_for_write.add(base)
            for base in bases_for_write:
                stats = candidates.setdefault(base, {"support_writes": 0, "support_bytes": 0})
                stats["support_writes"] += 1
                stats["support_bytes"] += len(data)
        if candidates:
            min_len_used = min_len
            break

    if not candidates:
        return None

    best_base: Optional[int] = None
    best_writes = -1
    best_bytes = -1
    for base, stats in candidates.items():
        writes = stats["support_writes"]
        bytes_len = stats["support_bytes"]
        if writes > best_writes or (writes == best_writes and bytes_len > best_bytes):
            best_base = base
            best_writes = writes
            best_bytes = bytes_len
    if best_base is None:
        return None

    witnessed_ranges: List[Tuple[int, int]] = []
    aligned_writes = 0
    mismatched_writes = 0
    for cursor, data in normalized:
        if not data:
            continue
        start = best_base + cursor
        end = start + len(data)
        if start < 0 or end > len(blob):
            mismatched_writes += 1
            continue
        if blob[start:end] == data:
            witnessed_ranges.append((cursor, cursor + len(data)))
            aligned_writes += 1
        else:
            mismatched_writes += 1

    merged = _merge_ranges(witnessed_ranges)
    witnessed_bytes = sum(end - start for start, end in merged)
    holes = _ranges_complement(merged, window_len)
    candidates_sorted = sorted(
        (
            {"base_offset": base, **stats}
            for base, stats in candidates.items()
        ),
        key=lambda item: (item["support_writes"], item["support_bytes"]),
        reverse=True,
    )
    return {
        "base_offset": best_base,
        "window_len": window_len,
        "support_writes": best_writes,
        "support_bytes": best_bytes,
        "aligned_writes": aligned_writes,
        "mismatched_writes": mismatched_writes,
        "witnessed_bytes": witnessed_bytes,
        "witnessed_ranges": merged,
        "hole_ranges": holes,
        "min_payload_len": min_len_used,
        "candidates": candidates_sorted[:5],
    }


def _reconstruct(
    writes: Iterable[Tuple[int, bytes]],
    *,
    cursor_mode: str,
) -> Dict[str, Any]:
    cursors = [cursor for cursor, _ in writes]
    if not cursors:
        return {
            "cursor_mode": cursor_mode,
            "reconstructed_len": 0,
            "coverage": 0,
            "overlaps": 0,
            "conflicts": 0,
            "match": {"kind": "none"},
        }

    base = 0
    if cursor_mode == "cursor_as_ptr":
        base = min(cursors)

    max_end = 0
    for cursor, data in writes:
        end = (cursor - base) + len(data)
        if end > max_end:
            max_end = end

    seen: Dict[int, int] = {}
    overlaps = 0
    conflicts = 0
    for cursor, data in writes:
        start = cursor - base
        for offset, b in enumerate(data):
            pos = start + offset
            if pos in seen:
                overlaps += 1
                if seen[pos] != b:
                    conflicts += 1
            seen[pos] = b

    coverage = len(seen)
    reconstructed = bytearray(max_end)
    for pos, b in seen.items():
        if 0 <= pos < max_end:
            reconstructed[pos] = b

    result = {
        "cursor_mode": cursor_mode,
        "reconstructed_len": max_end,
        "coverage": coverage,
        "overlaps": overlaps,
        "conflicts": conflicts,
        "match": {"kind": "none"},
    }
    if coverage != max_end:
        result["match"] = {"kind": "gapped"}
        return result

    result["reconstructed_bytes"] = bytes(reconstructed)
    return result


def _match_reconstruction(reconstructed: bytes, blob: bytes) -> Dict[str, Any]:
    if reconstructed == blob:
        return {"kind": "full", "blob_offset": 0}
    if reconstructed:
        pos = blob.find(reconstructed)
        if pos != -1:
            return {"kind": "subset", "blob_offset": pos}
        pos = reconstructed.find(blob)
        if pos != -1:
            return {"kind": "superset", "blob_offset": -pos}
    return {"kind": "none"}


def _score_match(kind: str) -> int:
    return {"full": 4, "subset": 3, "superset": 2, "gapped": 1, "none": 0}.get(kind, 0)


def _select_best(modes: List[Dict[str, Any]], preferred_buf: Optional[str] = None) -> Optional[Dict[str, Any]]:
    if preferred_buf:
        filtered = [mode for mode in modes if mode.get("buf") == preferred_buf]
        if filtered:
            modes = filtered
    best: Optional[Dict[str, Any]] = None
    for mode in modes:
        match = mode.get("match")
        kind = match.get("kind") if isinstance(match, Mapping) else "none"
        score = _score_match(str(kind))
        if best is None:
            best = mode
            best["_score"] = score
            continue
        best_score = int(best.get("_score", 0))
        if score > best_score:
            best = mode
            best["_score"] = score
        elif score == best_score:
            if kind == "gapped":
                best_match = best.get("match")
                best_kind = best_match.get("kind") if isinstance(best_match, Mapping) else "none"
                if best_kind == "gapped":
                    alignment = mode.get("alignment") if isinstance(mode.get("alignment"), Mapping) else {}
                    best_alignment = best.get("alignment") if isinstance(best.get("alignment"), Mapping) else {}
                    support = (
                        int(alignment.get("support_writes", 0)),
                        int(alignment.get("support_bytes", 0)),
                    )
                    best_support = (
                        int(best_alignment.get("support_writes", 0)),
                        int(best_alignment.get("support_bytes", 0)),
                    )
                    if support > best_support:
                        best = mode
                        best["_score"] = score
                        continue
            if int(mode.get("reconstructed_len", 0)) > int(best.get("reconstructed_len", 0)):
                best = mode
                best["_score"] = score
    if best is None:
        return None
    best = dict(best)
    best.pop("_score", None)
    return best


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="analyze-trace")
    ap.add_argument(
        "--manifest",
        type=Path,
        default=Path("book/evidence/experiments/encoder-write-trace/out/manifest.json"),
        help="Trace manifest (repo-relative)",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=Path("book/evidence/experiments/encoder-write-trace/out/trace_analysis.json"),
        help="Output JSON path",
    )
    args = ap.parse_args(argv)

    repo_root = find_repo_root()
    manifest_path = ensure_absolute(args.manifest, repo_root)
    out_path = ensure_absolute(args.out, repo_root)

    manifest = _load_json(manifest_path)
    expected_world = baseline_world_id(repo_root)
    if manifest.get("world_id") != expected_world:
        raise ValueError(f"manifest world_id mismatch: {manifest.get('world_id')} != {expected_world}")

    entries_out: List[Dict[str, Any]] = []

    for entry in manifest.get("inputs", []):
        if not isinstance(entry, Mapping):
            continue
        entry_id = entry.get("id")
        sbpl_rel = entry.get("sbpl")
        trace_rel = entry.get("trace")
        blob_rel = entry.get("blob")
        stats_rel = entry.get("stats")
        compile_info = entry.get("compile") if isinstance(entry.get("compile"), Mapping) else {}
        trace_integrity = entry.get("trace_integrity") if isinstance(entry.get("trace_integrity"), Mapping) else {}
        compile_status = None
        compile_error = None
        if isinstance(compile_info, Mapping):
            compile_status = compile_info.get("status")
            compile_error = compile_info.get("error")
            if not compile_error and isinstance(compile_info.get("output"), Mapping):
                compile_error = compile_info["output"].get("error")
        if compile_status is None and isinstance(trace_integrity, Mapping):
            compile_status = trace_integrity.get("compile_status")
        if not isinstance(entry_id, str):
            continue
        if not isinstance(trace_rel, str) or not isinstance(blob_rel, str):
            continue

        trace_path = ensure_absolute(trace_rel, repo_root)
        blob_path = ensure_absolute(blob_rel, repo_root)
        blob_bytes = blob_path.read_bytes() if blob_path.exists() else b""

        immutable_buffer = None
        if isinstance(stats_rel, str):
            stats_path = ensure_absolute(stats_rel, repo_root)
            if stats_path.exists():
                try:
                    stats_payload = _load_json(stats_path)
                except Exception:
                    stats_payload = None
                if isinstance(stats_payload, Mapping):
                    imm = stats_payload.get("immutable_buf")
                    if isinstance(imm, str) and imm.startswith("0x"):
                        immutable_buffer = imm

        records = _load_jsonl(trace_path)
        by_buf: Dict[str, List[Tuple[int, bytes]]] = {}
        for rec in records:
            if not isinstance(rec, Mapping):
                continue
            buf = rec.get("buf")
            cursor = rec.get("cursor")
            data_hex = rec.get("bytes_hex")
            if not isinstance(buf, str):
                continue
            if not isinstance(cursor, int):
                continue
            if not isinstance(data_hex, str):
                continue
            by_buf.setdefault(buf, []).append((cursor, _hex_to_bytes(data_hex)))

        buffers_out: List[Dict[str, Any]] = []
        best_buffer: Optional[Dict[str, Any]] = None

        for buf, writes in by_buf.items():
            writes_sorted = sorted(writes, key=lambda w: w[0])
            modes: List[Dict[str, Any]] = []
            for mode in ("cursor_as_offset", "cursor_as_ptr"):
                rec = _reconstruct(writes_sorted, cursor_mode=mode)
                reconstructed = rec.pop("reconstructed_bytes", None)
                if isinstance(reconstructed, (bytes, bytearray)) and rec.get("match", {}).get("kind") != "gapped":
                    rec["match"] = _match_reconstruction(bytes(reconstructed), blob_bytes)
                if rec.get("match", {}).get("kind") == "gapped":
                    alignment = _align_gapped(
                        writes_sorted,
                        cursor_mode=mode,
                        blob=blob_bytes,
                        window_len=int(rec.get("reconstructed_len", 0)),
                    )
                    if alignment:
                        rec["alignment"] = alignment
                rec.update({"buf": buf, "write_count": len(writes_sorted)})
                modes.append(rec)

            best_mode = _select_best(modes)
            if best_mode is not None:
                best_mode["modes"] = modes
                buffers_out.append(best_mode)

        if buffers_out:
            best_buffer = _select_best(buffers_out, preferred_buf=immutable_buffer)

        entries_out.append(
            {
                "id": entry_id,
                "sbpl": sbpl_rel,
                "trace": trace_rel,
                "blob": blob_rel,
                "compile_status": compile_status,
                "compile_error": compile_error,
                "immutable_buffer": immutable_buffer,
                "trace_records": len(records),
                "buffers": buffers_out,
                "best": best_buffer,
            }
        )

    payload = {
        "world_id": expected_world,
        "manifest": to_repo_relative(manifest_path, repo_root),
        "entries": entries_out,
    }

    _write_json(out_path, payload)
    return 0


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
