"""
Shared helpers for encoder write-trace analysis (Sonoma baseline).

These are structural utilities for aligning traced write records to compiled
blob bytes. They intentionally avoid runtime semantics.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple


def merge_ranges(ranges: Iterable[Tuple[int, int]]) -> List[Tuple[int, int]]:
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


def ranges_complement(ranges: Iterable[Tuple[int, int]], window_len: int) -> List[Tuple[int, int]]:
    holes: List[Tuple[int, int]] = []
    pos = 0
    for start, end in merge_ranges(ranges):
        if start > pos:
            holes.append((pos, start))
        pos = max(pos, end)
    if pos < window_len:
        holes.append((pos, window_len))
    return holes


def normalize_writes(
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


def find_all(haystack: bytes, needle: bytes) -> Iterable[int]:
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


def align_gapped(
    writes: Iterable[Tuple[int, bytes]],
    *,
    cursor_mode: str,
    blob: bytes,
    window_len: int,
) -> Optional[Dict[str, Any]]:
    if not blob or window_len <= 0:
        return None
    _, normalized = normalize_writes(writes, cursor_mode=cursor_mode)
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
            for pos in find_all(blob, data):
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

    merged = merge_ranges(witnessed_ranges)
    witnessed_bytes = sum(end - start for start, end in merged)
    holes = ranges_complement(merged, window_len)
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


def reconstruct(
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


def match_reconstruction(reconstructed: bytes, blob: bytes) -> Dict[str, Any]:
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


def score_match(kind: str) -> int:
    return {"full": 4, "subset": 3, "superset": 2, "gapped": 1, "none": 0}.get(kind, 0)


def select_best(modes: List[Dict[str, Any]], preferred_buf: Optional[str] = None) -> Optional[Dict[str, Any]]:
    if preferred_buf:
        filtered = [mode for mode in modes if mode.get("buf") == preferred_buf]
        if filtered:
            modes = filtered
    best: Optional[Dict[str, Any]] = None
    for mode in modes:
        match = mode.get("match")
        kind = match.get("kind") if isinstance(match, Mapping) else "none"
        score = score_match(str(kind))
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


def best_trace_map(analysis: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
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


def range_contains(ranges: List[List[int]], offset: int) -> bool:
    for start, end in ranges:
        if start <= offset < end:
            return True
    return False
