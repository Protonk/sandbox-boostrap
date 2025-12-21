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
from book.api.profile_tools.identity import baseline_world_id  # type: ignore


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


def _select_best(modes: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    best: Optional[Dict[str, Any]] = None
    for mode in modes:
        kind = mode.get("match", {}).get("kind") if isinstance(mode.get("match"), Mapping) else "none"
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
        default=Path("book/experiments/encoder-write-trace/out/manifest.json"),
        help="Trace manifest (repo-relative)",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=Path("book/experiments/encoder-write-trace/out/trace_analysis.json"),
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
        if not isinstance(entry_id, str):
            continue
        if not isinstance(trace_rel, str) or not isinstance(blob_rel, str):
            continue

        trace_path = ensure_absolute(trace_rel, repo_root)
        blob_path = ensure_absolute(blob_rel, repo_root)
        blob_bytes = blob_path.read_bytes() if blob_path.exists() else b""

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
                rec.update({"buf": buf, "write_count": len(writes_sorted)})
                modes.append(rec)

            best_mode = _select_best(modes)
            if best_mode is not None:
                best_mode["modes"] = modes
                buffers_out.append(best_mode)

        if buffers_out:
            best_buffer = _select_best(buffers_out)

        entries_out.append(
            {
                "id": entry_id,
                "sbpl": sbpl_rel,
                "trace": trace_rel,
                "blob": blob_rel,
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
