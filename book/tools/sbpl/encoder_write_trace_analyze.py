#!/usr/bin/env python3
"""
Analyze encoder write-trace outputs (Sonoma baseline).

Consumes the encoder-write-trace manifest + trace records and emits a join
analysis that aligns traced writes with compiled blob bytes.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils
from book.api.profile._shared import encoder_trace as trace_mod
from book.api.profile.identity import baseline_world_id


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


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="encoder-write-trace-analyze")
    ap.add_argument(
        "--manifest",
        type=Path,
        default=Path("book/evidence/experiments/profile-pipeline/encoder-write-trace/out/manifest.json"),
        help="Trace manifest (repo-relative)",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=Path("book/evidence/experiments/profile-pipeline/encoder-write-trace/out/trace_analysis.json"),
        help="Output JSON path",
    )
    args = ap.parse_args(argv)

    repo_root = path_utils.find_repo_root(Path(__file__))
    manifest_path = path_utils.ensure_absolute(args.manifest, repo_root)
    out_path = path_utils.ensure_absolute(args.out, repo_root)

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

        trace_path = path_utils.ensure_absolute(trace_rel, repo_root)
        blob_path = path_utils.ensure_absolute(blob_rel, repo_root)
        blob_bytes = blob_path.read_bytes() if blob_path.exists() else b""

        immutable_buffer = None
        if isinstance(stats_rel, str):
            stats_path = path_utils.ensure_absolute(stats_rel, repo_root)
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
                rec = trace_mod.reconstruct(writes_sorted, cursor_mode=mode)
                reconstructed = rec.pop("reconstructed_bytes", None)
                if isinstance(reconstructed, (bytes, bytearray)) and rec.get("match", {}).get("kind") != "gapped":
                    rec["match"] = trace_mod.match_reconstruction(bytes(reconstructed), blob_bytes)
                if rec.get("match", {}).get("kind") == "gapped":
                    alignment = trace_mod.align_gapped(
                        writes_sorted,
                        cursor_mode=mode,
                        blob=blob_bytes,
                        window_len=int(rec.get("reconstructed_len", 0)),
                    )
                    if alignment:
                        rec["alignment"] = alignment
                rec.update({"buf": buf, "write_count": len(writes_sorted)})
                modes.append(rec)

            best_mode = trace_mod.select_best(modes)
            if best_mode is not None:
                best_mode["modes"] = modes
                buffers_out.append(best_mode)

        if buffers_out:
            best_buffer = trace_mod.select_best(buffers_out, preferred_buf=immutable_buffer)

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
        "manifest": path_utils.to_repo_relative(manifest_path, repo_root),
        "entries": entries_out,
    }

    _write_json(out_path, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
