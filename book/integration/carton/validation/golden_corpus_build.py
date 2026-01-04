#!/usr/bin/env python3
"""
Build decoder/inspection artifacts for the golden-corpus regression set.
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Dict, List, Optional, Sequence


REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.path_utils import find_repo_root, to_repo_relative  # type: ignore
from book.api.profile import decode_profile_dict  # type: ignore
from book.api.profile import compile as compile_mod  # type: ignore
from book.api.profile import op_table as op_table_mod  # type: ignore
from book.api.profile.identity import baseline_world_id  # type: ignore
from book.api.profile.inspect import summarize_blob  # type: ignore


REPO_ROOT = find_repo_root(Path(__file__))
BOOK_ROOT = REPO_ROOT / "book"
OUT_DIR = BOOK_ROOT / "evidence" / "syncretic" / "validation" / "golden_corpus"
RAW_DIR = OUT_DIR / "raw"
DECODE_DIR = OUT_DIR / "decodes"
INSPECT_DIR = OUT_DIR / "inspect"
BLOB_DIR = OUT_DIR / "blobs"

TAG_LAYOUTS_PATH = BOOK_ROOT / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "tag_layouts" / "tag_layouts.json"

BLOBS: List[Dict[str, str]] = [
    {
        "id": "golden_allow_all",
        "category": "golden-triple",
        "path": "profiles/golden-triple/allow_all.sb.bin",
        "mode": "runtime-capable",
    },
    {
        "id": "golden_strict_1",
        "category": "golden-triple",
        "path": "profiles/golden-triple/strict_1.sb.bin",
        "mode": "runtime-capable",
    },
    {
        "id": "golden_bucket4_v1_read",
        "category": "golden-triple",
        "path": "profiles/golden-triple/bucket4_v1_read.sb.bin",
        "mode": "runtime-capable",
    },
    {
        "id": "golden_bucket5_v11_subpath",
        "category": "golden-triple",
        "path": "profiles/golden-triple/bucket5_v11_read_subpath.sb.bin",
        "mode": "runtime-capable",
    },
    {
        "id": "runtime_deny_all",
        "category": "sbpl-graph-runtime",
        "path": "evidence/experiments/runtime-final-final/suites/sbpl-graph-runtime/out/deny_all.sb.bin",
        "mode": "runtime-capable",
    },
    {
        "id": "runtime_param_path_concrete",
        "category": "sbpl-graph-runtime",
        "path": "evidence/experiments/runtime-final-final/suites/sbpl-graph-runtime/out/param_path_concrete.sb.bin",
        "mode": "runtime-capable",
    },
    {
        "id": "encoder_single_file_subpath",
        "category": "libsandbox-encoder",
        "path": "evidence/experiments/field2-final-final/libsandbox-encoder/out/single_file_subpath.sb.bin",
        "mode": "runtime-capable",
    },
    {
        "id": "platform_airlock",
        "category": "platform",
        "path": "evidence/syncretic/validation/fixtures/blobs/airlock.sb.bin",
        "mode": "static-only",
        "notes": "platform/system profile fixture; static-only, apply-gated on this host",
    },
]


def _rel(path: Path) -> str:
    return to_repo_relative(path, REPO_ROOT)


def _resolve_book_path(path_str: str) -> Path:
    path = Path(path_str)
    if path.is_absolute():
        return path
    if path.parts and path.parts[0] == "book":
        return REPO_ROOT / path
    return BOOK_ROOT / path


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tag_layout_digest() -> str:
    return _sha256_bytes(TAG_LAYOUTS_PATH.read_bytes())


def _ensure_dirs() -> None:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    DECODE_DIR.mkdir(parents=True, exist_ok=True)
    INSPECT_DIR.mkdir(parents=True, exist_ok=True)
    BLOB_DIR.mkdir(parents=True, exist_ok=True)


def _load_blob(entry: Dict[str, str]) -> Dict[str, str | int | bytes]:
    source_type = entry.get("source", "blob")
    if source_type == "sbpl":
        sbpl_path = _resolve_book_path(entry["path"])
        blob_path = BLOB_DIR / f"{entry['id']}.sb.bin"
        res = compile_mod.compile_sbpl_file(sbpl_path, blob_path)
        data = res.blob
        source_path = _rel(sbpl_path)
        compiled_path = _rel(blob_path)
    else:
        src = _resolve_book_path(entry["path"])
        data = src.read_bytes()
        source_path = _rel(src)
        compiled_path = source_path
    return {
        "id": entry["id"],
        "category": entry["category"],
        "mode": entry.get("mode", "runtime-capable"),
        "source_path": source_path,
        "compiled_path": compiled_path,
        "size_bytes": len(data),
        "sha256": _sha256_bytes(data),
        "data": data,
    }


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n")


def main(argv: Optional[Sequence[str]] = None) -> int:
    _ = argv
    _ensure_dirs()
    manifest: List[Dict[str, str | int]] = []
    summary_records: List[Dict[str, object]] = []
    layout_sha = _tag_layout_digest()
    world_id = baseline_world_id(REPO_ROOT)

    for entry in BLOBS:
        blob = _load_blob(entry)
        data = blob.pop("data")  # type: ignore[assignment]
        blob_id = blob["id"]  # type: ignore[index]

        decoded = decode_profile_dict(data)
        inspect_summary = summarize_blob(data)
        op_summary = op_table_mod.summarize_profile(
            name=str(blob_id),
            blob=data,
            ops=[],
            filters=[],
            op_count_override=None,
            filter_map=None,
        )

        raw_snapshot = {
            "id": blob_id,
            "source_path": blob["source_path"],
            "compiled_path": blob.get("compiled_path"),
            "mode": blob.get("mode"),
            "size_bytes": blob["size_bytes"],
            "sha256": blob["sha256"],
            "world_id": world_id,
            "tag_layouts_sha256": layout_sha,
            "header_bytes_hex_256": data[:256].hex(),
            "preamble_words_full": decoded.get("preamble_words_full"),
            "sections": decoded.get("sections"),
        }

        _write_json(DECODE_DIR / f"{blob_id}.json", decoded)
        _write_json(INSPECT_DIR / f"{blob_id}_inspect.json", asdict(inspect_summary))
        _write_json(INSPECT_DIR / f"{blob_id}_op_table.json", asdict(op_summary))
        _write_json(RAW_DIR / f"{blob_id}.json", raw_snapshot)

        manifest.append(dict(blob))

        sections = decoded.get("sections") or {}
        summary_records.append(
            {
                "id": blob_id,
                "category": blob["category"],
                "source_path": blob["source_path"],
                "compiled_path": blob.get("compiled_path"),
                "mode": blob.get("mode"),
                "sha256": blob["sha256"],
                "size_bytes": blob["size_bytes"],
                "decoder": {
                    "op_count": decoded.get("op_count"),
                    "node_bytes": sections.get("nodes"),
                    "literal_start": sections.get("literal_start"),
                    "tag_counts": decoded.get("tag_counts"),
                },
                "inspect": {
                    "op_count": inspect_summary.op_count,
                    "node_bytes": inspect_summary.section_lengths.get("nodes"),
                    "literal_bytes": inspect_summary.section_lengths.get("literals"),
                    "tag_counts_stride12": inspect_summary.tag_counts_stride12,
                },
            }
        )

    manifest_payload = {
        "world_id": world_id,
        "tag_layouts_sha256": layout_sha,
        "entries": manifest,
    }
    _write_json(OUT_DIR / "corpus_manifest.json", manifest_payload)

    summary_payload = {
        "world_id": world_id,
        "tag_layouts_sha256": layout_sha,
        "records": summary_records,
    }
    _write_json(OUT_DIR / "corpus_summary.json", summary_payload)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
