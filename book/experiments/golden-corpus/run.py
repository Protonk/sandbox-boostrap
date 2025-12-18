"""
Generate decoder/inspection artifacts for the golden-corpus experiment.
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Dict, List


EXPERIMENT_ROOT = Path(__file__).resolve().parent
REPO_ROOT = EXPERIMENT_ROOT.parents[2]
BOOK_ROOT = REPO_ROOT / "book"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.profile_tools import decode_profile_dict
from book.api.profile_tools.inspect import summarize_blob
from book.api.profile_tools import op_table as op_table_mod
from book.api.profile_tools import compile as compile_mod


WORLD_ID = "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5"
OUT_DIR = EXPERIMENT_ROOT / "out"
RAW_DIR = OUT_DIR / "raw"
DECODE_DIR = OUT_DIR / "decodes"
INSPECT_DIR = OUT_DIR / "inspect"
BLOB_DIR = OUT_DIR / "blobs"

TAG_LAYOUTS_PATH = BOOK_ROOT / "graph" / "mappings" / "tag_layouts" / "tag_layouts.json"

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
        "path": "experiments/sbpl-graph-runtime/out/deny_all.sb.bin",
        "mode": "runtime-capable",
    },
    {
        "id": "runtime_param_path_concrete",
        "category": "sbpl-graph-runtime",
        "path": "experiments/sbpl-graph-runtime/out/param_path_concrete.sb.bin",
        "mode": "runtime-capable",
    },
    {
        "id": "encoder_single_file_subpath",
        "category": "libsandbox-encoder",
        "path": "experiments/libsandbox-encoder/out/single_file_subpath.sb.bin",
        "mode": "runtime-capable",
    },
    {
        "id": "platform_airlock",
        "category": "platform",
        "source": "sbpl",
        "path": "/System/Library/Sandbox/Profiles/airlock.sb",
        "mode": "static-only",
        "notes": "platform/system profile; static-only, apply-gated on this host",
    },
]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tag_layout_digest() -> str:
    payload = TAG_LAYOUTS_PATH.read_bytes()
    return sha256_bytes(payload)


def ensure_dirs() -> None:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    DECODE_DIR.mkdir(parents=True, exist_ok=True)
    INSPECT_DIR.mkdir(parents=True, exist_ok=True)
    BLOB_DIR.mkdir(parents=True, exist_ok=True)


def load_blob(entry: Dict[str, str]) -> Dict[str, str | int]:
    source_type = entry.get("source", "blob")
    if source_type == "sbpl":
        sbpl_path = Path(entry["path"])
        if not sbpl_path.is_absolute():
            sbpl_path = BOOK_ROOT / entry["path"]
        blob_path = BLOB_DIR / f"{entry['id']}.sb.bin"
        res = compile_mod.compile_sbpl_file(sbpl_path, blob_path)
        data = res.blob
        source_path = str(sbpl_path)
        compiled_path = str(blob_path.relative_to(BOOK_ROOT.parent))
    else:
        src = BOOK_ROOT / entry["path"]
        data = src.read_bytes()
        source_path = str(src.relative_to(BOOK_ROOT.parent))
        compiled_path = source_path
    return {
        "id": entry["id"],
        "category": entry["category"],
        "mode": entry.get("mode", "runtime-capable"),
        "source_path": source_path,
        "compiled_path": compiled_path,
        "size_bytes": len(data),
        "sha256": sha256_bytes(data),
        "data": data,
    }


def main() -> int:
    ensure_dirs()
    manifest: List[Dict[str, str | int]] = []
    summary_records: List[Dict[str, object]] = []
    layout_sha = tag_layout_digest()

    for entry in BLOBS:
        blob = load_blob(entry)
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
            "world_id": WORLD_ID,
            "tag_layouts_sha256": layout_sha,
            "header_bytes_hex_256": data[:256].hex(),
            "preamble_words_full": decoded.get("preamble_words_full"),
            "sections": decoded.get("sections"),
        }

        (DECODE_DIR / f"{blob_id}.json").write_text(json.dumps(decoded, indent=2))
        (INSPECT_DIR / f"{blob_id}_inspect.json").write_text(json.dumps(asdict(inspect_summary), indent=2))
        (INSPECT_DIR / f"{blob_id}_op_table.json").write_text(json.dumps(asdict(op_summary), indent=2))
        (RAW_DIR / f"{blob_id}.json").write_text(json.dumps(raw_snapshot, indent=2))

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
        "world_id": WORLD_ID,
        "tag_layouts_sha256": layout_sha,
        "entries": manifest,
    }
    (OUT_DIR / "corpus_manifest.json").write_text(json.dumps(manifest_payload, indent=2))

    summary_payload = {
        "world_id": WORLD_ID,
        "tag_layouts_sha256": layout_sha,
        "records": summary_records,
    }
    (OUT_DIR / "corpus_summary.json").write_text(json.dumps(summary_payload, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
