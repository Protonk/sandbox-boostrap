#!/usr/bin/env python3
"""
Generate vocab attestation manifest tying ops/filters to their provenance.

Inputs:
- book/graph/mappings/vocab/ops.json
- book/graph/mappings/vocab/filters.json
- book/graph/concepts/validation/out/metadata.json (host/build)
- optional compiled blobs to sanity check counts (airlock/bsd/sample)

Outputs:
- book/graph/mappings/vocab/attestations.json
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List


REPO_ROOT = Path(__file__).resolve().parents[4]
OUT_PATH = REPO_ROOT / "book/graph/mappings/vocab/attestations.json"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def blob_hashes(paths: List[Path]) -> List[Dict[str, Any]]:
    rows = []
    for p in paths:
        if not p.exists():
            continue
        rows.append({"path": str(p.relative_to(REPO_ROOT)), "sha256": sha256(p), "size": p.stat().st_size})
    return rows


def main() -> None:
    meta = load_json(REPO_ROOT / "book/graph/concepts/validation/out/metadata.json")
    ops = load_json(REPO_ROOT / "book/graph/mappings/vocab/ops.json")
    filters = load_json(REPO_ROOT / "book/graph/mappings/vocab/filters.json")

    ops_src = blob_hashes(
        [
            REPO_ROOT / "book/experiments/vocab-from-cache/extracted/usr/lib/libsandbox.1.dylib",
            REPO_ROOT / "book/graph/mappings/dyld-libs/usr/lib/libsandbox.1.dylib",
        ]
    )
    filt_src = blob_hashes(
        [
            REPO_ROOT / "book/experiments/vocab-from-cache/extracted/usr/lib/libsandbox.1.dylib",
            REPO_ROOT / "book/graph/mappings/dyld-libs/usr/lib/libsandbox.1.dylib",
        ]
    )
    compiled_refs = blob_hashes(
        [
            REPO_ROOT / "book/examples/extract_sbs/build/profiles/airlock.sb.bin",
            REPO_ROOT / "book/examples/extract_sbs/build/profiles/bsd.sb.bin",
            REPO_ROOT / "book/examples/sb/build/sample.sb.bin",
        ]
    )

    manifest = {
        "generated_at": ops.get("generated_at") or filters.get("generated_at"),
        "host": meta.get("os", {}),
        "sip_status": meta.get("sip_status"),
        "ops": {
            "count": len(ops.get("ops", [])),
            "source": ops.get("ops", [{}])[0].get("source"),
            "hash": sha256(REPO_ROOT / "book/graph/mappings/vocab/ops.json"),
            "sources": ops_src,
        },
        "filters": {
            "count": len(filters.get("filters", [])),
            "source": filters.get("filters", [{}])[0].get("source"),
            "hash": sha256(REPO_ROOT / "book/graph/mappings/vocab/filters.json"),
            "sources": filt_src,
        },
        "compiled_reference_blobs": compiled_refs,
        "notes": "Attestation links vocab tables to dyld slices and reference blobs for this host/build.",
    }

    OUT_PATH.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    print(f"[+] wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
