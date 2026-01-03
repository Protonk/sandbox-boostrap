#!/usr/bin/env python3
"""
Inventory all in-repo compiled profile blobs (`*.sb.bin`) and compute sha256.

This is a static step: it does not compile or apply profiles.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.path_utils import to_repo_relative  # type: ignore
from book.api.profile import identity as identity_mod  # type: ignore


SCHEMA_VERSION = 1


def _rel(path: Path) -> str:
    return to_repo_relative(path, REPO_ROOT)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _bucket_for(path: Path) -> str:
    rel = _rel(path)
    if rel.startswith("book/evidence/graph/concepts/validation/fixtures/blobs/"):
        return "validation_fixtures"
    if rel.startswith("book/evidence/graph/concepts/validation/out/experiments/"):
        return "validation_out"
    if rel.startswith("book/integration/carton/bundle/relationships/mappings/"):
        return "mappings"
    if rel.startswith("book/profiles/"):
        return "profiles"
    if rel.startswith("book/evidence/experiments/"):
        return "experiments"
    return "other"


def _inventory_sb_bins(root: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    paths = sorted(root.rglob("*.sb.bin"))
    rows: List[Dict[str, Any]] = []
    digest_to_paths: Dict[str, List[str]] = {}
    for p in paths:
        sha = _sha256_file(p)
        rel = _rel(p)
        digest_to_paths.setdefault(sha, []).append(rel)
        rows.append(
            {
                "path": rel,
                "bucket": _bucket_for(p),
                "size": p.stat().st_size,
                "sha256": sha,
            }
        )

    duplicates = {sha: ps for sha, ps in digest_to_paths.items() if len(ps) > 1}
    metrics = {
        "files": len(rows),
        "unique_digests": len(digest_to_paths),
        "duplicate_digests": len(duplicates),
    }
    return rows, {"metrics": metrics, "duplicates": duplicates}


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="inventory_repo_blobs")
    ap.add_argument("--root", type=Path, default=REPO_ROOT / "book", help="root to scan (default: book/)")
    ap.add_argument("--out", type=Path, required=True, help="output JSON path")
    args = ap.parse_args(argv)

    world_id = identity_mod.baseline_world_id()
    rows, summary = _inventory_sb_bins(args.root)
    payload = {
        "tool": "book/evidence/experiments/runtime-final-final/suites/preflight-blob-digests",
        "schema_version": SCHEMA_VERSION,
        "world_id": world_id,
        "root": _rel(args.root),
        "rows": rows,
        "summary": summary,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
