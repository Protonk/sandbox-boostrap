#!/usr/bin/env python3
"""
Freeze the labeled digest sets used for structural signal listening.

Produces one compact artifact that records:
- apply-gate digests (positive set)
- known-not-apply-gated control digests
- representative paths for each digest from the repo inventory
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.path_utils import to_repo_relative  # type: ignore
from book.api.profile_tools import identity as identity_mod  # type: ignore


SCHEMA_VERSION = 1

DEFAULT_INVENTORY = REPO_ROOT / "book/experiments/preflight-blob-digests/out/repo_sb_bin_inventory.json"
DEFAULT_APPLY_GATED = REPO_ROOT / "book/experiments/preflight-blob-digests/out/apply_gate_blob_digests.json"
DEFAULT_CONTROLS = REPO_ROOT / "book/experiments/preflight-blob-digests/out/control_digests.json"


def _rel(path: Path) -> str:
    return to_repo_relative(path, REPO_ROOT)


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text())


def _inventory_digest_to_paths(inventory: Dict[str, Any]) -> Dict[str, List[str]]:
    digest_to_paths: Dict[str, List[str]] = {}
    for row in inventory.get("rows") or []:
        if not isinstance(row, dict):
            continue
        sha = row.get("sha256")
        p = row.get("path")
        if isinstance(sha, str) and isinstance(p, str):
            digest_to_paths.setdefault(sha, []).append(p)
    for sha in list(digest_to_paths.keys()):
        digest_to_paths[sha] = sorted(set(digest_to_paths[sha]))
    return digest_to_paths


def _representative_path(paths: List[str]) -> str | None:
    return sorted(paths)[0] if paths else None


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="freeze_structural_sets")
    ap.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    ap.add_argument("--apply-gated", type=Path, default=DEFAULT_APPLY_GATED)
    ap.add_argument("--controls", type=Path, default=DEFAULT_CONTROLS)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)

    world_id = identity_mod.baseline_world_id()
    inv = _load_json(args.inventory)
    gated = _load_json(args.apply_gated)
    controls = _load_json(args.controls)

    if inv.get("world_id") != world_id:
        raise ValueError("inventory world_id mismatch")
    if gated.get("world_id") != world_id:
        raise ValueError("apply-gated world_id mismatch")
    if controls.get("world_id") != world_id:
        raise ValueError("controls world_id mismatch")

    digest_to_paths = _inventory_digest_to_paths(inv)

    gated_digests = []
    for entry in gated.get("apply_gate_digests") or []:
        if not isinstance(entry, dict):
            continue
        sha = entry.get("blob_sha256")
        if not isinstance(sha, str):
            continue
        paths = digest_to_paths.get(sha) or []
        gated_digests.append(
            {
                "blob_sha256": sha,
                "representative_path": _representative_path(paths),
                "paths_count": len(paths),
                "evidence_count": len(entry.get("evidence") or []),
            }
        )

    control_digests = []
    for entry in controls.get("controls") or []:
        if not isinstance(entry, dict):
            continue
        sha = entry.get("blob_sha256")
        if not isinstance(sha, str):
            continue
        paths = digest_to_paths.get(sha) or []
        control_digests.append(
            {
                "blob_sha256": sha,
                "representative_path": _representative_path(paths),
                "paths_count": len(paths),
                "evidence_count": len(entry.get("evidence") or []),
            }
        )

    gated_set = {d["blob_sha256"] for d in gated_digests}
    control_set = {d["blob_sha256"] for d in control_digests}
    overlap = sorted(gated_set & control_set)

    payload = {
        "tool": "book/experiments/preflight-blob-digests",
        "schema_version": SCHEMA_VERSION,
        "world_id": world_id,
        "inputs": {
            "inventory": _rel(args.inventory),
            "apply_gated": _rel(args.apply_gated),
            "controls": _rel(args.controls),
        },
        "metrics": {
            "inventory_unique_digests": int(inv.get("summary", {}).get("metrics", {}).get("unique_digests", 0)),
            "apply_gated": len(gated_digests),
            "controls": len(control_digests),
            "overlap": len(overlap),
            "unknown": int(inv.get("summary", {}).get("metrics", {}).get("unique_digests", 0))
            - len(gated_set | control_set),
        },
        "apply_gated_digests": sorted(gated_digests, key=lambda e: (e["blob_sha256"], e.get("representative_path") or "")),
        "control_digests": sorted(control_digests, key=lambda e: (e["blob_sha256"], e.get("representative_path") or "")),
        "overlap": overlap,
        "notes": [
            "These labeled sets are host-scoped and are used only for structural signature discovery and validation planning.",
            "Do not treat control digests as semantics evidence; they are only 'not apply-gated' on this world in a control_ok context.",
        ],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

