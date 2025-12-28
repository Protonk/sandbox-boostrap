#!/usr/bin/env python3
"""
Create the CARTON manifest for Sonoma 14.4.1.

Outputs:
- book/api/carton/CARTON.json
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api import world as world_mod  # noqa: E402

FILES = [
    "book/graph/mappings/vocab/ops.json",
    "book/graph/mappings/vocab/filters.json",
    "book/graph/mappings/system_profiles/digests.json",
    "book/graph/mappings/carton/operation_coverage.json",
    "book/graph/mappings/carton/operation_index.json",
    "book/graph/mappings/carton/profile_layer_index.json",
    "book/graph/mappings/carton/filter_index.json",
    "book/graph/mappings/carton/concept_index.json",
    "book/graph/mappings/carton/anchor_index.json",
    "book/graph/concepts/validation/out/experiments/field2/field2_ir.json",
    "book/graph/concepts/validation/out/experiments/system-profile-digest/digests_ir.json",
    "book/graph/concepts/validation/out/vocab_status.json",
    "book/graph/concepts/validation/out/validation_status.json",
]

OUT_PATH = ROOT / "book/api/carton/CARTON.json"


def sha256(path: Path) -> str:
    """Stream a file to avoid huge reads and return its sha256 hex digest."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def load_baseline() -> Dict[str, str]:
    """
    Pull the world baseline for this host so the manifest is anchored to the
    same world_id the mappings were validated against.
    """
    data, resolution = world_mod.load_world(repo_root=ROOT)
    world_id = world_mod.require_world_id(data, world_path=resolution.entry.world_path)
    return {
        "host": world_mod.world_path_for_metadata(resolution, repo_root=ROOT),
        "world_id": world_id,
    }


def main() -> None:
    """
    Build the manifest by hashing the vetted mapping/validation outputs and
    pairing them with the host world_id. Consumers (carton_query, agents) treat
    this as the canonical contract for the Sonoma 14.4.1 CARTON bundle.
    """
    baseline = load_baseline()
    rows: List[Dict[str, str]] = []
    for rel in FILES:
        p = ROOT / rel
        rows.append({"path": rel, "sha256": sha256(p)})

    manifest = {
        "name": "CARTON",
        "world_id": baseline["world_id"],
        "files": rows,
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(manifest, indent=2))
    print(f"[+] wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
