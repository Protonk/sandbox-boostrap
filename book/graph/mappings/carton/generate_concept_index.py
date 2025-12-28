#!/usr/bin/env python3
"""
Generate the CARTON concept_index.json for the current baseline.

The concept index ties concept-inventory names (operation/filter/profile-layer)
to the specific CARTON-facing artifacts and their top-level keys.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api import evidence_tiers  # noqa: E402
from book.api import world as world_mod  # noqa: E402

OUT_PATH = ROOT / "book/graph/mappings/carton/concept_index.json"

CONCEPTS: Dict[str, List[Dict[str, str]]] = {
    "operation": [
        {
            "path": "book/graph/mappings/vocab/ops.json",
            "key": "ops",
            "by": "id/name",
        },
        {
            "path": "book/graph/mappings/carton/operation_coverage.json",
            "key": "coverage",
            "by": "op_name",
        },
        {
            "path": "book/graph/mappings/carton/operation_index.json",
            "key": "operations",
            "by": "op_name",
        },
    ],
    "filter": [
        {
            "path": "book/graph/mappings/vocab/filters.json",
            "key": "filters",
            "by": "id/name",
        },
        {
            "path": "book/graph/mappings/carton/filter_index.json",
            "key": "filters",
            "by": "filter_name (map keys)",
        },
    ],
    "profile-layer": [
        {
            "path": "book/graph/mappings/carton/profile_layer_index.json",
            "key": "profiles",
            "by": "profile_id (map keys)",
        },
    ],
}


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def load_baseline_world_id() -> tuple[str, str]:
    data, resolution = world_mod.load_world(repo_root=ROOT)
    world_id = world_mod.require_world_id(data, world_path=resolution.entry.world_path)
    world_path = world_mod.world_path_for_metadata(resolution, repo_root=ROOT)
    return world_id, world_path


def main() -> None:
    world_id, world_path = load_baseline_world_id()
    status = "ok"
    doc = {
        "metadata": {
            "notes": (
                "Maps concept-inventory names to CARTON artifacts and top-level keys. "
                "Paths are relative to repo root and must appear in CARTON.json."
            ),
            "status": status,
            "tier": evidence_tiers.evidence_tier_for_artifact(
                path=OUT_PATH,
                tier="mapped",
            ),
            "inputs": [world_path],
            "world_id": world_id,
        },
        "concepts": CONCEPTS,
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(doc, indent=2))
    print(f"[+] wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
