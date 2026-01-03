#!/usr/bin/env python3
"""Generate concept → artifact source index for CARTON."""

from __future__ import annotations

from typing import Any, Dict, List

from book.integration.carton.fixers import common

ROOT = common.repo_root()
OUT_PATH = ROOT / "book/integration/carton/bundle/relationships/concept_sources.json"

CONCEPTS: Dict[str, List[Dict[str, str]]] = {
    "operation": [
        {
            "path": "book/integration/carton/bundle/relationships/mappings/vocab/ops.json",
            "key": "ops",
            "by": "id/name",
        },
        {
            "path": "book/integration/carton/bundle/relationships/operation_coverage.json",
            "key": "coverage",
            "by": "op_name",
        },
        {
            "path": "book/integration/carton/bundle/views/operation_index.json",
            "key": "operations",
            "by": "op_name",
        },
    ],
    "filter": [
        {
            "path": "book/integration/carton/bundle/relationships/mappings/vocab/filters.json",
            "key": "filters",
            "by": "id/name",
        },
        {
            "path": "book/integration/carton/bundle/relationships/filter_usage.json",
            "key": "filters",
            "by": "filter_name (map keys)",
        },
        {
            "path": "book/integration/carton/bundle/views/filter_index.json",
            "key": "filters",
            "by": "filter_name (map keys)",
        },
    ],
    "profile-layer": [
        {
            "path": "book/integration/carton/bundle/relationships/profile_layer_ops.json",
            "key": "profiles",
            "by": "profile_id (map keys)",
        },
        {
            "path": "book/integration/carton/bundle/views/profile_layer_index.json",
            "key": "profiles",
            "by": "profile_id (map keys)",
        },
    ],
}


def build() -> Dict[str, Any]:
    baseline = common.baseline_ref(repo_root_path=ROOT)
    world_id = baseline["world_id"]
    world_path = baseline["host"]
    doc = {
        "metadata": {
            "notes": (
                "Maps concept-inventory names to CARTON artifacts and top-level keys. "
                "Paths are relative to repo root and must appear in CARTON.json."
            ),
            "status": "ok",
            "inputs": [world_path],
            "world_id": world_id,
        },
        "concepts": CONCEPTS,
    }
    return doc


def run() -> None:
    doc = build()
    common.write_json(OUT_PATH, doc)
    print(f"[+] wrote {OUT_PATH}")


if __name__ == "__main__":
    run()
