from __future__ import annotations

import json
from pathlib import Path

from book.api import path_utils

ROOT = path_utils.find_repo_root(Path(__file__))
INVENTORY = (
    ROOT
    / "book"
    / "integration"
    / "carton"
    / "bundle"
    / "relationships"
    / "mappings"
    / "runtime"
    / "other_runtime_inventory.json"
)


def _iter_inventory_paths(doc: dict) -> list[str]:
    paths: list[str] = []
    for entry in doc.get("in_repo", []):
        paths.extend(entry.get("paths") or [])
        for fentry in entry.get("files") or []:
            p = fentry.get("path")
            if p:
                paths.append(p)
    for entry in doc.get("unclassified_hits", []):
        p = entry.get("path")
        if p:
            paths.append(p)
    return paths


def test_hardened_runtime_inventory_paths_are_current():
    assert INVENTORY.exists(), (
        "missing inventory: "
        f"{INVENTORY} "
        "(run book/integration/carton/mappings/runtime/generate_other_runtime_inventory.py)"
    )
    doc = json.loads(INVENTORY.read_text())
    paths = _iter_inventory_paths(doc)
    assert paths, "expected inventory to include repo paths"

    missing = []
    old_test_paths = []
    absolute_paths = []
    legacy_test_plane_paths = []
    legacy_mapping_paths = []

    for rel in paths:
        if Path(rel).is_absolute():
            absolute_paths.append(rel)
            continue
        if rel.startswith("book/integration/test_"):
            old_test_paths.append(rel)
        if rel.startswith("book/tests/planes/") or rel.startswith("book/tests/"):
            legacy_test_plane_paths.append(rel)
        if rel.startswith("book/graph/mappings/"):
            legacy_mapping_paths.append(rel)
        if not (ROOT / rel).exists():
            missing.append(rel)

    assert not absolute_paths, f"inventory contains absolute paths: {absolute_paths[:5]}"
    assert not legacy_mapping_paths, (
        "inventory references legacy book/graph/mappings paths; "
        "regenerate via book/integration/carton/mappings/runtime/generate_other_runtime_inventory.py"
    )
    assert not legacy_test_plane_paths, (
        "inventory still references legacy test paths; regenerate via "
        "book/evidence/experiments/runtime-final-final/suites/hardened-runtime/build_other_runtime_inventory.py"
    )
    assert not old_test_paths, (
        "inventory still references legacy test paths; regenerate via book/evidence/experiments/runtime-final-final/suites/hardened-runtime/build_other_runtime_inventory.py"
    )
    assert not missing, f"inventory paths missing on disk: {missing[:5]}"
