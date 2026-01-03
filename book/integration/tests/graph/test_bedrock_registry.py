from __future__ import annotations

import json
import re
from pathlib import Path


from book.api import path_utils

ROOT = path_utils.find_repo_root(Path(__file__))
REGISTRY_PATH = ROOT / "book" / "evidence" / "graph" / "concepts" / "BEDROCK_SURFACES.json"
INVENTORY_PATH = ROOT / "book" / "evidence" / "graph" / "concepts" / "CONCEPT_INVENTORY.md"
AGENTS_PATHS = [
    ROOT / "book" / "graph" / "AGENTS.md",
]


def _registry_names() -> set[str]:
    data = json.loads(REGISTRY_PATH.read_text())
    names = {entry["name"] for entry in data.get("surfaces", [])}
    assert names, f"no surfaces found in {REGISTRY_PATH}"
    return names


def _inventory_names() -> set[str]:
    lines = INVENTORY_PATH.read_text().splitlines()
    try:
        start = lines.index("### Current bedrock surfaces (navigation)") + 1
    except ValueError:
        raise AssertionError("bedrock navigation section missing from CONCEPT_INVENTORY.md")

    names: set[str] = set()
    bullet_pattern = re.compile(r"^-+\s*(.*?)\s+in\s+`")
    for line in lines[start:]:
        if line.strip() == "":
            break
        if not line.lstrip().startswith("-"):
            continue
        match = bullet_pattern.match(line.strip())
        if match:
            names.add(match.group(1))
        else:
            # Fallback: take the bullet text without leading "- "
            names.add(line.strip().lstrip("-").strip())

    if not names:
        raise AssertionError("no bedrock bullets found in CONCEPT_INVENTORY.md bedrock section")
    return names


def test_inventory_matches_bedrock_registry():
    registry = _registry_names()
    inventory = _inventory_names()
    extra = inventory - registry
    missing = registry - inventory
    assert not extra and not missing, (
        "Bedrock navigation in CONCEPT_INVENTORY.md must mirror BEDROCK_SURFACES.json "
        f"(extra in inventory: {sorted(extra)}; missing from inventory: {sorted(missing)})"
    )


def test_agents_point_to_bedrock_registry():
    for path in AGENTS_PATHS:
        text = path.read_text()
        assert "BEDROCK_SURFACES" in text, (
            f"{path} should direct readers to book/evidence/graph/concepts/BEDROCK_SURFACES.json "
            "as the current bedrock registry"
        )


def test_bedrock_mapping_paths_emit_bedrock_tier():
    registry = json.loads(REGISTRY_PATH.read_text())
    mapping_paths: list[str] = []
    for surface in registry.get("surfaces", []) or []:
        mapping_paths.extend(surface.get("mapping_paths", []) or [])

    assert mapping_paths, f"no mapping_paths found in {REGISTRY_PATH}"
    for rel in mapping_paths:
        doc = json.loads((ROOT / rel).read_text())
        meta = doc.get("metadata") or doc.get("meta") or {}
        assert meta.get("tier") == "bedrock", f"{rel} should be tier=bedrock"
