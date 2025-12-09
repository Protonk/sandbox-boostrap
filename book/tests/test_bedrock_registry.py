from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "book" / "graph" / "concepts" / "BEDROCK_SURFACES.json"
INVENTORY_PATH = ROOT / "book" / "graph" / "concepts" / "CONCEPT_INVENTORY.md"
AGENTS_PATHS = [
    ROOT / "AGENTS.md",
    ROOT / "book" / "AGENTS.md",
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
            f"{path} should direct readers to book/graph/concepts/BEDROCK_SURFACES.json "
            "as the current bedrock registry"
        )
