#!/usr/bin/env python3
"""
Generate filter_index.json from CARTON mappings.

Inputs (all CARTON-facing):
- vocab/filters.json
- system_profiles/digests.json (for host check only)
- carton/CARTON.json (manifest/host)
- world baseline (host)

This intentionally stays conservative: it does not attempt deep filter usage
reconstruction from nodes. Each filter entry records vocab identity and a
usage_status field (one of: unknown, present-in-vocab-only, referenced-in-profiles,
referenced-in-runtime). System profile/runtime usage stays empty until we have
reliable mapping; callers can still ask for a filter and get an explicit answer
about what is (and is not) known.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parents[4]
FILTERS = ROOT / "book/graph/mappings/vocab/filters.json"
DIGESTS = ROOT / "book/graph/mappings/system_profiles/digests.json"
CARTON = ROOT / "book/api/carton/CARTON.json"
BASELINE_REF = "book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json"
BASELINE = ROOT / BASELINE_REF
OUT = ROOT / "book/graph/mappings/carton/filter_index.json"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def baseline_ref() -> dict:
    if not BASELINE.exists():
        raise FileNotFoundError(f"missing baseline: {BASELINE}")
    data = json.loads(BASELINE.read_text())
    world_id = data.get("world_id")
    if not world_id:
        raise RuntimeError("world_id missing from baseline")
    return {"host": str(BASELINE.relative_to(ROOT)), "world_id": world_id}


def assert_world_compatible(baseline_world: str, other: dict | str | None, label: str) -> None:
    if not other:
        return
    other_world = other.get("world_id") if isinstance(other, dict) else other
    if other_world and other_world != baseline_world:
        raise RuntimeError(f"world_id mismatch for {label}: baseline {baseline_world} vs {other_world}")


def build_index() -> dict:
    filters = load_json(FILTERS)
    digests = load_json(DIGESTS)
    baseline = baseline_ref()
    world_id = baseline["world_id"]
    assert_world_compatible(world_id, digests.get("metadata"), "system_digests")

    allowed_status = {"unknown", "present-in-vocab-only", "referenced-in-profiles", "referenced-in-runtime"}
    entries: Dict[str, dict] = {}
    for entry in sorted(filters.get("filters") or [], key=lambda e: e.get("name", "")):
        name = entry.get("name")
        filter_id = entry.get("id")
        if name is None or filter_id is None:
            raise ValueError("filter vocab entry missing name or id")
        entries[name] = {
            "name": name,
            "id": filter_id,
            "usage_status": "present-in-vocab-only",  # conservative default until usage mapping is wired
            "system_profiles": [],
            "runtime_signatures": [],
            "known": True,
        }

    inputs: List[str] = [
        "book/graph/mappings/vocab/filters.json",
        "book/graph/mappings/system_profiles/digests.json",
        "book/api/carton/CARTON.json",
    ]

    return {
        "metadata": {
            "world_id": world_id,
            "inputs": inputs,
            "source_jobs": digests.get("metadata", {}).get("source_jobs") or [],
            "status": "ok",
            "notes": "Filter vocab promoted into CARTON with explicit usage_status; usage wiring is intentionally conservative.",
        },
        "filters": entries,
    }


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    index = build_index()
    OUT.write_text(json.dumps(index, indent=2))
    print(f"[+] wrote {OUT}")


if __name__ == "__main__":
    main()
