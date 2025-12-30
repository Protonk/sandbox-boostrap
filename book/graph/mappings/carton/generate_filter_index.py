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
import sys
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api import evidence_tiers  # noqa: E402
from book.api import world as world_mod  # noqa: E402

FILTERS = ROOT / "book/graph/mappings/vocab/filters.json"
DIGESTS = ROOT / "book/graph/mappings/system_profiles/digests.json"
CARTON = ROOT / "book/integration/carton/CARTON.json"
OUT = ROOT / "book/graph/mappings/carton/filter_index.json"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def baseline_ref() -> dict:
    data, resolution = world_mod.load_world(repo_root=ROOT)
    world_id = world_mod.require_world_id(data, world_path=resolution.entry.world_path)
    return {
        "host": world_mod.world_path_for_metadata(resolution, repo_root=ROOT),
        "world_id": world_id,
    }


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
    # Filters inherit canonical system-profile status so CARTON callers see the
    # same degraded/ok signal even though filter usage is conservative today.
    canonical_status = (digests.get("metadata") or {}).get("status") or "unknown"

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
            "known": True,
        }

    inputs: List[str] = [
        "book/graph/mappings/vocab/filters.json",
        "book/graph/mappings/system_profiles/digests.json",
        "book/integration/carton/CARTON.json",
    ]

    return {
        "metadata": {
            "world_id": world_id,
            "inputs": inputs,
            "source_jobs": digests.get("metadata", {}).get("source_jobs") or [],
            "status": canonical_status,
            "tier": evidence_tiers.evidence_tier_for_artifact(
                path=OUT,
                tier="mapped",
            ),
            "notes": "Filter vocab promoted into CARTON with explicit usage_status; usage wiring is intentionally conservative and inherits canonical system profile status.",
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
