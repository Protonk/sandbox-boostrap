#!/usr/bin/env python3
"""
Generate profile_layer_index.json from CARTON mappings.

Inputs (all from CARTON):
- system_profiles/digests.json
- vocab/ops.json
- carton/operation_coverage.json
- carton/CARTON.json (for host, optional)
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

DIGESTS = ROOT / "book/graph/mappings/system_profiles/digests.json"
VOCAB = ROOT / "book/graph/mappings/vocab/ops.json"
COVERAGE = ROOT / "book/graph/mappings/carton/operation_coverage.json"
OUT = ROOT / "book/graph/mappings/carton/profile_layer_index.json"


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
    digests = load_json(DIGESTS)
    vocab = load_json(VOCAB)
    coverage = load_json(COVERAGE)
    ops = vocab.get("ops") or []
    id_to_name = {entry["id"]: entry["name"] for entry in ops if "id" in entry and "name" in entry}
    coverage_map: Dict[str, dict] = coverage.get("coverage") or {}

    baseline = baseline_ref()
    world_id = baseline["world_id"]
    assert_world_compatible(world_id, digests.get("metadata"), "system_digests")
    assert_world_compatible(world_id, coverage.get("metadata"), "coverage")
    source_jobs: List[str] = []
    inputs: List[str] = [
        "book/graph/mappings/system_profiles/digests.json",
        "book/graph/mappings/vocab/ops.json",
        "book/graph/mappings/carton/operation_coverage.json",
        "book/api/carton/CARTON.json",
    ]
    meta = digests.get("metadata") or {}
    source_jobs = meta.get("source_jobs") or source_jobs
    coverage_status = (coverage.get("metadata") or {}).get("status") or "unknown"
    raw_canonical = (digests.get("metadata") or {}).get("canonical_profiles") or {}
    # Profile layer status is keyed to the canonical contracts; do not silently
    # promote degraded profiles back to ok when wiring runtime signatures.
    canonical_status = {
        pid: (info.get("status") if isinstance(info, dict) else info) for pid, info in raw_canonical.items()
    }

    profiles: Dict[str, dict] = {}
    for profile_id, val in (digests.get("profiles") or {k: v for k, v in digests.items() if k != "metadata"}).items():
        op_ids = sorted(set(val.get("op_table") or []))
        ops_list = []
        for op_id in op_ids:
            name = id_to_name.get(op_id)
            if name is None:
                raise ValueError(f"op id {op_id} not found in vocab for profile {profile_id}")
            ops_list.append({"name": name, "id": op_id})
        op_names = [item["name"] for item in ops_list]
        profiles[profile_id] = {
            "id": profile_id,
            "layer": "system",
            "status": val.get("status") or "unknown",
            "ops": ops_list,
        }

    return {
        "metadata": {
            "world_id": world_id,
            "inputs": inputs,
            "source_jobs": source_jobs,
            "status": coverage_status,
            "tier": evidence_tiers.evidence_tier_for_artifact(
                path=OUT,
                tier="mapped",
            ),
            "canonical_profile_status": canonical_status,
            "notes": "Derived from CARTON system digests and coverage; inherits canonical profile status.",
        },
        "profiles": dict(sorted(profiles.items(), key=lambda kv: kv[0])),
    }


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    index = build_index()
    OUT.write_text(json.dumps(index, indent=2))
    print(f"[+] wrote {OUT}")


if __name__ == "__main__":
    main()
