#!/usr/bin/env python3
"""
Generate operation_index.json from CARTON mappings.

Inputs (all from CARTON):
- vocab/ops.json
- system_profiles/digests.json
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

VOCAB = ROOT / "book/graph/mappings/vocab/ops.json"
DIGESTS = ROOT / "book/graph/mappings/system_profiles/digests.json"
COVERAGE = ROOT / "book/graph/mappings/carton/operation_coverage.json"
OUT = ROOT / "book/graph/mappings/carton/operation_index.json"


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
    vocab = load_json(VOCAB)
    coverage = load_json(COVERAGE)
    digests = load_json(DIGESTS)
    ops = vocab.get("ops") or []
    coverage_map: Dict[str, dict] = (coverage.get("coverage") or {})
    baseline = baseline_ref()
    world_id = baseline["world_id"]
    assert_world_compatible(world_id, coverage.get("metadata"), "coverage")
    assert_world_compatible(world_id, digests.get("metadata"), "system_digests")
    source_jobs: List[str] = []
    inputs: List[str] = [
        "book/graph/mappings/vocab/ops.json",
        "book/graph/mappings/system_profiles/digests.json",
        "book/graph/mappings/carton/operation_coverage.json",
        "book/api/carton/CARTON.json",
    ]
    meta = coverage.get("metadata") or {}
    coverage_status = meta.get("status") or "unknown"
    source_jobs = meta.get("source_jobs") or source_jobs
    raw_canonical = meta.get("canonical_profile_status") or (digests.get("metadata") or {}).get("canonical_profiles") or {}
    # The operation index mirrors canonical system-profile health so callers
    # reading counts know whether “ok” coverage is still backed by bedrock
    # profiles or already degraded.
    canonical_status = {
        pid: (info.get("status") if isinstance(info, dict) else info) for pid, info in raw_canonical.items()
    }

    operations: Dict[str, dict] = {}
    for entry in ops:
        name = entry.get("name")
        op_id = entry.get("id")
        if name is None or op_id is None:
            raise ValueError("vocab entry missing name or id")
        cov = coverage_map.get(name) or {}
        counts = cov.get("counts") or {}
        system_profiles = cov.get("system_profiles") or []
        profile_layers = ["system"] if system_profiles else []
        operations[name] = {
            "name": name,
            "id": op_id,
            "profile_layers": profile_layers,
            "system_profiles": system_profiles,
            "system_profile_status": cov.get("system_profile_status") or {},
            "coverage_counts": {
                "system_profiles": counts.get("system_profiles", 0),
                "system_profiles_ok": counts.get("system_profiles_ok", 0),
            },
            "known": True,
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
            "notes": "Derived from CARTON mappings; coverage drives counts and layer presence and inherits canonical profile status.",
        },
        "operations": dict(sorted(operations.items(), key=lambda kv: kv[0])),
    }


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    index = build_index()
    OUT.write_text(json.dumps(index, indent=2))
    print(f"[+] wrote {OUT}")


if __name__ == "__main__":
    main()
