#!/usr/bin/env python3
"""
Generate profile_layer_index.json from CARTON mappings.

Inputs (all from CARTON):
- system_profiles/digests.json
- vocab/ops.json
- carton/operation_coverage.json (runtime signatures per op)
- carton/CARTON.json (for host, optional)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parents[4]
DIGESTS = ROOT / "book/graph/mappings/system_profiles/digests.json"
VOCAB = ROOT / "book/graph/mappings/vocab/ops.json"
COVERAGE = ROOT / "book/graph/mappings/carton/operation_coverage.json"
BASELINE_REF = "book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json"
BASELINE = ROOT / BASELINE_REF
OUT = ROOT / "book/graph/mappings/carton/profile_layer_index.json"


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
        runtime_sigs = set()
        for name in op_names:
            cov = coverage_map.get(name) or {}
            for sig in cov.get("runtime_signatures") or []:
                runtime_sigs.add(sig)
        profiles[profile_id] = {
            "id": profile_id,
            "layer": "system",
            "ops": ops_list,
            "runtime_signatures": sorted(runtime_sigs),
        }

    return {
        "metadata": {
            "world_id": world_id,
            "inputs": inputs,
            "source_jobs": source_jobs,
            "status": "ok",
            "notes": "Derived from CARTON system digests and coverage; runtime signatures are linked via coverage entries.",
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
