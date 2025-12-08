#!/usr/bin/env python3
"""
Generate operation_index.json from CARTON mappings.

Inputs (all from CARTON):
- vocab/ops.json
- system_profiles/digests.json
- runtime/runtime_signatures.json
- carton/operation_coverage.json
- carton/CARTON.json (for host, optional)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parents[4]
VOCAB = ROOT / "book/graph/mappings/vocab/ops.json"
DIGESTS = ROOT / "book/graph/mappings/system_profiles/digests.json"
COVERAGE = ROOT / "book/graph/mappings/carton/operation_coverage.json"
BASELINE_REF = "book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json"
BASELINE = ROOT / BASELINE_REF
OUT = ROOT / "book/graph/mappings/carton/operation_index.json"


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
    vocab = load_json(VOCAB)
    coverage = load_json(COVERAGE)
    ops = vocab.get("ops") or []
    coverage_map: Dict[str, dict] = (coverage.get("coverage") or {})
    baseline = baseline_ref()
    world_id = baseline["world_id"]
    assert_world_compatible(world_id, coverage.get("metadata"), "coverage")
    source_jobs: List[str] = []
    inputs: List[str] = [
        "book/graph/mappings/vocab/ops.json",
        "book/graph/mappings/system_profiles/digests.json",
        "book/graph/mappings/runtime/runtime_signatures.json",
        "book/graph/mappings/carton/operation_coverage.json",
        "book/api/carton/CARTON.json",
    ]
    meta = coverage.get("metadata") or {}
    source_jobs = meta.get("source_jobs") or source_jobs

    operations: Dict[str, dict] = {}
    for entry in ops:
        name = entry.get("name")
        op_id = entry.get("id")
        if name is None or op_id is None:
            raise ValueError("vocab entry missing name or id")
        cov = coverage_map.get(name) or {}
        counts = cov.get("counts") or {}
        system_profiles = cov.get("system_profiles") or []
        runtime_sigs = cov.get("runtime_signatures") or []
        profile_layers = ["system"] if system_profiles else []
        operations[name] = {
            "name": name,
            "id": op_id,
            "profile_layers": profile_layers,
            "system_profiles": system_profiles,
            "runtime_signatures": runtime_sigs,
            "coverage_counts": {
                "system_profiles": counts.get("system_profiles", 0),
                "runtime_signatures": counts.get("runtime_signatures", 0),
            },
            "known": True,
        }

    return {
        "metadata": {
            "world_id": world_id,
            "inputs": inputs,
            "source_jobs": source_jobs,
            "status": "ok",
            "notes": "Derived from CARTON mappings; coverage drives counts and layer presence.",
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
