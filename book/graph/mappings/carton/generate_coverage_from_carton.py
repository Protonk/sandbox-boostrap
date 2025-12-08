#!/usr/bin/env python3
"""
Build a simple operation coverage mapping from CARTON.

Inputs (CARTON-exposed only):
- book/graph/mappings/vocab/ops.json
- book/graph/mappings/system_profiles/digests.json
- book/graph/mappings/runtime/runtime_signatures.json

Flow:
- Run the validation driver for smoke + system-profiles tags to refresh upstream IR/mappings.
- Require the underlying jobs to be ok (or ok-unchanged/ok-changed) in validation_status.json.
- Emit book/graph/mappings/carton/operation_coverage.json with host/provenance metadata.

All inputs are already CARTON-facing mappings; no experiment out/ blobs are read here so
agents can treat the emitted coverage JSON as stable API surface.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

ROOT = Path(__file__).resolve().parents[4]
OPS_PATH = ROOT / "book/graph/mappings/vocab/ops.json"
DIGESTS_PATH = ROOT / "book/graph/mappings/system_profiles/digests.json"
RUNTIME_PATH = ROOT / "book/graph/mappings/runtime/runtime_signatures.json"
CARTON_PATH = ROOT / "book/api/carton/CARTON.json"
BASELINE_REF = "book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json"
BASELINE_PATH = ROOT / BASELINE_REF
STATUS_PATH = ROOT / "book/graph/concepts/validation/out/validation_status.json"
OUT_PATH = ROOT / "book/graph/mappings/carton/operation_coverage.json"
EXPECTED_JOBS = {
    "vocab:sonoma-14.4.1",
    "experiment:runtime-checks",
    "experiment:field2",
    "experiment:system-profile-digest",
}


def run_validation() -> None:
    cmd = [sys.executable, "-m", "book.graph.concepts.validation", "--tag", "smoke", "--tag", "system-profiles"]
    subprocess.check_call(cmd, cwd=ROOT)


def load_status() -> Dict[str, Dict]:
    if not STATUS_PATH.exists():
        raise FileNotFoundError(f"missing validation status: {STATUS_PATH}")
    data = json.loads(STATUS_PATH.read_text())
    return {rec.get("job_id") or rec.get("id"): rec for rec in data.get("jobs", [])}


def require_jobs(status: Dict[str, Dict]) -> None:
    for job_id in EXPECTED_JOBS:
        rec = status.get(job_id)
        if not rec:
            raise RuntimeError(f"job {job_id} missing from validation_status.json")
        if not str(rec.get("status", "")).startswith("ok"):
            raise RuntimeError(f"job {job_id} not ok: {rec.get('status')}")


def load_json(path: Path) -> Dict:
    if not path.exists():
        raise FileNotFoundError(f"missing input: {path}")
    return json.loads(path.read_text())


def load_baseline_world() -> str:
    if not BASELINE_PATH.exists():
        raise FileNotFoundError(f"missing baseline: {BASELINE_PATH}")
    data = json.loads(BASELINE_PATH.read_text())
    world_id = data.get("world_id")
    if not world_id:
        raise RuntimeError("world_id missing from baseline")
    return world_id


def assert_world_compatible(baseline_world: str, other: dict | str | None, label: str) -> None:
    if not other:
        return
    other_world = other.get("world_id") if isinstance(other, dict) else other
    if other_world and other_world != baseline_world:
        raise RuntimeError(f"world_id mismatch for {label}: baseline {baseline_world} vs {other_world}")


def init_coverage(ops: List[Dict]) -> Dict[str, Dict]:
    coverage: Dict[str, Dict] = {}
    for entry in ops:
        name = entry.get("name")
        if name is None:
            continue
        coverage[name] = {"op_id": entry.get("id"), "system_profiles": [], "runtime_signatures": []}
    return coverage


def apply_system_profiles(coverage: Dict[str, Dict], digests: Dict, id_to_name: Dict[int, str]) -> None:
    profiles = digests.get("profiles") or {k: v for k, v in digests.items() if k != "metadata"}
    for profile, body in profiles.items():
        op_ids = set(body.get("op_table") or [])
        for op_id in op_ids:
            name = id_to_name.get(op_id)
            if not name:
                continue
            bucket = coverage.setdefault(name, {"op_id": op_id, "system_profiles": [], "runtime_signatures": []})
            if profile not in bucket["system_profiles"]:
                bucket["system_profiles"].append(profile)


def apply_runtime(
    coverage: Dict[str, Dict], runtime_mapping: Dict, name_to_id: Dict[str, int]
) -> Tuple[Set[str], Set[str]]:
    # Runtime mapping is already normalized IR; collect which signatures touch which ops.
    unknown_ops: Set[str] = set()
    signatures_seen: Set[str] = set()
    profiles = (runtime_mapping.get("expected_matrix") or {}).get("profiles") or {}
    for sig_id, entry in profiles.items():
        probes = entry.get("probes") or []
        for probe in probes:
            op_name = probe.get("operation")
            if not op_name:
                continue
            op_id = name_to_id.get(op_name)
            if op_id is None:
                unknown_ops.add(op_name)
                continue
            bucket = coverage.setdefault(op_name, {"op_id": op_id, "system_profiles": [], "runtime_signatures": []})
            if sig_id not in bucket["runtime_signatures"]:
                bucket["runtime_signatures"].append(sig_id)
                signatures_seen.add(sig_id)
    return unknown_ops, signatures_seen


def summarize(coverage: Dict[str, Dict], unknown_ops: Set[str]) -> Dict[str, object]:
    ops_with_profiles = sum(1 for entry in coverage.values() if entry.get("system_profiles"))
    ops_with_runtime = sum(1 for entry in coverage.values() if entry.get("runtime_signatures"))
    zero_covered = sum(
        1
        for entry in coverage.values()
        if not entry.get("system_profiles") and not entry.get("runtime_signatures")
    )
    return {
        "ops_total": len(coverage),
        "ops_with_system_profiles": ops_with_profiles,
        "ops_with_runtime_signatures": ops_with_runtime,
        "ops_with_no_coverage": zero_covered,
        "unknown_runtime_ops": sorted(unknown_ops),
    }


def main() -> None:
    run_validation()
    status = load_status()
    require_jobs(status)

    ops = load_json(OPS_PATH).get("ops") or []
    digests = load_json(DIGESTS_PATH)
    runtime_mapping = load_json(RUNTIME_PATH)
    coverage = init_coverage(ops)
    id_to_name = {entry["id"]: entry["name"] for entry in ops if "id" in entry and "name" in entry}
    name_to_id = {entry["name"]: entry["id"] for entry in ops if "id" in entry and "name" in entry}

    apply_system_profiles(coverage, digests, id_to_name)
    unknown_ops, signatures_seen = apply_runtime(coverage, runtime_mapping, name_to_id)

    for entry in coverage.values():
        entry["system_profiles"] = sorted(entry.get("system_profiles") or [])
        entry["runtime_signatures"] = sorted(entry.get("runtime_signatures") or [])
        entry["counts"] = {
            "system_profiles": len(entry["system_profiles"]),
            "runtime_signatures": len(entry["runtime_signatures"]),
        }

    world_id = load_baseline_world()
    assert_world_compatible(world_id, runtime_mapping.get("metadata"), "runtime_signatures")
    assert_world_compatible(world_id, digests.get("metadata"), "system_digests")
    inputs = [
        str(OPS_PATH.relative_to(ROOT)),
        str(DIGESTS_PATH.relative_to(ROOT)),
        str(RUNTIME_PATH.relative_to(ROOT)),
        str(CARTON_PATH.relative_to(ROOT)),
    ]
    mapping = {
        "metadata": {
            "world_id": world_id,
            "inputs": inputs,
            "source_jobs": sorted(EXPECTED_JOBS),
            "status": "ok",
            "notes": "Derived purely from CARTON mappings; no experiment out/ is read here.",
        },
        "coverage": dict(sorted(coverage.items(), key=lambda kv: kv[0])),
        "summary": summarize(coverage, unknown_ops),
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(mapping, indent=2))
    print(f"[+] wrote {OUT_PATH} (runtime signatures seen: {len(signatures_seen)})")


if __name__ == "__main__":
    main()
