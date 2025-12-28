#!/usr/bin/env python3
"""
Build a simple operation coverage mapping from CARTON.

Inputs (CARTON-exposed only):
- book/graph/mappings/vocab/ops.json
- book/graph/mappings/system_profiles/digests.json

Flow:
- Run the validation driver for smoke + system-profiles tags to refresh upstream IR/mappings.
- Require the underlying jobs to be ok in validation_status.json.
- Emit book/graph/mappings/carton/operation_coverage.json with host/provenance metadata.

All inputs are already CARTON-facing mappings; no experiment out/ blobs are read here so
agents can treat the emitted coverage JSON as stable API surface.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api import evidence_tiers  # noqa: E402
from book.api import world as world_mod  # noqa: E402

OPS_PATH = ROOT / "book/graph/mappings/vocab/ops.json"
DIGESTS_PATH = ROOT / "book/graph/mappings/system_profiles/digests.json"
CARTON_PATH = ROOT / "book/api/carton/CARTON.json"
STATUS_PATH = ROOT / "book/graph/concepts/validation/out/validation_status.json"
OUT_PATH = ROOT / "book/graph/mappings/carton/operation_coverage.json"
EXPECTED_JOBS = {
    "vocab:sonoma-14.4.1",
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
        if rec.get("status") != "ok":
            raise RuntimeError(f"job {job_id} not ok: {rec.get('status')}")


def load_json(path: Path) -> Dict:
    if not path.exists():
        raise FileNotFoundError(f"missing input: {path}")
    return json.loads(path.read_text())


def load_baseline_world() -> str:
    data, resolution = world_mod.load_world(repo_root=ROOT)
    return world_mod.require_world_id(data, world_path=resolution.entry.world_path)


def assert_world_compatible(baseline_world: str, other: dict | str | None, label: str) -> None:
    if not other:
        return
    other_world = other.get("world_id") if isinstance(other, dict) else other
    if other_world and other_world != baseline_world:
        raise RuntimeError(f"world_id mismatch for {label}: baseline {baseline_world} vs {other_world}")


def canonical_status(digests: Dict[str, Any]) -> Tuple[str, Dict[str, str]]:
    meta = digests.get("metadata") or {}
    profiles_meta = meta.get("canonical_profiles") or {}
    # Coverage inherits canonical health: if any canonical profile is degraded,
    # the aggregate coverage status drops so downstream callers cannot treat
    # coverage as “ok” while the bedrock profiles are drifting.
    per_profile = {pid: info.get("status", "unknown") for pid, info in profiles_meta.items()}
    status = meta.get("status") or "unknown"
    if status == "ok" and any(val != "ok" for val in per_profile.values()):
        status = "brittle"
    return status, per_profile


def init_coverage(ops: List[Dict]) -> Dict[str, Dict]:
    coverage: Dict[str, Dict] = {}
    for entry in ops:
        name = entry.get("name")
        if name is None:
            continue
        coverage[name] = {"op_id": entry.get("id"), "system_profiles": []}
    return coverage


def apply_system_profiles(coverage: Dict[str, Dict], digests: Dict, id_to_name: Dict[int, str]) -> None:
    profiles = digests.get("profiles") or {k: v for k, v in digests.items() if k != "metadata"}
    for profile, body in profiles.items():
        op_ids = set(body.get("op_table") or [])
        profile_status = body.get("status") or "unknown"
        for op_id in op_ids:
            name = id_to_name.get(op_id)
            if not name:
                continue
            bucket = coverage.setdefault(name, {"op_id": op_id, "system_profiles": [], "system_profile_status": {}})
            if profile not in bucket["system_profiles"]:
                bucket["system_profiles"].append(profile)
            bucket.setdefault("system_profile_status", {})[profile] = profile_status


def summarize(coverage: Dict[str, Dict]) -> Dict[str, object]:
    ops_with_profiles = sum(1 for entry in coverage.values() if entry.get("system_profiles"))
    zero_covered = sum(1 for entry in coverage.values() if not entry.get("system_profiles"))
    return {
        "ops_total": len(coverage),
        "ops_with_system_profiles": ops_with_profiles,
        "ops_with_no_coverage": zero_covered,
    }


def main() -> None:
    run_validation()
    status = load_status()
    require_jobs(status)

    def rel(path: Path) -> str:
        try:
            return str(path.relative_to(ROOT))
        except ValueError:
            return str(path)

    ops = load_json(OPS_PATH).get("ops") or []
    digests = load_json(DIGESTS_PATH)
    coverage = init_coverage(ops)
    id_to_name = {entry["id"]: entry["name"] for entry in ops if "id" in entry and "name" in entry}

    canonical_overall_status, canonical_per_profile = canonical_status(digests)
    apply_system_profiles(coverage, digests, id_to_name)

    for entry in coverage.values():
        entry["system_profiles"] = sorted(entry.get("system_profiles") or [])
        profile_status = entry.get("system_profile_status") or {}
        ok_profiles = [pid for pid in entry["system_profiles"] if profile_status.get(pid) == "ok"]
        entry["counts"] = {
            "system_profiles": len(entry["system_profiles"]),
            "system_profiles_ok": len(ok_profiles),
        }

    world_id = load_baseline_world()
    assert_world_compatible(world_id, digests.get("metadata"), "system_digests")
    inputs = [
        rel(OPS_PATH),
        rel(DIGESTS_PATH),
        rel(CARTON_PATH),
    ]
    # Downstream consumers see coverage status as a proxy for canonical health;
    # do not upgrade to ok if canonical profiles have been demoted.
    coverage_status = canonical_overall_status if canonical_overall_status != "ok" else "ok"
    summary = summarize(coverage)
    summary["canonical_profile_status"] = canonical_per_profile
    summary["canonical_overall_status"] = canonical_overall_status
    mapping = {
        "metadata": {
            "world_id": world_id,
            "inputs": inputs,
            "source_jobs": sorted(EXPECTED_JOBS),
            "status": coverage_status,
            "tier": evidence_tiers.evidence_tier_for_artifact(
                path=OUT_PATH,
                tier="mapped",
            ),
            "canonical_profile_status": canonical_per_profile,
            "notes": "Derived purely from CARTON mappings; locked to canonical system profile contract status.",
        },
        "coverage": dict(sorted(coverage.items(), key=lambda kv: kv[0])),
        "summary": summary,
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(mapping, indent=2))
    print(f"[+] wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
