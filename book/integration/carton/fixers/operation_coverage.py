#!/usr/bin/env python3
"""
Build operation coverage relationships from CARTON inputs.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

from book.integration.carton.fixers import common

ROOT = common.repo_root()
OPS_PATH = ROOT / "book/integration/carton/bundle/relationships/mappings/vocab/ops.json"
DIGESTS_PATH = ROOT / "book/integration/carton/bundle/relationships/mappings/system_profiles/digests.json"
MANIFEST_PATH = ROOT / "book/integration/carton/bundle/CARTON.json"
STATUS_PATH = ROOT / "book/evidence/syncretic/validation/out/validation_status.json"
OUT_PATH = ROOT / "book/integration/carton/bundle/relationships/operation_coverage.json"
EXPECTED_JOBS = {
    "vocab:sonoma-14.4.1",
    "experiment:system-profile-digest",
}


def run_validation() -> None:
    cmd = [
        sys.executable,
        "-m",
        "book.integration.carton",
        "validate",
        "--tag",
        "smoke",
        "--tag",
        "system-profiles",
    ]
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


def canonical_status(digests: Dict[str, Any]) -> Tuple[str, Dict[str, str]]:
    meta = digests.get("metadata") or {}
    profiles_meta = meta.get("canonical_profiles") or {}
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


def build() -> Dict[str, Any]:
    run_validation()
    status = load_status()
    require_jobs(status)

    ops = common.load_json(OPS_PATH).get("ops") or []
    digests = common.load_json(DIGESTS_PATH)
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

    world_id = common.baseline_world_id(repo_root_path=ROOT)
    common.assert_world_compatible(world_id, digests.get("metadata"), "system_digests")
    inputs = [
        common.repo_relative(OPS_PATH, repo_root_path=ROOT),
        common.repo_relative(DIGESTS_PATH, repo_root_path=ROOT),
        common.repo_relative(MANIFEST_PATH, repo_root_path=ROOT),
    ]
    coverage_status = canonical_overall_status if canonical_overall_status != "ok" else "ok"
    summary = summarize(coverage)
    summary["canonical_profile_status"] = canonical_per_profile
    summary["canonical_overall_status"] = canonical_overall_status

    return {
        "metadata": {
            "world_id": world_id,
            "inputs": inputs,
            "source_jobs": sorted(EXPECTED_JOBS),
            "status": coverage_status,
            "canonical_profile_status": canonical_per_profile,
            "notes": "Derived purely from CARTON mappings; locked to canonical system profile contract status.",
        },
        "coverage": dict(sorted(coverage.items(), key=lambda kv: kv[0])),
        "summary": summary,
    }


def run() -> None:
    doc = build()
    common.write_json(OUT_PATH, doc)
    print(f"[+] wrote {OUT_PATH}")


if __name__ == "__main__":
    run()
