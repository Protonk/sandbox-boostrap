#!/usr/bin/env python3
"""
Generate runtime_signatures.json from validation IR only.

Inputs (IR produced by the validation driver):
- book/graph/concepts/validation/out/experiments/runtime-checks/runtime_results.normalized.json
- book/graph/concepts/validation/out/experiments/field2/field2_ir.json

Flow:
- Run the validation driver with the smoke tag (vocab + field2 + runtime-checks).
- Require those jobs to be status=ok in validation_status.json.
- Read normalized IR and emit a small mapping in book/graph/mappings/runtime/runtime_signatures.json.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, Any

ROOT = Path(__file__).resolve().parents[4]
RUNTIME_IR = ROOT / "book/graph/concepts/validation/out/experiments/runtime-checks/runtime_results.normalized.json"
FIELD2_IR = ROOT / "book/graph/concepts/validation/out/experiments/field2/field2_ir.json"
STATUS_PATH = ROOT / "book/graph/concepts/validation/out/validation_status.json"
OUT_PATH = ROOT / "book/graph/mappings/runtime/runtime_signatures.json"
BASELINE_REF = "book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json"
BASELINE_PATH = ROOT / BASELINE_REF
EXPECTED_JOBS = {"experiment:runtime-checks", "experiment:field2"}


def run_smoke_validation():
    cmd = [sys.executable, "-m", "book.graph.concepts.validation", "--tag", "smoke"]
    subprocess.check_call(cmd, cwd=ROOT)


def load_status(job_id: str) -> Dict[str, Any]:
    if not STATUS_PATH.exists():
        raise FileNotFoundError(f"missing validation status: {STATUS_PATH}")
    status = json.loads(STATUS_PATH.read_text())
    jobs = {j.get("job_id") or j.get("id"): j for j in status.get("jobs", [])}
    job = jobs.get(job_id)
    if not job:
        raise RuntimeError(f"job {job_id} missing from validation_status.json")
    if not str(job.get("status", "")).startswith("ok"):
        raise RuntimeError(f"job {job_id} not ok: {job.get('status')}")
    return job


def load_json(path: Path) -> Dict[str, Any]:
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


def build_signatures(runtime_ir: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
    signatures: Dict[str, Dict[str, str]] = {}
    profile_meta: Dict[str, Dict[str, str]] = {}
    results = runtime_ir.get("results") or {}
    for profile, entry in results.items():
        probes = entry.get("probes") or []
        signatures[profile] = {probe["name"]: probe.get("actual") for probe in probes if "name" in probe}
        # Capture runtime profile path from command (second argv if present)
        if probes:
            cmd = probes[0].get("command") or []
            if len(cmd) >= 2:
                profile_meta[profile] = {"runtime_profile": cmd[1]}
    return signatures, profile_meta


def summarize_field2(field2_ir: Dict[str, Any]) -> Dict[str, Any]:
    profiles = field2_ir.get("profiles") or {}
    summary = {}
    for name, entry in profiles.items():
        vals = entry.get("field2") or []
        summary[name] = {
            "field2_entries": len(vals),
            "unknown_named": sum(1 for v in vals if v.get("name") is None),
        }
    unknown_nodes = field2_ir.get("unknown_nodes", {})
    return {"profiles": summary, "unknown_nodes": unknown_nodes}


def main() -> None:
    run_smoke_validation()
    for job_id in EXPECTED_JOBS:
        load_status(job_id)

    runtime_ir = load_json(RUNTIME_IR)
    field2_ir = load_json(FIELD2_IR)
    world_id = load_baseline_world()

    signatures, profiles_meta = build_signatures(runtime_ir)
    field2_summary = summarize_field2(field2_ir)

    mapping = {
        "metadata": {
            "world_id": world_id,
            "inputs": [
                str(RUNTIME_IR.relative_to(ROOT)),
                str(FIELD2_IR.relative_to(ROOT)),
            ],
            "source_jobs": list(EXPECTED_JOBS),
            "status": "ok",
            "notes": "Derived from validation IR (smoke tag).",
        },
        "signatures": signatures,
        "expected_matrix": runtime_ir.get("expected_matrix"),
        "field2_summary": field2_summary,
        "profiles_metadata": profiles_meta,
    }
    OUT_PATH.write_text(json.dumps(mapping, indent=2, sort_keys=True))
    print(f"[+] wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
