#!/usr/bin/env python3
"""
Regenerate system profile digests mapping from validation IR only.

Inputs:
- book/graph/concepts/validation/out/experiments/system-profile-digest/digests_ir.json

Flow:
- Run validation driver with tag `system-profiles` (and smoke for dependencies).
- Require job experiment:system-profile-digest to be ok.
- Write book/graph/mappings/system_profiles/digests.json with host metadata and source_jobs.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, Any

ROOT = Path(__file__).resolve().parents[4]
IR_PATH = ROOT / "book" / "graph" / "concepts" / "validation" / "out" / "experiments" / "system-profile-digest" / "digests_ir.json"
STATUS_PATH = ROOT / "book" / "graph" / "concepts" / "validation" / "out" / "validation_status.json"
OUT_PATH = ROOT / "book" / "graph" / "mappings" / "system_profiles" / "digests.json"
BASELINE_REF = "book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json"
BASELINE_PATH = ROOT / BASELINE_REF
EXPECTED_JOB = "experiment:system-profile-digest"


def run_validation():
    cmd = [sys.executable, "-m", "book.graph.concepts.validation", "--tag", "system-profiles"]
    subprocess.check_call(cmd, cwd=ROOT)


def load_status(job_id: str) -> Dict[str, Any]:
    status = json.loads(STATUS_PATH.read_text())
    jobs = {j.get("job_id") or j.get("id"): j for j in status.get("jobs", [])}
    job = jobs.get(job_id)
    if not job:
        raise RuntimeError(f"job {job_id} missing from validation_status.json")
    if job.get("status") != "ok":
        raise RuntimeError(f"job {job_id} not ok: {job.get('status')}")
    return job


def load_ir(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"missing IR: {path}")
    return json.loads(path.read_text())


def load_baseline_world() -> str:
    if not BASELINE_PATH.exists():
        raise FileNotFoundError(f"missing baseline: {BASELINE_PATH}")
    data = json.loads(BASELINE_PATH.read_text())
    world_id = data.get("world_id")
    if not world_id:
        raise RuntimeError("world_id missing from baseline")
    return world_id


def main() -> None:
    run_validation()
    job = load_status(EXPECTED_JOB)
    ir = load_ir(IR_PATH)
    world_id = load_baseline_world()

    profiles = ir.get("profiles") or {}
    mapping = {
        "metadata": {
            "world_id": world_id,
            "inputs": [str(IR_PATH.relative_to(ROOT))],
            "source_jobs": ir.get("source_jobs") or [EXPECTED_JOB],
            "decoder": "book.api.decoder",
        },
    }
    mapping.update({k: v for k, v in profiles.items()})
    OUT_PATH.write_text(json.dumps(mapping, indent=2))
    print(f"[+] wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
