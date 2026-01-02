"""
Validation job for sandbox-init-params: asserts canonical runs for this world_id
still produce the expected blob length/sha256 and call_code, and that required
run records are present.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Any, List

from book.api.path_utils import find_repo_root, to_repo_relative
from book.graph.concepts.validation import registry
from book.graph.concepts.validation.registry import ValidationJob

ROOT = find_repo_root(Path(__file__))
WORLD_ID = "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5"
SUMMARY_PATH = ROOT / "book/evidence/experiments/profile-pipeline/sandbox-init-params/out/validation_summary.json"
STATUS_PATH = ROOT / "book/evidence/graph/concepts/validation/out/experiments/sandbox-init-params/status.json"
META_PATH = ROOT / "book/evidence/graph/concepts/validation/out/metadata.json"

EXPECTED_RUNS = {
    "init_params_probe": {
        "call_code": 0,
        "blob_len": 416,
        "blob_sha256": "19832eb9716a32459bee8398c8977fd1dfd575fa26606928f95728462a833c92",
    },
    "init_params_probe_container": {
        "call_code": 0,
        "blob_len": 416,
        "blob_sha256": "19832eb9716a32459bee8398c8977fd1dfd575fa26606928f95728462a833c92",
    },
}


def load_summary() -> Dict[str, Any]:
    if not SUMMARY_PATH.exists():
        raise FileNotFoundError(f"missing required input: {SUMMARY_PATH}")
    return json.loads(SUMMARY_PATH.read_text())


def rel(path: Path) -> str:
    return to_repo_relative(path, ROOT)


def run_sandbox_init_params_job() -> Dict[str, Any]:
    summary = load_summary()
    host = {}
    if META_PATH.exists():
        try:
            host = json.loads(META_PATH.read_text()).get("os", {})
        except Exception:
            host = {}
    mismatches: List[str] = []

    if summary.get("world_id") != WORLD_ID:
        mismatches.append(f"world_id mismatch (expected {WORLD_ID}, got {summary.get('world_id')})")

    runs = {r.get("run_id"): r for r in summary.get("runs", [])}
    for run_id, expectations in EXPECTED_RUNS.items():
        if run_id not in runs:
            mismatches.append(f"missing run {run_id}")
            continue
        run = runs[run_id]
        if run.get("world_id") != WORLD_ID:
            mismatches.append(f"{run_id}: world_id mismatch ({run.get('world_id')})")
        if run.get("call_code") != expectations["call_code"]:
            mismatches.append(f"{run_id}: call_code {run.get('call_code')} != {expectations['call_code']}")
        if run.get("blob_len") != expectations["blob_len"]:
            mismatches.append(f"{run_id}: blob_len {run.get('blob_len')} != {expectations['blob_len']}")
        if run.get("blob_sha256") != expectations["blob_sha256"]:
            mismatches.append(f"{run_id}: blob_sha256 {run.get('blob_sha256')} != {expectations['blob_sha256']}")
        if not run.get("pointer_nonzero", False):
            mismatches.append(f"{run_id}: pointer_nonzero is false")

    status = "ok" if not mismatches else "brittle"
    payload = {
        "job_id": "experiment:sandbox-init-params",
        "status": status,
        "tier": "mapped",
        "host": host,
        "world_id": WORLD_ID,
        "inputs": [rel(SUMMARY_PATH)],
        "outputs": [rel(STATUS_PATH)],
        "tags": ["experiment:sandbox-init-params", "experiment", "static-format"],
        "metrics": {"runs_checked": len(EXPECTED_RUNS), "mismatches": len(mismatches)},
        "mismatches": mismatches,
    }
    STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATUS_PATH.write_text(json.dumps(payload, indent=2))
    return payload


registry.register(
    ValidationJob(
        id="experiment:sandbox-init-params",
        inputs=[rel(SUMMARY_PATH)],
        outputs=[rel(STATUS_PATH)],
        tags=["experiment:sandbox-init-params", "experiment", "static-format"],
        description="Guardrail for sandbox-init-params: asserts canonical runs match expected blob len/sha for this world_id.",
        example_command="python -m book.graph.concepts.validation --experiment sandbox-init-params",
        runner=run_sandbox_init_params_job,
    )
)
