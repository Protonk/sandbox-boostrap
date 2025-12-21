"""
Validation job for the runtime-checks experiment. Normalizes runtime_results.json
into shared IR and records status.
"""

from __future__ import annotations

import json
from pathlib import Path

from book.api.path_utils import find_repo_root, to_repo_relative
from book.api.runtime_tools import observations as runtime_observations
from book.graph.concepts.validation import registry
from book.graph.concepts.validation.registry import ValidationJob

ROOT = find_repo_root(Path(__file__))
EXP_ROOT = ROOT / "book/experiments/runtime-checks/out"
RUNTIME_RESULTS = EXP_ROOT / "runtime_results.json"
EXPECTED_MATRIX = EXP_ROOT / "expected_matrix.json"
META_PATH = ROOT / "book/graph/concepts/validation/out/metadata.json"
STATUS_PATH = ROOT / "book/graph/concepts/validation/out/experiments/runtime-checks/status.json"
IR_PATH = ROOT / "book/graph/concepts/validation/out/experiments/runtime-checks/runtime_results.normalized.json"


def rel(path: Path) -> str:
    return to_repo_relative(path, ROOT)


def run_runtime_job():
    if not RUNTIME_RESULTS.exists():
        raise FileNotFoundError(f"missing required input: {RUNTIME_RESULTS}")

    results = json.loads(RUNTIME_RESULTS.read_text())
    meta = json.loads(META_PATH.read_text()) if META_PATH.exists() else {}
    expected_matrix = json.loads(EXPECTED_MATRIX.read_text()) if EXPECTED_MATRIX.exists() else {}

    STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    observations = runtime_observations.normalize_runtime_results(expected_matrix, results)
    IR_PATH.write_text(
        json.dumps(
            {
                "world_id": expected_matrix.get("world_id") or runtime_observations.WORLD_ID,
                "host": meta.get("os", {}),
                "expected_matrix": expected_matrix,
                "raw_results": results,
                "events": [runtime_observations.serialize_observation(o) for o in observations],
            },
            indent=2,
            sort_keys=True,
        )
    )

    payload = {
        "job_id": "experiment:runtime-checks",
        "status": "ok",
        "host": meta.get("os", {}),
        "inputs": [rel(RUNTIME_RESULTS)],
        "outputs": [rel(IR_PATH)],
        "metrics": {"events": len(observations)},
        "notes": "Normalized runtime_results into contract-shaped runtime events for this world.",
        "tags": ["experiment:runtime-checks", "experiment", "runtime", "smoke"],
    }
    STATUS_PATH.write_text(json.dumps(payload, indent=2))
    return {
        "status": "ok",
        "inputs": payload["inputs"],
        "outputs": [rel(IR_PATH), rel(STATUS_PATH)],
        "metrics": payload["metrics"],
        "host": payload["host"],
        "notes": payload["notes"],
    }


registry.register(
    ValidationJob(
        id="experiment:runtime-checks",
        inputs=[rel(RUNTIME_RESULTS)],
        outputs=[rel(IR_PATH), rel(STATUS_PATH)],
        tags=["experiment:runtime-checks", "experiment", "runtime", "smoke", "golden"],
        description="Normalize runtime-checks experiment outputs into shared IR.",
        example_command="python -m book.graph.concepts.validation --experiment runtime-checks",
        runner=run_runtime_job,
    )
)
