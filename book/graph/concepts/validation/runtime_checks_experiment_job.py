"""
Validation job for the runtime-checks experiment. Normalizes runtime_results.json
into shared IR and records status.
"""

from __future__ import annotations

import json
from pathlib import Path

from book.graph.concepts.validation import registry
from book.graph.concepts.validation.registry import ValidationJob

ROOT = Path(__file__).resolve().parents[4]
EXP_ROOT = ROOT / "book/experiments/runtime-checks/out"
RUNTIME_RESULTS = EXP_ROOT / "runtime_results.json"
EXPECTED_MATRIX = EXP_ROOT / "expected_matrix.json"
META_PATH = ROOT / "book/graph/concepts/validation/out/metadata.json"
STATUS_PATH = ROOT / "book/graph/concepts/validation/out/experiments/runtime-checks/status.json"
IR_PATH = ROOT / "book/graph/concepts/validation/out/experiments/runtime-checks/runtime_results.normalized.json"


def run_runtime_job():
    if not RUNTIME_RESULTS.exists():
        raise FileNotFoundError(f"missing required input: {RUNTIME_RESULTS}")

    results = json.loads(RUNTIME_RESULTS.read_text())
    meta = json.loads(META_PATH.read_text()) if META_PATH.exists() else {}
    expected_matrix = json.loads(EXPECTED_MATRIX.read_text()) if EXPECTED_MATRIX.exists() else {}

    STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    IR_PATH.write_text(json.dumps({"host": meta.get("os", {}), "results": results, "expected_matrix": expected_matrix}, indent=2))

    payload = {
        "job_id": "experiment:runtime-checks",
        "status": "ok",
        "host": meta.get("os", {}),
        "inputs": [str(RUNTIME_RESULTS)],
        "outputs": [str(IR_PATH)],
        "metrics": {"entries": len(results) if isinstance(results, list) else 1},
        "notes": "Normalized runtime_results into shared IR.",
        "tags": ["experiment:runtime-checks", "experiment", "runtime", "smoke"],
    }
    STATUS_PATH.write_text(json.dumps(payload, indent=2))
    return {
        "status": "ok",
        "outputs": [str(IR_PATH), str(STATUS_PATH)],
        "metrics": payload["metrics"],
        "host": payload["host"],
        "notes": payload["notes"],
    }


registry.register(
    ValidationJob(
        id="experiment:runtime-checks",
        inputs=[str(RUNTIME_RESULTS)],
        outputs=[str(IR_PATH), str(STATUS_PATH)],
        tags=["experiment:runtime-checks", "experiment", "runtime", "smoke", "golden"],
        description="Normalize runtime-checks experiment outputs into shared IR.",
        example_command="python -m book.graph.concepts.validation --experiment runtime-checks",
        runner=run_runtime_job,
    )
)
