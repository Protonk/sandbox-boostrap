"""
Validation job for the runtime-checks experiment. Normalizes runtime_results.json
into shared IR and records status.
"""

from __future__ import annotations

import json
from pathlib import Path

from book.api.path_utils import find_repo_root, to_repo_relative
from book.api.runtime.bundles import reader as bundle_reader
from book.api.runtime.contracts import normalize as runtime_normalize
from book.api.runtime.contracts import models as runtime_models
from book.graph.concepts.validation import registry
from book.graph.concepts.validation.registry import ValidationJob

ROOT = find_repo_root(Path(__file__))
BUNDLE_ROOT = ROOT / "book/experiments/runtime-final-final/suites/runtime-checks/out"
META_PATH = ROOT / "book/graph/concepts/validation/out/metadata.json"
STATUS_PATH = ROOT / "book/graph/concepts/validation/out/experiments/runtime-checks/status.json"
IR_PATH = ROOT / "book/graph/concepts/validation/out/experiments/runtime-checks/runtime_results.normalized.json"


def rel(path: Path) -> str:
    return to_repo_relative(path, ROOT)

def _load_bundle() -> tuple[dict, Path, str | None]:
    index = bundle_reader.load_bundle_index_strict(BUNDLE_ROOT, repo_root=ROOT)
    bundle_dir, run_id = bundle_reader.resolve_bundle_dir(BUNDLE_ROOT, repo_root=ROOT)
    return index, bundle_dir, run_id

def run_runtime_job():
    _index, bundle_dir, _run_id = _load_bundle()
    runtime_results_path = bundle_dir / "runtime_results.json"
    expected_matrix_path = bundle_dir / "expected_matrix.json"
    if not runtime_results_path.exists():
        raise FileNotFoundError(f"missing required input: {runtime_results_path}")

    results = json.loads(runtime_results_path.read_text())
    meta = json.loads(META_PATH.read_text()) if META_PATH.exists() else {}
    expected_matrix = json.loads(expected_matrix_path.read_text()) if expected_matrix_path.exists() else {}

    STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    observations = runtime_normalize.normalize_matrix(expected_matrix, results)
    IR_PATH.write_text(
        json.dumps(
            {
                "world_id": expected_matrix.get("world_id") or runtime_models.WORLD_ID,
                "host": meta.get("os", {}),
                "expected_matrix": expected_matrix,
                "raw_results": results,
                "events": [runtime_normalize.observation_to_dict(o) for o in observations],
            },
            indent=2,
            sort_keys=True,
        )
    )

    payload = {
        "job_id": "experiment:runtime-checks",
        "status": "ok",
        "tier": "mapped",
        "host": meta.get("os", {}),
        "inputs": [rel(bundle_dir / "artifact_index.json"), rel(runtime_results_path)],
        "outputs": [rel(IR_PATH)],
        "metrics": {"events": len(observations)},
        "notes": "Normalized runtime_results into contract-shaped runtime events for this world.",
        "tags": ["experiment:runtime-checks", "experiment", "runtime", "smoke"],
    }
    STATUS_PATH.write_text(json.dumps(payload, indent=2))
    return {
        "status": "ok",
        "tier": "mapped",
        "inputs": payload["inputs"],
        "outputs": [rel(IR_PATH), rel(STATUS_PATH)],
        "metrics": payload["metrics"],
        "host": payload["host"],
        "notes": payload["notes"],
    }


registry.register(
    ValidationJob(
        id="experiment:runtime-checks",
        inputs=["book/experiments/runtime-final-final/suites/runtime-checks/out/*/artifact_index.json"],
        outputs=[rel(IR_PATH), rel(STATUS_PATH)],
        tags=["experiment:runtime-checks", "experiment", "runtime", "smoke", "golden"],
        description="Normalize runtime-checks experiment outputs into shared IR.",
        example_command="python -m book.graph.concepts.validation --experiment runtime-checks",
        runner=run_runtime_job,
    )
)
