"""
Validation job for the metadata-runner experiment.

Normalizes the experiment's bespoke runtime_results.json into contract-shaped
RuntimeObservation rows, written as a standalone JSON array under validation/out.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional

from book.api.path_utils import find_repo_root, to_repo_relative
from book.api.runtime_tools.core import normalize as runtime_normalize
from book.graph.concepts.validation import registry
from book.graph.concepts.validation.registry import ValidationJob

ROOT = find_repo_root(Path(__file__))
EXP_ROOT = ROOT / "book/experiments/metadata-runner/out"
RUNTIME_RESULTS = EXP_ROOT / "runtime_results.json"
RUNNER_BIN = ROOT / "book/experiments/metadata-runner/build/metadata_runner"
META_PATH = ROOT / "book/graph/concepts/validation/out/metadata.json"
STATUS_PATH = ROOT / "book/graph/concepts/validation/out/experiments/metadata-runner/status.json"
IR_PATH = ROOT / "book/graph/concepts/validation/out/experiments/metadata-runner/runtime_events.normalized.json"


def rel(path: Path) -> str:
    return to_repo_relative(path, ROOT)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _build_runner_info() -> Optional[Dict[str, Any]]:
    if not RUNNER_BIN.exists():
        return None
    digest = _sha256(RUNNER_BIN)
    return {
        "entrypoint": "metadata_runner",
        "apply_model": "self_apply",
        "apply_timing": "pre_syscall",
        "entrypoint_path": rel(RUNNER_BIN),
        "entrypoint_sha256": digest,
        "tool_build_id": digest,
    }


def run_metadata_runner_job():
    if not RUNTIME_RESULTS.exists():
        raise FileNotFoundError(f"missing required input: {RUNTIME_RESULTS}")

    results_doc = json.loads(RUNTIME_RESULTS.read_text())
    meta = json.loads(META_PATH.read_text()) if META_PATH.exists() else {}

    runner_info = None
    if isinstance(results_doc.get("runner_info"), dict):
        runner_info = results_doc.get("runner_info")
    else:
        runner_info = _build_runner_info()

    observations = runtime_normalize.normalize_metadata_results(results_doc, runner_info=runner_info)
    IR_PATH.parent.mkdir(parents=True, exist_ok=True)
    IR_PATH.write_text(
        json.dumps([runtime_normalize.observation_to_dict(o) for o in observations], indent=2, sort_keys=True)
    )

    STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "job_id": "experiment:metadata-runner",
        "status": "ok",
        "tier": "mapped",
        "host": meta.get("os", {}),
        "inputs": [rel(RUNTIME_RESULTS)],
        "outputs": [rel(IR_PATH)],
        "metrics": {"events": len(observations)},
        "notes": "Normalized metadata-runner runtime_results into contract-shaped runtime events for this world.",
        "tags": ["experiment:metadata-runner", "experiment", "runtime"],
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
        id="experiment:metadata-runner",
        inputs=[rel(RUNTIME_RESULTS)],
        outputs=[rel(IR_PATH), rel(STATUS_PATH)],
        tags=["experiment:metadata-runner", "experiment", "runtime"],
        description="Normalize metadata-runner experiment outputs into shared runtime IR.",
        example_command="python -m book.graph.concepts.validation --experiment metadata-runner",
        runner=run_metadata_runner_job,
    )
)
