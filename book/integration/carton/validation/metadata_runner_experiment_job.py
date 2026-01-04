"""
Validation job for the metadata-runner experiment.

Copies committed runtime bundle outputs into validation IR.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from book.api.path_utils import find_repo_root, to_repo_relative
from book.api.runtime.bundles import reader as bundle_reader
from book.integration.carton.validation import registry
from book.integration.carton.validation.registry import ValidationJob

ROOT = find_repo_root(Path(__file__))
BUNDLE_ROOT = ROOT / "book/evidence/experiments/runtime-final-final/suites/metadata-runner/out"
META_PATH = ROOT / "book/evidence/syncretic/validation/out/metadata.json"
STATUS_PATH = ROOT / "book/evidence/syncretic/validation/out/experiments/metadata-runner/status.json"
IR_PATH = ROOT / "book/evidence/syncretic/validation/out/experiments/metadata-runner/runtime_events.normalized.json"


def rel(path: Path) -> str:
    return to_repo_relative(path, ROOT)


def _load_bundle() -> tuple[Dict[str, Any], Path, Optional[str]]:
    index = bundle_reader.load_bundle_index_strict(BUNDLE_ROOT, repo_root=ROOT)
    bundle_dir, run_id = bundle_reader.resolve_bundle_dir(BUNDLE_ROOT, repo_root=ROOT)
    return index, bundle_dir, run_id


def run_metadata_runner_job():
    _index, bundle_dir, _run_id = _load_bundle()
    events_path = bundle_dir / "runtime_events.normalized.json"
    if not events_path.exists():
        raise FileNotFoundError(f"missing required input: {events_path}")

    events = json.loads(events_path.read_text())
    if not isinstance(events, list):
        raise AssertionError("runtime_events.normalized.json must be a list")

    IR_PATH.parent.mkdir(parents=True, exist_ok=True)
    IR_PATH.write_text(json.dumps(events, indent=2, sort_keys=True))

    meta = json.loads(META_PATH.read_text()) if META_PATH.exists() else {}
    STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "job_id": "experiment:metadata-runner",
        "status": "ok",
        "host": meta.get("os", {}),
        "inputs": [rel(bundle_dir / "artifact_index.json"), rel(events_path)],
        "outputs": [rel(IR_PATH)],
        "metrics": {"events": len(events)},
        "notes": "Copied committed metadata-runner runtime events into validation IR.",
        "tags": ["experiment:metadata-runner", "experiment", "runtime"],
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
        id="experiment:metadata-runner",
        inputs=["book/evidence/experiments/runtime-final-final/suites/metadata-runner/out/*/artifact_index.json"],
        outputs=[rel(IR_PATH), rel(STATUS_PATH)],
        tags=["experiment:metadata-runner", "experiment", "runtime"],
        description="Copy metadata-runner runtime bundle outputs into shared runtime IR.",
        example_command="python -m book.integration.carton validate --experiment metadata-runner",
        runner=run_metadata_runner_job,
    )
)
