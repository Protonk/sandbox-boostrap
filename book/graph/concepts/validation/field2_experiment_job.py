"""
Validation job for the field2-filters experiment. Normalizes experiment outputs
and records status in the shared validation status log.
"""

from __future__ import annotations

import json
from pathlib import Path

from book.api.path_utils import find_repo_root, to_repo_relative
from book.graph.concepts.validation import registry
from book.graph.concepts.validation.registry import ValidationJob

ROOT = find_repo_root(Path(__file__))
FIELD2_INV = ROOT / "book/experiments/field2-filters/out/field2_inventory.json"
UNKNOWN_NODES = ROOT / "book/experiments/field2-filters/out/unknown_nodes.json"
META_PATH = ROOT / "book/graph/concepts/validation/out/metadata.json"
STATUS_PATH = ROOT / "book/graph/concepts/validation/out/experiments/field2/status.json"
IR_PATH = ROOT / "book/graph/concepts/validation/out/experiments/field2/field2_ir.json"


def rel(path: Path) -> str:
    return to_repo_relative(path, ROOT)


def run_field2_job():
    for required in [FIELD2_INV]:
        if not required.exists():
            raise FileNotFoundError(f"missing required input: {required}")

    inv = json.loads(FIELD2_INV.read_text())
    unknown = json.loads(UNKNOWN_NODES.read_text()) if UNKNOWN_NODES.exists() else {}
    meta = json.loads(META_PATH.read_text()) if META_PATH.exists() else {}

    profile_count = len(inv.keys())
    unknown_count = len(unknown.get("nodes", [])) if isinstance(unknown, dict) else 0

    ir = {
        "host": meta.get("os", {}),
        "profiles": inv,
        "unknown_nodes": unknown,
    }
    STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    IR_PATH.write_text(json.dumps(ir, indent=2))

    payload = {
        "job_id": "experiment:field2",
        "status": "ok",
        "host": meta.get("os", {}),
        "inputs": [rel(FIELD2_INV), rel(UNKNOWN_NODES)],
        "outputs": [rel(IR_PATH)],
        "metrics": {
            "profiles": profile_count,
            "unknown_nodes": unknown_count,
        },
        "notes": "Normalized field2 inventory and unknown nodes into IR.",
        "tags": ["experiment:field2", "experiment", "field2", "smoke"],
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
        id="experiment:field2",
        inputs=[rel(FIELD2_INV), rel(UNKNOWN_NODES)],
        outputs=[rel(IR_PATH), rel(STATUS_PATH)],
        tags=["experiment:field2", "experiment", "field2", "smoke"],
        description="Normalize field2-filters experiment outputs into validation status.",
        example_command="python -m book.graph.concepts.validation --experiment field2",
        runner=run_field2_job,
    )
)
