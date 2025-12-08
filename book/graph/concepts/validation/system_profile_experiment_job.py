"""
Validation job for system-profile-digest experiment.
Normalizes digests into shared IR and records status.
"""

from __future__ import annotations

import json
from pathlib import Path

from book.graph.concepts.validation import registry
from book.graph.concepts.validation.registry import ValidationJob

ROOT = Path(__file__).resolve().parents[4]
EXP_DIGESTS = ROOT / "book" / "experiments" / "system-profile-digest" / "out" / "digests.json"
META_PATH = ROOT / "book" / "graph" / "concepts" / "validation" / "out" / "metadata.json"
STATUS_PATH = ROOT / "book" / "graph" / "concepts" / "validation" / "out" / "experiments" / "system-profile-digest" / "status.json"
IR_PATH = ROOT / "book" / "graph" / "concepts" / "validation" / "out" / "experiments" / "system-profile-digest" / "digests_ir.json"


def _load_host():
    if META_PATH.exists():
        try:
            return json.loads(META_PATH.read_text()).get("os", {})
        except Exception:
            return {}
    return {}


def run_system_profiles_job():
    if not EXP_DIGESTS.exists():
        raise FileNotFoundError(f"missing required input: {EXP_DIGESTS}")

    raw = json.loads(EXP_DIGESTS.read_text())
    host = _load_host()

    # Normalize keys to sys:<name>
    profiles = {}
    for name, entry in raw.items():
        key = name if name.startswith("sys:") else f"sys:{name}"
        profiles[key] = entry

    IR_PATH.parent.mkdir(parents=True, exist_ok=True)
    ir_payload = {
        "host": host,
        "source_jobs": ["experiment:system-profile-digest"],
        "profiles": profiles,
    }
    IR_PATH.write_text(json.dumps(ir_payload, indent=2))

    status_payload = {
        "job_id": "experiment:system-profile-digest",
        "status": "ok",
        "host": host,
        "inputs": [str(EXP_DIGESTS)],
        "outputs": [str(IR_PATH)],
        "metrics": {"profiles": len(profiles)},
        "notes": "Normalized system profile digests into IR.",
        "tags": ["experiment:system-profile-digest", "experiment", "system-profiles", "golden"],
    }
    STATUS_PATH.write_text(json.dumps(status_payload, indent=2))
    return {
        "status": "ok",
        "outputs": [str(IR_PATH), str(STATUS_PATH)],
        "metrics": status_payload["metrics"],
        "host": host,
        "notes": status_payload["notes"],
        "tags": status_payload["tags"],
    }


registry.register(
    ValidationJob(
        id="experiment:system-profile-digest",
        inputs=[str(EXP_DIGESTS)],
        outputs=[str(IR_PATH), str(STATUS_PATH)],
        tags=["experiment:system-profile-digest", "experiment", "system-profiles", "golden"],
        description="Normalize system-profile-digest outputs into shared IR for mappings.",
        example_command="python -m book.graph.concepts.validation --experiment system-profile-digest",
        runner=run_system_profiles_job,
    )
)
