"""
Validation job for system-profile digests.
Normalizes canonical blob digests into shared IR and records status.
"""

from __future__ import annotations

import json
from pathlib import Path

from book.api.path_utils import find_repo_root, to_repo_relative
from book.api.profile import digests
from book.integration.carton.validation import registry
from book.integration.carton.validation.registry import ValidationJob

ROOT = find_repo_root(Path(__file__))
META_PATH = ROOT / "book" / "evidence" / "syncretic" / "validation" / "out" / "metadata.json"
STATUS_PATH = (
    ROOT
    / "book"
    / "evidence" / "syncretic" / "validation"
    / "out"
    / "experiments"
    / "system-profile-digest"
    / "status.json"
)
IR_PATH = (
    ROOT
    / "book"
    / "evidence" / "syncretic" / "validation"
    / "out"
    / "experiments"
    / "system-profile-digest"
    / "digests_ir.json"
)


def rel(path: Path) -> str:
    return to_repo_relative(path, ROOT)


def _load_host():
    if META_PATH.exists():
        try:
            return json.loads(META_PATH.read_text()).get("os", {})
        except Exception:
            return {}
    return {}


def run_system_profiles_job():
    blobs = digests.canonical_system_profile_blobs(ROOT)
    for path in blobs.values():
        if not path.exists():
            raise FileNotFoundError(f"missing required input: {path}")
    raw = digests.digest_named_blobs(blobs, repo_root=ROOT)
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
        "inputs": [rel(path) for path in blobs.values()],
        "outputs": [rel(IR_PATH)],
        "metrics": {"profiles": len(profiles)},
        "notes": "Normalized system profile digests into IR.",
        "tags": ["experiment:system-profile-digest", "experiment", "system-profiles", "golden"],
    }
    STATUS_PATH.write_text(json.dumps(status_payload, indent=2))
    return {
        "status": "ok",
        "inputs": status_payload["inputs"],
        "outputs": [rel(IR_PATH), rel(STATUS_PATH)],
        "metrics": status_payload["metrics"],
        "host": host,
        "notes": status_payload["notes"],
        "tags": status_payload["tags"],
    }


registry.register(
    ValidationJob(
        id="experiment:system-profile-digest",
        inputs=[rel(path) for path in digests.canonical_system_profile_blobs(ROOT).values()],
        outputs=[rel(IR_PATH), rel(STATUS_PATH)],
        tags=["experiment:system-profile-digest", "experiment", "system-profiles", "golden"],
        description="Normalize canonical system profile digests into shared IR for mappings.",
        example_command="python -m book.integration.carton validate --experiment system-profile-digest",
        runner=run_system_profiles_job,
    )
)
