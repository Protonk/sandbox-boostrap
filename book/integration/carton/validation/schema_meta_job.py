"""
Meta validation job to assert status files conform to the expected schema.
"""

from __future__ import annotations

import json
from pathlib import Path

from book.api.path_utils import find_repo_root, to_repo_relative
from book.integration.carton.validation import registry
from book.integration.carton.validation.registry import ValidationJob

ROOT = find_repo_root(Path(__file__))
STATUS_PATH = ROOT / "book" / "evidence" / "carton" / "validation" / "out" / "validation_status.json"
EXPERIMENT_STATUS_DIR = ROOT / "book" / "evidence" / "carton" / "validation" / "out" / "experiments"
CARTON_MANIFEST = ROOT / "book" / "integration" / "carton" / "bundle" / "CARTON.json"
MAPPING_CHECKS = [
    ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "runtime" / "runtime_signatures.json",
    ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "runtime" / "runtime_coverage.json",
    ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "runtime" / "expectations.json",
    ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "system_profiles" / "digests.json",
    ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "vocab" / "ops.json",
    ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "vocab" / "filters.json",
    ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "operation_coverage.json",
]
META_PATH = ROOT / "book" / "evidence" / "carton" / "validation" / "out" / "metadata.json"

REQUIRED_FIELDS = {"job_id", "status", "host", "inputs", "outputs", "tags"}
ALLOWED_STATUS = {"ok", "partial", "brittle", "blocked", "skipped"}


def rel(path: Path) -> str:
    return to_repo_relative(path, ROOT)


def check_record(rec: dict, source: Path) -> None:
    src = rel(source)
    missing = REQUIRED_FIELDS - set(rec.keys())
    if missing:
        raise ValueError(f"{src} missing fields: {missing}")
    if rec.get("status") not in ALLOWED_STATUS:
        raise ValueError(f"{src} has invalid status: {rec.get('status')}")
    if not isinstance(rec.get("inputs"), list) or not isinstance(rec.get("outputs"), list):
        raise ValueError(f"{src} inputs/outputs must be lists")
    if not isinstance(rec.get("tags"), list):
        raise ValueError(f"{src} tags must be a list")


def run_schema_job():
    host = {}
    if META_PATH.exists():
        try:
            host = json.loads(META_PATH.read_text()).get("os", {})
        except Exception:
            host = {}

    sources = []
    errors = []

    if STATUS_PATH.exists():
        data = json.loads(STATUS_PATH.read_text())
        for rec in data.get("jobs", []):
            try:
                check_record(rec, STATUS_PATH)
                sources.append(rel(STATUS_PATH))
            except Exception as exc:
                errors.append(str(exc))

    if EXPERIMENT_STATUS_DIR.exists():
        for status_file in EXPERIMENT_STATUS_DIR.glob("*/status.json"):
            try:
                rec = json.loads(status_file.read_text())
                check_record(rec, status_file)
                sources.append(rel(status_file))
            except Exception as exc:
                errors.append(str(exc))

    # Mapping provenance checks
    for mapping_path in MAPPING_CHECKS:
        if not mapping_path.exists():
            errors.append(f"missing mapping for provenance check: {rel(mapping_path)}")
            continue
        data = json.loads(mapping_path.read_text())
        meta = data.get("metadata") or {}
        world_id = meta.get("world_id") or data.get("world_id")
        if not world_id:
            errors.append(f"{rel(mapping_path)} missing world_id metadata")
        source_jobs = meta.get("source_jobs")
        if not source_jobs and "vocab" in str(mapping_path):
            source_jobs = ["vocab:sonoma-14.4.1"]
        if not source_jobs:
            errors.append(f"{rel(mapping_path)} missing source_jobs metadata")
    # CARTON manifest presence
    if not CARTON_MANIFEST.exists():
        errors.append(f"missing CARTON manifest: {rel(CARTON_MANIFEST)}")

    status = "ok" if not errors else "blocked"
    payload = {
        "job_id": "validation:schema-check",
        "status": status,
        "host": host,
        "inputs": [rel(STATUS_PATH), "book/evidence/carton/validation/out/experiments/*/status.json"],
        "outputs": [],
        "notes": "; ".join(errors) if errors else "status files conform to schema",
        "metrics": {"checked": len(sources), "errors": len(errors)},
    }
    return {**payload, "outputs": []}


registry.register(
    ValidationJob(
        id="validation:schema-check",
        inputs=[rel(STATUS_PATH)],
        outputs=[],
        tags=["meta", "schema"],
        description="Sanity-check validation status files for schema compliance.",
        example_command="python -m book.integration.carton validate --tag meta",
        runner=run_schema_job,
    )
)
