"""
Meta validation job to assert status files conform to the expected schema.
"""

from __future__ import annotations

import json
from pathlib import Path

from book.api import evidence_tiers
from book.api.path_utils import find_repo_root, to_repo_relative
from book.graph.concepts.validation import registry
from book.graph.concepts.validation.registry import ValidationJob

ROOT = find_repo_root(Path(__file__))
STATUS_PATH = ROOT / "book" / "graph" / "concepts" / "validation" / "out" / "validation_status.json"
EXPERIMENT_STATUS_DIR = ROOT / "book" / "graph" / "concepts" / "validation" / "out" / "experiments"
CARTON_MANIFEST = ROOT / "book" / "api" / "carton" / "CARTON.json"
MAPPING_CHECKS = [
    ROOT / "book" / "graph" / "mappings" / "runtime" / "runtime_signatures.json",
    ROOT / "book" / "graph" / "mappings" / "runtime" / "runtime_coverage.json",
    ROOT / "book" / "graph" / "mappings" / "runtime" / "expectations.json",
    ROOT / "book" / "graph" / "mappings" / "system_profiles" / "digests.json",
    ROOT / "book" / "graph" / "mappings" / "vocab" / "ops.json",
    ROOT / "book" / "graph" / "mappings" / "vocab" / "filters.json",
    ROOT / "book" / "graph" / "mappings" / "carton" / "operation_coverage.json",
]
META_PATH = ROOT / "book" / "graph" / "concepts" / "validation" / "out" / "metadata.json"

REQUIRED_FIELDS = {"job_id", "status", "tier", "host", "inputs", "outputs", "tags"}
ALLOWED_STATUS = {"ok", "partial", "brittle", "blocked", "skipped"}
ALLOWED_TIERS = set(evidence_tiers.EVIDENCE_TIERS)


def rel(path: Path) -> str:
    return to_repo_relative(path, ROOT)


def check_record(rec: dict, source: Path) -> None:
    src = rel(source)
    missing = REQUIRED_FIELDS - set(rec.keys())
    if missing:
        raise ValueError(f"{src} missing fields: {missing}")
    if rec.get("status") not in ALLOWED_STATUS:
        raise ValueError(f"{src} has invalid status: {rec.get('status')}")
    if rec.get("tier") not in ALLOWED_TIERS:
        raise ValueError(f"{src} has invalid tier: {rec.get('tier')}")
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
        tier = meta.get("tier")
        if tier not in ALLOWED_TIERS:
            errors.append(f"{rel(mapping_path)} missing/invalid tier metadata")
        elif evidence_tiers.is_bedrock_mapping_path(rel(mapping_path)) and tier != "bedrock":
            errors.append(f"{rel(mapping_path)} tier mismatch for bedrock mapping path (expected bedrock, got {tier})")
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
        "tier": "mapped",
        "host": host,
        "inputs": [rel(STATUS_PATH), "book/graph/concepts/validation/out/experiments/*/status.json"],
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
        example_command="python -m book.graph.concepts.validation --tag meta",
        runner=run_schema_job,
    )
)
