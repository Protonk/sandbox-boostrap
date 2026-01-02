"""
Validation job for the preflight-blob-digests experiment.

Normalizes a small corpus of known apply-gated blob digests into validation IR so
tools (notably `book/tools/preflight`) can consult it for `.sb.bin` inputs.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List

from book.api.path_utils import find_repo_root, to_repo_relative
from book.api.profile import identity as identity_mod
from book.graph.concepts.validation import registry
from book.graph.concepts.validation.registry import ValidationJob

ROOT = find_repo_root(Path(__file__))

EXP_OUT = (
    ROOT
    / "book"
    / "evidence"
    / "experiments"
    / "runtime-final-final"
    / "suites"
    / "preflight-blob-digests"
    / "out"
    / "apply_gate_blob_digests.json"
)
META_PATH = ROOT / "book" / "evidence" / "graph" / "concepts" / "validation" / "out" / "metadata.json"

OUT_DIR = (
    ROOT / "book" / "evidence" / "graph" / "concepts" / "validation" / "out" / "experiments" / "preflight-blob-digests"
)
STATUS_PATH = OUT_DIR / "status.json"
IR_PATH = OUT_DIR / "blob_digests_ir.json"

SCHEMA_VERSION = 1


def rel(path: Path) -> str:
    return to_repo_relative(path, ROOT)


def _load_host() -> Dict[str, Any]:
    if META_PATH.exists():
        try:
            return json.loads(META_PATH.read_text()).get("os", {})
        except Exception:
            return {}
    return {}


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_hex_sha256(s: str) -> bool:
    if len(s) != 64:
        return False
    try:
        int(s, 16)
    except ValueError:
        return False
    return True


def run_preflight_blob_digests_job() -> Dict[str, Any]:
    if not EXP_OUT.exists():
        raise FileNotFoundError(f"missing required input: {EXP_OUT}")

    raw = json.loads(EXP_OUT.read_text())
    host = _load_host()

    baseline_world = identity_mod.baseline_world_id()
    if raw.get("world_id") != baseline_world:
        raise ValueError(f"world_id mismatch: {raw.get('world_id')!r} != {baseline_world!r}")
    if raw.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unexpected schema_version")

    apply_gate_digests = raw.get("apply_gate_digests") or []
    if not isinstance(apply_gate_digests, list):
        raise ValueError("apply_gate_digests must be a list")

    validated: List[Dict[str, Any]] = []
    evidence_count = 0
    for entry in apply_gate_digests:
        if not isinstance(entry, dict):
            raise ValueError("apply_gate_digests entries must be objects")
        blob_sha256 = entry.get("blob_sha256")
        if not isinstance(blob_sha256, str) or not _is_hex_sha256(blob_sha256):
            raise ValueError("invalid blob_sha256")

        evidence = entry.get("evidence") or []
        if not isinstance(evidence, list) or not evidence:
            raise ValueError("each digest entry must include non-empty evidence[]")

        for ev in evidence:
            if not isinstance(ev, dict):
                raise ValueError("evidence[] entries must be objects")
            blob_path = ev.get("blob_path")
            if not isinstance(blob_path, str):
                raise ValueError("evidence.blob_path must be a string")
            blob_abs = ROOT / blob_path
            if not blob_abs.exists():
                raise FileNotFoundError(f"evidence blob missing: {blob_path}")
            computed = _sha256_file(blob_abs)
            if computed != blob_sha256:
                raise ValueError(f"blob digest mismatch for {blob_path}")
            evidence_count += 1

        validated.append(entry)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    ir_payload = {
        "schema_version": SCHEMA_VERSION,
        "world_id": baseline_world,
        "host": host,
        "source_jobs": ["experiment:gate-witnesses", "experiment:preflight-blob-digests"],
        "inputs": raw.get("inputs") if isinstance(raw.get("inputs"), dict) else {},
        "apply_gate_digests": validated,
    }
    IR_PATH.write_text(json.dumps(ir_payload, indent=2, sort_keys=True) + "\n")

    status_payload = {
        "job_id": "experiment:preflight-blob-digests",
        "status": "ok",
        "tier": "mapped",
        "host": host,
        "inputs": [rel(EXP_OUT)],
        "outputs": [rel(IR_PATH)],
        "metrics": {"digests": len(validated), "evidence_rows": evidence_count},
        "notes": "Validated and normalized apply-gated blob digest corpus for preflight.",
        "tags": ["experiment:preflight-blob-digests", "experiment", "apply-gate"],
    }
    STATUS_PATH.write_text(json.dumps(status_payload, indent=2, sort_keys=True) + "\n")

    return {
        "status": "ok",
        "tier": "mapped",
        "inputs": status_payload["inputs"],
        "outputs": [rel(IR_PATH), rel(STATUS_PATH)],
        "metrics": status_payload["metrics"],
        "host": host,
        "notes": status_payload["notes"],
    }


registry.register(
    ValidationJob(
        id="experiment:preflight-blob-digests",
        inputs=[rel(EXP_OUT)],
        outputs=[rel(IR_PATH), rel(STATUS_PATH)],
        tags=["experiment:preflight-blob-digests", "experiment", "apply-gate"],
        description="Validate and normalize preflight blob digest corpus for .sb.bin inputs.",
        example_command="python -m book.graph.concepts.validation --experiment preflight-blob-digests",
        runner=run_preflight_blob_digests_job,
    )
)
