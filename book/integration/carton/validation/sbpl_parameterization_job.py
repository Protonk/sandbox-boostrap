"""
Validation job for SBPL parameterization on the Sonoma baseline.

This job exists to make the `(param "...")` compilation story concrete for this
world:
- compiling a parameterized SBPL specimen without parameters should fail, and
- compiling it with a parameter dictionary (via libsandbox params handles)
  should succeed and materialize the parameter value into the compiled blob.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List

from book.api.profile import decoder
from book.api.path_utils import find_repo_root, to_repo_relative
from book.api.profile import compile as compile_mod
from book.integration.carton.validation import registry
from book.integration.carton.validation.registry import ValidationJob

ROOT = find_repo_root(Path(__file__))
WORLD_ID = "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5"

SBPL_PATH = ROOT / "book/evidence/experiments/runtime-final-final/suites/sbpl-graph-runtime/profiles/param_path.sb"
META_PATH = ROOT / "book/evidence/syncretic/validation/out/metadata.json"
STATUS_PATH = ROOT / "book/evidence/syncretic/validation/out/sbpl_parameterization/status.json"

PARAM_KEY = "ROOT"
PARAM_VALUE = "/private/tmp"
EXPECTED_NO_PARAMS_ERROR = "invalid data type of path filter; expected pattern, got boolean"


def rel(path: Path) -> str:
    return to_repo_relative(path, ROOT)


def _sha256(buf: bytes) -> str:
    return hashlib.sha256(buf).hexdigest()


def run_sbpl_parameterization_job() -> Dict[str, Any]:
    if not SBPL_PATH.exists():
        raise FileNotFoundError(f"missing required SBPL specimen: {SBPL_PATH}")

    meta = json.loads(META_PATH.read_text()) if META_PATH.exists() else {}
    host = meta.get("os", {})

    mismatches: List[str] = []

    if meta.get("world_id") and meta.get("world_id") != WORLD_ID:
        mismatches.append(f"world_id mismatch (expected {WORLD_ID}, got {meta.get('world_id')})")

    # 1) Without params: expect a deterministic compile-time error for this specimen.
    no_params_error: str | None = None
    try:
        compile_mod.compile_sbpl_file(SBPL_PATH)
        mismatches.append("expected compilation without params to fail, but it succeeded")
    except Exception as exc:  # expected
        no_params_error = str(exc)
        if EXPECTED_NO_PARAMS_ERROR not in no_params_error:
            mismatches.append(f"unexpected error without params: {no_params_error}")

    # 2) With params: should compile, and the parameter value should appear in the blob.
    compiled = compile_mod.compile_sbpl_file(SBPL_PATH, params={PARAM_KEY: PARAM_VALUE})
    blob = compiled.blob
    blob_sha = _sha256(blob)

    if PARAM_VALUE.encode() not in blob:
        mismatches.append("compiled blob does not contain PARAM_VALUE bytes")

    decoded = decoder.decode_profile_dict(blob)
    literal_strings = decoded.get("literal_strings") or []
    if not any(PARAM_VALUE in s for s in literal_strings):
        mismatches.append("decoded literal_strings do not include PARAM_VALUE")

    status = "ok" if not mismatches else "brittle"

    payload: Dict[str, Any] = {
        "job_id": "structure:sbpl-parameterization",
        "status": status,
        "host": host,
        "world_id": WORLD_ID,
        "inputs": [rel(SBPL_PATH)],
        "outputs": [rel(STATUS_PATH)],
        "tags": ["structure", "sbpl", "sbpl-parameterization", "static-format"],
        "metrics": {
            "compiled_len": compiled.length,
            "compiled_sha256": blob_sha,
            "compiled_profile_type": compiled.profile_type,
            "literal_strings_count": len(literal_strings),
        },
        "no_params_error": no_params_error,
        "mismatches": mismatches,
        "notes": "Asserts libsandbox params-handle compilation supports a minimal `(param ...)`-using SBPL specimen on this world.",
    }

    STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATUS_PATH.write_text(json.dumps(payload, indent=2))
    return payload


registry.register(
    ValidationJob(
        id="structure:sbpl-parameterization",
        inputs=[rel(SBPL_PATH)],
        outputs=[rel(STATUS_PATH)],
        tags=["structure", "sbpl", "sbpl-parameterization", "static-format"],
        description="Compile a minimal `(param ...)` profile with/without params and assert deterministic outcomes.",
        example_command="python -m book.integration.carton validate --id structure:sbpl-parameterization",
        runner=run_sbpl_parameterization_job,
    )
)
