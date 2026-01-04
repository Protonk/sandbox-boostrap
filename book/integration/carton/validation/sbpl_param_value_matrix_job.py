"""
Validation job: probe SBPL param value parsing at compile time on this world.

This job focuses on a single, minimal question:

  When a profile uses `(when (param "ALLOW_DOWNLOADS") ...)`, do different
  parameter *values* change the compiled blob, or is the gating purely
  “present vs missing”?

On this Sonoma baseline we treat the result as a small, host-bound corpus
(one specimen, one key) intended to prevent accidental regressions in the
parameterization shim and to record observed behavior explicitly.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from book.api.profile import decoder
from book.api.path_utils import find_repo_root, to_repo_relative
from book.api.profile import compile as compile_mod
from book.integration.carton.validation import registry
from book.integration.carton.validation.registry import ValidationJob

ROOT = find_repo_root(Path(__file__))
WORLD_ID = "sonoma-14.4.1-23E224-arm64-dyld-a3a840f9"

SBPL_PATH = ROOT / "book/evidence/experiments/runtime-final-final/suites/sbpl-graph-runtime/profiles/param_write_gate.sb"
STATUS_PATH = ROOT / "book/evidence/syncretic/validation/out/sbpl_param_value_matrix/status.json"

PARAM_KEY = "ALLOW_DOWNLOADS"
VALUES = ["1", "0", "", "#t", "#f", "/private/tmp"]


def rel(path: Path) -> str:
    return to_repo_relative(path, ROOT)


def _sha256(buf: bytes) -> str:
    return hashlib.sha256(buf).hexdigest()


def _compile(params: Optional[Dict[str, str]]) -> Dict[str, Any]:
    res = compile_mod.compile_sbpl_file(SBPL_PATH, params=params)
    decoded = decoder.decode_profile_dict(res.blob)
    literal_strings = decoded.get("literal_strings") or []
    return {
        "params": params,
        "compiled_len": res.length,
        "compiled_sha256": _sha256(res.blob),
        "literal_strings_count": len(literal_strings),
        "has_param_root_literal": any("param_root" in s for s in literal_strings),
    }


def run_sbpl_param_value_matrix_job() -> Dict[str, Any]:
    if not SBPL_PATH.exists():
        raise FileNotFoundError(f"missing required SBPL specimen: {SBPL_PATH}")

    mismatches: List[str] = []

    base = _compile(params=None)
    rows = [base]

    compiled_by_value: Dict[str, Dict[str, Any]] = {}
    for value in VALUES:
        row = _compile(params={PARAM_KEY: value})
        rows.append(row)
        compiled_by_value[value] = row

    # Presence vs missing should change the compiled blob (gated allow rule).
    if base["has_param_root_literal"]:
        mismatches.append("expected no-params build to omit param_root literal, but it was present")

    reference = compiled_by_value[VALUES[0]]
    if not reference["has_param_root_literal"]:
        mismatches.append("expected params build to include param_root literal, but it was absent")

    if base["compiled_sha256"] == reference["compiled_sha256"]:
        mismatches.append("expected params build sha256 to differ from no-params build sha256")

    # Different values should not change the compiled blob on this host baseline:
    # any provided value makes the param “present” (truthy) in `(when (param ...))`.
    for value, row in compiled_by_value.items():
        if row["compiled_sha256"] != reference["compiled_sha256"]:
            mismatches.append(f"param value {value!r} produced different sha256 than {VALUES[0]!r}")
        if row["compiled_len"] != reference["compiled_len"]:
            mismatches.append(f"param value {value!r} produced different len than {VALUES[0]!r}")
        if not row["has_param_root_literal"]:
            mismatches.append(f"param value {value!r} omitted param_root literal (unexpected)")

    status = "ok" if not mismatches else "brittle"
    payload: Dict[str, Any] = {
        "job_id": "structure:sbpl-param-value-matrix",
        "status": status,
        "world_id": WORLD_ID,
        "inputs": [rel(SBPL_PATH)],
        "outputs": [rel(STATUS_PATH)],
        "tags": ["structure", "sbpl", "sbpl-parameterization", "static-format"],
        "metrics": {
            "cases": 1 + len(VALUES),
            "no_params_sha256": base["compiled_sha256"],
            "with_params_sha256": reference["compiled_sha256"],
            "with_params_len": reference["compiled_len"],
        },
        "results": rows,
        "mismatches": mismatches,
        "notes": (
            "On this world baseline, `(when (param KEY) ...)` is gated by param presence: "
            "any provided value compiles to the same blob; missing param compiles to a distinct blob without the gated rule."
        ),
    }

    STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATUS_PATH.write_text(json.dumps(payload, indent=2))
    return payload


registry.register(
    ValidationJob(
        id="structure:sbpl-param-value-matrix",
        inputs=[rel(SBPL_PATH)],
        outputs=[rel(STATUS_PATH)],
        tags=["structure", "sbpl", "sbpl-parameterization", "static-format"],
        description="Compile param_write_gate.sb with/without params and assert param presence (not value) gates compilation.",
        example_command="python -m book.integration.carton validate --id structure:sbpl-param-value-matrix",
        runner=run_sbpl_param_value_matrix_job,
    )
)
