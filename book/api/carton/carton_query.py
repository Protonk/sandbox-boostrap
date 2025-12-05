"""
Public CARTON query API (stable entrypoint for agents and tools).

Implements simple lookups over CARTON mappings (vocab, system profile digests,
runtime signatures, coverage) without touching experiment out/ directly.

This module enforces a small error contract so helpers get predictable failures
when CARTON data is missing or out of date.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[3]
CARTON_MANIFEST = ROOT / "book/graph/carton/CARTON.json"

_MANIFEST_CACHE: Optional[dict] = None

LOGICAL_PATHS = {
    "vocab.ops": "book/graph/mappings/vocab/ops.json",
    "system.digests": "book/graph/mappings/system_profiles/digests.json",
    "runtime.signatures": "book/graph/mappings/runtime/runtime_signatures.json",
    "carton.coverage": "book/graph/mappings/carton/operation_coverage.json",
}


class CartonError(Exception):
    """Base CARTON error."""


class CartonDataError(CartonError):
    """Raised when CARTON data is missing or malformed."""


class UnknownOperationError(CartonError):
    """Raised when an operation name is not present in the CARTON vocab."""


def _load_manifest() -> dict:
    global _MANIFEST_CACHE
    if _MANIFEST_CACHE is not None:
        return _MANIFEST_CACHE
    try:
        manifest = json.loads(CARTON_MANIFEST.read_text())
    except FileNotFoundError as exc:
        raise CartonDataError(f"Missing CARTON manifest at {CARTON_MANIFEST}") from exc
    except json.JSONDecodeError as exc:
        raise CartonDataError(f"Malformed CARTON manifest at {CARTON_MANIFEST}") from exc
    if not isinstance(manifest, dict) or "files" not in manifest:
        raise CartonDataError(f"CARTON manifest at {CARTON_MANIFEST} is not well-formed")
    _MANIFEST_CACHE = manifest
    return manifest


def _manifest_entry(logical_name: str) -> Tuple[Path, Optional[str]]:
    expected_path = LOGICAL_PATHS.get(logical_name)
    if not expected_path:
        raise CartonDataError(f"Unknown CARTON logical path {logical_name}")
    manifest = _load_manifest()
    for entry in manifest.get("files", []):
        if entry.get("path") == expected_path:
            path = ROOT / entry["path"]
            return path, entry.get("sha256")
    raise CartonDataError(f"CARTON manifest does not list {expected_path}")


def _compute_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_json_from_manifest(logical_name: str, required_keys: Optional[List[str]] = None) -> dict:
    path, expected_hash = _manifest_entry(logical_name)
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise CartonDataError(f"Missing CARTON mapping at {path}") from exc
    except json.JSONDecodeError as exc:
        raise CartonDataError(f"Malformed JSON in CARTON mapping at {path}") from exc
    if expected_hash:
        actual_hash = _compute_sha256(path)
        if actual_hash != expected_hash:
            raise CartonDataError(
                f"CARTON mapping at {path} does not match manifest hash (expected {expected_hash}, got {actual_hash})"
            )
    if required_keys:
        for key in required_keys:
            if key not in data:
                raise CartonDataError(f"CARTON mapping at {path} is missing required key '{key}'")
    return data


def _load_vocab() -> Tuple[Dict[str, int], Dict[int, str]]:
    vocab = _load_json_from_manifest("vocab.ops", required_keys=["ops"])
    ops = vocab.get("ops") or []
    name_to_id = {entry["name"]: entry["id"] for entry in ops if "name" in entry and "id" in entry}
    id_to_name = {entry["id"]: entry["name"] for entry in ops if "name" in entry and "id" in entry}
    return name_to_id, id_to_name


def _load_coverage() -> dict:
    coverage = _load_json_from_manifest("carton.coverage", required_keys=["coverage"])
    cov = coverage.get("coverage")
    if not isinstance(cov, dict):
        raise CartonDataError("CARTON coverage mapping is malformed (coverage should be a dict)")
    return cov


def _lookup_op_id(op_name: str) -> int:
    name_to_id, _ = _load_vocab()
    op_id = name_to_id.get(op_name)
    if op_id is None:
        raise UnknownOperationError(f"Operation '{op_name}' not found in CARTON vocab")
    return op_id


def profiles_with_operation(op_name: str) -> List[str]:
    op_id = _lookup_op_id(op_name)
    coverage = _load_coverage()
    if op_name not in coverage:
        raise CartonDataError(f"CARTON coverage mapping does not include operation '{op_name}'")
    entry = coverage[op_name] or {}
    profiles = entry.get("system_profiles")
    if profiles is not None:
        return profiles
    # If the coverage entry is missing system profile data, fall back to digests.
    digests = _load_json_from_manifest("system.digests")
    profiles = []
    for key, val in digests.items():
        if key == "metadata":
            continue
        op_table = val.get("op_table") or []
        if op_id in op_table:
            profiles.append(key)
    return profiles


def profiles_and_signatures_for_operation(op_name: str) -> Dict[str, Any]:
    op_id = _lookup_op_id(op_name)
    coverage = _load_coverage()
    if op_name not in coverage:
        raise CartonDataError(f"CARTON coverage mapping does not include operation '{op_name}'")
    entry = coverage.get(op_name) or {}
    counts = entry.get("counts") or {}
    return {
        "op_name": op_name,
        "op_id": op_id,
        "system_profiles": entry.get("system_profiles") or [],
        "runtime_signatures": entry.get("runtime_signatures") or [],
        "counts": {
            "system_profiles": counts.get("system_profiles", 0),
            "runtime_signatures": counts.get("runtime_signatures", 0),
        },
        "known": True,
    }


def runtime_signature_info(sig_id: str) -> Dict[str, object]:
    sigs = _load_json_from_manifest("runtime.signatures", required_keys=["signatures"])
    signatures = sigs.get("signatures") or {}
    meta = sigs.get("profiles_metadata") or {}
    expected = (sigs.get("expected_matrix") or {}).get("profiles") or {}
    return {
        "probes": signatures.get(sig_id),
        "runtime_profile": (meta.get(sig_id) or {}).get("runtime_profile"),
        "expected": expected.get(sig_id),
    }


def ops_with_low_coverage(threshold: int = 0) -> List[Dict[str, object]]:
    coverage = _load_coverage()
    low = []
    for name, entry in coverage.items():
        counts = entry.get("counts") or {}
        total = (counts.get("system_profiles", 0) + counts.get("runtime_signatures", 0))
        if total <= threshold:
            low.append({"name": name, "op_id": entry.get("op_id"), "counts": counts})
    low.sort(
        key=lambda rec: (
            rec.get("counts", {}).get("system_profiles", 0)
            + rec.get("counts", {}).get("runtime_signatures", 0),
            rec.get("name"),
        )
    )
    return low


def list_carton_paths() -> Dict[str, str]:
    paths: Dict[str, str] = {}
    for logical, key in [
        ("vocab.ops", "vocab_ops"),
        ("system.digests", "system_profiles"),
        ("runtime.signatures", "runtime_signatures"),
        ("carton.coverage", "coverage"),
    ]:
        path, _ = _manifest_entry(logical)
        paths[key] = str(path)
    return paths


__all__ = [
    "CartonDataError",
    "UnknownOperationError",
    "list_carton_paths",
    "ops_with_low_coverage",
    "profiles_and_signatures_for_operation",
    "profiles_with_operation",
    "runtime_signature_info",
]
