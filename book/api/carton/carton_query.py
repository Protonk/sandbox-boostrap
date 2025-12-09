"""
Public CARTON query API (stable entrypoint for agents and tools).

Implements simple lookups over CARTON mappings (vocab, system profile digests,
runtime signatures, coverage) without touching experiment out/ directly.

This module enforces a small error contract so helpers get predictable failures
when CARTON data is missing or out of date. Coverage and index helpers surface
canonical system-profile status so callers can see when “known” data is sitting
on top of a degraded bedrock contract.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[3]
CARTON_MANIFEST = ROOT / "book/api/carton/CARTON.json"

_MANIFEST_CACHE: Optional[dict] = None

LOGICAL_PATHS = {
    "vocab.ops": "book/graph/mappings/vocab/ops.json",
    "vocab.filters": "book/graph/mappings/vocab/filters.json",
    "system.digests": "book/graph/mappings/system_profiles/digests.json",
    "runtime.signatures": "book/graph/mappings/runtime/runtime_signatures.json",
    "carton.coverage": "book/graph/mappings/carton/operation_coverage.json",
    "carton.operation_index": "book/graph/mappings/carton/operation_index.json",
    "carton.profile_layer_index": "book/graph/mappings/carton/profile_layer_index.json",
    "carton.filter_index": "book/graph/mappings/carton/filter_index.json",
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
    """
    Load a CARTON-mapped JSON by logical name, enforcing manifest hashes and
    presence of expected top-level keys so callers get consistent failures
    rather than partial data.
    """
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
    """Return both name->id and id->name maps from the CARTON ops vocab."""
    vocab = _load_json_from_manifest("vocab.ops", required_keys=["ops"])
    ops = vocab.get("ops") or []
    name_to_id = {entry["name"]: entry["id"] for entry in ops if "name" in entry and "id" in entry}
    id_to_name = {entry["id"]: entry["name"] for entry in ops if "name" in entry and "id" in entry}
    return name_to_id, id_to_name


def _load_coverage() -> dict:
    """Minimal coverage load that keeps a small surface for low-level queries."""
    coverage = _load_json_from_manifest("carton.coverage", required_keys=["coverage"])
    cov = coverage.get("coverage")
    if not isinstance(cov, dict):
        raise CartonDataError("CARTON coverage mapping is malformed (coverage should be a dict)")
    return cov


def _load_coverage_full() -> dict:
    """Full coverage record including metadata/canonical profile health."""
    return _load_json_from_manifest("carton.coverage", required_keys=["coverage"])


def _lookup_op_id(op_name: str) -> int:
    """Resolve op name to id with a clear error when vocab is stale."""
    name_to_id, _ = _load_vocab()
    op_id = name_to_id.get(op_name)
    if op_id is None:
        raise UnknownOperationError(f"Operation '{op_name}' not found in CARTON vocab")
    return op_id


def profiles_with_operation(op_name: str) -> List[str]:
    """
    System profile ids that carry the given op. Falls back to digests when
    coverage lacks explicit profile lists.
    """
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
    profile_map = digests.get("profiles") or digests
    profiles = []
    for key, val in profile_map.items():
        if key == "metadata":
            continue
        op_table = val.get("op_table") or []
        if op_id in op_table:
            profiles.append(key)
    return profiles


def profiles_and_signatures_for_operation(op_name: str) -> Dict[str, Any]:
    """
    Combine coverage entries for an op into a single record, keeping coverage
    health visible so callers can distinguish “known but degraded” from fully
    backed mappings.
    """
    op_id = _lookup_op_id(op_name)
    coverage_full = _load_coverage_full()
    coverage = coverage_full.get("coverage") or {}
    if op_name not in coverage:
        raise CartonDataError(f"CARTON coverage mapping does not include operation '{op_name}'")
    entry = coverage.get(op_name) or {}
    counts = entry.get("counts") or {}
    # coverage_status and canonical_profile_status report whether the coverage
    # data is still backed by canonical contracts; callers should treat non-ok
    # states as “known but degraded,” not business-as-usual.
    return {
        "op_name": op_name,
        "op_id": op_id,
        "system_profiles": entry.get("system_profiles") or [],
        "system_profile_status": entry.get("system_profile_status") or {},
        "runtime_signatures": entry.get("runtime_signatures") or [],
        "counts": {
            "system_profiles": counts.get("system_profiles", 0),
            "system_profiles_ok": counts.get("system_profiles_ok", 0),
            "runtime_signatures": counts.get("runtime_signatures", 0),
        },
        "coverage_status": (coverage_full.get("metadata") or {}).get("status"),
        "canonical_profile_status": (coverage_full.get("metadata") or {}).get("canonical_profile_status") or {},
        "known": True,
    }


def runtime_signature_info(sig_id: str) -> Dict[str, object]:
    """Fetch probe list, runtime profile, and expectation matrix for a runtime signature id."""
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
    """
    Return ops whose combined system-profile + runtime-signature coverage is at
    or below the threshold. Coverage metadata is preserved for upstream sorting.
    """
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


def _load_filter_index() -> dict:
    return _load_json_from_manifest("carton.filter_index", required_keys=["filters"])


def _load_operation_index() -> dict:
    return _load_json_from_manifest("carton.operation_index", required_keys=["operations"])


def _load_profile_layer_index() -> dict:
    return _load_json_from_manifest("carton.profile_layer_index", required_keys=["profiles"])


def list_operations() -> List[str]:
    ops = _load_operation_index().get("operations") or {}
    return sorted(ops.keys())


def list_profiles() -> List[str]:
    profiles = _load_profile_layer_index().get("profiles") or {}
    return sorted(profiles.keys())


def list_filters() -> List[str]:
    filters = _load_filter_index().get("filters") or {}
    return sorted(filters.keys())


def filter_story(filter_name: str) -> Dict[str, Any]:
    """Small story for a filter: ids plus where it appears across layers."""
    filters = _load_filter_index().get("filters") or {}
    entry = filters.get(filter_name)
    if entry is None:
        raise CartonDataError(f"filter '{filter_name}' not found in CARTON filter index")
    return {
        "filter_name": filter_name,
        "filter_id": entry.get("id"),
        "known": entry.get("known", False),
        "usage_status": entry.get("usage_status"),
        "system_profiles": entry.get("system_profiles") or [],
        "runtime_signatures": entry.get("runtime_signatures") or [],
    }


def list_carton_paths() -> Dict[str, str]:
    paths: Dict[str, str] = {}
    for logical, key in [
        ("vocab.ops", "vocab_ops"),
        ("vocab.filters", "vocab_filters"),
        ("system.digests", "system_profiles"),
        ("runtime.signatures", "runtime_signatures"),
        ("carton.coverage", "coverage"),
        ("carton.operation_index", "operation_index"),
        ("carton.profile_layer_index", "profile_layer_index"),
        ("carton.filter_index", "filter_index"),
    ]:
        path, _ = _manifest_entry(logical)
        paths[key] = str(path)
    return paths


def operation_story(op_name: str) -> Dict[str, Any]:
    """Narrative view for an op: ids plus linkage to profiles/signatures and health fields."""
    op_info = profiles_and_signatures_for_operation(op_name)
    coverage_full = _load_coverage_full()
    coverage = coverage_full.get("coverage") or {}
    entry = coverage.get(op_name, {})
    # Keep canonical/cov status visible so the mini-story reads as “this is what
    # we know, and here is the health of the canonical evidence it rests on.”
    return {
        "op_name": op_name,
        "op_id": op_info["op_id"],
        "known": op_info["known"],
        "system_profiles": op_info["system_profiles"],
        "system_profile_status": op_info.get("system_profile_status") or entry.get("system_profile_status") or {},
        "profile_layers": ["system"] if op_info["system_profiles"] else [],
        "runtime_signatures": op_info["runtime_signatures"],
        "coverage_counts": op_info["counts"],
        "coverage_status": (coverage_full.get("metadata") or {}).get("status"),
        "canonical_profile_status": (coverage_full.get("metadata") or {}).get("canonical_profile_status") or {},
    }


def profile_story(profile_id: str) -> Dict[str, Any]:
    """Narrative view for a system profile, keeping canonical/coverage status visible."""
    digests = _load_json_from_manifest("system.digests")
    meta = digests.get("metadata") or {}
    profiles = digests.get("profiles") or {k: v for k, v in digests.items() if k != "metadata"}
    if profile_id not in profiles:
        raise CartonDataError(f"profile '{profile_id}' not found in system digests")
    profile_body = profiles[profile_id]
    op_ids = profile_body.get("op_table") or []
    _, id_to_name = _load_vocab()
    ops = [{"name": id_to_name.get(op_id), "id": op_id} for op_id in op_ids if op_id in id_to_name]
    coverage_full = _load_json_from_manifest("carton.coverage", required_keys=["coverage"])  # reused coverage shape
    coverage = coverage_full.get("coverage") or {}
    runtime_sigs = set()
    for op in ops:
        cov = coverage.get(op["name"]) or {}
        for sig in cov.get("runtime_signatures") or []:
            runtime_sigs.add(sig)
    # Filter linkage is not yet mapped per profile; keep an explicit placeholder to avoid ad-hoc guesses.
    filters_info = {
        "known": False,
        "filters": [],
    }
    canonical_profiles_meta = meta.get("canonical_profiles") or {}
    canonical_profile_status = {
        pid: (info.get("status") if isinstance(info, dict) else info) for pid, info in canonical_profiles_meta.items()
    }
    # Coverage status here mirrors the canonical profile health to keep profile
    # stories consistent with the generator guardrails.
    return {
        "profile_id": profile_id,
        "layer": "system",
        "status": profile_body.get("status") or meta.get("status"),
        "ops": ops,
        "runtime_signatures": sorted(runtime_sigs),
        "filters": filters_info,
        "canonical_profile_status": canonical_profile_status,
        "coverage_status": (coverage_full.get("metadata") or {}).get("status"),
    }


__all__ = [
    "CartonDataError",
    "UnknownOperationError",
    "filter_story",
    "list_filters",
    "list_operations",
    "list_profiles",
    "list_carton_paths",
    "ops_with_low_coverage",
    "operation_story",
    "profile_story",
    "profiles_and_signatures_for_operation",
    "profiles_with_operation",
    "runtime_signature_info",
]
