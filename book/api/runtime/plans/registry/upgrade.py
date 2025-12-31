"""
Registry normalization and upgrade helpers.

This module standardizes probe/profile registries to the current schema
version, filling explicit defaults so downstream consumers do not have to
infer missing fields.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Dict

from book.api import path_utils


REPO_ROOT = path_utils.find_repo_root(Path(__file__))

PROBE_SCHEMA_VERSION = "runtime-tools.probe_registry.v0.2"
PROFILE_SCHEMA_VERSION = "runtime-tools.profile_registry.v0.2"
SUPPORTED_PROBE_SCHEMA_VERSIONS = {
    "runtime-tools.probe_registry.v0.1",
    PROBE_SCHEMA_VERSION,
}
SUPPORTED_PROFILE_SCHEMA_VERSIONS = {
    "runtime-tools.profile_registry.v0.1",
    PROFILE_SCHEMA_VERSION,
}

PROBE_CORE_REQUIRED = {
    "probe_id",
    "name",
    "operation",
    "target",
    "expected",
}
PROBE_NORMALIZED_REQUIRED = PROBE_CORE_REQUIRED | {
    "supports_lanes",
    "expected_primary_ops",
    "expected_predicates",
    "capabilities_required",
    "controls_supported",
}
PROBE_OPTIONAL = {
    "expectation_id",
    "mode",
    "driver",
    "anchor_ctx_id",
}
PROBE_ALLOWED = PROBE_NORMALIZED_REQUIRED | PROBE_OPTIONAL

PROFILE_CORE_REQUIRED = {
    "profile_id",
    "profile_path",
    "mode",
    "probe_refs",
}
PROFILE_NORMALIZED_REQUIRED = PROFILE_CORE_REQUIRED | {
    "family",
    "semantic_group",
    "key_specific_rules",
    "notes",
}
PROFILE_OPTIONAL: set[str] = set()
PROFILE_ALLOWED = PROFILE_NORMALIZED_REQUIRED | PROFILE_OPTIONAL

DEFAULT_SUPPORTS_LANES = {"baseline": True, "scenario": True, "oracle": True}
DEFAULT_EXPECTED_PRIMARY_OPS: list[str] = []
DEFAULT_EXPECTED_PREDICATES: list[str] = []
DEFAULT_CAPABILITIES_REQUIRED: list[str] = []
DEFAULT_CONTROLS_SUPPORTED: list[str] = []

DEFAULT_FAMILY = None
DEFAULT_SEMANTIC_GROUP = None
DEFAULT_KEY_SPECIFIC_RULES: list[str] = []
DEFAULT_NOTES = None

ALLOWED_EXPECTED = {"allow", "deny"}
ALLOWED_PROFILE_MODES = {"sbpl", "blob"}
ALLOWED_CONTROL_VALUES = {"baseline", "allow_default", "deny_default"}


@dataclass(frozen=True)
class RegistryUpgradeResult:
    probes_path: Path
    profiles_path: Path


def _ensure_dict(value: Any, label: str, errors: list[str]) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    errors.append(f"{label} must be a dict")
    return {}


def _ensure_str(value: Any, label: str, errors: list[str]) -> str:
    if isinstance(value, str):
        return value
    errors.append(f"{label} must be a string")
    return ""


def _ensure_str_list(value: Any, label: str, errors: list[str]) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        errors.append(f"{label} must be a list")
        return []
    out: list[str] = []
    for idx, item in enumerate(value):
        if not isinstance(item, str):
            errors.append(f"{label}[{idx}] must be a string")
            continue
        out.append(item)
    return out


def _ensure_supports_lanes(value: Any, label: str, errors: list[str]) -> Dict[str, bool]:
    if value is None:
        return dict(DEFAULT_SUPPORTS_LANES)
    if not isinstance(value, dict):
        errors.append(f"{label} must be an object")
        return dict(DEFAULT_SUPPORTS_LANES)
    out = dict(DEFAULT_SUPPORTS_LANES)
    for key in ["baseline", "scenario", "oracle"]:
        if key in value:
            if isinstance(value[key], bool):
                out[key] = value[key]
            else:
                errors.append(f"{label}.{key} must be a boolean")
    return out


def validate_probe_entry(probe_id: str, probe: Dict[str, Any], *, strict: bool) -> list[str]:
    errors: list[str] = []
    required = PROBE_NORMALIZED_REQUIRED if strict else PROBE_CORE_REQUIRED

    if not isinstance(probe, dict):
        return [f"probe {probe_id} must be an object"]

    extra = set(probe.keys()) - PROBE_ALLOWED
    if extra:
        errors.append(f"probe {probe_id} has unexpected keys: {sorted(extra)}")
    missing = required - set(probe.keys())
    if missing:
        errors.append(f"probe {probe_id} missing required keys: {sorted(missing)}")

    pid = probe.get("probe_id")
    if pid != probe_id:
        errors.append(f"probe_id mismatch ({probe_id} -> {pid})")

    for key in ["probe_id", "name", "operation", "target"]:
        if key in probe:
            _ensure_str(probe.get(key), f"probe {probe_id}.{key}", errors)

    expected = probe.get("expected")
    if expected not in ALLOWED_EXPECTED:
        errors.append(f"probe {probe_id}.expected must be one of {sorted(ALLOWED_EXPECTED)}")

    if "supports_lanes" in probe:
        _ensure_supports_lanes(probe.get("supports_lanes"), f"probe {probe_id}.supports_lanes", errors)

    for key in ["expected_primary_ops", "expected_predicates", "capabilities_required", "controls_supported"]:
        if key in probe:
            _ensure_str_list(probe.get(key), f"probe {probe_id}.{key}", errors)

    controls = probe.get("controls_supported")
    if isinstance(controls, list):
        for item in controls:
            if item not in ALLOWED_CONTROL_VALUES:
                errors.append(
                    f"probe {probe_id}.controls_supported has unknown value {item!r}"
                )

    for key in ["expectation_id", "mode", "driver", "anchor_ctx_id"]:
        if key in probe and probe[key] is not None:
            _ensure_str(probe.get(key), f"probe {probe_id}.{key}", errors)

    return errors


def normalize_probe_entry(probe_id: str, probe: Dict[str, Any]) -> Dict[str, Any]:
    errors = validate_probe_entry(probe_id, probe, strict=False)
    if errors:
        raise ValueError("; ".join(errors))

    operation = probe["operation"]
    target = probe["target"]

    supports_lanes = _ensure_supports_lanes(probe.get("supports_lanes"), f"probe {probe_id}.supports_lanes", [])

    if "expected_primary_ops" in probe:
        expected_primary_ops = _ensure_str_list(
            probe.get("expected_primary_ops"),
            f"probe {probe_id}.expected_primary_ops",
            [],
        )
    else:
        expected_primary_ops = [operation] if operation else list(DEFAULT_EXPECTED_PRIMARY_OPS)

    if "expected_predicates" in probe:
        expected_predicates = _ensure_str_list(
            probe.get("expected_predicates"),
            f"probe {probe_id}.expected_predicates",
            [],
        )
    else:
        expected_predicates = [target] if target else list(DEFAULT_EXPECTED_PREDICATES)

    capabilities_required = _ensure_str_list(
        probe.get("capabilities_required"),
        f"probe {probe_id}.capabilities_required",
        [],
    )
    controls_supported = _ensure_str_list(
        probe.get("controls_supported"),
        f"probe {probe_id}.controls_supported",
        [],
    )

    normalized: Dict[str, Any] = {
        "probe_id": probe["probe_id"],
        "name": probe["name"],
        "operation": operation,
        "target": target,
        "expected": probe["expected"],
        "supports_lanes": supports_lanes,
        "expected_primary_ops": expected_primary_ops,
        "expected_predicates": expected_predicates,
        "capabilities_required": capabilities_required,
        "controls_supported": controls_supported,
    }
    for key in ["expectation_id", "mode", "driver", "anchor_ctx_id"]:
        if key in probe:
            normalized[key] = probe[key]
    return normalized


def validate_profile_entry(profile_id: str, profile: Dict[str, Any], *, strict: bool) -> list[str]:
    errors: list[str] = []
    required = PROFILE_NORMALIZED_REQUIRED if strict else PROFILE_CORE_REQUIRED

    if not isinstance(profile, dict):
        return [f"profile {profile_id} must be an object"]

    extra = set(profile.keys()) - PROFILE_ALLOWED
    if extra:
        errors.append(f"profile {profile_id} has unexpected keys: {sorted(extra)}")
    missing = required - set(profile.keys())
    if missing:
        errors.append(f"profile {profile_id} missing required keys: {sorted(missing)}")

    pid = profile.get("profile_id")
    if pid != profile_id:
        errors.append(f"profile_id mismatch ({profile_id} -> {pid})")

    for key in ["profile_id", "profile_path", "mode"]:
        if key in profile:
            _ensure_str(profile.get(key), f"profile {profile_id}.{key}", errors)

    mode = profile.get("mode")
    if mode not in ALLOWED_PROFILE_MODES:
        errors.append(f"profile {profile_id}.mode must be one of {sorted(ALLOWED_PROFILE_MODES)}")

    if "probe_refs" in profile:
        _ensure_str_list(profile.get("probe_refs"), f"profile {profile_id}.probe_refs", errors)

    for key in ["family", "semantic_group", "notes"]:
        if key in profile and profile[key] is not None and not isinstance(profile[key], str):
            errors.append(f"profile {profile_id}.{key} must be a string or null")

    if "key_specific_rules" in profile:
        _ensure_str_list(profile.get("key_specific_rules"), f"profile {profile_id}.key_specific_rules", errors)

    return errors


def normalize_profile_entry(profile_id: str, profile: Dict[str, Any]) -> Dict[str, Any]:
    errors = validate_profile_entry(profile_id, profile, strict=False)
    if errors:
        raise ValueError("; ".join(errors))

    normalized: Dict[str, Any] = {
        "profile_id": profile["profile_id"],
        "profile_path": profile["profile_path"],
        "mode": profile["mode"],
        "family": profile.get("family", DEFAULT_FAMILY),
        "semantic_group": profile.get("semantic_group", DEFAULT_SEMANTIC_GROUP),
        "probe_refs": _ensure_str_list(profile.get("probe_refs"), f"profile {profile_id}.probe_refs", []),
        "key_specific_rules": _ensure_str_list(
            profile.get("key_specific_rules"),
            f"profile {profile_id}.key_specific_rules",
            [],
        ),
        "notes": profile.get("notes", DEFAULT_NOTES),
    }
    return normalized


def normalize_probe_registry(doc: Dict[str, Any]) -> Dict[str, Any]:
    schema = doc.get("schema_version")
    if schema not in SUPPORTED_PROBE_SCHEMA_VERSIONS:
        raise ValueError(f"unsupported probe registry schema_version: {schema}")

    registry_id = doc.get("registry_id")
    world_id = doc.get("world_id")
    probes_raw = doc.get("probes") or {}

    if not isinstance(probes_raw, dict):
        raise ValueError("probe registry probes must be an object")
    if not isinstance(registry_id, str) or not isinstance(world_id, str):
        raise ValueError("probe registry missing registry_id/world_id")

    probes: Dict[str, Any] = {}
    for probe_id in sorted(probes_raw.keys()):
        probe = probes_raw[probe_id]
        normalized = normalize_probe_entry(probe_id, probe)
        probes[probe_id] = normalized

    return {
        "schema_version": PROBE_SCHEMA_VERSION,
        "registry_id": registry_id,
        "world_id": world_id,
        "probes": probes,
    }


def normalize_profile_registry(doc: Dict[str, Any]) -> Dict[str, Any]:
    schema = doc.get("schema_version")
    if schema not in SUPPORTED_PROFILE_SCHEMA_VERSIONS:
        raise ValueError(f"unsupported profile registry schema_version: {schema}")

    registry_id = doc.get("registry_id")
    world_id = doc.get("world_id")
    profiles_raw = doc.get("profiles") or {}

    if not isinstance(profiles_raw, dict):
        raise ValueError("profile registry profiles must be an object")
    if not isinstance(registry_id, str) or not isinstance(world_id, str):
        raise ValueError("profile registry missing registry_id/world_id")

    profiles: Dict[str, Any] = {}
    for profile_id in sorted(profiles_raw.keys()):
        profile = profiles_raw[profile_id]
        normalized = normalize_profile_entry(profile_id, profile)
        profiles[profile_id] = normalized

    return {
        "schema_version": PROFILE_SCHEMA_VERSION,
        "registry_id": registry_id,
        "world_id": world_id,
        "profiles": profiles,
    }


def upgrade_registry_files(
    *,
    probes_path: Path,
    profiles_path: Path,
    out_dir: Path | None = None,
    overwrite: bool = False,
) -> RegistryUpgradeResult:
    probes_doc = json.loads(probes_path.read_text())
    profiles_doc = json.loads(profiles_path.read_text())

    normalized_probes = normalize_probe_registry(probes_doc)
    normalized_profiles = normalize_profile_registry(profiles_doc)

    out_dir = out_dir or probes_path.parent
    out_dir = path_utils.ensure_absolute(out_dir, repo_root=REPO_ROOT)

    out_probes = out_dir / probes_path.name
    out_profiles = out_dir / profiles_path.name

    if out_probes.exists() and not overwrite:
        raise FileExistsError(f"refusing to overwrite {out_probes}")
    if out_profiles.exists() and not overwrite:
        raise FileExistsError(f"refusing to overwrite {out_profiles}")

    out_probes.write_text(json.dumps(normalized_probes, indent=2, sort_keys=True) + "\n")
    out_profiles.write_text(json.dumps(normalized_profiles, indent=2, sort_keys=True) + "\n")

    return RegistryUpgradeResult(probes_path=out_probes, profiles_path=out_profiles)
