"""
Runtime registry loader (service contract).

Registries describe probes and SBPL profiles as data. They are the bridge
between plan JSON ("run these profiles") and the runnable harness inputs.

Responsibilities:
- Load a registry index that maps registry_id -> {probes.json, profiles.json}.
- Validate schemas for registry index, probes, and profiles.
- Provide stable lookup helpers (`resolve_probe`, `resolve_profile`) used by
  plan compilation.
- Provide linting helpers that catch missing files and obvious descriptor drift.

Key invariant:
- Registries are loaded as JSON descriptors without importing experiment code.
  This keeps `runtime` usable from tooling/agents without side effects.

Non-goals / refusals:
- This module does not execute probes and does not interpret runtime evidence.
- It does not auto-heal registries; descriptor drift should be fixed at the
  source (the registry JSON and referenced files).

Registry JSON is the "index card" for runtime probes. Keeping it
data-only makes automation safer and reproducible.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple

from book.api import path_utils


REPO_ROOT = path_utils.find_repo_root(Path(__file__))
# Registry index stays in-repo; resolve once for consistent paths.
REGISTRY_INDEX = REPO_ROOT / "book" / "api" / "runtime" / "plans" / "registry" / "index.json"

INDEX_SCHEMA_VERSION = "runtime-tools.registry_index.v0.1"
PROBE_SCHEMA_VERSION = "runtime-tools.probe_registry.v0.1"
PROFILE_SCHEMA_VERSION = "runtime-tools.profile_registry.v0.1"


@dataclass(frozen=True)
class RegistryPaths:
    registry_id: str
    probes: Path
    profiles: Path
    description: Optional[str] = None


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text())


def load_registry_index(path: Optional[Path] = None) -> Dict[str, Any]:
    """Load the registry index file and validate its schema."""
    index_path = path_utils.ensure_absolute(path or REGISTRY_INDEX, REPO_ROOT)
    doc = _load_json(index_path)
    if doc.get("schema_version") != INDEX_SCHEMA_VERSION:
        raise ValueError(f"registry index schema mismatch: {doc.get('schema_version')}")
    return doc


def iter_registry_paths(index_doc: Optional[Dict[str, Any]] = None) -> Iterable[RegistryPaths]:
    """Yield registry path entries from the registry index document."""
    doc = index_doc or load_registry_index()
    for entry in doc.get("registries") or []:
        registry_id = entry.get("id")
        probes = entry.get("probes")
        profiles = entry.get("profiles")
        if not registry_id or not probes or not profiles:
            continue
        yield RegistryPaths(
            registry_id=registry_id,
            probes=path_utils.ensure_absolute(Path(probes), REPO_ROOT),
            profiles=path_utils.ensure_absolute(Path(profiles), REPO_ROOT),
            description=entry.get("description"),
        )


def _load_probe_registry(path: Path) -> Dict[str, Any]:
    doc = _load_json(path)
    if doc.get("schema_version") != PROBE_SCHEMA_VERSION:
        raise ValueError(f"probe registry schema mismatch: {doc.get('schema_version')}")
    return doc


def _load_profile_registry(path: Path) -> Dict[str, Any]:
    doc = _load_json(path)
    if doc.get("schema_version") != PROFILE_SCHEMA_VERSION:
        raise ValueError(f"profile registry schema mismatch: {doc.get('schema_version')}")
    return doc


def load_registry(registry_id: str, index_doc: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Load probes and profiles for a registry id."""
    for entry in iter_registry_paths(index_doc):
        if entry.registry_id == registry_id:
            probes = _load_probe_registry(entry.probes)
            profiles = _load_profile_registry(entry.profiles)
            return {
                "id": registry_id,
                "probes": probes.get("probes") or {},
                "profiles": profiles.get("profiles") or {},
                "probes_meta": probes,
                "profiles_meta": profiles,
            }
    raise KeyError(f"registry not found: {registry_id}")


def list_registries() -> list[RegistryPaths]:
    """Return registry path records from the registry index."""
    return list(iter_registry_paths())


def list_probes(registry_id: str) -> list[Dict[str, Any]]:
    """Return probe descriptors for a registry id."""
    reg = load_registry(registry_id)
    return list((reg.get("probes") or {}).values())


def list_profiles(registry_id: str) -> list[Dict[str, Any]]:
    """Return profile descriptors for a registry id."""
    reg = load_registry(registry_id)
    return list((reg.get("profiles") or {}).values())


def resolve_probe(registry_id: str, probe_id: str) -> Dict[str, Any]:
    """Resolve a probe descriptor by id within a registry."""
    reg = load_registry(registry_id)
    probe = (reg.get("probes") or {}).get(probe_id)
    if not probe:
        raise KeyError(f"probe not found: {registry_id}:{probe_id}")
    return probe


def resolve_profile(registry_id: str, profile_id: str) -> Dict[str, Any]:
    """Resolve a profile descriptor by id within a registry."""
    reg = load_registry(registry_id)
    profile = (reg.get("profiles") or {}).get(profile_id)
    if not profile:
        raise KeyError(f"profile not found: {registry_id}:{profile_id}")
    return profile


def lint_registry(registry_id: Optional[str] = None) -> Tuple[Optional[Dict[str, Any]], list[str]]:
    """Lint registry descriptors and return (index_doc, errors)."""
    errors: list[str] = []
    try:
        index_doc = load_registry_index()
    except Exception as exc:
        return None, [str(exc)]

    registries = [r for r in iter_registry_paths(index_doc) if not registry_id or r.registry_id == registry_id]
    if registry_id and not registries:
        return index_doc, [f"registry not found: {registry_id}"]

    for entry in registries:
        if not entry.probes.exists():
            errors.append(f"missing probes registry: {entry.registry_id}:{entry.probes}")
            continue
        if not entry.profiles.exists():
            errors.append(f"missing profiles registry: {entry.registry_id}:{entry.profiles}")
            continue

        try:
            probes_doc = _load_probe_registry(entry.probes)
        except Exception as exc:
            errors.append(f"probe registry error ({entry.registry_id}): {exc}")
            continue
        try:
            profiles_doc = _load_profile_registry(entry.profiles)
        except Exception as exc:
            errors.append(f"profile registry error ({entry.registry_id}): {exc}")
            continue

        probes = probes_doc.get("probes") or {}
        profiles = profiles_doc.get("profiles") or {}
        if not isinstance(probes, dict):
            errors.append(f"probes must be a dict ({entry.registry_id})")
        if not isinstance(profiles, dict):
            errors.append(f"profiles must be a dict ({entry.registry_id})")
        for probe_id, probe in probes.items():
            if probe.get("probe_id") != probe_id:
                errors.append(f"probe_id mismatch ({entry.registry_id}:{probe_id})")
            if not probe.get("operation"):
                errors.append(f"probe missing operation ({entry.registry_id}:{probe_id})")
        for profile_id, profile in profiles.items():
            if profile.get("profile_id") != profile_id:
                errors.append(f"profile_id mismatch ({entry.registry_id}:{profile_id})")
            profile_path = profile.get("profile_path")
            if not profile_path:
                errors.append(f"profile missing profile_path ({entry.registry_id}:{profile_id})")
            else:
                abs_path = path_utils.ensure_absolute(Path(profile_path), REPO_ROOT)
                if not abs_path.exists():
                    errors.append(f"profile_path missing ({entry.registry_id}:{profile_id} -> {profile_path})")
            probe_refs = profile.get("probe_refs") or []
            if not probe_refs:
                errors.append(f"profile has no probe_refs ({entry.registry_id}:{profile_id})")
            for probe_ref in probe_refs:
                if probe_ref not in probes:
                    errors.append(f"unknown probe_ref ({entry.registry_id}:{profile_id}:{probe_ref})")

    return index_doc, errors
