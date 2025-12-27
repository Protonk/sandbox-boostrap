"""
Data-driven registry for runtime probes and profiles.

Registry entries are JSON descriptors loaded without importing experiment code.
Probe/profile implementations are resolved only when a plan is compiled.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from book.api import path_utils


REPO_ROOT = path_utils.find_repo_root(Path(__file__))
REGISTRY_INDEX = REPO_ROOT / "book" / "api" / "runtime_tools" / "registry" / "index.json"

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
    index_path = path_utils.ensure_absolute(path or REGISTRY_INDEX, REPO_ROOT)
    doc = _load_json(index_path)
    if doc.get("schema_version") != INDEX_SCHEMA_VERSION:
        raise ValueError(f"registry index schema mismatch: {doc.get('schema_version')}")
    return doc


def iter_registry_paths(index_doc: Optional[Dict[str, Any]] = None) -> Iterable[RegistryPaths]:
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
    return list(iter_registry_paths())


def list_probes(registry_id: str) -> list[Dict[str, Any]]:
    reg = load_registry(registry_id)
    return list((reg.get("probes") or {}).values())


def list_profiles(registry_id: str) -> list[Dict[str, Any]]:
    reg = load_registry(registry_id)
    return list((reg.get("profiles") or {}).values())


def resolve_probe(registry_id: str, probe_id: str) -> Dict[str, Any]:
    reg = load_registry(registry_id)
    probe = (reg.get("probes") or {}).get(probe_id)
    if not probe:
        raise KeyError(f"probe not found: {registry_id}:{probe_id}")
    return probe


def resolve_profile(registry_id: str, profile_id: str) -> Dict[str, Any]:
    reg = load_registry(registry_id)
    profile = (reg.get("profiles") or {}).get(profile_id)
    if not profile:
        raise KeyError(f"profile not found: {registry_id}:{profile_id}")
    return profile

