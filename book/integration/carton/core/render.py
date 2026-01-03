"""Render registry definitions into spec artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

from book.integration.carton import paths
from book.integration.carton.core.models import Registry

SPEC_SCHEMA_VERSION = 1
FIXERS_SCHEMA_VERSION = 1
INVARIANTS_SCHEMA_VERSION = 1


def _write_json(path: Path, payload: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n")


def render_carton_spec(registry: Registry, world_id: str) -> Dict[str, object]:
    artifacts = []
    for art in registry.artifacts:
        entry: Dict[str, object] = {
            "id": art.id,
            "path": art.path,
            "role": art.role,
            "hash_mode": art.hash_mode,
        }
        if art.checks:
            entry["checks"] = art.checks
        if art.schema:
            entry["schema"] = art.schema
        artifacts.append(entry)
    return {
        "schema_version": SPEC_SCHEMA_VERSION,
        "name": "CARTON",
        "world_id": world_id,
        "artifacts": artifacts,
    }


def render_fixers_spec(registry: Registry, world_id: str) -> Dict[str, object]:
    fixers = []
    for job in registry.jobs_by_kind("fixer"):
        if not job.module or not job.function:
            continue
        fixers.append(
            {
                "id": job.id,
                "module": job.module,
                "function": job.function,
                "inputs": job.inputs,
                "outputs": job.outputs,
            }
        )
    return {
        "schema_version": FIXERS_SCHEMA_VERSION,
        "world_id": world_id,
        "fixers": fixers,
    }


def render_invariants(registry: Registry, world_id: str) -> Dict[str, object]:
    payload = dict(registry.invariants)
    payload["schema_version"] = INVARIANTS_SCHEMA_VERSION
    payload["world_id"] = world_id
    return payload


def write_specs(*, registry: Registry, world_id: str, repo_root: Path) -> None:
    spec_path = paths.ensure_absolute(paths.CARTON_SPEC, repo_root_path=repo_root)
    fixers_path = paths.ensure_absolute(paths.FIXERS_SPEC, repo_root_path=repo_root)
    invariants_path = paths.ensure_absolute(paths.INVARIANTS_SPEC, repo_root_path=repo_root)

    _write_json(spec_path, render_carton_spec(registry, world_id))
    _write_json(fixers_path, render_fixers_spec(registry, world_id))
    _write_json(invariants_path, render_invariants(registry, world_id))
