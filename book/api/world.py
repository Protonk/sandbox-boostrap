"""
World registry resolver helpers.

This module resolves world baselines via book/world/registry.json and returns
world.json paths + world_id for generators and tools.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from book.api import path_utils


REGISTRY_REL = Path("book/world/registry.json")
WORLD_JSON_NAME = "world.json"


class WorldRegistryError(RuntimeError):
    """Raised when the world registry is missing or malformed."""


class WorldResolutionError(RuntimeError):
    """Raised when a world reference cannot be resolved."""


@dataclass(frozen=True)
class WorldEntry:
    world_name: Optional[str]
    world_id: Optional[str]
    world_path: Path
    kind: Optional[str]


@dataclass(frozen=True)
class WorldResolution:
    entry: WorldEntry
    source: str
    registry_path: Optional[Path]


def _load_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise WorldRegistryError(f"missing json: {path}") from exc
    except json.JSONDecodeError as exc:
        raise WorldRegistryError(f"invalid json: {path}") from exc


def _world_entry_from_registry(entry: Dict[str, Any], repo_root: Path) -> WorldEntry:
    world_path = entry.get("world_path")
    if not isinstance(world_path, str) or not world_path:
        raise WorldRegistryError("registry entry missing world_path")
    abs_path = path_utils.ensure_absolute(Path(world_path), repo_root)
    return WorldEntry(
        world_name=entry.get("world_name"),
        world_id=entry.get("world_id"),
        world_path=abs_path,
        kind=entry.get("kind"),
    )


def load_registry(repo_root: Optional[Path] = None) -> Dict[str, Any]:
    root = repo_root or path_utils.find_repo_root(Path(__file__))
    registry_path = root / REGISTRY_REL
    return _load_json(registry_path)


def list_worlds(repo_root: Optional[Path] = None) -> list[WorldEntry]:
    root = repo_root or path_utils.find_repo_root(Path(__file__))
    registry = load_registry(root)
    entries = registry.get("worlds") or []
    worlds: list[WorldEntry] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        worlds.append(_world_entry_from_registry(entry, root))
    return worlds


def _resolve_default_world(repo_root: Path) -> WorldResolution:
    registry = load_registry(repo_root)
    entries = registry.get("worlds") or []
    baseline_entries: list[WorldEntry] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("kind") == "baseline":
            baseline_entries.append(_world_entry_from_registry(entry, repo_root))
    if not baseline_entries:
        raise WorldResolutionError("no baseline world in registry")
    if len(baseline_entries) > 1:
        names = [e.world_name for e in baseline_entries]
        raise WorldResolutionError(f"multiple baseline worlds in registry: {names}")
    return WorldResolution(entry=baseline_entries[0], source="registry_default", registry_path=repo_root / REGISTRY_REL)


def _resolve_world_path(path: Path) -> Path:
    if path.is_dir():
        direct = path / WORLD_JSON_NAME
        if direct.exists():
            return direct
        raise WorldResolutionError(f"world.json missing under {path}")
    if path.is_file():
        if path.name == WORLD_JSON_NAME:
            return path
        if path.name == "manifest.json" and path.parent.name == "dyld":
            world_dir = path.parent.parent
            return _resolve_world_path(world_dir)
    raise WorldResolutionError(f"unsupported world path: {path}")


def resolve_world(world_ref: Optional[str | Path] = None, *, repo_root: Optional[Path] = None) -> WorldResolution:
    root = repo_root or path_utils.find_repo_root(Path(__file__))
    if world_ref is None:
        return _resolve_default_world(root)
    if isinstance(world_ref, Path) or str(world_ref).startswith(("/", ".")):
        path = path_utils.ensure_absolute(Path(world_ref), root)
        world_path = _resolve_world_path(path)
        entry = WorldEntry(world_name=None, world_id=None, world_path=world_path, kind=None)
        return WorldResolution(entry=entry, source="path", registry_path=None)
    registry = load_registry(root)
    entries = registry.get("worlds") or []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("world_name") == world_ref or entry.get("world_id") == world_ref:
            return WorldResolution(
                entry=_world_entry_from_registry(entry, root),
                source="registry",
                registry_path=root / REGISTRY_REL,
            )
    raise WorldResolutionError(f"world not found in registry: {world_ref}")


def load_world(world_ref: Optional[str | Path] = None, *, repo_root: Optional[Path] = None) -> tuple[Dict[str, Any], WorldResolution]:
    root = repo_root or path_utils.find_repo_root(Path(__file__))
    resolution = resolve_world(world_ref, repo_root=root)
    data = _load_json(resolution.entry.world_path)
    return data, resolution


def require_world_id(world: Dict[str, Any], *, world_path: Path) -> str:
    world_id = world.get("world_id")
    if not world_id:
        rel = path_utils.to_repo_relative(world_path, repo_root=path_utils.find_repo_root(Path(__file__)))
        raise WorldResolutionError(f"world_id missing in {rel}")
    return str(world_id)


def world_path_for_metadata(resolution: WorldResolution, *, repo_root: Optional[Path] = None) -> str:
    root = repo_root or path_utils.find_repo_root(Path(__file__))
    return path_utils.to_repo_relative(resolution.entry.world_path, repo_root=root)


def world_registry_path(repo_root: Optional[Path] = None) -> Path:
    root = repo_root or path_utils.find_repo_root(Path(__file__))
    return root / REGISTRY_REL


def iter_world_paths(repo_root: Optional[Path] = None) -> Iterable[Path]:
    for entry in list_worlds(repo_root):
        yield entry.world_path
