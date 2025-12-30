"""Shared helpers for CARTON fixers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from book.api import path_utils
from book.api import world as world_mod


def repo_root() -> Path:
    return path_utils.find_repo_root(Path(__file__))


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"missing input: {path}")
    return json.loads(path.read_text())


def write_json(path: Path, doc: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2) + "\n")


def baseline_world_id(*, repo_root_path: Path) -> str:
    data, resolution = world_mod.load_world(repo_root=repo_root_path)
    return world_mod.require_world_id(data, world_path=resolution.entry.world_path)


def baseline_ref(*, repo_root_path: Path) -> Dict[str, str]:
    data, resolution = world_mod.load_world(repo_root=repo_root_path)
    world_id = world_mod.require_world_id(data, world_path=resolution.entry.world_path)
    return {
        "host": world_mod.world_path_for_metadata(resolution, repo_root=repo_root_path),
        "world_id": world_id,
    }


def assert_world_compatible(baseline_world: str, other: dict | str | None, label: str) -> None:
    if not other:
        return
    other_world = other.get("world_id") if isinstance(other, dict) else other
    if other_world and other_world != baseline_world:
        raise RuntimeError(f"world_id mismatch for {label}: baseline {baseline_world} vs {other_world}")


def repo_relative(path: Path, *, repo_root_path: Path) -> str:
    return path_utils.to_repo_relative(path, repo_root=repo_root_path)
