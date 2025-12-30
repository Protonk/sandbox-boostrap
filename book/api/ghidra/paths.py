"""Shared path constants for the Ghidra tooling surface.

These paths keep headless Ghidra operations confined to repo-local directories
so analysis runs are reproducible and do not touch global user settings. The
defaults are pinned to the Sonoma baseline build id.
"""

from __future__ import annotations

import json
from pathlib import Path


BASELINE_BUILD_ID_FALLBACK = "14.4.1-23E224"


REPO_ROOT = Path(__file__).resolve().parents[3]
BOOK_ROOT = REPO_ROOT / "book"
# Keep all Ghidra state under book/dumps/ to avoid polluting the user's global config.
DUMPS_ROOT = BOOK_ROOT / "dumps"
GHIDRA_ROOT = DUMPS_ROOT / "ghidra"
GHIDRA_PRIVATE_ROOT = GHIDRA_ROOT / "private"
SANDBOX_PRIVATE = GHIDRA_PRIVATE_ROOT / "aapl-restricted"
SANDBOX_OVERSIZE = GHIDRA_PRIVATE_ROOT / "oversize"
SCRIPTS_DIR = Path(__file__).resolve().parent / "scripts"
OUT_ROOT = GHIDRA_ROOT / "out"
KERNEL_SYMBOLS_OUT_ROOT = BOOK_ROOT / "experiments" / "kernel-symbols" / "out"
PROJECTS_ROOT = GHIDRA_ROOT / "projects"
TEMP_ROOT = GHIDRA_ROOT / "tmp"
def _derive_build_id_from_world(world: dict) -> str | None:
    host = world.get("host", {})
    version = host.get("version")
    build = host.get("build")
    if version and build:
        return f"{version}-{build}"
    world_id = world.get("world_id") or ""
    parts = world_id.split("-")
    if len(parts) >= 3:
        return f"{parts[1]}-{parts[2]}"
    return None


def _baseline_world_path() -> Path | None:
    registry_path = REPO_ROOT / "book" / "world" / "registry.json"
    if not registry_path.exists():
        return None
    try:
        registry = json.loads(registry_path.read_text())
    except json.JSONDecodeError:
        return None
    for entry in registry.get("worlds", []):
        if entry.get("kind") == "baseline":
            world_path = entry.get("world_path")
            if world_path:
                return REPO_ROOT / world_path
    return None


def _load_baseline_world() -> dict | None:
    world_path = _baseline_world_path()
    if not world_path or not world_path.exists():
        return None
    try:
        return json.loads(world_path.read_text())
    except json.JSONDecodeError:
        return None


def _derive_default_build_id() -> str:
    world = _load_baseline_world()
    if world:
        derived = _derive_build_id_from_world(world)
        if derived:
            return derived
    return BASELINE_BUILD_ID_FALLBACK


# Default build id matches the Sonoma baseline world; override only when rebaselining.
DEFAULT_BUILD_ID = _derive_default_build_id()
