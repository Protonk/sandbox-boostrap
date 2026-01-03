"""Spec generation jobs."""

from __future__ import annotations

from pathlib import Path

from book.api import world as world_mod
from book.integration.carton.core import registry as registry_mod
from book.integration.carton.core import render


def write_specs(repo_root: Path) -> None:
    reg = registry_mod.build_registry()
    world_doc, resolution = world_mod.load_world(repo_root=repo_root)
    world_id = world_mod.require_world_id(world_doc, world_path=resolution.entry.world_path)
    render.write_specs(registry=reg, world_id=world_id, repo_root=repo_root)
