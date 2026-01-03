"""Inventory graph job wrapper."""

from __future__ import annotations

from pathlib import Path

from book.integration.carton.jobs import common


def run_inventory_graph(repo_root: Path) -> None:
    common.run_module("book.integration.carton.inventory.generate_inventory_graph", repo_root=repo_root)
