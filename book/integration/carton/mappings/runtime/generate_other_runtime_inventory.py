#!/usr/bin/env python3
"""Normalize hardened runtime inventory paths for the CARTON mapping layout."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable

from book.api import path_utils

DEFAULT_SOURCE = (
    "book/evidence/experiments/runtime-final-final/suites/hardened-runtime/other_runtime_inventory.json"
)
DEFAULT_OUT = "book/integration/carton/bundle/relationships/mappings/runtime/other_runtime_inventory.json"

REWRITE_PREFIXES = (
    ("book/graph/mappings/", "book/integration/carton/mappings/"),
)


def _rewrite_path(path: str) -> str:
    for old, new in REWRITE_PREFIXES:
        if path.startswith(old):
            return f"{new}{path[len(old):]}"
    return path


def _rewrite_paths(paths: Iterable[str]) -> list[str]:
    return [_rewrite_path(p) if isinstance(p, str) else p for p in paths]


def _rewrite_inventory(doc: dict) -> dict:
    for entry in doc.get("in_repo", []) or []:
        paths = entry.get("paths")
        if isinstance(paths, list):
            entry["paths"] = _rewrite_paths(paths)
        for fentry in entry.get("files", []) or []:
            path = fentry.get("path")
            if isinstance(path, str):
                fentry["path"] = _rewrite_path(path)

    for entry in doc.get("unclassified_hits", []) or []:
        path = entry.get("path")
        if isinstance(path, str):
            entry["path"] = _rewrite_path(path)
    return doc


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Normalize hardened runtime inventory paths for CARTON mappings"
    )
    parser.add_argument(
        "--source",
        default=DEFAULT_SOURCE,
        help=f"source inventory JSON (default: {DEFAULT_SOURCE})",
    )
    parser.add_argument(
        "--out",
        default=DEFAULT_OUT,
        help=f"output JSON path (default: {DEFAULT_OUT})",
    )
    args = parser.parse_args(argv)

    repo_root = path_utils.find_repo_root(Path(__file__))
    source_path = path_utils.ensure_absolute(args.source, repo_root=repo_root)
    out_path = path_utils.ensure_absolute(args.out, repo_root=repo_root)

    doc = json.loads(source_path.read_text())
    doc = _rewrite_inventory(doc)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(doc, indent=2, ensure_ascii=True) + "\n")

    rel_out = path_utils.to_repo_relative(out_path, repo_root=repo_root)
    print(f"[runtime-inventory] wrote {rel_out}")


if __name__ == "__main__":
    main()
