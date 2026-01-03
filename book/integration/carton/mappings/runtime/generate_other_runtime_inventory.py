#!/usr/bin/env python3
"""Validate hardened runtime inventory paths for the CARTON mapping layout."""

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

LEGACY_PREFIXES = ("book/graph/",)

REWRITE_PREFIXES = (
    ("book/graph/concepts/validation/", "book/integration/carton/validation/"),
    ("book/graph/swift/", "book/integration/carton/graph/swift/"),
    ("book/graph/mappings/", "book/integration/carton/mappings/"),
)

SPECIAL_REWRITES = {
    "book/graph/concepts/validation/Concept_map.md": "book/integration/carton/Concept_map.md",
    "book/graph/AGENTS.md": "book/integration/carton/graph/AGENTS.md",
}


def _iter_paths(doc: dict) -> Iterable[str]:
    for entry in doc.get("in_repo", []) or []:
        for path in entry.get("paths") or []:
            if isinstance(path, str):
                yield path
        for fentry in entry.get("files", []) or []:
            path = fentry.get("path")
            if isinstance(path, str):
                yield path

    for entry in doc.get("unclassified_hits", []) or []:
        path = entry.get("path")
        if isinstance(path, str):
            yield path


def _rewrite_path(path: str) -> str:
    if path in SPECIAL_REWRITES:
        return SPECIAL_REWRITES[path]
    for old_prefix, new_prefix in REWRITE_PREFIXES:
        if path.startswith(old_prefix):
            return f"{new_prefix}{path[len(old_prefix):]}"
    return path


def _rewrite_inventory(doc: dict) -> None:
    for entry in doc.get("in_repo", []) or []:
        paths = entry.get("paths")
        if isinstance(paths, list):
            entry["paths"] = [
                _rewrite_path(path) if isinstance(path, str) else path for path in paths
            ]
        files = entry.get("files")
        if isinstance(files, list):
            for fentry in files:
                if isinstance(fentry, dict):
                    path = fentry.get("path")
                    if isinstance(path, str):
                        fentry["path"] = _rewrite_path(path)

    for entry in doc.get("unclassified_hits", []) or []:
        if isinstance(entry, dict):
            path = entry.get("path")
            if isinstance(path, str):
                entry["path"] = _rewrite_path(path)


def _validate_inventory(doc: dict) -> None:
    legacy_paths = []
    for path in _iter_paths(doc):
        for prefix in LEGACY_PREFIXES:
            if path.startswith(prefix):
                legacy_paths.append(path)
                break
    if legacy_paths:
        sample = ", ".join(legacy_paths[:3])
        raise SystemExit(
            "inventory references legacy graph paths; "
            f"found {len(legacy_paths)} entries (sample: {sample})"
        )


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
    _rewrite_inventory(doc)
    _validate_inventory(doc)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(doc, indent=2, ensure_ascii=True) + "\n")

    rel_out = path_utils.to_repo_relative(out_path, repo_root=repo_root)
    print(f"[runtime-inventory] wrote {rel_out}")


if __name__ == "__main__":
    main()
