#!/usr/bin/env python3
"""Derive operation ↔ system profile relationships from coverage."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from book.integration.carton.fixers import common

ROOT = common.repo_root()
COVERAGE_PATH = ROOT / "book/integration/carton/bundle/relationships/operation_coverage.json"
MANIFEST_PATH = ROOT / "book/integration/carton/bundle/CARTON.json"
OUT_PATH = ROOT / "book/integration/carton/bundle/relationships/operation_system_profiles.json"


def build() -> Dict[str, Any]:
    coverage_doc = common.load_json(COVERAGE_PATH)
    coverage = coverage_doc.get("coverage") or {}
    meta = coverage_doc.get("metadata") or {}
    world_id = meta.get("world_id")
    if not world_id:
        world_id = common.baseline_world_id(repo_root_path=ROOT)

    operations: Dict[str, Dict[str, Any]] = {}
    for name, entry in coverage.items():
        operations[name] = {
            "op_id": entry.get("op_id"),
            "system_profiles": entry.get("system_profiles") or [],
            "system_profile_status": entry.get("system_profile_status") or {},
        }

    with_profiles = sum(1 for entry in operations.values() if entry.get("system_profiles"))
    summary = {
        "ops_total": len(operations),
        "ops_with_system_profiles": with_profiles,
    }

    inputs = [
        common.repo_relative(COVERAGE_PATH, repo_root_path=ROOT),
        common.repo_relative(MANIFEST_PATH, repo_root_path=ROOT),
    ]

    return {
        "metadata": {
            "world_id": world_id,
            "inputs": inputs,
            "source_jobs": meta.get("source_jobs") or [],
            "status": meta.get("status") or "unknown",
            "notes": "Derived from operation_coverage; exposes operation ↔ system profile edges.",
        },
        "operations": dict(sorted(operations.items(), key=lambda kv: kv[0])),
        "summary": summary,
    }


def run() -> None:
    doc = build()
    common.write_json(OUT_PATH, doc)
    print(f"[+] wrote {OUT_PATH}")


if __name__ == "__main__":
    run()
