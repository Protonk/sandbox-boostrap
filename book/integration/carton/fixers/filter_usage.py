#!/usr/bin/env python3
"""Generate filter usage relationships from CARTON inputs."""

from __future__ import annotations

from typing import Any, Dict, List

from book.integration.carton.fixers import common

ROOT = common.repo_root()
FILTERS_PATH = ROOT / "book/integration/carton/bundle/relationships/mappings/vocab/filters.json"
DIGESTS_PATH = ROOT / "book/integration/carton/bundle/relationships/mappings/system_profiles/digests.json"
MANIFEST_PATH = ROOT / "book/integration/carton/bundle/CARTON.json"
OUT_PATH = ROOT / "book/integration/carton/bundle/relationships/filter_usage.json"


def build() -> Dict[str, Any]:
    filters = common.load_json(FILTERS_PATH)
    digests = common.load_json(DIGESTS_PATH)
    baseline = common.baseline_ref(repo_root_path=ROOT)
    world_id = baseline["world_id"]
    common.assert_world_compatible(world_id, digests.get("metadata"), "system_digests")
    canonical_status = (digests.get("metadata") or {}).get("status") or "unknown"

    entries: Dict[str, dict] = {}
    for entry in sorted(filters.get("filters") or [], key=lambda e: e.get("name", "")):
        name = entry.get("name")
        filter_id = entry.get("id")
        if name is None or filter_id is None:
            raise ValueError("filter vocab entry missing name or id")
        entries[name] = {
            "name": name,
            "id": filter_id,
            "usage_status": "present-in-vocab-only",
            "system_profiles": [],
            "known": True,
        }

    inputs: List[str] = [
        common.repo_relative(FILTERS_PATH, repo_root_path=ROOT),
        common.repo_relative(DIGESTS_PATH, repo_root_path=ROOT),
        common.repo_relative(MANIFEST_PATH, repo_root_path=ROOT),
    ]

    return {
        "metadata": {
            "world_id": world_id,
            "inputs": inputs,
            "source_jobs": digests.get("metadata", {}).get("source_jobs") or [],
            "status": canonical_status,
            "notes": "Filter vocab promoted into CARTON with explicit usage_status; usage wiring remains conservative.",
        },
        "filters": entries,
    }


def run() -> None:
    doc = build()
    common.write_json(OUT_PATH, doc)
    print(f"[+] wrote {OUT_PATH}")


if __name__ == "__main__":
    run()
