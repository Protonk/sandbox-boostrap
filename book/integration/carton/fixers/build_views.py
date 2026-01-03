#!/usr/bin/env python3
"""Build CARTON view indices from relationship outputs."""

from __future__ import annotations

import copy
from typing import Any, Dict, List

from book.integration.carton.fixers import common

ROOT = common.repo_root()
OPS_PATH = ROOT / "book/integration/carton/bundle/relationships/mappings/vocab/ops.json"
DIGESTS_PATH = ROOT / "book/integration/carton/bundle/relationships/mappings/system_profiles/digests.json"
COVERAGE_PATH = ROOT / "book/integration/carton/bundle/relationships/operation_coverage.json"
MANIFEST_PATH = ROOT / "book/integration/carton/bundle/CARTON.json"

PROFILE_REL_PATH = ROOT / "book/integration/carton/bundle/relationships/profile_layer_ops.json"
FILTER_REL_PATH = ROOT / "book/integration/carton/bundle/relationships/filter_usage.json"
ANCHOR_REL_PATH = ROOT / "book/integration/carton/bundle/relationships/anchor_field2.json"
CONCEPT_REL_PATH = ROOT / "book/integration/carton/bundle/relationships/concept_sources.json"

OP_INDEX_PATH = ROOT / "book/integration/carton/bundle/views/operation_index.json"
PROFILE_INDEX_PATH = ROOT / "book/integration/carton/bundle/views/profile_layer_index.json"
FILTER_INDEX_PATH = ROOT / "book/integration/carton/bundle/views/filter_index.json"
ANCHOR_INDEX_PATH = ROOT / "book/integration/carton/bundle/views/anchor_index.json"
CONCEPT_INDEX_PATH = ROOT / "book/integration/carton/bundle/views/concept_index.json"


def _view_from_relationship(rel_path, out_path, *, note: str) -> Dict[str, Any]:
    doc = common.load_json(rel_path)
    view = copy.deepcopy(doc)
    meta = view.get("metadata") or {}
    meta["inputs"] = [
        common.repo_relative(rel_path, repo_root_path=ROOT),
        common.repo_relative(MANIFEST_PATH, repo_root_path=ROOT),
    ]
    meta["notes"] = note
    view["metadata"] = meta
    return view


def build_operation_index() -> Dict[str, Any]:
    vocab = common.load_json(OPS_PATH)
    coverage = common.load_json(COVERAGE_PATH)
    digests = common.load_json(DIGESTS_PATH)
    ops = vocab.get("ops") or []
    coverage_map: Dict[str, dict] = (coverage.get("coverage") or {})
    baseline = common.baseline_ref(repo_root_path=ROOT)
    world_id = baseline["world_id"]
    common.assert_world_compatible(world_id, coverage.get("metadata"), "coverage")
    common.assert_world_compatible(world_id, digests.get("metadata"), "system_digests")

    inputs: List[str] = [
        common.repo_relative(OPS_PATH, repo_root_path=ROOT),
        common.repo_relative(DIGESTS_PATH, repo_root_path=ROOT),
        common.repo_relative(COVERAGE_PATH, repo_root_path=ROOT),
        common.repo_relative(MANIFEST_PATH, repo_root_path=ROOT),
    ]
    meta = coverage.get("metadata") or {}
    coverage_status = meta.get("status") or "unknown"
    source_jobs = meta.get("source_jobs") or []
    raw_canonical = meta.get("canonical_profile_status") or (digests.get("metadata") or {}).get("canonical_profiles") or {}
    canonical_status = {
        pid: (info.get("status") if isinstance(info, dict) else info) for pid, info in raw_canonical.items()
    }

    operations: Dict[str, dict] = {}
    for entry in ops:
        name = entry.get("name")
        op_id = entry.get("id")
        if name is None or op_id is None:
            raise ValueError("vocab entry missing name or id")
        cov = coverage_map.get(name) or {}
        counts = cov.get("counts") or {}
        system_profiles = cov.get("system_profiles") or []
        profile_layers = ["system"] if system_profiles else []
        operations[name] = {
            "name": name,
            "id": op_id,
            "profile_layers": profile_layers,
            "system_profiles": system_profiles,
            "system_profile_status": cov.get("system_profile_status") or {},
            "coverage_counts": {
                "system_profiles": counts.get("system_profiles", 0),
                "system_profiles_ok": counts.get("system_profiles_ok", 0),
            },
            "known": True,
        }

    return {
        "metadata": {
            "world_id": world_id,
            "inputs": inputs,
            "source_jobs": source_jobs,
            "status": coverage_status,
            "canonical_profile_status": canonical_status,
            "notes": "View derived from operation_coverage; expands coverage into per-operation index rows.",
        },
        "operations": dict(sorted(operations.items(), key=lambda kv: kv[0])),
    }


def build_profile_layer_index() -> Dict[str, Any]:
    return _view_from_relationship(
        PROFILE_REL_PATH,
        PROFILE_INDEX_PATH,
        note="View derived from profile_layer_ops relationship.",
    )


def build_filter_index() -> Dict[str, Any]:
    return _view_from_relationship(
        FILTER_REL_PATH,
        FILTER_INDEX_PATH,
        note="View derived from filter_usage relationship.",
    )


def build_anchor_index() -> Dict[str, Any]:
    return _view_from_relationship(
        ANCHOR_REL_PATH,
        ANCHOR_INDEX_PATH,
        note="View derived from anchor_field2 relationship.",
    )


def build_concept_index() -> Dict[str, Any]:
    return _view_from_relationship(
        CONCEPT_REL_PATH,
        CONCEPT_INDEX_PATH,
        note="View derived from concept_sources relationship.",
    )


def run() -> None:
    common.write_json(OP_INDEX_PATH, build_operation_index())
    common.write_json(PROFILE_INDEX_PATH, build_profile_layer_index())
    common.write_json(FILTER_INDEX_PATH, build_filter_index())
    common.write_json(ANCHOR_INDEX_PATH, build_anchor_index())
    common.write_json(CONCEPT_INDEX_PATH, build_concept_index())
    print(f"[+] wrote {OP_INDEX_PATH}")
    print(f"[+] wrote {PROFILE_INDEX_PATH}")
    print(f"[+] wrote {FILTER_INDEX_PATH}")
    print(f"[+] wrote {ANCHOR_INDEX_PATH}")
    print(f"[+] wrote {CONCEPT_INDEX_PATH}")


if __name__ == "__main__":
    run()
