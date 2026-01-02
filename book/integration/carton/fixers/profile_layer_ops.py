#!/usr/bin/env python3
"""Generate profile_layer_ops relationship from CARTON inputs."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from book.api import evidence_tiers
from book.integration.carton.fixers import common

ROOT = common.repo_root()
DIGESTS_PATH = ROOT / "book/evidence/graph/mappings/system_profiles/digests.json"
VOCAB_PATH = ROOT / "book/evidence/graph/mappings/vocab/ops.json"
COVERAGE_PATH = ROOT / "book/integration/carton/bundle/relationships/operation_coverage.json"
MANIFEST_PATH = ROOT / "book/integration/carton/bundle/CARTON.json"
OUT_PATH = ROOT / "book/integration/carton/bundle/relationships/profile_layer_ops.json"


def build() -> Dict[str, Any]:
    digests = common.load_json(DIGESTS_PATH)
    vocab = common.load_json(VOCAB_PATH)
    coverage = common.load_json(COVERAGE_PATH)
    ops = vocab.get("ops") or []
    id_to_name = {entry["id"]: entry["name"] for entry in ops if "id" in entry and "name" in entry}

    baseline = common.baseline_ref(repo_root_path=ROOT)
    world_id = baseline["world_id"]
    common.assert_world_compatible(world_id, digests.get("metadata"), "system_digests")
    common.assert_world_compatible(world_id, coverage.get("metadata"), "coverage")

    inputs: List[str] = [
        common.repo_relative(DIGESTS_PATH, repo_root_path=ROOT),
        common.repo_relative(VOCAB_PATH, repo_root_path=ROOT),
        common.repo_relative(COVERAGE_PATH, repo_root_path=ROOT),
        common.repo_relative(MANIFEST_PATH, repo_root_path=ROOT),
    ]
    meta = digests.get("metadata") or {}
    source_jobs = meta.get("source_jobs") or []
    coverage_status = (coverage.get("metadata") or {}).get("status") or "unknown"
    raw_canonical = (digests.get("metadata") or {}).get("canonical_profiles") or {}
    canonical_status = {
        pid: (info.get("status") if isinstance(info, dict) else info) for pid, info in raw_canonical.items()
    }

    profiles: Dict[str, dict] = {}
    for profile_id, val in (digests.get("profiles") or {k: v for k, v in digests.items() if k != "metadata"}).items():
        op_ids = sorted(set(val.get("op_table") or []))
        ops_list = []
        for op_id in op_ids:
            name = id_to_name.get(op_id)
            if name is None:
                raise ValueError(f"op id {op_id} not found in vocab for profile {profile_id}")
            ops_list.append({"name": name, "id": op_id})
        profiles[profile_id] = {
            "id": profile_id,
            "layer": "system",
            "status": val.get("status") or "unknown",
            "ops": ops_list,
        }

    return {
        "metadata": {
            "world_id": world_id,
            "inputs": inputs,
            "source_jobs": source_jobs,
            "status": coverage_status,
            "tier": evidence_tiers.evidence_tier_for_artifact(
                path=OUT_PATH,
                tier="mapped",
            ),
            "canonical_profile_status": canonical_status,
            "notes": "Derived from CARTON system digests and coverage; expresses profile-layer → op relationships.",
        },
        "profiles": dict(sorted(profiles.items(), key=lambda kv: kv[0])),
    }


def run() -> None:
    doc = build()
    common.write_json(OUT_PATH, doc)
    print(f"[+] wrote {OUT_PATH}")


if __name__ == "__main__":
    run()
