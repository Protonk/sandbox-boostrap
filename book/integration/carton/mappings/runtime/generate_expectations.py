#!/usr/bin/env python3
"""
Generate runtime/expectations.json from runtime story + traces.

Inputs:
- book/integration/carton/bundle/relationships/mappings/runtime_cuts/runtime_story.json
- book/integration/carton/bundle/relationships/mappings/runtime/traces/*.jsonl
- book/evidence/experiments/runtime-final-final/suites/runtime-adversarial/out/impact_map.json (for allowlisted mismatches)
- world baseline (host/world_id)

Status is downgraded to partial if any profile has disallowed mismatches.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Dict, Any, List

ROOT = Path(__file__).resolve().parents[5]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api import evidence_tiers  # noqa: E402
from book.api import world as world_mod  # noqa: E402
from book.api.runtime.bundles import reader as bundle_reader  # noqa: E402

RUNTIME_STORY = ROOT / "book/integration/carton/bundle/relationships/mappings/runtime_cuts/runtime_story.json"
IMPACT_MAP = ROOT / "book/evidence/experiments/runtime-final-final/suites/runtime-adversarial/out/impact_map.json"
OUT = ROOT / "book/integration/carton/bundle/relationships/mappings/runtime/expectations.json"


def resolve_run_manifest(bundle_root: Path) -> Path:
    try:
        bundle_dir, _ = bundle_reader.resolve_bundle_dir(bundle_root, repo_root=ROOT)
    except FileNotFoundError:
        bundle_dir = bundle_root
    return bundle_dir / "run_manifest.json"


RUN_MANIFEST_CHECKS = resolve_run_manifest(ROOT / "book/evidence/experiments/runtime-final-final/suites/runtime-checks/out")
RUN_MANIFEST_ADV = resolve_run_manifest(ROOT / "book/evidence/experiments/runtime-final-final/suites/runtime-adversarial/out")

TRACE_PATHS = {
    "runtime:allow_all": "book/integration/carton/bundle/relationships/mappings/runtime/traces/runtime_allow_all.jsonl",
    "runtime:metafilter_any": "book/integration/carton/bundle/relationships/mappings/runtime/traces/runtime_metafilter_any.jsonl",
    "bucket4:v1_read": "book/integration/carton/bundle/relationships/mappings/runtime/traces/bucket4_v1_read.jsonl",
    "bucket5:v11_read_subpath": "book/integration/carton/bundle/relationships/mappings/runtime/traces/bucket5_v11_read_subpath.jsonl",
}

PROFILE_BLOBS = {
    "runtime:allow_all": "book/profiles/golden-triple/allow_all.sb.bin",
    "runtime:metafilter_any": "book/profiles/golden-triple/metafilter_any.sb.bin",
    "bucket4:v1_read": "book/profiles/golden-triple/runtime_profiles/v1_read.bucket4_v1_read.runtime.sb",
    "bucket5:v11_read_subpath": "book/profiles/golden-triple/runtime_profiles/v11_read_subpath.bucket5_v11_read_subpath.runtime.sb",
}


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def require_clean_manifest(manifest: Dict[str, Any], label: str) -> None:
    channel = manifest.get("channel")
    if channel != "launchd_clean":
        raise RuntimeError(f"{label} run manifest is not clean: channel={channel!r}")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def baseline_world() -> str:
    data, resolution = world_mod.load_world(repo_root=ROOT)
    return world_mod.require_world_id(data, world_path=resolution.entry.world_path)


def count_trace_rows(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8") as fh:
        return sum(1 for _ in fh)


def allowed_mismatch(expectation_id: str, impact_map: Dict[str, Any]) -> bool:
    allowed_tags = set((impact_map.get("metadata") or {}).get("allowed_tags") or [])
    entry = impact_map.get(expectation_id) or {}
    tags = set(entry.get("tags") or [])
    return bool(allowed_tags and tags and tags.issubset(allowed_tags))


def gather_profile_results(story: Dict[str, Any], impact_map: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    results: Dict[str, Dict[str, Any]] = {}
    for op_entry in (story.get("ops") or {}).values():
        for scenario in op_entry.get("scenarios") or []:
            pid = scenario.get("profile_id")
            if not pid:
                continue
            bucket = results.setdefault(pid, {"total": 0, "mismatches": [], "allowed_mismatches": []})
            bucket["total"] += (scenario.get("results") or {}).get("total", len(scenario.get("expectations") or []))
            for mismatch in scenario.get("mismatches") or []:
                eid = mismatch.get("expectation_id") or ""
                if allowed_mismatch(eid, impact_map):
                    bucket["allowed_mismatches"].append(mismatch)
                else:
                    bucket["mismatches"].append(mismatch)
    return results


def build_profiles(story: Dict[str, Any], impact_map: Dict[str, Any]) -> List[Dict[str, Any]]:
    profiles: List[Dict[str, Any]] = []
    profile_results = gather_profile_results(story, impact_map)

    for profile_id, trace_rel in TRACE_PATHS.items():
        trace_path = ROOT / trace_rel
        blob_rel = PROFILE_BLOBS.get(profile_id)
        blob_path = ROOT / blob_rel if blob_rel else None
        sha = sha256(blob_path) if blob_path and blob_path.exists() else None
        profile_mode = None
        if blob_rel:
            profile_mode = "blob" if blob_rel.endswith(".bin") else "sbpl"

        res = profile_results.get(profile_id) or {}
        mismatches = res.get("mismatches") or []
        allowed = res.get("allowed_mismatches") or []
        status = "ok" if not mismatches else "partial"
        notes = None
        if mismatches:
            notes = f"{len(mismatches)} disallowed mismatches"
        elif allowed:
            notes = f"{len(allowed)} mismatches allowed by impact_map"

        profiles.append(
            {
                "profile_id": profile_id,
                "profile_path": blob_rel,
                "profile_sha256": sha,
                "profile_mode": profile_mode,
                "status": status,
                "probe_count": count_trace_rows(trace_path),
                "trace_path": trace_rel if trace_path.exists() else None,
                "notes": notes,
            }
        )
    return profiles


def main() -> None:
    world_id = baseline_world()
    story = load_json(RUNTIME_STORY)
    impact_map = load_json(IMPACT_MAP)
    run_manifest_checks = load_json(RUN_MANIFEST_CHECKS)
    if not run_manifest_checks:
        raise RuntimeError("missing runtime-checks run_manifest.json; run via launchctl clean channel")
    require_clean_manifest(run_manifest_checks, "runtime-checks")
    if IMPACT_MAP.exists():
        run_manifest_adv = load_json(RUN_MANIFEST_ADV)
        if not run_manifest_adv:
            raise RuntimeError("missing runtime-adversarial run_manifest.json; run via launchctl clean channel")
        require_clean_manifest(run_manifest_adv, "runtime-adversarial")

    profiles = build_profiles(story, impact_map)
    overall_status = "ok" if all(p.get("status") == "ok" for p in profiles) else "partial"

    inputs = [
        "book/integration/carton/bundle/relationships/mappings/runtime_cuts/runtime_story.json",
        "book/evidence/experiments/runtime-final-final/suites/runtime-adversarial/out/impact_map.json",
    ] + sorted(TRACE_PATHS.values())

    mapping = {
        "metadata": {
            "world_id": world_id,
            "inputs": inputs,
            "source_jobs": ["experiment:runtime-checks", "experiment:runtime-adversarial"],
            "status": overall_status,
            "tier": evidence_tiers.evidence_tier_for_artifact(
                path=OUT,
                tier="mapped",
            ),
            "notes": "Runtime expectations summarized from runtime cuts and traces; mismatches are allowed only when tagged in impact_map.json.",
        },
        "profiles": profiles,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(mapping, indent=2))
    print(f"[+] wrote {OUT}")


if __name__ == "__main__":
    main()
