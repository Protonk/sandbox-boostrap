#!/usr/bin/env python3
"""
Regenerate system profile digests mapping from validation IR only.

Inputs:
- book/evidence/graph/concepts/validation/out/experiments/system-profile-digest/digests_ir.json

Flow:
- Run validation driver with tag `system-profiles` (and smoke for dependencies).
- Require job experiment:system-profile-digest to be ok.
- Write book/integration/carton/bundle/relationships/mappings/system_profiles/digests.json with host metadata and source_jobs.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[5]
SCRIPT_ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api import world as world_mod  # noqa: E402

IR_PATH = (
    ROOT
    / "book"
    / "evidence"
    / "graph"
    / "concepts"
    / "validation"
    / "out"
    / "experiments"
    / "system-profile-digest"
    / "digests_ir.json"
)
STATUS_PATH = ROOT / "book" / "evidence" / "graph" / "concepts" / "validation" / "out" / "validation_status.json"
OUT_PATH = ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "system_profiles" / "digests.json"
STATIC_CHECKS_PATH = ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "system_profiles" / "static_checks.json"
EXPECTED_JOB = "experiment:system-profile-digest"
# Canonical profiles are the baseline policy layers for this host. They are not a
# mutable set: each entry pins a specific profile id, its descriptive role, and
# (optionally) the SBPL source used to sanity-check the blob when present.
#
# Contract version bumps are used when a deliberate decoder framing change
# (e.g. node slicing / tag layout hash) invalidates previously published
# expectations for the canonical trio on this world baseline.
CONTRACT_VERSION = 2
CANONICAL_PROFILES: Dict[str, Dict[str, Optional[str]]] = {
    "sys:airlock": {"role": "canonical-system-profile", "description": "Platform airlock baseline", "sbpl_path": None},
    "sys:bsd": {"role": "canonical-system-profile", "description": "Platform bsd baseline", "sbpl_path": None},
    "sys:sample": {
        "role": "canonical-system-profile",
        "description": "Book sample profile",
        "sbpl_path": "book/tools/sbpl/corpus/baseline/sample.sb",
    },
}
# Each contract must carry these fields so downstream tools can answer “what
# exactly were we expecting for this world pointer?” without rereading the code.
# The world_id here is a pointer back to the fixed host baseline, not a knob we
# ever mint or change inside the generator.
CONTRACT_FIELDS = [
    "contract_version",
    "sbpl_hash",
    "blob_sha256",
    "blob_size",
    "op_table_hash",
    "op_table_len",
    "tag_counts",
    "tag_layout_hash",
    "world_id",
]


def run_validation():
    cmd = [sys.executable, "-m", "book.graph.concepts.validation", "--tag", "system-profiles"]
    subprocess.check_call(cmd, cwd=ROOT)


def run_static_checks() -> None:
    script = SCRIPT_ROOT / "generate_static_checks.py"
    subprocess.check_call([sys.executable, str(script)], cwd=ROOT)


def load_status(job_id: str) -> Dict[str, Any]:
    status = json.loads(STATUS_PATH.read_text())
    jobs = {j.get("job_id") or j.get("id"): j for j in status.get("jobs", [])}
    job = jobs.get(job_id)
    if not job:
        raise RuntimeError(f"job {job_id} missing from validation_status.json")
    if job.get("status") != "ok":
        raise RuntimeError(f"job {job_id} not ok: {job.get('status')}")
    return job


def load_ir(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"missing IR: {path}")
    return json.loads(path.read_text())


def load_existing_mapping() -> Dict[str, Any]:
    if not OUT_PATH.exists():
        return {}
    return json.loads(OUT_PATH.read_text())


def load_baseline_world() -> str:
    data, resolution = world_mod.load_world(repo_root=ROOT)
    return world_mod.require_world_id(data, world_path=resolution.entry.world_path)


def sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def load_static_checks() -> Tuple[Dict[str, Any], str]:
    if not STATIC_CHECKS_PATH.exists():
        raise FileNotFoundError(f"missing static checks: {STATIC_CHECKS_PATH}")
    data = json.loads(STATIC_CHECKS_PATH.read_text())
    entries = data.get("entries") or []
    by_path = {entry.get("path"): entry for entry in entries if isinstance(entry, dict)}
    tag_layout_hash = (data.get("metadata") or {}).get("tag_layout_hash") or data.get("tag_layout_hash")
    if not tag_layout_hash:
        raise RuntimeError("tag_layout_hash missing from static_checks.json")
    return by_path, tag_layout_hash


def observed_contract(
    profile_id: str, profile_body: Dict[str, Any], static_checks: Dict[str, Any], tag_layout_hash: str, world_id: str
) -> Dict[str, Any]:
    src = profile_body.get("source")
    if not src:
        raise RuntimeError(f"profile {profile_id} missing source path")
    compiled_path = (ROOT / src).resolve()
    if not compiled_path.exists():
        raise FileNotFoundError(f"missing compiled blob for {profile_id}: {compiled_path}")
    checks = static_checks.get(str(compiled_path.relative_to(ROOT)))
    if not checks:
        raise RuntimeError(f"no static checks entry for {profile_id} ({compiled_path})")
    op_table_hash = checks.get("op_table_hash")
    if not op_table_hash:
        raise RuntimeError(f"op_table_hash missing for {profile_id}")
    tag_counts = checks.get("tag_counts") or {}
    tag_counts = {str(k): v for k, v in tag_counts.items()}
    sbpl_path = CANONICAL_PROFILES.get(profile_id, {}).get("sbpl_path")
    sbpl_sha = None
    if sbpl_path:
        sb_path = ROOT / sbpl_path
        if sb_path.exists():
            sbpl_sha = sha256_path(sb_path)
    # The observed contract is the verbatim snapshot of what the host gives us
    # today. The world_id is passed through untouched to keep the contract
    # anchored to the baseline metadata rather than anything inferred here.
    return {
        "contract_version": CONTRACT_VERSION,
        "sbpl_hash": sbpl_sha,
        "blob_sha256": sha256_path(compiled_path),
        "blob_size": compiled_path.stat().st_size,
        "op_table_hash": op_table_hash,
        "op_table_len": checks.get("op_count_header") or len(profile_body.get("op_table") or []),
        "tag_counts": tag_counts,
        "tag_layout_hash": tag_layout_hash,
        "world_id": world_id,
    }


def compare_contract(contract: Dict[str, Any], observed: Dict[str, Any]) -> List[Dict[str, Any]]:
    drift: List[Dict[str, Any]] = []
    for field in CONTRACT_FIELDS:
        expected = contract.get(field)
        seen = observed.get(field)
        if expected != seen:
            drift.append({"field": field, "expected": expected, "observed": seen})
    return drift


def downgrade_status(current: str, drift: List[Dict[str, Any]], existing_reason: str | None) -> Tuple[str, str | None]:
    if not drift:
        return "ok", None
    downgrade_target = "brittle" if current in {"ok", None, ""} else current
    reason = existing_reason or f"contract drift on fields: {', '.join(d['field'] for d in drift)}"
    return downgrade_target, reason


def main() -> None:
    run_validation()
    run_static_checks()
    job = load_status(EXPECTED_JOB)
    ir = load_ir(IR_PATH)
    world_id = load_baseline_world()
    static_checks, tag_layout_hash = load_static_checks()
    existing = load_existing_mapping()
    existing_profiles = (existing.get("profiles") if isinstance(existing, dict) else None) or {}

    profiles = ir.get("profiles") or {}
    canonical_statuses: Dict[str, Dict[str, Any]] = {}
    out_profiles: Dict[str, Any] = {}

    for profile_id, meta in CANONICAL_PROFILES.items():
        if profile_id not in profiles:
            raise RuntimeError(f"canonical profile {profile_id} missing from digests IR")
        body = profiles[profile_id]
        observed = observed_contract(profile_id, body, static_checks, tag_layout_hash, world_id)
        existing_entry = existing_profiles.get(profile_id) or {}
        existing_contract = existing_entry.get("contract") or {}
        missing_fields = any(field not in existing_contract for field in CONTRACT_FIELDS)
        version_mismatch = existing_contract.get("contract_version") not in {None, CONTRACT_VERSION}
        # Prefer the stored contract (the published promise) when shape matches;
        # fall back to the freshly observed one when the file is incomplete or
        # from an older contract version.
        if missing_fields or version_mismatch:
            contract = observed
        else:
            contract = existing_contract
        contract.setdefault("contract_version", CONTRACT_VERSION)
        contract.setdefault("world_id", world_id)
        if contract.get("world_id") != world_id:
            # Canonical contracts are pointers to the frozen host. If a file on
            # disk claims a different world_id, treat that as corruption rather
            # than trying to “fix up” or mint a new world pointer here.
            raise RuntimeError(f"contract world mismatch for {profile_id}: {contract.get('world_id')} vs {world_id}")
        drift = compare_contract(contract, observed)
        status, downgrade_reason = downgrade_status(
            existing_entry.get("status") or "ok", drift, existing_entry.get("downgrade_reason")
        )
        # Persist both the degraded status and the list of drifted fields so
        # downstream mappings can echo the reason without re-running the probe.
        downgrade_meta = {"fields": [d["field"] for d in drift], "reason": downgrade_reason}
        canonical_statuses[profile_id] = {
            "status": status,
            "role": meta.get("role"),
            "world_id": world_id,
            "drift_fields": [d["field"] for d in drift],
            "downgrade_reason": downgrade_reason,
        }
        out_profiles[profile_id] = {
            **body,
            "id": profile_id,
            "profile_id": profile_id,
            "role": meta.get("role"),
            "description": meta.get("description"),
            "world_id": world_id,
            "status": status,
            "contract": contract,
            "observed": observed,
            "drift": drift,
            "downgrade": downgrade_meta,
        }

    aggregate_status = "ok"
    if any(entry["status"] != "ok" for entry in canonical_statuses.values()):
        aggregate_status = "brittle"

    mapping = {
        "metadata": {
            "world_id": world_id,
            "inputs": [str(IR_PATH.relative_to(ROOT)), str(STATIC_CHECKS_PATH.relative_to(ROOT))],
            "source_jobs": (ir.get("source_jobs") or []) + ["generator:system_profiles:static_checks"],
            "decoder": "book.api.profile.decoder",
            "status": aggregate_status,
            "canonical_profiles": canonical_statuses,
            "contract_fields": CONTRACT_FIELDS,
        },
        "profiles": out_profiles,
    }
    OUT_PATH.write_text(json.dumps(mapping, indent=2))
    print(f"[+] wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
