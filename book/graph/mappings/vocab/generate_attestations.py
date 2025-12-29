#!/usr/bin/env python3
"""
Generate vocab attestation manifest tying ops/filters to their provenance.

Inputs:
- book/graph/mappings/vocab/ops.json
- book/graph/mappings/vocab/filters.json
- book/graph/concepts/validation/out/metadata.json (host/build)
- optional compiled blobs to sanity check counts (airlock/bsd/sample)

Outputs:
- book/graph/mappings/vocab/attestations.json
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List
import subprocess
import sys

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.profile import digests as digests_mod  # type: ignore
from book.api import world as world_mod  # type: ignore
OUT_PATH = REPO_ROOT / "book/graph/mappings/vocab/attestations.json"
VALIDATION_STATUS = REPO_ROOT / "book/graph/concepts/validation/out/validation_status.json"
VALIDATION_JOB_ID = "vocab:sonoma-14.4.1"
def load_baseline() -> Dict[str, Any]:
    data, resolution = world_mod.load_world(repo_root=REPO_ROOT)
    world_id = world_mod.require_world_id(data, world_path=resolution.entry.world_path)
    data["world_id"] = world_id
    data["host_ref"] = world_mod.world_path_for_metadata(resolution, repo_root=REPO_ROOT)
    return data


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def blob_hashes(paths: List[Path]) -> List[Dict[str, Any]]:
    rows = []
    for p in paths:
        if not p.exists():
            continue
        rows.append({"path": str(p.relative_to(REPO_ROOT)), "sha256": sha256(p), "size": p.stat().st_size})
    return rows


def run_validation_job(job_id: str) -> None:
    """Invoke the validation driver for the given job id and gate on status."""
    cmd = [sys.executable, "-m", "book.graph.concepts.validation", "--id", job_id]
    subprocess.check_call(cmd, cwd=REPO_ROOT)
    if not VALIDATION_STATUS.exists():
        raise SystemExit(f"validation status missing after running {cmd}")
    status = json.loads(VALIDATION_STATUS.read_text())
    jobs = {j.get("job_id") or j.get("id"): j for j in status.get("jobs", [])}
    job = jobs.get(job_id)
    if not job:
        raise SystemExit(f"validation job {job_id} missing from validation_status.json")
    status = job.get("status") or ""
    if status != "ok":
        raise SystemExit(f"validation job {job_id} not ok: {status}")
    # Simple freshness check: status file must be newer than libsandbox slice.
    lib_path = REPO_ROOT / "book/graph/mappings/dyld-libs/usr/lib/libsandbox.1.dylib"
    if lib_path.exists():
        if VALIDATION_STATUS.stat().st_mtime < lib_path.stat().st_mtime:
            raise SystemExit(f"validation status older than libsandbox slice for {job_id}")


def main() -> None:
    run_validation_job(VALIDATION_JOB_ID)
    baseline = load_baseline()
    meta = load_json(REPO_ROOT / "book/graph/concepts/validation/out/metadata.json")
    ops = load_json(REPO_ROOT / "book/graph/mappings/vocab/ops.json")
    filters = load_json(REPO_ROOT / "book/graph/mappings/vocab/filters.json")

    ops_src = blob_hashes(
        [
            REPO_ROOT / "book/graph/mappings/dyld-libs/usr/lib/libsandbox.1.dylib",
        ]
    )
    filt_src = blob_hashes(
        [
            REPO_ROOT / "book/graph/mappings/dyld-libs/usr/lib/libsandbox.1.dylib",
        ]
    )
    canonical = digests_mod.canonical_system_profile_blobs(REPO_ROOT)
    compiled_refs = blob_hashes(
        [canonical["airlock"], canonical["bsd"], canonical["sample"]]
    )

    manifest = {
        "metadata": {
            "world_id": baseline["world_id"],
            "sip_status": meta.get("sip_status"),
            "notes": "Attestation links vocab tables to dyld slices and reference blobs for this host/build.",
        },
        "ops": {
            "count": len(ops.get("ops", [])),
            "source": ops.get("ops", [{}])[0].get("source"),
            "hash": sha256(REPO_ROOT / "book/graph/mappings/vocab/ops.json"),
            "sources": ops_src,
        },
        "filters": {
            "count": len(filters.get("filters", [])),
            "source": filters.get("filters", [{}])[0].get("source"),
            "hash": sha256(REPO_ROOT / "book/graph/mappings/vocab/filters.json"),
            "sources": filt_src,
        },
        "compiled_reference_blobs": compiled_refs,
    }

    OUT_PATH.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    print(f"[+] wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
