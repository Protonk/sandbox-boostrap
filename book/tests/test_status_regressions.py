import json
from pathlib import Path

from book.api import evidence_tiers


ROOT = Path(__file__).resolve().parents[2]
BASELINE = ROOT / "book" / "world" / "sonoma-14.4.1-23E224-arm64" / "world.json"
VALIDATION_STATUS = ROOT / "book" / "graph" / "concepts" / "validation" / "out" / "validation_status.json"

STATUS_TARGETS = [
    ROOT / "book" / "graph" / "mappings" / "system_profiles" / "digests.json",
    ROOT / "book" / "graph" / "mappings" / "system_profiles" / "static_checks.json",
    ROOT / "book" / "graph" / "mappings" / "system_profiles" / "attestations.json",
    ROOT / "book" / "graph" / "mappings" / "vocab" / "ops.json",
    ROOT / "book" / "graph" / "mappings" / "vocab" / "filters.json",
    ROOT / "book" / "graph" / "mappings" / "vocab" / "ops_coverage.json",
    ROOT / "book" / "graph" / "mappings" / "runtime" / "runtime_signatures.json",
    ROOT / "book" / "graph" / "mappings" / "runtime" / "runtime_coverage.json",
    ROOT / "book" / "graph" / "mappings" / "runtime" / "expectations.json",
]
RUNTIME_STATUS_TARGETS = {
    ROOT / "book" / "graph" / "mappings" / "runtime" / "runtime_signatures.json",
    ROOT / "book" / "graph" / "mappings" / "runtime" / "runtime_coverage.json",
    ROOT / "book" / "graph" / "mappings" / "runtime" / "expectations.json",
}

# These jobs should remain ok/ok-*; a downgrade is treated as a regression on this world.
REQUIRED_JOBS = {
    "vocab:sonoma-14.4.1",
    "experiment:system-profile-digest",
    "experiment:runtime-checks",
    "experiment:field2",
}
ALLOWED_TIERS = set(evidence_tiers.EVIDENCE_TIERS)


def load_json(path: Path):
    assert path.exists(), f"missing required file: {path}"
    return json.loads(path.read_text())


def test_core_mappings_remain_ok_for_world():
    world_id = load_json(BASELINE).get("world_id")
    assert world_id, "baseline world_id missing"
    for path in STATUS_TARGETS:
        doc = load_json(path)
        meta = doc.get("metadata") or doc.get("meta") or {}
        assert meta.get("world_id") == world_id, f"{path} world mismatch"
        status = meta.get("status")
        rel = str(path.relative_to(ROOT))
        tier = meta.get("tier")
        assert tier in evidence_tiers.EVIDENCE_TIERS, f"{rel} missing/invalid tier: {tier!r}"
        expected_tier = evidence_tiers.evidence_tier_for_artifact(path=rel, tier=tier)
        assert tier == expected_tier, f"{rel} tier mismatch (expected {expected_tier}, got {tier})"
        if path in RUNTIME_STATUS_TARGETS:
            assert status in {"ok", "partial", "brittle", "blocked"}, f"{path} status missing or invalid"
        else:
            assert status == "ok", f"{path} status regressed from ok"


def test_validation_jobs_remain_ok():
    status_doc = load_json(VALIDATION_STATUS)
    jobs = {entry.get("job_id") or entry.get("id"): entry for entry in status_doc.get("jobs", [])}
    for job_id in REQUIRED_JOBS:
        entry = jobs.get(job_id)
        assert entry, f"validation job missing: {job_id}"
        job_status = str(entry.get("status", ""))
        assert job_status == "ok", f"validation job {job_id} not ok (status={job_status})"
        assert entry.get("tier") in ALLOWED_TIERS, f"validation job {job_id} missing/invalid tier: {entry.get('tier')!r}"


def test_runtime_ok_implies_no_mismatches():
    runtime_sig = load_json(ROOT / "book" / "graph" / "mappings" / "runtime" / "runtime_signatures.json")
    meta = runtime_sig.get("metadata") or {}
    if meta.get("status") != "ok":
        # If already partial/brittle, let other tests handle it.
        return
    mismatch_path = ROOT / "book" / "experiments" / "runtime-adversarial" / "out" / "mismatch_summary.json"
    if not mismatch_path.exists():
        return
    mismatches = load_json(mismatch_path).get("mismatches") or []
    if not mismatches:
        return

    impact_map_path = ROOT / "book" / "experiments" / "runtime-adversarial" / "out" / "impact_map.json"
    impact_map = load_json(impact_map_path) if impact_map_path.exists() else {}

    allowed_tags = set((impact_map.get("metadata") or {}).get("allowed_tags") or [])

    def mismatch_allowed(eid: str) -> bool:
        entry = impact_map.get(eid) or {}
        tags = set(entry.get("tags") or [])
        return bool(allowed_tags and tags and tags.issubset(allowed_tags))

    disallowed = [m for m in mismatches if not mismatch_allowed(m.get("expectation_id", ""))]
    assert not disallowed, f"runtime_signatures is ok but disallowed mismatches are present: {disallowed}"
