import json
from pathlib import Path

from book.api import evidence_tiers


from book.api import path_utils
from book.integration.tests.runtime.runtime_bundle_helpers import load_bundle_json

ROOT = path_utils.find_repo_root(Path(__file__))
BASELINE = ROOT / "book" / "world" / "sonoma-14.4.1-23E224-arm64" / "world.json"
VALIDATION_STATUS = (
    ROOT / "book" / "evidence" / "graph" / "concepts" / "validation" / "out" / "validation_status.json"
)

STATUS_TARGETS = [
    ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "system_profiles" / "digests.json",
    ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "system_profiles" / "static_checks.json",
    ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "system_profiles" / "attestations.json",
    ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "vocab" / "ops.json",
    ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "vocab" / "filters.json",
    ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "vocab" / "ops_coverage.json",
    ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "runtime" / "runtime_signatures.json",
    ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "runtime" / "runtime_coverage.json",
    ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "runtime" / "expectations.json",
]
RUNTIME_STATUS_TARGETS = {
    ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "runtime" / "runtime_signatures.json",
    ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "runtime" / "runtime_coverage.json",
    ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "runtime" / "expectations.json",
}

# These jobs should remain ok/ok-*; a downgrade is treated as a regression on this world.
# Validation status currently tracks a minimal subset; runtime checks are guarded separately.
REQUIRED_JOBS = {
    "experiment:system-profile-digest",
}
ALLOWED_TIERS = set(evidence_tiers.EVIDENCE_TIERS)


def load_json(path: Path):
    assert path.exists(), f"missing required file: {path}"
    return json.loads(path.read_text())


def test_status_regressions():
    failures: list[str] = []

    world_id = load_json(BASELINE).get("world_id")
    assert world_id, "baseline world_id missing"
    for path in STATUS_TARGETS:
        doc = load_json(path)
        meta = doc.get("metadata") or doc.get("meta") or {}
        if meta.get("world_id") != world_id:
            failures.append(f"{path} world mismatch")
            continue
        status = meta.get("status")
        rel = str(path.relative_to(ROOT))
        tier = meta.get("tier")
        if tier not in evidence_tiers.EVIDENCE_TIERS:
            failures.append(f"{rel} missing/invalid tier: {tier!r}")
            continue
        expected_tier = evidence_tiers.evidence_tier_for_artifact(path=rel, tier=tier)
        if tier != expected_tier:
            failures.append(f"{rel} tier mismatch (expected {expected_tier}, got {tier})")
            continue
        if path in RUNTIME_STATUS_TARGETS:
            if status not in {"ok", "partial", "brittle", "blocked"}:
                failures.append(f"{path} status missing or invalid")
        else:
            if status != "ok":
                failures.append(f"{path} status regressed from ok")

    status_doc = load_json(VALIDATION_STATUS)
    jobs = {entry.get("job_id") or entry.get("id"): entry for entry in status_doc.get("jobs", [])}
    for job_id in REQUIRED_JOBS:
        entry = jobs.get(job_id)
        if not entry:
            failures.append(f"validation job missing: {job_id}")
            continue
        job_status = str(entry.get("status", ""))
        if job_status != "ok":
            failures.append(f"validation job {job_id} not ok (status={job_status})")
        if entry.get("tier") not in ALLOWED_TIERS:
            failures.append(f"validation job {job_id} missing/invalid tier: {entry.get('tier')!r}")

    runtime_sig = load_json(ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "runtime" / "runtime_signatures.json")
    meta = runtime_sig.get("metadata") or {}
    if meta.get("status") != "ok":
        # If already partial/brittle, let other tests handle it.
        assert not failures, "\n".join(failures)
        return
    runtime_adv_out = (
        ROOT / "book" / "evidence" / "experiments" / "runtime-final-final" / "suites" / "runtime-adversarial" / "out"
    )
    try:
        mismatch_doc = load_bundle_json(runtime_adv_out, "mismatch_summary.json")
    except AssertionError:
        assert not failures, "\n".join(failures)
        return
    mismatches = mismatch_doc.get("mismatches") or []
    if not mismatches:
        assert not failures, "\n".join(failures)
        return

    impact_map_path = (
        ROOT
        / "book"
        / "evidence"
        / "experiments"
        / "runtime-final-final"
        / "suites"
        / "runtime-adversarial"
        / "out"
        / "impact_map.json"
    )
    impact_map = load_json(impact_map_path) if impact_map_path.exists() else {}

    allowed_tags = set((impact_map.get("metadata") or {}).get("allowed_tags") or [])

    def mismatch_allowed(eid: str) -> bool:
        entry = impact_map.get(eid) or {}
        tags = set(entry.get("tags") or [])
        return bool(allowed_tags and tags and tags.issubset(allowed_tags))

    disallowed = [m for m in mismatches if not mismatch_allowed(m.get("expectation_id", ""))]
    if disallowed:
        failures.append(f"runtime_signatures is ok but disallowed mismatches are present: {disallowed}")

    assert not failures, "\n".join(failures)
