import json
from pathlib import Path


from book.api import path_utils

ROOT = path_utils.find_repo_root(Path(__file__))
MANIFEST = ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "runtime" / "lifecycle.json"
STORY = ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "runtime" / "lifecycle_story.json"
COVERAGE = ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "runtime" / "lifecycle_coverage.json"


def load(path: Path):
    assert path.exists(), f"missing required file: {path}"
    return json.loads(path.read_text())


def scenario_ids_from_manifest(manifest_doc):
    return {entry.get("scenario_id") for entry in manifest_doc.get("scenarios") or [] if entry.get("scenario_id")}


def test_lifecycle_story_coverage_parity():
    manifest = load(MANIFEST)
    story = load(STORY)
    coverage = load(COVERAGE)

    world = manifest.get("metadata", {}).get("world_id")
    assert world
    assert (story.get("metadata") or {}).get("world_id") == world
    assert (coverage.get("metadata") or {}).get("world_id") == world

    manifest_ids = scenario_ids_from_manifest(manifest)
    story_ids = set((story.get("scenarios") or {}).keys())
    coverage_ids = set((coverage.get("coverage") or {}).keys())

    assert manifest_ids == story_ids == coverage_ids, "lifecycle scenario ids diverged across manifest/story/coverage"

    for sid, scenario in (story.get("scenarios") or {}).items():
        cov_entry = (coverage.get("coverage") or {}).get(sid) or {}
        mismatches = scenario.get("mismatches") or []
        cov_mismatches = cov_entry.get("mismatches") or []
        assert mismatches == cov_mismatches, f"mismatches not mirrored in coverage for {sid}"

        status = cov_entry.get("status")
        if scenario.get("classification") == "present_ok":
            assert status == "ok"
        else:
            assert status != "ok", f"{sid} should not exceed ok when classification is {scenario.get('classification')}"

        # static reference should be present for traceability
        assert scenario.get("static_ref"), f"{sid} missing static_ref back-pointer"


def test_lifecycle_coverage_summaries():
    coverage = load(COVERAGE)
    summary = (coverage.get("metadata") or {}).get("mismatch_summary") or {}
    total = summary.get("total_mismatches")
    assert total is not None, "lifecycle coverage missing mismatch summary totals"
    # recompute from coverage entries
    recomputed = sum(len(entry.get("mismatches") or []) for entry in (coverage.get("coverage") or {}).values())
    assert total == recomputed, "lifecycle mismatch summary totals do not match coverage entries"
