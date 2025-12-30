import json
from pathlib import Path


from book.api import path_utils
ROOT = path_utils.find_repo_root(Path(__file__))
STORY = ROOT / "book" / "graph" / "mappings" / "runtime_cuts" / "runtime_story.json"
COVERAGE = ROOT / "book" / "graph" / "mappings" / "runtime" / "runtime_coverage.json"
SIGNATURES = ROOT / "book" / "graph" / "mappings" / "runtime" / "runtime_signatures.json"
EXPECTED_CATEGORIES = {
    "covered_ok",
    "covered_mismatch_allowed",
    "covered_mismatch_disallowed",
    "uncovered",
}


def load(path: Path):
    assert path.exists(), f"missing required file: {path}"
    return json.loads(path.read_text())


def scenario_ids_from_story(story_doc):
    ids = set()
    for op_entry in (story_doc.get("ops") or {}).values():
        for scenario in op_entry.get("scenarios") or []:
            sid = scenario.get("scenario_id")
            if sid:
                ids.add(sid)
    return ids


def test_runtime_story_coverage_signature_align():
    story_doc = load(STORY)
    coverage_doc = load(COVERAGE)
    signatures_doc = load(SIGNATURES)
    expected_doc = signatures_doc.get("expected_matrix") or {}
    expected_profiles = (expected_doc.get("profiles") or {})

    world = (story_doc.get("meta") or {}).get("world_id")
    assert world
    assert (coverage_doc.get("metadata") or {}).get("world_id") == world
    assert (signatures_doc.get("metadata") or {}).get("world_id") == world

    story_ids = scenario_ids_from_story(story_doc)
    coverage_ids = {
        sid for entry in (coverage_doc.get("coverage") or {}).values() for sid in entry.get("runtime_signatures") or []
    }
    signature_ids = set((signatures_doc.get("scenarios") or {}).keys())

    assert story_ids == coverage_ids == signature_ids, "runtime scenario ids diverged across story/coverage/signatures"

    coverage_map = coverage_doc.get("coverage") or {}
    for sid, entry in (signatures_doc.get("scenarios") or {}).items():
        op_name = entry.get("op_name")
        cov_entry = coverage_map.get(op_name) or {}
        cov_status = cov_entry.get("status")
        disallowed = set(entry.get("disallowed_mismatches") or [])
        cov_mismatches = set(cov_entry.get("mismatches") or [])

        if cov_status and cov_status != "ok":
            assert entry.get("status") == cov_status, f"{sid} status exceeds coverage status for {op_name}"
        assert disallowed.issubset(cov_mismatches), f"{sid} disallowed mismatches not reflected in coverage"

        # parity with story mismatches
        story_mismatches = set()
        for op in (story_doc.get("ops") or {}).values():
            for scenario in op.get("scenarios") or []:
                if scenario.get("scenario_id") == sid:
                    story_mismatches = {m.get("expectation_id") for m in scenario.get("mismatches") or [] if m.get("expectation_id")}
                    break
        assert set(entry.get("mismatches") or []) == story_mismatches, f"{sid} mismatch ids differ from story"

    # expected_matrix rows must be classified into a known bucket and reference scenarios when covered
    summary = signatures_doc.get("expected_summary") or {}
    for profile_id, profile in expected_profiles.items():
        for probe in profile.get("probes") or []:
            cls = probe.get("classification")
            assert cls in EXPECTED_CATEGORIES, f"{profile_id}:{probe.get('name')} missing classification"
            if cls != "uncovered":
                assert probe.get("scenario_id") in signature_ids, "covered probe missing scenario reference"
                # Covered probes should appear in the scenario's expected_row_ids
                scenario = (signatures_doc.get("scenarios") or {}).get(probe["scenario_id"]) or {}
                assert probe["expectation_id"] in (scenario.get("expected_row_ids") or []), (
                    f"{profile_id}:{probe.get('name')} not linked back from scenario"
                )
    # summary should be consistent with counts
    for op_name, counts in summary.items():
        total = counts.get("total_expected_rows")
        covered = counts.get("covered_rows")
        assert total is not None and covered is not None, f"missing summary counts for {op_name}"
        calc_total = (
            counts.get("covered_ok", 0)
            + counts.get("covered_mismatch_allowed", 0)
            + counts.get("covered_mismatch_disallowed", 0)
            + counts.get("uncovered", 0)
        )
        assert calc_total == total, f"summary total mismatch for {op_name}"
        ratio = counts.get("coverage_ratio")
        if total:
            assert abs(ratio - (covered / total)) < 1e-9, f"coverage_ratio mismatch for {op_name}"
