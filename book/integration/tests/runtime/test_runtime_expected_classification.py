from book.integration.carton.mappings.runtime.generate_runtime_signatures import classify_expected
from book.integration.carton.mappings.runtime.generate_runtime_signatures import build_from_story


def test_classify_expected_covers_all_buckets():
    expected_matrix = {
        "profiles": {
            "p:ok": {"probes": [{"name": "ok", "operation": "file-read*"}]},
            "p:allow": {"probes": [{"name": "allow", "operation": "file-read*"}]},
            "p:disallow": {"probes": [{"name": "disallow", "operation": "file-read*"}]},
            "p:uncovered": {"probes": [{"name": "uncov", "operation": "file-read*"}]},
        }
    }
    expectation_index = {
        "p:ok:ok": {"scenario_id": "s-ok", "op_name": "file-read*", "mismatch": False, "allowed": True},
        "p:allow:allow": {"scenario_id": "s-allow", "op_name": "file-read*", "mismatch": True, "allowed": True},
        "p:disallow:disallow": {"scenario_id": "s-disallow", "op_name": "file-read*", "mismatch": True, "allowed": False},
    }

    classified, summary = classify_expected(expected_matrix, expectation_index)

    # Per-probe classifications
    profiles = classified["profiles"]
    assert profiles["p:ok"]["probes"][0]["classification"] == "covered_ok"
    assert profiles["p:allow"]["probes"][0]["classification"] == "covered_mismatch_allowed"
    assert profiles["p:disallow"]["probes"][0]["classification"] == "covered_mismatch_disallowed"
    assert profiles["p:uncovered"]["probes"][0]["classification"] == "uncovered"

    # Summary should count each bucket once and compute ratio
    counts = summary["file-read*"]
    assert counts["covered_ok"] == 1
    assert counts["covered_mismatch_allowed"] == 1
    assert counts["covered_mismatch_disallowed"] == 1
    assert counts["uncovered"] == 1
    assert counts["total_expected_rows"] == 4
    assert counts["covered_rows"] == 3
    assert counts["coverage_ratio"] == 0.75


def test_runtime_only_scenario_flagged_and_tolerated():
    story = {
        "ops": {
            "21": {
                "op_name": "file-read*",
                "op_id": 21,
                "scenarios": [
                    {
                        "scenario_id": "runtime-only-scenario",
                        "profile_id": "adv:runtime_only",
                        "expectations": [],
                        "mismatches": [],
                        "results": {},
                    }
                ],
            }
        }
    }
    coverage = {
        "coverage": {
            "file-read*": {
                "op_id": 21,
                "runtime_signatures": ["runtime-only-scenario"],
                "status": "ok",
                "mismatches": [],
            }
        },
        "metadata": {"status": "ok"},
    }

    scenarios, profiles, expectation_index, disallowed = build_from_story(story, coverage, {})

    assert "runtime-only-scenario" in scenarios
    scenario = scenarios["runtime-only-scenario"]
    assert scenario["runtime_only"] is True
    assert scenario["expected_row_ids"] == []
    assert not expectation_index
    assert not profiles
    assert not disallowed
