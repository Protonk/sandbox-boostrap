import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load_json(path: Path):
    assert path.exists(), f"missing expected file: {path}"
    return json.loads(path.read_text())


def test_vfs_expected_and_runtime_shapes():
    """Shape guardrail: expected_matrix.json and runtime_results.json exist and have basic structure."""
    exp_path = ROOT / "book" / "experiments" / "vfs-canonicalization" / "out" / "expected_matrix.json"
    res_path = ROOT / "book" / "experiments" / "vfs-canonicalization" / "out" / "runtime_results.json"
    expected = load_json(exp_path)
    results = load_json(res_path)

    assert isinstance(expected, list) and expected, "expected_matrix.json should be a non-empty list"
    for entry in expected:
        for key in ["profile_id", "operation", "requested_path", "expected_decision"]:
            assert key in entry, f"expected_matrix entry missing {key}"

    assert isinstance(results, list) and results, "runtime_results.json should be a non-empty list"
    for row in results:
        for key in ["profile_id", "operation", "requested_path", "observed_path", "decision"]:
            assert key in row, f"runtime_results entry missing {key}"

    expected_profiles = {e["profile_id"] for e in expected}
    result_profiles = {r["profile_id"] for r in results}
    # Ensure we have runtime observations for all profiles we planned for.
    assert expected_profiles.issubset(result_profiles), "missing runtime results for some profiles in expected_matrix"


def test_vfs_semantic_pattern():
    """Semantic guardrail: coarse allow/deny pattern per profile should remain stable on this world."""
    res_path = ROOT / "book" / "experiments" / "vfs-canonicalization" / "out" / "runtime_results.json"
    results = load_json(res_path)

    def decisions_for(profile_id: str):
        return {
            (row["requested_path"], row["decision"])
            for row in results
            if row.get("profile_id") == profile_id
        }

    tmp_only = decisions_for("vfs_tmp_only")
    priv_only = decisions_for("vfs_private_tmp_only")
    both = decisions_for("vfs_both_paths")

    assert ("/tmp/foo", "deny") in tmp_only and ("/private/tmp/foo", "deny") in tmp_only, (
        "vfs_tmp_only should deny both /tmp/foo and /private/tmp/foo on this world"
    )
    assert ("/tmp/foo", "allow") in priv_only and ("/private/tmp/foo", "allow") in priv_only, (
        "vfs_private_tmp_only should allow both /tmp/foo and /private/tmp/foo on this world"
    )
    assert ("/tmp/foo", "allow") in both and ("/private/tmp/foo", "allow") in both, (
        "vfs_both_paths should allow both /tmp/foo and /private/tmp/foo on this world"
    )
