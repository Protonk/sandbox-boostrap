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

