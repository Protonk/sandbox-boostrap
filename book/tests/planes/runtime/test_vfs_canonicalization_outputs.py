import json
from pathlib import Path


from book.api import path_utils
ROOT = path_utils.find_repo_root(Path(__file__))


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
    ops = {row.get("operation") for row in results}
    assert ops == {"file-read*", "file-write*"}, "unexpected operations in vfs-canonicalization runtime results"

    def decisions_for(profile_id: str):
        out = {}
        for row in results:
            if row.get("profile_id") != profile_id:
                continue
            out[(row["operation"], row["requested_path"])] = row["decision"]
        return out

    tmp_only = decisions_for("vfs_tmp_only")
    priv_only = decisions_for("vfs_private_tmp_only")
    both = decisions_for("vfs_both_paths")

    # tmp-only profile denies everything (canonicalization makes /tmp literals ineffective)
    assert all(dec == "deny" for dec in tmp_only.values()), "vfs_tmp_only should deny all ops/paths in this suite"

    # Expected allow/deny per op for private-tmp-only and both-paths
    read_write_allow = [
        "/tmp/foo",
        "/private/tmp/foo",
        "/tmp/bar",
        "/private/tmp/bar",
        "/tmp/nested/child",
        "/private/tmp/nested/child",
        "/private/var/tmp/canon",
    ]
    read_write_deny = ["/var/tmp/canon"]

    def assert_decisions(decisions, label: str):
        for path in read_write_allow:
            assert decisions.get(("file-read*", path)) == "allow", f"{label} should allow read {path}"
            assert decisions.get(("file-write*", path)) == "allow", f"{label} should allow write {path}"
        for path in read_write_deny:
            assert decisions.get(("file-read*", path)) == "deny", f"{label} should deny read {path}"
            assert decisions.get(("file-write*", path)) == "deny", f"{label} should deny write {path}"

    assert_decisions(priv_only, "vfs_private_tmp_only")
    assert_decisions(both, "vfs_both_paths")
