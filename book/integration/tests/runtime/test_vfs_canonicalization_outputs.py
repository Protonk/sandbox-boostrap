import json
from pathlib import Path

from book.api import path_utils
from book.integration.tests.runtime.runtime_bundle_helpers import load_bundle_json

ROOT = path_utils.find_repo_root(Path(__file__))
OUT_ROOT = ROOT / "book" / "experiments" / "vfs-canonicalization" / "out"
DERIVED_ROOT = OUT_ROOT / "derived"


def load_json(path: Path):
    assert path.exists(), f"missing expected file: {path}"
    return json.loads(path.read_text())


def test_vfs_expected_and_runtime_shapes():
    """Shape guardrail: expected_matrix.json and derived runtime_results.json exist and have basic structure."""
    expected = load_bundle_json(OUT_ROOT, "expected_matrix.json")
    results = load_json(DERIVED_ROOT / "runtime_results.json")

    assert isinstance(expected, dict), "expected_matrix.json should be an object"
    profiles = expected.get("profiles")
    assert isinstance(profiles, dict) and profiles, "expected_matrix.json should include profiles"
    for profile_id, profile in profiles.items():
        assert profile_id, "expected_matrix profile_id should be non-empty"
        probes = profile.get("probes")
        assert isinstance(probes, list) and probes, f"expected_matrix probes missing for {profile_id}"
        for probe in probes:
            for key in ["operation", "target", "expected"]:
                assert key in probe, f"expected_matrix probe missing {key}"

    assert isinstance(results, dict), "runtime_results.json should be an object"
    records = results.get("records")
    assert isinstance(records, list) and records, "runtime_results.json should include records"
    for row in records:
        for key in ["profile_id", "operation", "requested_path", "actual", "observed_path"]:
            assert key in row, f"runtime_results record missing {key}"

    expected_profiles = set(profiles.keys())
    result_profiles = {r["profile_id"] for r in records}
    # Ensure we have runtime observations for all profiles we planned for.
    assert expected_profiles.issubset(result_profiles), "missing runtime results for some profiles in expected_matrix"


def test_vfs_semantic_pattern():
    """Semantic guardrail: coarse allow/deny pattern per profile should remain stable on this world."""
    results = load_json(DERIVED_ROOT / "runtime_results.json")
    records = results.get("records") or []
    ops = {row.get("operation") for row in records}
    assert ops == {"file-read*", "file-write*"}, "unexpected operations in vfs-canonicalization runtime results"

    def decisions_for(profile_id: str):
        out = {}
        for row in records:
            if row.get("profile_id") != profile_id:
                continue
            out[(row["operation"], row["requested_path"])] = row["actual"]
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
