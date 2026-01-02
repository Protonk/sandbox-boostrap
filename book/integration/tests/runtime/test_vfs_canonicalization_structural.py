import json
from pathlib import Path


from book.api import path_utils
ROOT = path_utils.find_repo_root(Path(__file__))


def load_json(path: Path):
    assert path.exists(), f"missing expected file: {path}"
    return json.loads(path.read_text())


def test_vfs_decode_tmp_profiles_shape():
    """Structural guardrail: decode_tmp_profiles.json exists and has expected anchor entries."""
    path = (
        ROOT
        / "book"
        / "experiments"
        / "runtime-final-final"
        / "suites"
        / "vfs-canonicalization"
        / "out"
        / "derived"
        / "decode_tmp_profiles.json"
    )
    data = load_json(path)
    profiles = data.get("profiles") or {}
    expected_anchors = {
        "/tmp/foo",
        "/private/tmp/foo",
        "/tmp/bar",
        "/private/tmp/bar",
        "/tmp/nested/child",
        "/private/tmp/nested/child",
        "/var/tmp/canon",
        "/private/var/tmp/canon",
    }
    for profile_id in ["vfs_tmp_only", "vfs_private_tmp_only", "vfs_both_paths"]:
        assert profile_id in profiles, f"missing profile {profile_id} in decode_tmp_profiles.json"
        anchors = profiles[profile_id].get("anchors") or []
        anchor_paths = {a.get("path") for a in anchors}
        # Expect all alias and canonical anchors for each profile.
        for ap in expected_anchors:
            assert ap in anchor_paths, f"missing {ap} anchor entry for {profile_id}"
