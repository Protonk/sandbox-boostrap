import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load_json(path: Path):
    assert path.exists(), f"missing expected file: {path}"
    return json.loads(path.read_text())


def test_vfs_decode_tmp_profiles_shape():
    """Structural guardrail: decode_tmp_profiles.json exists and has expected anchor entries."""
    path = ROOT / "book" / "experiments" / "vfs-canonicalization" / "out" / "decode_tmp_profiles.json"
    data = load_json(path)
    for profile_id in ["vfs_tmp_only", "vfs_private_tmp_only", "vfs_both_paths"]:
        assert profile_id in data, f"missing profile {profile_id} in decode_tmp_profiles.json"
        anchors = data[profile_id].get("anchors") or []
        anchor_paths = {a.get("path") for a in anchors}
        # Expect both /tmp/foo and /private/tmp/foo entries for each profile.
        assert "/tmp/foo" in anchor_paths, f"missing /tmp/foo anchor entry for {profile_id}"
        assert "/private/tmp/foo" in anchor_paths, f"missing /private/tmp/foo anchor entry for {profile_id}"

