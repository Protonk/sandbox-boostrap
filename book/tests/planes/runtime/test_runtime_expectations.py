import json
from pathlib import Path

from book.api import path_utils
ROOT = path_utils.find_repo_root(Path(__file__))
EXPECTATIONS = ROOT / "book" / "graph" / "mappings" / "runtime" / "expectations.json"
BASELINE_REF = ROOT / "book" / "world" / "sonoma-14.4.1-23E224-arm64" / "world.json"


def load(path: Path) -> dict:
    assert path.exists(), f"missing {path}"
    return json.loads(path.read_text())


def baseline_world() -> str:
    return load(BASELINE_REF).get("world_id")


def test_expectations_metadata_and_profiles():
    data = load(EXPECTATIONS)
    meta = data.get("metadata") or {}
    assert meta.get("world_id") == baseline_world()
    assert meta.get("status")
    assert isinstance(meta.get("inputs"), list)
    profiles = data.get("profiles") or []
    assert profiles, "expected profiles in runtime expectations"
    for profile in profiles:
        assert profile.get("profile_id")
        assert profile.get("status") in {"ok", "partial", "brittle", "blocked"}
        assert "probe_count" in profile
        # profile_path/sha256 are allowed to be missing for non-local blobs, but keys should exist.
        assert "profile_path" in profile
        assert "profile_sha256" in profile
