import json
from pathlib import Path


from book.api import path_utils

ROOT = path_utils.find_repo_root(Path(__file__))
LIFECYCLE = ROOT / "book" / "evidence" / "graph" / "mappings" / "runtime" / "lifecycle.json"
BASELINE = ROOT / "book" / "world" / "sonoma-14.4.1-23E224-arm64" / "world.json"


def load(path: Path):
    assert path.exists(), f"missing required file: {path}"
    return json.loads(path.read_text())


def test_lifecycle_metadata_present():
    lifecycle = load(LIFECYCLE)
    baseline_world = load(BASELINE).get("world_id")
    meta = lifecycle.get("metadata") or {}

    assert meta.get("world_id") == baseline_world
    assert meta.get("status") in {"ok", "partial", "blocked"}
    assert meta.get("inputs"), "lifecycle metadata should include inputs"
