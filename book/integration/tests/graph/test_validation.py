import json
import pytest

from pathlib import Path

from book.api.profile import decoder

from book.api import path_utils

ROOT = path_utils.find_repo_root(Path(__file__))
FIXTURES_PATH = ROOT / "book" / "evidence" / "carton" / "validation" / "fixtures" / "fixtures.json"


def load_fixtures():
    if not FIXTURES_PATH.exists():
        return []
    return json.loads(FIXTURES_PATH.read_text()).get("blobs", [])


@pytest.mark.system
def test_fixture_structures():
    blobs = load_fixtures()
    assert blobs, "No fixtures found"
    repo_root = path_utils.find_repo_root(Path(__file__))
    for entry in blobs:
        path = repo_root / entry["path"]
        assert path.exists(), f"missing fixture {path}"
        data = path.read_bytes()
        decoded = decoder.decode_profile_dict(data)
        # Structural sanity: op_table length should match op_count*2 when op_count is present.
        op_count = decoded.get("op_count")
        op_table = decoded.get("op_table", [])
        if op_count:
            assert len(op_table) == op_count, f"op_table entries mismatch for {path.name}"
        sections = decoded.get("sections", {})
        assert sections.get("nodes", 0) >= 0
        assert sections.get("literal_pool", 0) >= 0
        # Tag counts should align with node_count.
        node_count = decoded.get("node_count", 0)
        tag_counts = sum(decoded.get("tag_counts", {}).values())
        assert tag_counts == node_count, f"tag count mismatch for {path.name}"
