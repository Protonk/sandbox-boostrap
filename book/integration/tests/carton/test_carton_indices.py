import json
from pathlib import Path

from book.api import path_utils
ROOT = path_utils.find_repo_root(Path(__file__))
OP_INDEX = ROOT / "book" / "graph" / "mappings" / "carton" / "operation_index.json"
PROFILE_INDEX = ROOT / "book" / "graph" / "mappings" / "carton" / "profile_layer_index.json"
FILTER_INDEX = ROOT / "book" / "graph" / "mappings" / "carton" / "filter_index.json"
CONCEPT_INDEX = ROOT / "book" / "graph" / "mappings" / "carton" / "concept_index.json"
BASELINE_REF = "book/world/sonoma-14.4.1-23E224-arm64/world.json"


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def baseline_world():
    return json.loads((ROOT / BASELINE_REF).read_text()).get("world_id")


def test_operation_index_shape_and_sample():
    data = load(OP_INDEX)
    assert "metadata" in data and "operations" in data
    assert "generated_at" not in data["metadata"]
    assert data["metadata"].get("world_id") == baseline_world()
    op = data["operations"]["file-read*"]
    assert op["known"] is True
    assert isinstance(op["id"], int)
    assert "system" in op["profile_layers"]
    assert "sys:bsd" in op["system_profiles"]
    counts = op["coverage_counts"]
    assert counts["system_profiles"] >= 1


def test_profile_layer_index_shape_and_sample():
    data = load(PROFILE_INDEX)
    assert "metadata" in data and "profiles" in data
    assert "generated_at" not in data["metadata"]
    assert data["metadata"].get("world_id") == baseline_world()
    bsd = data["profiles"]["sys:bsd"]
    assert bsd["layer"] == "system"
    assert bsd["ops"], "expected ops for sys:bsd"
    assert all("name" in op and "id" in op for op in bsd["ops"])
    # Ensure ops are unique by id
    ids = [op["id"] for op in bsd["ops"]]
    assert len(ids) == len(set(ids))


def test_filter_index_shape():
    data = load(FILTER_INDEX)
    meta = data.get("metadata") or {}
    assert meta.get("world_id") == baseline_world()
    filters = data.get("filters") or {}
    assert "path" in filters, "expected at least the path filter in filter index"
    path_entry = filters["path"]
    assert path_entry["known"] is True
    assert path_entry["usage_status"] in {
        "present-in-vocab-only",
        "referenced-in-profiles",
        "referenced-in-runtime",
        "unknown",
    }
    assert path_entry["system_profiles"] == []
    # Ensure at least one filter is marked present-in-vocab-only (current conservative default).
    assert any(entry.get("usage_status") == "present-in-vocab-only" for entry in filters.values())


def test_concept_index_contains_expected_concepts():
    data = load(CONCEPT_INDEX)
    meta = data.get("metadata") or {}
    assert meta.get("world_id") == baseline_world()
    concepts = data.get("concepts") or {}
    expected = {"operation", "filter", "profile-layer"}
    assert expected <= set(concepts.keys())
    op_entries = concepts["operation"]
    paths = {entry["path"] for entry in op_entries}
    assert "book/graph/mappings/vocab/ops.json" in paths
    assert "book/graph/mappings/carton/operation_index.json" in paths
    filter_entries = concepts["filter"]
    filter_paths = {entry["path"] for entry in filter_entries}
    assert "book/graph/mappings/carton/filter_index.json" in filter_paths
