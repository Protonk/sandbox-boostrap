import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASELINE_REF = "book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json"


def baseline_world():
    return json.loads((ROOT / BASELINE_REF).read_text()).get("world_id")


def load_json(path: Path):
    assert path.exists(), f"missing expected file: {path}"
    return json.loads(path.read_text())


def test_system_profile_digests_present():
    digests = load_json(ROOT / "book" / "graph" / "mappings" / "system_profiles" / "digests.json")
    profiles = digests.get("profiles") or {}
    for key in ["sys:airlock", "sys:bsd", "sys:sample"]:
        assert key in profiles, f"missing digest for {key}"
    meta = digests.get("metadata", {})
    assert meta.get("world_id") == baseline_world()


def test_anchor_filter_map_present():
    amap = load_json(ROOT / "book" / "graph" / "mappings" / "anchors" / "anchor_filter_map.json")
    # Ensure known anchors are present and at least one has a resolved filter_id.
    assert "/var/log" in amap
    mapped = [v for v in amap.values() if v.get("filter_id") is not None]
    assert mapped, "expected at least one mapped anchor → filter_id"


def test_tag_layouts_present():
    layouts = load_json(ROOT / "book" / "graph" / "mappings" / "tag_layouts" / "tag_layouts.json")
    tags = layouts.get("tags") or []
    assert tags, "expected non-empty tag layouts"
    sample = tags[0]
    for field in ["tag", "record_size_bytes", "edge_fields", "payload_fields"]:
        assert field in sample, f"tag layout missing {field}"


def test_field2_inventory_present():
    inv_path = ROOT / "book" / "graph" / "concepts" / "validation" / "out" / "experiments" / "field2" / "field2_ir.json"
    inv = load_json(inv_path)
    profiles = inv.get("profiles") or {}
    assert "sys:bsd" in profiles and "sys:sample" in profiles, "expected system profiles in field2 inventory"


def test_op_table_mappings_and_metadata():
    meta_path = ROOT / "book" / "graph" / "mappings" / "op_table" / "metadata.json"
    meta = load_json(meta_path)
    world_id = (meta.get("metadata") or {}).get("world_id") or meta.get("world_id")
    assert world_id == baseline_world(), "op_table metadata world mismatch"
    vocab = meta.get("vocab", {})
    assert vocab.get("status") == "ok"
    assert vocab.get("ops_count") == 196 and vocab.get("filters_count") == 93

    artifacts = meta.get("artifacts", {})
    required = {
        "op_table_operation_summary": "op_table_operation_summary.json",
        "op_table_map": "op_table_map.json",
        "op_table_signatures": "op_table_signatures.json",
        "op_table_vocab_alignment": "op_table_vocab_alignment.json",
    }
    assert artifacts == required

    base = meta_path.parent
    op_summary = load_json(base / artifacts["op_table_operation_summary"])
    assert (op_summary.get("records") or []), "op_table_operation_summary should contain records"

    op_map = load_json(base / artifacts["op_table_map"])
    assert op_map, "op_table_map should not be empty"

    op_sigs = load_json(base / artifacts["op_table_signatures"])
    assert (op_sigs.get("records") or []), "op_table_signatures should be a non-empty list"

    alignment = load_json(base / artifacts["op_table_vocab_alignment"])
    assert isinstance(alignment, dict) and alignment.get("records"), "op_table_vocab_alignment should contain records"
