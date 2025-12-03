import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load_json(path: Path):
    assert path.exists(), f"missing expected file: {path}"
    return json.loads(path.read_text())


def test_system_profile_digests_present():
    digests = load_json(ROOT / "book" / "graph" / "mappings" / "system_profiles" / "digests.json")
    for key in ["sys:airlock", "sys:bsd", "sys:sample"]:
        assert key in digests, f"missing digest for {key}"
    meta = digests.get("metadata", {})
    assert meta.get("host", {}).get("build") == "23E224"


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
    inv_path = ROOT / "book" / "experiments" / "field2-filters" / "out" / "field2_inventory.json"
    inv = load_json(inv_path)
    assert "sys:bsd" in inv and "sys:sample" in inv, "expected system profiles in field2 inventory"


def test_op_table_mappings_and_metadata():
    meta_path = ROOT / "book" / "graph" / "mappings" / "op_table" / "metadata.json"
    meta = load_json(meta_path)
    host = meta.get("host", {})
    assert host.get("build") == "23E224", "op_table metadata host build mismatch"
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
    assert isinstance(op_summary, list) and op_summary, "op_table_operation_summary should be a non-empty list"

    op_map = load_json(base / artifacts["op_table_map"])
    assert op_map, "op_table_map should not be empty"

    op_sigs = load_json(base / artifacts["op_table_signatures"])
    assert isinstance(op_sigs, list) and op_sigs, "op_table_signatures should be a non-empty list"

    alignment = load_json(base / artifacts["op_table_vocab_alignment"])
    assert isinstance(alignment, dict) and alignment.get("records"), "op_table_vocab_alignment should contain records"
