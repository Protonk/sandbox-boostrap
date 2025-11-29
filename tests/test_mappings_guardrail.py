import json
from pathlib import Path


def load_json(path: Path):
    assert path.exists(), f"missing expected file: {path}"
    return json.loads(path.read_text())


def test_system_profile_digests_present():
    digests = load_json(Path("book/graph/mappings/system_profiles/digests.json"))
    for key in ["sys:airlock", "sys:bsd", "sys:sample"]:
        assert key in digests, f"missing digest for {key}"
    meta = digests.get("metadata", {})
    assert meta.get("host", {}).get("build") == "23E224"


def test_anchor_filter_map_present():
    amap = load_json(Path("book/graph/mappings/anchors/anchor_filter_map.json"))
    # Ensure known anchors are present and at least one has a resolved filter_id.
    assert "/var/log" in amap
    mapped = [v for v in amap.values() if v.get("filter_id") is not None]
    assert mapped, "expected at least one mapped anchor → filter_id"


def test_tag_layouts_present():
    layouts = load_json(Path("book/graph/mappings/tag_layouts/tag_layouts.json"))
    tags = layouts.get("tags") or []
    assert tags, "expected non-empty tag layouts"
    sample = tags[0]
    for field in ["tag", "record_size_bytes", "edge_fields", "payload_fields"]:
        assert field in sample, f"tag layout missing {field}"
