import json
from pathlib import Path

from book.integration.carton.mappings.system_profiles import generate_static_checks as gsc


def test_tag_layout_hash_resists_metadata_only_changes(tmp_path: Path):
    """Tag-layout contract hash should ignore metadata churn but flag tag changes."""
    base = {"tags": [{"tag": 1, "record_size_bytes": 12}], "metadata": {"note": "original"}}
    p1 = tmp_path / "tag_layouts.json"
    p1.write_text(json.dumps(base))
    h1 = gsc.tag_layout_hash(p1)

    modified_meta = dict(base)
    modified_meta["metadata"] = {"note": "changed"}
    p2 = tmp_path / "tag_layouts_meta.json"
    p2.write_text(json.dumps(modified_meta))
    h2 = gsc.tag_layout_hash(p2)
    assert h1 == h2, "metadata-only edit should not change tag-layout hash"

    modified_tags = dict(base)
    modified_tags["tags"] = [{"tag": 1, "record_size_bytes": 12}, {"tag": 99, "record_size_bytes": 8}]
    p3 = tmp_path / "tag_layouts_tags.json"
    p3.write_text(json.dumps(modified_tags))
    h3 = gsc.tag_layout_hash(p3)
    assert h3 != h1, "changing tag set should change tag-layout hash"
