import json
from pathlib import Path


from book.api import path_utils
def _load_json(path: Path):
    assert path.exists(), f"missing {path}"
    return json.loads(path.read_text())


def test_node_layout_experiment_outputs_are_coherent():
    root = path_utils.find_repo_root(Path(__file__))
    summary = root / "book/experiments/node-layout/out/summary.json"
    data = _load_json(summary)
    assert isinstance(data, list)
    assert data, "summary.json should not be empty"

    # Each entry should have expected keys.
    for entry in data:
        for key in ("name", "op_entries", "section_lengths"):
            assert key in entry

        dec = entry.get("decoder")
        assert dec, f"missing decoder block in {entry.get('name')}"
        for key in ("node_count", "tag_counts", "op_table_offset"):
            assert key in dec, f"decoder.{key} missing in {entry.get('name')}"

    by_name = {entry.get("name"): entry for entry in data}
    assert "v20_read_literal" in by_name and "v21_two_literals_require_any" in by_name
    v20 = by_name["v20_read_literal"]
    v21 = by_name["v21_two_literals_require_any"]
    v20_tags = {int(k): v for k, v in (v20.get("decoder") or {}).get("tag_counts", {}).items()}
    v21_tags = {int(k): v for k, v in (v21.get("decoder") or {}).get("tag_counts", {}).items()}
    assert v21_tags.get(0, 0) >= v20_tags.get(0, 0) + 1


def test_op_table_experiment_outputs_are_present():
    root = path_utils.find_repo_root(Path(__file__))
    summary = root / "book/experiments/op-table-operation/out/summary.json"
    data = _load_json(summary)
    assert isinstance(data, list)
    op_map = _load_json(root / "book/experiments/op-table-operation/out/op_table_map.json")
    assert "profiles" in op_map

    align = _load_json(root / "book/experiments/op-table-vocab-alignment/out/op_table_vocab_alignment.json")
    assert "records" in align
    assert isinstance(align["records"], list)
