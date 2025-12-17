import json
from pathlib import Path


def _load_json(path: Path):
    assert path.exists(), f"missing {path}"
    return json.loads(path.read_text())


def test_node_layout_artifacts():
    root = Path(__file__).resolve().parents[2]
    summary = root / "book/experiments/node-layout/out/summary.json"
    data = _load_json(summary)
    assert isinstance(data, list)
    # Each entry should have expected keys.
    for entry in data:
        for key in ("name", "op_entries", "section_lengths"):
            assert key in entry


def test_op_table_operation_artifacts():
    root = Path(__file__).resolve().parents[2]
    summary = root / "book/experiments/op-table-operation/out/summary.json"
    data = _load_json(summary)
    assert isinstance(data, list)
    op_map = _load_json(root / "book/experiments/op-table-operation/out/op_table_map.json")
    assert "profiles" in op_map


def test_op_table_vocab_alignment_artifacts():
    root = Path(__file__).resolve().parents[2]
    align = _load_json(root / "book/experiments/op-table-vocab-alignment/out/op_table_vocab_alignment.json")
    assert "records" in align
    assert isinstance(align["records"], list)


def test_node_layout_decoder_blocks():
    root = Path(__file__).resolve().parents[2]
    summary = _load_json(root / "book/experiments/node-layout/out/summary.json")
    assert summary, "summary should not be empty"
    for entry in summary:
        dec = entry.get("decoder")
        assert dec, f"missing decoder block in {entry.get('name')}"
        for key in ("node_count", "tag_counts", "op_table_offset"):
            assert key in dec, f"decoder.{key} missing in {entry.get('name')}"


def test_node_layout_literal_probe_shapes():
    root = Path(__file__).resolve().parents[2]
    summary = {entry["name"]: entry for entry in _load_json(root / "book/experiments/node-layout/out/summary.json")}
    assert "v20_read_literal" in summary and "v21_two_literals_require_any" in summary
    v20 = summary["v20_read_literal"]
    v21 = summary["v21_two_literals_require_any"]
    # Decoder tag counts should show the require-any profile adding at least one tag0 node.
    # (Under the current stride=8 framing, tag5 counts are stable across these probes while
    # the number of literal-bearing tag0 nodes grows with the literal set.)
    v20_tags = {int(k): v for k, v in v20["decoder"]["tag_counts"].items()}
    v21_tags = {int(k): v for k, v in v21["decoder"]["tag_counts"].items()}
    assert v21_tags.get(0, 0) >= v20_tags.get(0, 0) + 1
