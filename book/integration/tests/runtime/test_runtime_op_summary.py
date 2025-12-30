import json
from pathlib import Path


from book.api import path_utils
ROOT = path_utils.find_repo_root(Path(__file__))
SUMMARY = ROOT / "book" / "graph" / "mappings" / "runtime" / "op_runtime_summary.json"
CUTS = ROOT / "book" / "graph" / "mappings" / "runtime_cuts" / "ops.json"
BASELINE = ROOT / "book" / "world" / "sonoma-14.4.1-23E224-arm64" / "world.json"


def _load_json(path: Path) -> dict:
    assert path.exists(), f"missing {path}"
    return json.loads(path.read_text())


def test_op_runtime_summary_metadata():
    data = _load_json(SUMMARY)
    meta = data.get("meta") or {}
    world_id = _load_json(BASELINE).get("world_id")
    assert meta.get("world_id") == world_id
    assert meta.get("tier") == "mapped"
    assert meta.get("status") in {"ok", "partial", "brittle", "blocked"}
    assert meta.get("schema_version"), "missing schema_version"
    inputs = meta.get("inputs") or []
    assert inputs, "expected inputs list"
    assert all(not Path(p).is_absolute() for p in inputs)
    input_hashes = meta.get("input_hashes") or {}
    assert set(input_hashes.keys()) == set(inputs)


def test_op_runtime_summary_aligns_with_runtime_cuts():
    summary = _load_json(SUMMARY)
    cuts = _load_json(CUTS)
    ops = summary.get("ops") or {}
    cuts_ops = cuts.get("ops") or {}
    assert ops, "expected op runtime summary entries"
    assert set(ops.keys()) == set(cuts_ops.keys())
    for op_name, entry in ops.items():
        assert entry.get("op_id") == cuts_ops[op_name].get("op_id")
