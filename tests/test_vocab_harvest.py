import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
VOCAB_CACHE_OUT = ROOT / "book" / "experiments" / "vocab-from-cache" / "out"
VALIDATION_VOCAB_OUT = ROOT / "book" / "graph" / "concepts" / "validation" / "out" / "vocab"


def load_json(path: Path) -> dict:
    assert path.exists(), f"missing expected file: {path}"
    return json.loads(path.read_text())


def test_operation_vocab_harvest_matches_validation():
    harvested = load_json(VOCAB_CACHE_OUT / "operation_names.json")
    ops_vocab = load_json(VALIDATION_VOCAB_OUT / "ops.json")

    assert harvested["count"] == len(harvested["names"]) > 0
    assert harvested["names"][0] == "default"
    assert harvested["names"][-1] == "xpc-message-send"

    assert ops_vocab["status"] == "ok"
    harvested_names = harvested["names"]
    ops_entries = ops_vocab["ops"]
    assert len(ops_entries) == len(harvested_names)
    assert [e["name"] for e in ops_entries] == harvested_names
    assert [e["id"] for e in ops_entries] == list(range(len(harvested_names)))


def test_filter_vocab_harvest_matches_validation():
    harvested = load_json(VOCAB_CACHE_OUT / "filter_names.json")
    filters_vocab = load_json(VALIDATION_VOCAB_OUT / "filters.json")

    assert harvested["count"] == len(harvested["names"]) > 0
    assert harvested["names"][0] == "path"
    assert harvested["names"][-1] == "kas-info-selector"

    assert filters_vocab["status"] == "ok"
    harvested_names = harvested["names"]
    filt_entries = filters_vocab["filters"]
    assert len(filt_entries) == len(harvested_names)
    assert [e["name"] for e in filt_entries] == harvested_names
    assert [e["id"] for e in filt_entries] == list(range(len(harvested_names)))
