import json
from pathlib import Path


from book.api import path_utils

ROOT = path_utils.find_repo_root(Path(__file__))
VOCAB_MAPPINGS = ROOT / "book" / "evidence" / "graph" / "mappings" / "vocab"
DYLD_LIB_SOURCE = "book/evidence/graph/mappings/dyld-libs/usr/lib/libsandbox.1.dylib"


def load_json(path: Path) -> dict:
    assert path.exists(), f"missing expected file: {path}"
    return json.loads(path.read_text())


def test_operation_vocab_harvest_matches_validation():
    harvested = load_json(VOCAB_MAPPINGS / "operation_names.json")
    ops_vocab = load_json(VOCAB_MAPPINGS / "ops.json")

    assert harvested["count"] == len(harvested["names"]) > 0
    assert harvested["source"] == DYLD_LIB_SOURCE
    assert harvested["names"][0] == "default"
    assert harvested["names"][-1] == "xpc-message-send"

    assert (ops_vocab.get("metadata") or {}).get("status") == "ok"
    harvested_names = harvested["names"]
    ops_entries = ops_vocab["ops"]
    assert len(ops_entries) == len(harvested_names)
    assert [e["name"] for e in ops_entries] == harvested_names
    assert [e["id"] for e in ops_entries] == list(range(len(harvested_names)))
    assert {e.get("source") for e in ops_entries} == {DYLD_LIB_SOURCE}


def test_filter_vocab_harvest_matches_validation():
    harvested = load_json(VOCAB_MAPPINGS / "filter_names.json")
    filters_vocab = load_json(VOCAB_MAPPINGS / "filters.json")

    assert harvested["count"] == len(harvested["names"]) > 0
    assert harvested["source"] == DYLD_LIB_SOURCE
    assert harvested["names"][0] == "path"
    assert harvested["names"][-1] == "kas-info-selector"

    assert (filters_vocab.get("metadata") or {}).get("status") == "ok"
    harvested_names = harvested["names"]
    filt_entries = filters_vocab["filters"]
    assert len(filt_entries) == len(harvested_names)
    assert [e["name"] for e in filt_entries] == harvested_names
    assert [e["id"] for e in filt_entries] == list(range(len(harvested_names)))
    assert {e.get("source") for e in filt_entries} == {DYLD_LIB_SOURCE}
