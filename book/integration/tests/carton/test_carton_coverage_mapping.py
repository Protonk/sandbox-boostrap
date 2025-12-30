import json
from pathlib import Path

from book.api import path_utils
ROOT = path_utils.find_repo_root(Path(__file__))
COVERAGE_PATH = ROOT / "book" / "graph" / "mappings" / "carton" / "operation_coverage.json"
BASELINE_REF = "book/world/sonoma-14.4.1-23E224-arm64/world.json"


def load() -> dict:
    assert COVERAGE_PATH.exists(), "missing CARTON coverage mapping"
    return json.loads(COVERAGE_PATH.read_text())


def baseline_world():
    return json.loads((ROOT / BASELINE_REF).read_text()).get("world_id")


def test_coverage_metadata():
    data = load()
    meta = data.get("metadata") or {}
    assert "generated_at" not in meta
    assert meta.get("world_id") == baseline_world()
    assert meta.get("source_jobs"), "source_jobs missing from coverage metadata"
    assert meta.get("inputs"), "inputs missing from coverage metadata"


def test_coverage_for_file_read():
    data = load()
    coverage = data.get("coverage") or {}
    entry = coverage.get("file-read*")
    assert entry, "file-read* should be present in coverage mapping"
    assert entry.get("op_id") == 21
    assert entry.get("counts", {}).get("system_profiles", 0) > 0
    assert "sys:bsd" in entry.get("system_profiles", [])


def test_coverage_zero_bucket_present():
    data = load()
    summary = data.get("summary") or {}
    assert summary.get("ops_total"), "summary missing ops_total"
    assert summary.get("ops_with_no_coverage") is not None


def test_coverage_summary_matches_counts():
    data = load()
    coverage = data.get("coverage") or {}
    summary = data.get("summary") or {}
    assert len(coverage) == summary.get("ops_total")
    zero = sum(1 for entry in coverage.values() if not entry.get("system_profiles"))
    assert zero == summary.get("ops_with_no_coverage")


def test_coverage_metadata_inputs_include_carton_manifest():
    data = load()
    inputs = data.get("metadata", {}).get("inputs") or []
    assert any(
        path == "book/integration/carton/CARTON.json" for path in inputs
    ), "coverage mapping should cite CARTON manifest"
