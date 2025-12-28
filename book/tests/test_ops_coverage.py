import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OPS = ROOT / "book" / "graph" / "mappings" / "vocab" / "ops.json"
COVERAGE = ROOT / "book" / "graph" / "mappings" / "vocab" / "ops_coverage.json"
BASELINE = ROOT / "book" / "world" / "sonoma-14.4.1-23E224-arm64" / "world.json"


def test_ops_coverage_has_all_ops():
    world_id = json.loads(BASELINE.read_text()).get("world_id")
    ops = json.loads(OPS.read_text())["ops"]
    cov_doc = json.loads(COVERAGE.read_text())
    meta = cov_doc.get("metadata") or {}
    assert meta.get("world_id") == world_id
    coverage = cov_doc.get("coverage") or cov_doc
    assert len(coverage) == len(ops), "coverage should have one entry per op"
    names = {o["name"] for o in ops}
    assert set(coverage.keys()) == names
    # Known strong ops must have runtime evidence.
    for op in ["file-read*", "file-write*", "mach-lookup", "network-outbound"]:
        entry = coverage[op]
        assert entry["runtime_evidence"] is True, f"{op} should have runtime evidence"
        assert entry["structural_evidence"] is True
