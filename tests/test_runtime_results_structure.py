import json
from pathlib import Path


def test_runtime_results_have_match_fields():
    path = Path("book/experiments/runtime-checks/out/runtime_results.json")
    assert path.exists(), "expected runtime_results.json"
    data = json.loads(path.read_text())
    for key in ["bucket4:v1_read", "bucket5:v11_read_subpath"]:
        assert key in data, f"missing runtime result for {key}"
        entry = data[key]
        assert entry.get("status") in {"ok", "partial", "blocked", "brittle"}
        probes = entry.get("probes") or []
        assert probes, f"expected probes for {key}"
        for probe in probes:
            assert "expected" in probe, f"missing expected in {key}:{probe.get('name')}"
            assert "actual" in probe, f"missing actual in {key}:{probe.get('name')}"
            assert "match" in probe, f"missing match in {key}:{probe.get('name')}"
