import json
from pathlib import Path


from book.api import path_utils
ROOT = path_utils.find_repo_root(Path(__file__))


def test_metafilter_runtime_entry_present():
    path = ROOT / "book" / "experiments" / "runtime-checks" / "out" / "runtime_results.json"
    assert path.exists(), "missing runtime_results.json"
    data = json.loads(path.read_text())
    assert "runtime:metafilter_any" in data
    entry = data["runtime:metafilter_any"]
    probes = entry.get("probes") or []
    assert probes, "expected probes for metafilter_any"
    for probe in probes:
        assert "exit_code" in probe
        assert "expected" in probe
        assert "actual" in probe
