from pathlib import Path


from book.api import path_utils
from book.integration.tests.runtime.runtime_bundle_helpers import load_bundle_json

ROOT = path_utils.find_repo_root(Path(__file__))


def test_metafilter_runtime_entry_present():
    out_root = ROOT / "book" / "evidence" / "experiments" / "runtime-final-final" / "suites" / "runtime-checks" / "out"
    data = load_bundle_json(out_root, "runtime_results.json")
    assert "runtime:metafilter_any" in data
    entry = data["runtime:metafilter_any"]
    probes = entry.get("probes") or []
    assert probes, "expected probes for metafilter_any"
    for probe in probes:
        assert "exit_code" in probe
        assert "expected" in probe
        assert "actual" in probe
