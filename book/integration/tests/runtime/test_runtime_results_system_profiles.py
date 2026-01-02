from pathlib import Path

from book.api import path_utils
from book.integration.tests.runtime.runtime_bundle_helpers import load_bundle_json
ROOT = path_utils.find_repo_root(Path(__file__))


def test_system_profiles_present_in_runtime_results():
    out_root = ROOT / "book" / "evidence" / "experiments" / "runtime-final-final" / "suites" / "runtime-checks" / "out"
    data = load_bundle_json(out_root, "runtime_results.json")
    for key in ["sys:airlock", "sys:bsd"]:
        assert key in data, f"missing runtime result for {key}"
        entry = data[key]
        probes = entry.get("probes") or []
        assert probes, f"expected probes for {key}"
        for probe in probes:
            assert "exit_code" in probe
            assert "expected" in probe
            assert "actual" in probe
