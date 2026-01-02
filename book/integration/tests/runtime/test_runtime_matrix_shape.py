from pathlib import Path


from book.api import path_utils
from book.integration.tests.runtime.runtime_bundle_helpers import load_bundle_json

ROOT = path_utils.find_repo_root(Path(__file__))


def test_runtime_matrix_has_bucket_profiles():
    out_root = ROOT / "book" / "evidence" / "experiments" / "runtime-final-final" / "suites" / "runtime-checks" / "out"
    matrix = load_bundle_json(out_root, "expected_matrix.json")
    profiles = matrix.get("profiles") or {}
    for key in ["bucket4:v1_read", "bucket5:v11_read_subpath"]:
        assert key in profiles, f"missing runtime profile {key}"
        probes = profiles[key].get("probes") or []
        assert probes, f"expected probes for {key}"
