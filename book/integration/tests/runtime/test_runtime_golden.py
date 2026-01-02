from pathlib import Path

import book.api.runtime.execution.harness.golden as rg


from book.api import path_utils
from book.integration.tests.runtime.runtime_bundle_helpers import resolve_bundle_dir
ROOT = path_utils.find_repo_root(Path(__file__))
OUT_ROOT = ROOT / "book" / "experiments" / "runtime-final-final" / "suites" / "runtime-checks" / "out"
BUNDLE_DIR, _ = resolve_bundle_dir(OUT_ROOT)
MATRIX = BUNDLE_DIR / "expected_matrix.json"
RUNTIME_RESULTS = BUNDLE_DIR / "runtime_results.json"


def test_load_matrix_has_golden_profiles():
    profiles = rg.load_golden_matrix(MATRIX)
    assert set(rg.GOLDEN_KEYS).issubset(profiles.keys())
    for key in rg.GOLDEN_KEYS:
        assert profiles[key].path.exists()


def test_compile_and_decode_bucket4():
    profiles = rg.load_golden_matrix(MATRIX)
    prof = profiles["bucket4:v1_read"]
    blob = rg.compile_golden_profile(prof)
    assert isinstance(blob, (bytes, bytearray))
    assert len(blob) > 0
    decoded = rg.decode_blob(blob)
    assert decoded.get("node_count") is not None
    assert decoded.get("op_count") is not None


def test_normalize_runtime_results_rows_present():
    rows = rg.normalize_golden_results(RUNTIME_RESULTS, rg.GOLDEN_KEYS)
    assert rows, "expected runtime rows for golden profiles"
    profiles_present = {r["profile"] for r in rows}
    assert "bucket4:v1_read" in profiles_present
    assert "bucket5:v11_read_subpath" in profiles_present
