import json
from pathlib import Path

import book.api.runtime_tools.harness_generate as rg


ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "book" / "experiments" / "runtime-checks" / "out" / "expected_matrix.json"
RUNTIME_RESULTS = ROOT / "book" / "experiments" / "runtime-checks" / "out" / "runtime_results.json"


def test_load_matrix_has_golden_profiles():
    profiles = rg.load_matrix(MATRIX)
    assert set(rg.GOLDEN_KEYS).issubset(profiles.keys())
    for key in rg.GOLDEN_KEYS:
        assert profiles[key].path.exists()


def test_compile_and_decode_bucket4():
    profiles = rg.load_matrix(MATRIX)
    prof = profiles["bucket4:v1_read"]
    blob = rg.compile_profile(prof)
    assert isinstance(blob, (bytes, bytearray))
    assert len(blob) > 0
    decoded = rg.decode_profile(blob)
    assert decoded.get("node_count") is not None
    assert decoded.get("op_count") is not None


def test_normalize_runtime_results_rows_present():
    rows = rg.normalize_runtime_results(RUNTIME_RESULTS, rg.GOLDEN_KEYS)
    assert rows, "expected runtime rows for golden profiles"
    profiles_present = {r["profile"] for r in rows}
    assert "bucket4:v1_read" in profiles_present
    assert "bucket5:v11_read_subpath" in profiles_present
