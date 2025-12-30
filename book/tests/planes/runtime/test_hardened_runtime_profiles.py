import json
from pathlib import Path


from book.api import path_utils
REPO_ROOT = path_utils.find_repo_root(Path(__file__))
BASE_DIR = REPO_ROOT / "book" / "experiments" / "hardened-runtime"
OUT_DIR = BASE_DIR / "out"
SUMMARY = OUT_DIR / "summary.json"
EXPECTED_MATRIX = OUT_DIR / "expected_matrix.json"
RUNTIME_RESULTS = OUT_DIR / "runtime_results.json"

EXPECTED_PROFILES = {
    "hardened:mach_lookup",
    "hardened:mach_lookup_allow",
    "hardened:sysctl_read",
    "hardened:sysctl_read_allow",
    "hardened:notifications",
    "hardened:notifications_allow",
    "hardened:process_info_allow",
    "hardened:process_info_allow_canary",
    "hardened:process_info_deny",
    "hardened:signal_self_allow",
    "hardened:signal_self_deny",
}


def load_json(path: Path):
    assert path.exists(), f"missing required file: {path}"
    return json.loads(path.read_text())


def test_hardened_runtime_profile_set():
    summary = load_json(SUMMARY)
    summary_profiles = set(summary.get("expected_profiles") or [])
    assert summary_profiles == EXPECTED_PROFILES

    if EXPECTED_MATRIX.exists():
        matrix = load_json(EXPECTED_MATRIX)
        matrix_profiles = set((matrix.get("profiles") or {}).keys())
        assert matrix_profiles == EXPECTED_PROFILES
        if RUNTIME_RESULTS.exists():
            runtime = load_json(RUNTIME_RESULTS)
            assert set(runtime.keys()) == matrix_profiles
            for key in matrix_profiles:
                assert runtime[key].get("schema_version"), f"missing schema_version in {key}"
    else:
        assert summary.get("status") == "not_run"
