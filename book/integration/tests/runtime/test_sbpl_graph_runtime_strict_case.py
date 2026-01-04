import json
from pathlib import Path


from book.api import path_utils
ROOT = path_utils.find_repo_root(Path(__file__))
MATRIX_PATH = ROOT / "book" / "evidence" / "profiles" / "golden-triple" / "expected_matrix.json"
RESULTS_PATH = ROOT / "book" / "evidence" / "profiles" / "golden-triple" / "runtime_results.json"


def load_json(path: Path) -> dict:
    assert path.exists(), f"missing {path}"
    return json.loads(path.read_text())


def test_matrix_uses_sbpl_for_golden_profiles():
    matrix = load_json(MATRIX_PATH)
    profiles = matrix.get("profiles") or {}
    for key in ["runtime:allow_all", "runtime:metafilter_any", "runtime:strict_1"]:
        assert key in profiles, f"missing profile {key}"
        assert profiles[key].get("mode") == "sbpl", f"{key} should run in SBPL mode"


def test_runtime_outcomes_and_bucket5_partial():
    runtime = load_json(RESULTS_PATH)
    for key in ["runtime:allow_all", "runtime:metafilter_any", "bucket4:v1_read", "runtime:strict_1", "runtime:param_deny_root_ok"]:
        assert key in runtime, f"missing runtime result for {key}"
        assert runtime[key].get("status") == "ok", f"{key} should be ok"
    bucket5 = runtime.get("bucket5:v11_read_subpath")
    assert bucket5, "missing bucket5 runtime result"
    assert bucket5.get("status") == "partial", "bucket5 should stay partial (divergence on /tmp/foo)"
    probes = bucket5.get("probes") or []
    allow_probe = next((p for p in probes if p.get("name") == "read_/tmp/foo"), None)
    assert allow_probe, "expected bucket5 read_/tmp/foo probe"
    assert allow_probe.get("expected") == "allow"
    assert allow_probe.get("actual") == "deny"

    param = runtime.get("runtime:param_deny_root_ok") or {}
    probes = param.get("probes") or []
    allow_probe = next((p for p in probes if p.get("name") == "read_/private/tmp/sbpl_rt/read.txt"), None)
    deny_probe = next((p for p in probes if p.get("name") == "read_/private/tmp/ok/allow.txt"), None)
    assert allow_probe and deny_probe
    assert allow_probe.get("actual") == "allow"
    assert deny_probe.get("actual") == "deny"
