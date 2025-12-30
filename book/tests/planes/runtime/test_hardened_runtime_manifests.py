import json
from pathlib import Path


from book.api import path_utils
REPO_ROOT = path_utils.find_repo_root(Path(__file__))
OUT_DIR = REPO_ROOT / "book" / "experiments" / "hardened-runtime" / "out"
SUMMARY = OUT_DIR / "summary.json"
RUN_MANIFEST = OUT_DIR / "run_manifest.json"
ARTIFACT_INDEX = OUT_DIR / "artifact_index.json"
RUNTIME_RESULTS = OUT_DIR / "runtime_results.json"


def load_json(path: Path):
    assert path.exists(), f"missing required file: {path}"
    return json.loads(path.read_text())


def test_hardened_runtime_manifest_gating():
    summary = load_json(SUMMARY)
    if RUNTIME_RESULTS.exists():
        manifest = load_json(RUN_MANIFEST)
        assert manifest.get("schema_version")
        assert manifest.get("channel") == "launchd_clean"
        apply_preflight = (manifest.get("apply_preflight") or {}).get("record") or {}
        assert apply_preflight.get("apply_ok") is True
        assert ARTIFACT_INDEX.exists(), "missing artifact_index.json"
    else:
        assert summary.get("status") == "not_run"
