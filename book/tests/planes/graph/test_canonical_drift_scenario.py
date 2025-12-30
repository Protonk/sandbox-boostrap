import importlib
import json
from pathlib import Path

import pytest


from book.api import path_utils
ROOT = path_utils.find_repo_root(Path(__file__))
DIGESTS_PATH = ROOT / "book/graph/mappings/system_profiles/digests.json"
TAG_LAYOUTS_PATH = ROOT / "book/graph/mappings/tag_layouts/tag_layouts.json"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def test_canonical_drift_demotes_and_propagates(monkeypatch, tmp_path):
    """Simulate a fabricated blob-hash drift and assert demotion flows through digests → tag layouts → CARTON."""
    # Baseline expectation from current canonical mapping
    baseline_digests = load_json(DIGESTS_PATH)
    baseline_tag_layouts = TAG_LAYOUTS_PATH.read_text()

    # Force a blob hash drift for sys:bsd while keeping contract expectations from baseline.
    gd = importlib.import_module("book.graph.mappings.system_profiles.generate_digests_from_ir")
    tmp_digests = tmp_path / "digests.json"
    monkeypatch.setattr(gd, "OUT_PATH", tmp_digests)
    monkeypatch.setattr(gd, "STATIC_CHECKS_PATH", gd.STATIC_CHECKS_PATH)
    monkeypatch.setattr(gd, "IR_PATH", gd.IR_PATH)
    monkeypatch.setattr(gd, "load_existing_mapping", lambda: baseline_digests)
    real_sha = gd.sha256_path

    def fake_sha(path: Path) -> str:
        if path.name == "bsd.sb.bin":
            return "0" * 64
        return real_sha(path)

    monkeypatch.setattr(gd, "sha256_path", fake_sha)
    gd.main()
    degraded = load_json(tmp_digests)
    assert degraded["metadata"]["status"] == "brittle"
    bsd_meta = degraded["metadata"]["canonical_profiles"]["sys:bsd"]
    assert bsd_meta["status"] == "brittle"
    assert "blob_sha256" in bsd_meta["drift_fields"]
    assert degraded["profiles"]["sys:bsd"]["downgrade"]["fields"]
    # Drift should not invent new world pointers or demote unaffected canonical entries.
    assert degraded["metadata"]["canonical_profiles"]["sys:airlock"]["status"] == "ok"

    # Propagate to tag layouts
    tl = importlib.import_module("book.graph.mappings.tag_layouts.annotate_metadata")
    tmp_tag_layouts = tmp_path / "tag_layouts.json"
    tmp_tag_layouts.write_text(baseline_tag_layouts)
    monkeypatch.setattr(tl, "TAG_LAYOUTS_PATH", tmp_tag_layouts)
    monkeypatch.setattr(tl, "DIGESTS_PATH", tmp_digests)
    tl.main()
    tag_layouts = load_json(tmp_tag_layouts)
    assert tag_layouts["metadata"]["status"] == "brittle"
    assert tag_layouts["metadata"]["canonical_profiles"]["sys:bsd"] == "brittle"

    # Propagate to coverage and indices (with temp outputs to avoid touching real mappings)
    cov = importlib.import_module("book.graph.mappings.carton.generate_coverage_from_carton")
    tmp_cov = tmp_path / "operation_coverage.json"
    monkeypatch.setattr(cov, "DIGESTS_PATH", tmp_digests)
    monkeypatch.setattr(cov, "OUT_PATH", tmp_cov)
    monkeypatch.setattr(cov, "run_validation", lambda: None)
    monkeypatch.setattr(cov, "require_jobs", lambda status: None)
    cov.main()
    coverage = load_json(tmp_cov)
    assert coverage["metadata"]["status"] == "brittle"
    assert coverage["metadata"]["canonical_profile_status"]["sys:bsd"] == "brittle"

    op_idx = importlib.import_module("book.graph.mappings.carton.generate_operation_index")
    tmp_op_idx = tmp_path / "operation_index.json"
    monkeypatch.setattr(op_idx, "COVERAGE", tmp_cov)
    monkeypatch.setattr(op_idx, "DIGESTS", tmp_digests)
    monkeypatch.setattr(op_idx, "OUT", tmp_op_idx)
    op_idx.main()
    operation_index = load_json(tmp_op_idx)
    assert operation_index["metadata"]["status"] == "brittle"
    assert operation_index["metadata"]["canonical_profile_status"]["sys:bsd"] == "brittle"

    profile_idx = importlib.import_module("book.graph.mappings.carton.generate_profile_layer_index")
    tmp_profile_idx = tmp_path / "profile_layer_index.json"
    monkeypatch.setattr(profile_idx, "DIGESTS", tmp_digests)
    monkeypatch.setattr(profile_idx, "COVERAGE", tmp_cov)
    monkeypatch.setattr(profile_idx, "OUT", tmp_profile_idx)
    profile_idx.main()
    profile_layer_index = load_json(tmp_profile_idx)
    assert profile_layer_index["metadata"]["status"] == "brittle"
    assert profile_layer_index["metadata"]["canonical_profile_status"]["sys:bsd"] == "brittle"
    assert profile_layer_index["profiles"]["sys:bsd"]["status"] == "brittle"
    # Future downstream consumers should wire into this same path: fabricate drift, run generator, expect the same demotion signal.
