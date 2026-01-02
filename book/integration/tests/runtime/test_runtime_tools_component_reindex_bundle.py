from __future__ import annotations

import json
from pathlib import Path

import pytest

from book.api.runtime.execution import service as runtime_api
from book.api.runtime.execution.channels import ChannelSpec


from book.api import path_utils
REPO_ROOT = path_utils.find_repo_root(Path(__file__))
HARDENED_PLAN = REPO_ROOT / "book" / "experiments" / "runtime-final-final" / "suites" / "hardened-runtime" / "plan.json"


def test_reindex_bundle_repair_fixes_digest_mismatch(tmp_path, monkeypatch):
    monkeypatch.setenv("SANDBOX_LORE_RUN_ID", "run-test-repair")
    bundle_root = (tmp_path / "bundle").resolve()
    channel = ChannelSpec(channel="direct", lock_mode="fail", lock_timeout_seconds=0.1)

    bundle = runtime_api.run_plan(HARDENED_PLAN, bundle_root, channel=channel, dry_run=True)
    index_path = bundle.out_dir / "artifact_index.json"
    doc = json.loads(index_path.read_text())
    artifacts = doc.get("artifacts") or []
    assert artifacts, "expected at least one indexed artifact"
    artifacts[0]["sha256"] = "0" * 64
    index_path.write_text(json.dumps(doc, indent=2))

    with pytest.raises(ValueError):
        runtime_api.load_bundle(bundle.out_dir)

    with pytest.raises(ValueError):
        runtime_api.reindex_bundle(bundle.out_dir, repair=False)

    repaired = runtime_api.reindex_bundle(bundle.out_dir, repair=True)
    assert repaired.get("status") == "repaired"
    assert (bundle.out_dir / "repair_log.json").exists()

    # Post-repair strict load should pass.
    _ = runtime_api.load_bundle(bundle.out_dir)

    repair_log = json.loads((bundle.out_dir / "repair_log.json").read_text())
    assert repair_log.get("schema_version") == "runtime-tools.repair_log.v0.1"
    assert repair_log.get("before", {}).get("digest_mismatches")
    assert repair_log.get("after", {}).get("digest_mismatches") == []

