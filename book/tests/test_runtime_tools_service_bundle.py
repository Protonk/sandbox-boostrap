from __future__ import annotations

import fcntl
import json
import threading
import time
from pathlib import Path

import pytest

from book.api.runtime import api as runtime_api
from book.api.runtime.channels import ChannelSpec


REPO_ROOT = Path(__file__).resolve().parents[2]
HARDENED_PLAN = REPO_ROOT / "book" / "experiments" / "hardened-runtime" / "plan.json"


def test_run_plan_dry_writes_run_scoped_bundle_and_latest(tmp_path, monkeypatch):
    monkeypatch.setenv("SANDBOX_LORE_RUN_ID", "run-test-1")
    bundle_root = (tmp_path / "bundle").resolve()
    channel = ChannelSpec(channel="direct", lock_mode="fail", lock_timeout_seconds=0.1)

    bundle = runtime_api.run_plan(HARDENED_PLAN, bundle_root, channel=channel, dry_run=True)
    assert bundle.out_dir == bundle_root / "run-test-1"
    assert (bundle_root / "LATEST").read_text().strip() == "run-test-1"
    assert (bundle.out_dir / "artifact_index.json").exists()
    assert (bundle.out_dir / "run_status.json").exists()

    manifest = json.loads((bundle.out_dir / "run_manifest.json").read_text())
    assert manifest.get("schema_version")
    status = json.loads((bundle.out_dir / "run_status.json").read_text())
    assert status.get("schema_version")
    index_doc = json.loads((bundle.out_dir / "artifact_index.json").read_text())
    assert index_doc.get("schema_version")

    # Root resolution should follow LATEST.
    index = runtime_api.load_bundle(bundle_root)
    assert index.get("run_id") == "run-test-1"


def test_bundle_lock_fail_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("SANDBOX_LORE_RUN_ID", "run-test-lock")
    bundle_root = (tmp_path / "bundle").resolve()
    bundle_root.mkdir(parents=True, exist_ok=True)
    lock_path = bundle_root / ".runtime.lock"

    with lock_path.open("a+") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        channel = ChannelSpec(channel="direct", lock_mode="fail", lock_timeout_seconds=0.1)
        with pytest.raises(RuntimeError):
            runtime_api.run_plan(HARDENED_PLAN, bundle_root, channel=channel, dry_run=True)
        fcntl.flock(fh, fcntl.LOCK_UN)


def test_bundle_lock_wait_mode_eventually_acquires(tmp_path, monkeypatch):
    monkeypatch.setenv("SANDBOX_LORE_RUN_ID", "run-test-wait")
    bundle_root = (tmp_path / "bundle").resolve()
    bundle_root.mkdir(parents=True, exist_ok=True)
    lock_path = bundle_root / ".runtime.lock"

    fh = lock_path.open("a+")
    fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def release_lock():
        time.sleep(0.2)
        fcntl.flock(fh, fcntl.LOCK_UN)
        fh.close()

    t = threading.Thread(target=release_lock)
    t.start()
    channel = ChannelSpec(channel="direct", lock_mode="wait", lock_timeout_seconds=2.0)
    bundle = runtime_api.run_plan(HARDENED_PLAN, bundle_root, channel=channel, dry_run=True)
    t.join(timeout=2.0)

    assert bundle.out_dir == bundle_root / "run-test-wait"
    assert (bundle_root / "LATEST").read_text().strip() == "run-test-wait"


def test_emit_promotion_packet_requires_promotable(tmp_path, monkeypatch):
    monkeypatch.setenv("SANDBOX_LORE_RUN_ID", "run-test-packet")
    bundle_root = (tmp_path / "bundle").resolve()
    channel = ChannelSpec(channel="direct", lock_mode="fail", lock_timeout_seconds=0.1)
    bundle = runtime_api.run_plan(HARDENED_PLAN, bundle_root, channel=channel, dry_run=True)

    out_path = tmp_path / "promotion_packet.json"
    packet = runtime_api.emit_promotion_packet(bundle_root, out_path)
    assert packet.get("schema_version") == "runtime-tools.promotion_packet.v0.2"
    promotability = packet.get("promotability") or {}
    assert promotability.get("promotable_decision_stage") is False

    with pytest.raises(RuntimeError):
        runtime_api.emit_promotion_packet(bundle_root, out_path, require_promotable=True)


def test_failed_bundle_commits_failed_state(tmp_path, monkeypatch):
    monkeypatch.setenv("SANDBOX_LORE_RUN_ID", "run-test-fail")
    bundle_root = (tmp_path / "bundle").resolve()
    channel = ChannelSpec(channel="direct", lock_mode="fail", lock_timeout_seconds=0.1)

    def boom(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(runtime_api.workflow, "build_matrix", boom)

    bundle = runtime_api.run_plan(HARDENED_PLAN, bundle_root, channel=channel, dry_run=True)
    assert bundle.status == "failed"
    status_doc = (bundle.out_dir / "run_status.json").read_text()
    assert '"state": "failed"' in status_doc

    index = runtime_api.open_bundle_unverified(bundle.out_dir).get("artifact_index") or {}
    assert index.get("status") == "failed"


def test_commit_barrier_missing_artifact_index_does_not_update_latest(tmp_path, monkeypatch):
    monkeypatch.setenv("SANDBOX_LORE_RUN_ID", "run-test-no-index")
    bundle_root = (tmp_path / "bundle").resolve()
    channel = ChannelSpec(channel="direct", lock_mode="fail", lock_timeout_seconds=0.1)

    def boom(*_args, **_kwargs):
        raise RuntimeError("boom-index")

    monkeypatch.setattr(runtime_api, "_write_artifact_index", boom)

    with pytest.raises(RuntimeError):
        _ = runtime_api.run_plan(HARDENED_PLAN, bundle_root, channel=channel, dry_run=True)

    run_dir = bundle_root / "run-test-no-index"
    assert (run_dir / "run_status.json").exists()
    assert not (run_dir / "artifact_index.json").exists()
    assert not (bundle_root / "LATEST").exists()


def test_committed_bundle_loads_even_if_latest_update_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("SANDBOX_LORE_RUN_ID", "run-test-no-latest")
    bundle_root = (tmp_path / "bundle").resolve()
    channel = ChannelSpec(channel="direct", lock_mode="fail", lock_timeout_seconds=0.1)

    orig_write_text = runtime_api._write_text

    def boom_latest(path: Path, text: str):
        if path.name == "LATEST":
            raise RuntimeError("boom-latest")
        return orig_write_text(path, text)

    monkeypatch.setattr(runtime_api, "_write_text", boom_latest)

    with pytest.raises(RuntimeError):
        _ = runtime_api.run_plan(HARDENED_PLAN, bundle_root, channel=channel, dry_run=True)

    run_dir = bundle_root / "run-test-no-latest"
    assert (run_dir / "artifact_index.json").exists()
    assert not (bundle_root / "LATEST").exists()

    # The run-scoped directory is still a committed bundle even if the pointer update failed.
    index = runtime_api.load_bundle(run_dir)
    assert index.get("run_id") == "run-test-no-latest"
