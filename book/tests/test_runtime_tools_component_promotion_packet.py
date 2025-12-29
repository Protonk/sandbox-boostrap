from __future__ import annotations

import json
from pathlib import Path

import pytest

from book.api.runtime import api as runtime_api
from book.api.runtime.artifacts import writer as artifact_writer


ROOT = Path(__file__).resolve().parents[2]
WORLD_ID = "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5"


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))


def _make_minimal_bundle(
    run_dir: Path,
    *,
    run_id: str,
    channel: str,
    apply_ok: bool,
    sandboxed: bool,
    include_decision_stage: bool,
    extra_expected_missing: list[str] | None = None,
) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)

    apply_preflight_record = {
        "apply_ok": apply_ok,
        "sandbox_check_self": {"sandboxed": sandboxed},
    }
    _write_json(
        run_dir / "run_manifest.json",
        {
            "schema_version": "runtime-tools.run_manifest.v0.1",
            "run_id": run_id,
            "world_id": WORLD_ID,
            "channel": channel,
            "plan_id": "test:synthetic",
            "plan_digest": "synthetic",
            "dry_run": False,
            "output_root": "synthetic",
            "apply_preflight": {"path": "apply_preflight.json", "record": apply_preflight_record},
        },
    )
    _write_json(
        run_dir / "run_status.json",
        {
            "schema_version": "runtime-tools.run_status.v0.1",
            "run_id": run_id,
            "world_id": WORLD_ID,
            "channel": channel,
            "plan_id": "test:synthetic",
            "plan_digest": "synthetic",
            "state": "complete",
        },
    )

    expected_artifacts = ["run_manifest.json", "run_status.json"]
    if include_decision_stage:
        _write_json(run_dir / "expected_matrix.json", {"world_id": WORLD_ID, "profiles": {}})
        _write_json(run_dir / "runtime_results.json", {})
        _write_json(run_dir / "runtime_events.normalized.json", [])
        expected_artifacts.extend(["expected_matrix.json", "runtime_results.json", "runtime_events.normalized.json"])

    if extra_expected_missing:
        expected_artifacts.extend(extra_expected_missing)

    artifact_writer.write_artifact_index(
        run_dir,
        run_id=run_id,
        world_id=WORLD_ID,
        schema_version="runtime-tools.artifact_index.v0.1",
        expected_artifacts=expected_artifacts,
        repo_root=ROOT,
    )


def test_promotability_rejects_non_clean_channel_even_with_decision_stage_artifacts(tmp_path):
    run_dir = tmp_path / "bundle" / "run-1"
    _make_minimal_bundle(
        run_dir,
        run_id="run-1",
        channel="direct",
        apply_ok=True,
        sandboxed=False,
        include_decision_stage=True,
    )

    out_path = tmp_path / "promotion_packet.json"
    packet = runtime_api.emit_promotion_packet(run_dir, out_path)
    promotability = packet.get("promotability") or {}
    assert promotability.get("promotable_decision_stage") is False
    assert "not_clean_channel" in (promotability.get("reasons") or [])

    with pytest.raises(RuntimeError):
        runtime_api.emit_promotion_packet(run_dir, out_path, require_promotable=True)


def test_promotability_rejects_apply_failed_on_clean_channel(tmp_path):
    run_dir = tmp_path / "bundle" / "run-2"
    _make_minimal_bundle(
        run_dir,
        run_id="run-2",
        channel="launchd_clean",
        apply_ok=False,
        sandboxed=False,
        include_decision_stage=True,
    )

    packet = runtime_api.emit_promotion_packet(run_dir, tmp_path / "promotion_packet.json")
    promotability = packet.get("promotability") or {}
    assert promotability.get("promotable_decision_stage") is False
    assert "apply_failed" in (promotability.get("reasons") or [])


def test_promotability_marks_bundle_incomplete_from_index_missing_list(tmp_path):
    run_dir = tmp_path / "bundle" / "run-3"
    _make_minimal_bundle(
        run_dir,
        run_id="run-3",
        channel="launchd_clean",
        apply_ok=True,
        sandboxed=False,
        include_decision_stage=True,
        extra_expected_missing=["missing_artifact.json"],
    )

    packet = runtime_api.emit_promotion_packet(run_dir, tmp_path / "promotion_packet.json")
    promotability = packet.get("promotability") or {}
    assert promotability.get("promotable_decision_stage") is False
    assert "bundle_incomplete" in (promotability.get("reasons") or [])


def test_promotability_marks_integrity_unverified_on_digest_mismatch(tmp_path):
    run_dir = tmp_path / "bundle" / "run-4"
    _make_minimal_bundle(
        run_dir,
        run_id="run-4",
        channel="launchd_clean",
        apply_ok=True,
        sandboxed=False,
        include_decision_stage=True,
    )

    # Introduce drift: mutate a file after indexing so strict verification fails.
    manifest = json.loads((run_dir / "run_manifest.json").read_text())
    manifest["plan_id"] = "test:drift"
    _write_json(run_dir / "run_manifest.json", manifest)

    packet = runtime_api.emit_promotion_packet(run_dir, tmp_path / "promotion_packet.json")
    promotability = packet.get("promotability") or {}
    assert promotability.get("promotable_decision_stage") is False
    assert "bundle_integrity_unverified" in (promotability.get("reasons") or [])


def test_open_bundle_unverified_allows_incomplete_bundles_and_packet_marks_non_promotable(tmp_path):
    run_dir = tmp_path / "bundle" / "run-5"
    run_dir.mkdir(parents=True, exist_ok=True)
    _write_json(
        run_dir / "run_manifest.json",
        {
            "schema_version": "runtime-tools.run_manifest.v0.1",
            "run_id": "run-5",
            "world_id": WORLD_ID,
            "channel": "launchd_clean",
            "plan_id": "test:synthetic",
            "plan_digest": "synthetic",
            "dry_run": False,
            "output_root": "synthetic",
            "apply_preflight": {"path": "apply_preflight.json", "record": {"apply_ok": True, "sandbox_check_self": {}}},
        },
    )
    _write_json(
        run_dir / "run_status.json",
        {
            "schema_version": "runtime-tools.run_status.v0.1",
            "run_id": "run-5",
            "world_id": WORLD_ID,
            "channel": "launchd_clean",
            "plan_id": "test:synthetic",
            "plan_digest": "synthetic",
            "state": "complete",
        },
    )

    # No artifact_index.json here: strict load must fail, but debug open must not.
    debug = runtime_api.open_bundle_unverified(run_dir)
    assert debug.get("integrity") == "unverified"
    assert debug.get("artifact_index_present") is False

    packet = runtime_api.emit_promotion_packet(run_dir, tmp_path / "promotion_packet.json")
    promotability = packet.get("promotability") or {}
    assert promotability.get("promotable_decision_stage") is False
    assert "bundle_integrity_unverified" in (promotability.get("reasons") or [])
