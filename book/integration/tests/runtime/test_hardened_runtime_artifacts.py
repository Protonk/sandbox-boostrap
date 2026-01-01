from __future__ import annotations

from pathlib import Path

from book.api import path_utils
from book.integration.tests.runtime.runtime_bundle_helpers import load_bundle_json, load_bundle_jsonl, resolve_bundle_dir


REPO_ROOT = path_utils.find_repo_root(Path(__file__))
BASE_DIR = REPO_ROOT / "book" / "experiments" / "hardened-runtime"
OUT_DIR = BASE_DIR / "out"

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

ALLOWED_REASONS = {
    "ambient_platform_restriction",
    "canonicalization_boundary",
    "path_normalization_sensitivity",
    "anchor_alias_gap",
    "expectation_too_strong",
    "capture_pipeline_disagreement",
}


def test_hardened_runtime_artifacts_are_coherent():
    bundle_dir, _ = resolve_bundle_dir(OUT_DIR)
    artifact_index_path = bundle_dir / "artifact_index.json"
    expected_matrix_path = bundle_dir / "expected_matrix.json"
    runtime_results_path = bundle_dir / "runtime_results.json"
    mismatch_summary_path = bundle_dir / "mismatch_summary.json"
    mismatch_packets_path = bundle_dir / "mismatch_packets.jsonl"

    summary = load_bundle_json(OUT_DIR, "summary.json")
    status = summary.get("status")

    summary_profiles = set(summary.get("expected_profiles") or [])
    assert summary_profiles == EXPECTED_PROFILES

    if expected_matrix_path.exists():
        matrix = load_bundle_json(OUT_DIR, "expected_matrix.json")
        matrix_profiles = set((matrix.get("profiles") or {}).keys())
        assert matrix_profiles == EXPECTED_PROFILES
    else:
        assert status == "not_run"

    if runtime_results_path.exists():
        runtime = load_bundle_json(OUT_DIR, "runtime_results.json")
        assert set(runtime.keys()) == EXPECTED_PROFILES
        for key in EXPECTED_PROFILES:
            assert runtime[key].get("schema_version"), f"missing schema_version in {key}"

        manifest = load_bundle_json(OUT_DIR, "run_manifest.json")
        assert manifest.get("schema_version")
        assert manifest.get("channel") == "launchd_clean"
        apply_preflight = (manifest.get("apply_preflight") or {}).get("record") or {}
        assert apply_preflight.get("apply_ok") is True
        assert artifact_index_path.exists(), "missing artifact_index.json"
    else:
        assert status == "not_run"

    if not mismatch_summary_path.exists():
        assert status == "not_run"
        return

    mismatches = load_bundle_json(OUT_DIR, "mismatch_summary.json").get("mismatches") or []
    if not mismatches:
        return

    packets = load_bundle_jsonl(OUT_DIR, "mismatch_packets.jsonl")
    packet_ids = {row.get("expectation_id") for row in packets if row.get("expectation_id")}
    missing = {row.get("expectation_id") for row in mismatches} - packet_ids
    assert not missing, f"missing mismatch packets for {len(missing)} expectations"
    for row in packets:
        assert row.get("schema_version"), "missing schema_version in mismatch packet"
        reason = row.get("mismatch_reason")
        assert reason in ALLOWED_REASONS, f"unexpected mismatch_reason: {reason}"
