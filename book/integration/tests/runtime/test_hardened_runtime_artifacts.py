from __future__ import annotations

import json
from pathlib import Path

from book.api import path_utils


REPO_ROOT = path_utils.find_repo_root(Path(__file__))
BASE_DIR = REPO_ROOT / "book" / "experiments" / "hardened-runtime"
OUT_DIR = BASE_DIR / "out"

SUMMARY = OUT_DIR / "summary.json"
RUN_MANIFEST = OUT_DIR / "run_manifest.json"
ARTIFACT_INDEX = OUT_DIR / "artifact_index.json"
EXPECTED_MATRIX = OUT_DIR / "expected_matrix.json"
RUNTIME_RESULTS = OUT_DIR / "runtime_results.json"
MISMATCH_SUMMARY = OUT_DIR / "mismatch_summary.json"
MISMATCH_PACKETS = OUT_DIR / "mismatch_packets.jsonl"

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
    "path_normalization_sensitivity",
    "anchor_alias_gap",
    "expectation_too_strong",
    "capture_pipeline_disagreement",
}


def _load_json(path: Path) -> dict:
    assert path.exists(), f"missing required file: {path}"
    return json.loads(path.read_text())


def _load_jsonl(path: Path) -> list[dict]:
    assert path.exists(), f"missing required file: {path}"
    rows: list[dict] = []
    for line in path.read_text().splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def test_hardened_runtime_artifacts_are_coherent():
    summary = _load_json(SUMMARY)
    status = summary.get("status")

    summary_profiles = set(summary.get("expected_profiles") or [])
    assert summary_profiles == EXPECTED_PROFILES

    if EXPECTED_MATRIX.exists():
        matrix = _load_json(EXPECTED_MATRIX)
        matrix_profiles = set((matrix.get("profiles") or {}).keys())
        assert matrix_profiles == EXPECTED_PROFILES
    else:
        assert status == "not_run"

    if RUNTIME_RESULTS.exists():
        runtime = _load_json(RUNTIME_RESULTS)
        assert set(runtime.keys()) == EXPECTED_PROFILES
        for key in EXPECTED_PROFILES:
            assert runtime[key].get("schema_version"), f"missing schema_version in {key}"

        manifest = _load_json(RUN_MANIFEST)
        assert manifest.get("schema_version")
        assert manifest.get("channel") == "launchd_clean"
        apply_preflight = (manifest.get("apply_preflight") or {}).get("record") or {}
        assert apply_preflight.get("apply_ok") is True
        assert ARTIFACT_INDEX.exists(), "missing artifact_index.json"
    else:
        assert status == "not_run"

    if not MISMATCH_SUMMARY.exists():
        assert status == "not_run"
        return

    mismatches = _load_json(MISMATCH_SUMMARY).get("mismatches") or []
    if not mismatches:
        return

    packets = _load_jsonl(MISMATCH_PACKETS)
    packet_ids = {row.get("expectation_id") for row in packets if row.get("expectation_id")}
    missing = {row.get("expectation_id") for row in mismatches} - packet_ids
    assert not missing, f"missing mismatch packets for {len(missing)} expectations"
    for row in packets:
        assert row.get("schema_version"), "missing schema_version in mismatch packet"
        reason = row.get("mismatch_reason")
        assert reason in ALLOWED_REASONS, f"unexpected mismatch_reason: {reason}"

