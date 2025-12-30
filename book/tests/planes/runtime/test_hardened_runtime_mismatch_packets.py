import json
from pathlib import Path


from book.api import path_utils
REPO_ROOT = path_utils.find_repo_root(Path(__file__))
OUT_DIR = REPO_ROOT / "book" / "experiments" / "hardened-runtime" / "out"
SUMMARY = OUT_DIR / "summary.json"
MISMATCH_SUMMARY = OUT_DIR / "mismatch_summary.json"
MISMATCH_PACKETS = OUT_DIR / "mismatch_packets.jsonl"

ALLOWED_REASONS = {
    "ambient_platform_restriction",
    "path_normalization_sensitivity",
    "anchor_alias_gap",
    "expectation_too_strong",
    "capture_pipeline_disagreement",
}


def load_json(path: Path):
    assert path.exists(), f"missing required file: {path}"
    return json.loads(path.read_text())


def load_jsonl(path: Path):
    assert path.exists(), f"missing required file: {path}"
    rows = []
    for line in path.read_text().splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def test_hardened_runtime_mismatch_packets():
    summary = load_json(SUMMARY)
    if not MISMATCH_SUMMARY.exists():
        assert summary.get("status") == "not_run"
        return

    mismatches = load_json(MISMATCH_SUMMARY).get("mismatches") or []
    if not mismatches:
        return

    packets = load_jsonl(MISMATCH_PACKETS)
    packet_ids = {row.get("expectation_id") for row in packets if row.get("expectation_id")}
    missing = {row.get("expectation_id") for row in mismatches} - packet_ids
    assert not missing, f"missing mismatch packets for {len(missing)} expectations"
    for row in packets:
        assert row.get("schema_version"), "missing schema_version in mismatch packet"
        reason = row.get("mismatch_reason")
        assert reason in ALLOWED_REASONS, f"unexpected mismatch_reason: {reason}"
