import json
from pathlib import Path

from book.graph.mappings.runtime import promotion_packets


ROOT = Path(__file__).resolve().parents[2]
STORY = ROOT / "book" / "graph" / "mappings" / "runtime_cuts" / "runtime_story.json"
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
    rows = []
    if not path.exists():
        return rows
    for line in path.read_text().splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def _story_mismatches(story_doc):
    mismatches = set()
    for op_entry in (story_doc.get("ops") or {}).values():
        for scenario in op_entry.get("scenarios") or []:
            for mismatch in scenario.get("mismatches") or []:
                eid = mismatch.get("expectation_id")
                if eid:
                    mismatches.add(eid)
    return mismatches


def test_mismatch_packets_cover_story_mismatches():
    story_doc = load_json(STORY)
    mismatch_ids = _story_mismatches(story_doc)

    packets = promotion_packets.load_packets(
        promotion_packets.DEFAULT_PACKET_PATHS,
        allow_missing=True,
    )
    rows = []
    for pkt in packets:
        mismatch_path = pkt.paths.get("mismatch_packets")
        if mismatch_path:
            rows.extend(load_jsonl(mismatch_path))

    packet_ids = {row.get("expectation_id") for row in rows if row.get("expectation_id")}
    missing = mismatch_ids - packet_ids
    assert not missing, f"missing mismatch packets for {len(missing)} expectations: {sorted(missing)[:5]}"
    for row in rows:
        reason = row.get("mismatch_reason")
        assert reason in ALLOWED_REASONS, f"unexpected mismatch_reason: {reason}"
