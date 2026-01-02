import json
import os
from pathlib import Path

import pytest

from book.api import path_utils
from book.api.runtime.analysis import packet_utils

ROOT = path_utils.find_repo_root(Path(__file__))
MILESTONE_PATH = ROOT / "book" / "evidence" / "experiments" / "field2-final-final" / "active_milestone.json"
DECISIONS_PATH = ROOT / "book" / "evidence" / "experiments" / "field2-final-final" / "decisions.jsonl"


def _load_json(path: Path):
    assert path.exists(), f"missing expected file: {path}"
    return json.loads(path.read_text())


def _load_jsonl(path: Path):
    assert path.exists(), f"missing expected file: {path}"
    records = []
    for line in path.read_text().splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def _assert_relpath(path_str: str, *, root: Path):
    assert path_str, "expected non-empty path"
    rel_path = Path(path_str)
    assert not rel_path.is_absolute(), f"expected repo-relative path, got absolute: {path_str}"
    abs_path = (root / rel_path).resolve()
    assert abs_path.exists(), f"expected path to exist: {path_str}"
    return abs_path


def test_field2_progress_gate():
    if not os.environ.get("FIELD2_PROGRESS"):
        pytest.skip("FIELD2_PROGRESS not set")

    milestone = _load_json(MILESTONE_PATH)
    decisions = _load_jsonl(DECISIONS_PATH)

    candidates = milestone.get("candidates") or []
    assert candidates, "milestone candidates list is empty"

    claim_keys = [entry.get("claim_key") for entry in candidates]
    assert all(claim_keys), "milestone contains missing claim_key entries"
    expected = set(claim_keys)

    decision_map = {}
    for rec in decisions:
        key = rec.get("claim_key")
        assert key, "decision missing claim_key"
        assert key not in decision_map, f"duplicate decision for {key}"
        decision_map[key] = rec

    missing = expected - set(decision_map)
    assert not missing, f"missing decisions for: {sorted(missing)}"

    reqs = milestone.get("requirements") or {}
    require_packet = bool(reqs.get("require_packet"))
    require_lanes = bool(reqs.get("require_lane_attribution"))
    require_delta_or_retire = bool(reqs.get("require_mapping_delta_or_retire"))

    for key in expected:
        rec = decision_map[key]
        decision = rec.get("decision")
        assert decision in {"promoted", "retired"}, f"invalid decision for {key}: {decision}"

        evidence = rec.get("evidence") or {}
        consumer = rec.get("consumer") or {}
        attempt_count = rec.get("attempt_count")
        last_attempt_packet = rec.get("last_attempt_packet")
        assert isinstance(attempt_count, int), f"missing attempt_count for {key}"
        assert attempt_count >= 0, f"invalid attempt_count for {key}: {attempt_count}"
        assert last_attempt_packet, f"missing last_attempt_packet for {key}"
        _assert_relpath(last_attempt_packet, root=ROOT)

        if require_packet:
            assert evidence.get("packet_run_id"), f"missing packet_run_id for {key}"
            assert evidence.get("artifact_index_digest"), f"missing artifact_index_digest for {key}"
            packet_path = evidence.get("packet_relpath")
            packet_abs = _assert_relpath(packet_path, root=ROOT)
            ctx = packet_utils.resolve_packet_context(packet_abs, required_exports=(), repo_root=ROOT)
            assert ctx.run_id == evidence.get("packet_run_id"), f"run_id mismatch for {key}"
            assert ctx.artifact_index_sha256 == evidence.get("artifact_index_digest"), f"digest mismatch for {key}"

        if require_lanes:
            lanes = evidence.get("lanes")
            assert isinstance(lanes, dict), f"missing lanes for {key}"
            for lane in ("baseline", "scenario", "negative"):
                assert lane in lanes, f"missing lane {lane} for {key}"

        assert evidence.get("suite_id"), f"missing suite_id for {key}"
        assert evidence.get("stage_attribution"), f"missing stage_attribution for {key}"
        assert consumer.get("atlas_run_id"), f"missing atlas_run_id for {key}"

        if require_delta_or_retire:
            if decision == "promoted":
                delta_path = consumer.get("mapping_delta_relpath")
                delta_abs = _assert_relpath(delta_path, root=ROOT)
                delta_doc = json.loads(delta_abs.read_text())
                proposals = delta_doc.get("proposals") or []
                unresolved = delta_doc.get("unresolved") or []
                assert proposals or unresolved, f"mapping delta empty for {key}"
            else:
                blocker = rec.get("blocker") or {}
                assert blocker.get("blocker_class"), f"retired claim missing blocker_class: {key}"
                assert blocker.get("retire_reason"), f"retired claim missing retire_reason: {key}"
