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


def _index_atlas(atlas_doc: dict) -> dict:
    entries = atlas_doc.get("atlas") or []
    index = {}
    for entry in entries:
        field2 = entry.get("field2")
        if field2 is None:
            continue
        if field2 in index:
            raise AssertionError(f"duplicate atlas entry for field2={field2}")
        index[field2] = entry
    return index


def test_field2_progress_gate():
    if not os.environ.get("FIELD2_PROGRESS"):
        pytest.skip("FIELD2_PROGRESS not set")

    milestone = _load_json(MILESTONE_PATH)
    decisions = _load_jsonl(DECISIONS_PATH)

    candidates = milestone.get("candidates") or []
    assert candidates, "milestone candidates list is empty"

    claim_keys = [entry.get("claim_key") for entry in candidates]
    assert all(claim_keys), "milestone contains missing claim_key entries"
    claim_field2 = {}
    for entry in candidates:
        key = entry.get("claim_key")
        field2 = entry.get("field2")
        assert key, "milestone contains missing claim_key entries"
        assert field2 is not None, f"milestone missing field2 for {key}"
        claim_field2[key] = field2
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
    require_no_runtime_candidate = bool(reqs.get("require_no_runtime_candidate"))
    require_no_unresolved = bool(reqs.get("require_no_unresolved"))
    require_unresolved_retired = bool(reqs.get("require_unresolved_retired"))
    min_lane_witnesses = reqs.get("min_lane_witnesses")
    if min_lane_witnesses is not None:
        assert isinstance(min_lane_witnesses, int), "min_lane_witnesses must be an integer"

    atlas_runs = {}
    for key in expected:
        rec = decision_map[key]
        field2 = claim_field2.get(key)
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

        delta_abs = None
        if consumer.get("mapping_delta_relpath"):
            delta_abs = _assert_relpath(consumer.get("mapping_delta_relpath"), root=ROOT)

        if require_packet:
            assert evidence.get("packet_run_id"), f"missing packet_run_id for {key}"
            assert evidence.get("artifact_index_digest"), f"missing artifact_index_digest for {key}"
            packet_path = evidence.get("packet_relpath")
            packet_abs = _assert_relpath(packet_path, root=ROOT)
            ctx = packet_utils.resolve_packet_context(packet_abs, required_exports=(), repo_root=ROOT)
            assert ctx.run_id == evidence.get("packet_run_id"), f"run_id mismatch for {key}"
            assert ctx.artifact_index_sha256 == evidence.get("artifact_index_digest"), f"digest mismatch for {key}"

        lanes = evidence.get("lanes")
        if require_lanes or min_lane_witnesses is not None:
            assert isinstance(lanes, dict), f"missing lanes for {key}"
            for lane in ("baseline", "scenario", "negative"):
                assert lane in lanes, f"missing lane {lane} for {key}"
        if min_lane_witnesses is not None:
            lane_hits = sum(1 for val in lanes.values() if val)
            assert (
                lane_hits >= min_lane_witnesses
            ), f"insufficient lane witnesses for {key}: {lane_hits}"

        assert evidence.get("suite_id"), f"missing suite_id for {key}"
        assert evidence.get("stage_attribution"), f"missing stage_attribution for {key}"
        assert consumer.get("atlas_run_id"), f"missing atlas_run_id for {key}"

        run_id = consumer.get("atlas_run_id")
        if run_id:
            run_entry = atlas_runs.setdefault(run_id, {"field2s": set(), "delta_abs": None})
            if field2 is not None:
                run_entry["field2s"].add(field2)
            if delta_abs is not None:
                if run_entry["delta_abs"] is None:
                    run_entry["delta_abs"] = delta_abs
                else:
                    assert (
                        run_entry["delta_abs"] == delta_abs
                    ), f"mismatched mapping_delta for atlas run {run_id}"

        if require_delta_or_retire:
            if decision == "promoted":
                assert delta_abs is not None, f"missing mapping_delta_relpath for {key}"
                delta_doc = json.loads(delta_abs.read_text())
                proposals = delta_doc.get("proposals") or []
                unresolved = delta_doc.get("unresolved") or []
                assert proposals or unresolved, f"mapping delta empty for {key}"
            else:
                blocker = rec.get("blocker") or {}
                assert blocker.get("blocker_class"), f"retired claim missing blocker_class: {key}"
                assert blocker.get("retire_reason"), f"retired claim missing retire_reason: {key}"

    if require_no_runtime_candidate or require_no_unresolved or require_unresolved_retired:
        for run_id, run_entry in atlas_runs.items():
            delta_abs = run_entry.get("delta_abs")
            assert delta_abs is not None, f"missing mapping_delta_relpath for atlas run {run_id}"
            field2s = run_entry.get("field2s") or set()

            atlas_dir = delta_abs.parent
            atlas_path = atlas_dir / "field2_atlas.json"
            atlas_doc = _load_json(atlas_path)
            atlas_index = _index_atlas(atlas_doc)

            if require_no_runtime_candidate:
                missing = []
                for fid in field2s:
                    entry = atlas_index.get(fid)
                    assert entry is not None, f"missing atlas entry for field2={fid}"
                    if entry.get("status") in {"missing_probe", "no_runtime_candidate"}:
                        missing.append(fid)
                assert not missing, f"missing runtime candidates for: {sorted(missing)}"

            if require_no_unresolved or require_unresolved_retired:
                delta_doc = json.loads(delta_abs.read_text())
                unresolved = [
                    item for item in (delta_doc.get("unresolved") or []) if item.get("field2") in field2s
                ]
                if require_no_unresolved:
                    assert not unresolved, f"unresolved mapping_delta entries: {sorted({u.get('field2') for u in unresolved})}"
                if require_unresolved_retired:
                    for item in unresolved:
                        fid = item.get("field2")
                        key = f"field2={fid}"
                        rec = decision_map.get(key)
                        assert rec is not None, f"missing decision for unresolved field2={fid}"
                        assert rec.get("decision") == "retired", f"unresolved field2={fid} not retired"
                        blocker = rec.get("blocker") or {}
                        assert blocker.get("blocker_class"), f"missing blocker_class for field2={fid}"
                        assert blocker.get("retire_reason"), f"missing retire_reason for field2={fid}"
