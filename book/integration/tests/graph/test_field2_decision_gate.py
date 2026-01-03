import json
import os
from pathlib import Path

import pytest

from book.api import path_utils

ROOT = path_utils.find_repo_root(Path(__file__))
FIELD2_ROOT = ROOT / "book" / "evidence" / "experiments" / "field2-final-final"
POLICY_PATH = ROOT / "book" / "tools" / "policy" / "ratchet" / "decision_policy.json"
MILESTONE_PATH = FIELD2_ROOT / "active_milestone.json"
DECISIONS_PATH = FIELD2_ROOT / "decisions.jsonl"
WITNESSES_PATH = FIELD2_ROOT / "decision_witnesses.jsonl"


CONFIDENCE_ORDER = {
    "low": 0,
    "medium": 1,
    "high": 2,
}


def _load_json(path: Path):
    assert path.exists(), f"missing expected file: {path}"
    return json.loads(path.read_text())


def _load_jsonl(path: Path):
    if not path.exists():
        return []
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


def _confidence_ok(confidence: str | None, minimum: str | None) -> bool:
    if minimum is None:
        return True
    if confidence is None:
        return False
    return CONFIDENCE_ORDER.get(confidence, -1) >= CONFIDENCE_ORDER.get(minimum, 0)


def _merge_driver_min(defaults: dict, overrides: dict) -> dict[str, int]:
    merged = dict(defaults or {})
    merged.update(overrides or {})
    return merged


def _merge_optional(defaults: list | None, overrides: list | None) -> set[str]:
    merged = set(defaults or [])
    merged.update(overrides or [])
    return merged


def test_field2_decision_gate():
    if not os.environ.get("FIELD2_DECIDE"):
        pytest.skip("FIELD2_DECIDE not set")

    policy = _load_json(POLICY_PATH)
    milestone = _load_json(MILESTONE_PATH)
    decisions = _load_jsonl(DECISIONS_PATH)
    witnesses = _load_jsonl(WITNESSES_PATH)

    defaults = policy.get("defaults") or {}
    claim_overrides = policy.get("claim_overrides") or {}

    candidates = milestone.get("candidates") or []
    assert candidates, "milestone candidates list is empty"

    claim_field2 = {}
    for entry in candidates:
        key = entry.get("claim_key")
        field2 = entry.get("field2")
        assert key, "milestone contains missing claim_key entries"
        assert field2 is not None, f"milestone missing field2 for {key}"
        claim_field2[key] = field2

    decision_map = {}
    for rec in decisions:
        key = rec.get("claim_key")
        assert key, "decision missing claim_key"
        assert key not in decision_map, f"duplicate decision for {key}"
        decision_map[key] = rec

    witness_map = {}
    for rec in witnesses:
        key = rec.get("claim_key")
        if not key:
            continue
        witness_map[key] = rec

    failures: list[str] = []
    for key, field2 in claim_field2.items():
        decision = decision_map.get(key)
        if decision is None:
            failures.append(f"missing decision for {key}")
            continue

        decision_state = decision.get("decision")
        if decision_state not in {"promoted", "retired"}:
            failures.append(f"invalid decision for {key}: {decision_state}")
            continue

        if decision_state == "retired":
            blocker = decision.get("blocker") or {}
            if not blocker.get("blocker_class") or not blocker.get("retire_reason"):
                failures.append(f"retired claim missing blocker metadata: {key}")
            continue

        witness = witness_map.get(key)
        if witness is None:
            failures.append(f"missing decision witnesses for {key}")
            continue

        packet_relpath = witness.get("packet_relpath")
        if not packet_relpath:
            failures.append(f"missing packet_relpath in witness for {key}")
        else:
            _assert_relpath(packet_relpath, root=ROOT)
            last_attempt = decision.get("last_attempt_packet")
            if last_attempt and packet_relpath != last_attempt:
                failures.append(f"packet mismatch for {key}: {packet_relpath} vs {last_attempt}")

        runtime_events_relpath = witness.get("runtime_events_relpath")
        if runtime_events_relpath:
            _assert_relpath(runtime_events_relpath, root=ROOT)

        overrides = claim_overrides.get(key) or {}
        min_clean = overrides.get("min_clean_witnesses", defaults.get("min_clean_witnesses", 1))
        noisy_budget = overrides.get("noisy_runtime_retry_budget", defaults.get("noisy_runtime_retry_budget", 0))
        driver_min = _merge_driver_min(defaults.get("driver_min_clean"), overrides.get("driver_min_clean"))
        optional_drivers = _merge_optional(defaults.get("optional_drivers"), overrides.get("optional_drivers"))

        require_inside = bool(defaults.get("require_inside"))
        inside_accept = defaults.get("inside_accept") or {}
        inside_expected = inside_accept.get("harness_constrained")
        inside_min_conf = inside_accept.get("min_confidence")

        inside_block = False
        inside = witness.get("inside") if isinstance(witness.get("inside"), dict) else {}
        summary = inside.get("summary") if isinstance(inside.get("summary"), dict) else None
        if require_inside:
            if summary is None:
                inside_block = True
                failures.append(f"missing inside summary for {key}")
            else:
                constrained = summary.get("harness_constrained")
                if constrained is not inside_expected:
                    inside_block = True
                    failures.append(f"inside mismatch for {key}: harness_constrained={constrained}")
                if not _confidence_ok(summary.get("confidence"), inside_min_conf):
                    inside_block = True
                    failures.append(f"inside confidence below {inside_min_conf} for {key}")

        require_preflight = bool(defaults.get("require_preflight"))
        allowed_preflight = set(defaults.get("preflight_accept") or [])
        blocked_stages = set(defaults.get("blocked_failure_stages") or [])

        clean_count = 0
        noisy_count = 0
        clean_by_driver: dict[str, int] = {}

        for event in witness.get("witnesses") or []:
            if not isinstance(event, dict):
                continue
            driver = event.get("driver")
            runtime_status = event.get("runtime_status")
            failure_stage = event.get("failure_stage")
            match = event.get("match")
            preflight = event.get("preflight") if isinstance(event.get("preflight"), dict) else {}
            preflight_class = preflight.get("classification")

            if require_preflight and preflight_class not in allowed_preflight:
                failures.append(f"preflight missing/blocked for {key}: {preflight_class}")
                continue
            if inside_block:
                continue

            blocked = runtime_status == "blocked" or (failure_stage in blocked_stages if failure_stage else False)
            clean = False
            if runtime_status == "success":
                clean = match is not False

            if blocked:
                continue
            if clean:
                clean_count += 1
                if driver:
                    clean_by_driver[driver] = clean_by_driver.get(driver, 0) + 1
            else:
                if driver in optional_drivers:
                    continue
                noisy_count += 1

        if clean_count < min_clean:
            failures.append(f"insufficient clean witnesses for {key}: {clean_count} < {min_clean}")
        for driver, required in driver_min.items():
            if clean_by_driver.get(driver, 0) < required:
                failures.append(f"insufficient clean witnesses for {key} driver {driver}")
        if noisy_count > noisy_budget:
            failures.append(f"noisy runtime exceeded for {key}: {noisy_count} > {noisy_budget}")

    assert not failures, "decision gate failures:\n" + "\n".join(failures)
