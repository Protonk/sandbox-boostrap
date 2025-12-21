#!/usr/bin/env python3
"""
Generate runtime_signatures.json from validation IR only.

Inputs (IR produced by the validation driver):
- book/graph/concepts/validation/out/experiments/runtime-checks/runtime_results.normalized.json
- book/graph/concepts/validation/out/experiments/field2/field2_ir.json

Flow:
- Run the validation driver with the smoke tag (vocab + field2 + runtime-checks).
- Require those jobs to be status=ok in validation_status.json.
- Read normalized IR and emit a small mapping in book/graph/mappings/runtime/runtime_signatures.json.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, Any, Tuple

from book.api.runtime_tools import observations as runtime_observations

ROOT = Path(__file__).resolve().parents[4]
RUNTIME_IR = ROOT / "book/graph/concepts/validation/out/experiments/runtime-checks/runtime_results.normalized.json"
FIELD2_IR = ROOT / "book/graph/concepts/validation/out/experiments/field2/field2_ir.json"
STATUS_PATH = ROOT / "book/graph/concepts/validation/out/validation_status.json"
OUT_PATH = ROOT / "book/graph/mappings/runtime/runtime_signatures.json"
BASELINE_REF = "book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json"
BASELINE_PATH = ROOT / BASELINE_REF
EXPECTED_JOBS = {"experiment:runtime-checks", "experiment:field2"}
RUNTIME_STORY = ROOT / "book" / "graph" / "mappings" / "runtime_cuts" / "runtime_story.json"
ADV_EXPECTED = ROOT / "book" / "experiments" / "runtime-adversarial" / "out" / "expected_matrix.json"
ADV_RESULTS = ROOT / "book" / "experiments" / "runtime-adversarial" / "out" / "runtime_results.json"
ADV_MISMATCH = ROOT / "book" / "experiments" / "runtime-adversarial" / "out" / "mismatch_summary.json"
IMPACT_MAP = ROOT / "book" / "experiments" / "runtime-adversarial" / "out" / "impact_map.json"
RUNTIME_COVERAGE = ROOT / "book" / "graph" / "mappings" / "runtime" / "runtime_coverage.json"


def run_smoke_validation():
    cmd = [sys.executable, "-m", "book.graph.concepts.validation", "--tag", "smoke"]
    subprocess.check_call(cmd, cwd=ROOT)


def load_status(job_id: str) -> Dict[str, Any]:
    if not STATUS_PATH.exists():
        raise FileNotFoundError(f"missing validation status: {STATUS_PATH}")
    status = json.loads(STATUS_PATH.read_text())
    jobs = {j.get("job_id") or j.get("id"): j for j in status.get("jobs", [])}
    job = jobs.get(job_id)
    if not job:
        raise RuntimeError(f"job {job_id} missing from validation_status.json")
    if not str(job.get("status", "")).startswith("ok"):
        raise RuntimeError(f"job {job_id} not ok: {job.get('status')}")
    return job


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"missing input: {path}")
    return json.loads(path.read_text())


def load_baseline_world() -> str:
    if not BASELINE_PATH.exists():
        raise FileNotFoundError(f"missing baseline: {BASELINE_PATH}")
    data = json.loads(BASELINE_PATH.read_text())
    world_id = data.get("world_id")
    if not world_id:
        raise RuntimeError("world_id missing from baseline")
    return world_id


def hash_expected_matrix(matrix: Dict[str, Any]) -> str:
    payload = json.dumps(matrix or {}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def mismatch_allowed(expectation_id: str, impact_map: Dict[str, Any]) -> bool:
    allowed_tags = set((impact_map.get("metadata") or {}).get("allowed_tags") or [])
    entry = impact_map.get(expectation_id) or {}
    tags = set(entry.get("tags") or [])
    return bool(allowed_tags and tags and tags.issubset(allowed_tags))


def mismatch_tags(expectation_id: str, impact_map: Dict[str, Any]) -> set[str]:
    entry = impact_map.get(expectation_id) or {}
    return set(entry.get("tags") or [])


def build_from_story(
    story_doc: Dict[str, Any], coverage_doc: Dict[str, Any], impact_map: Dict[str, Any]
) -> Tuple[Dict[str, Any], Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]], Dict[str, Any], list]:
    scenarios: Dict[str, Any] = {}
    profiles: Dict[str, Dict[str, Any]] = {}
    expectation_index: Dict[str, Any] = {}
    disallowed: list = []
    coverage_map = coverage_doc.get("coverage") or {}

    for op_entry in (story_doc.get("ops") or {}).values():
        op_name = op_entry.get("op_name")
        op_id = op_entry.get("op_id")
        cov_entry = coverage_map.get(op_name) or {}
        cov_status = cov_entry.get("status") or "partial"

        for scenario in op_entry.get("scenarios") or []:
            scenario_id = scenario.get("scenario_id")
            if not scenario_id:
                continue
            profile_id = scenario.get("profile_id")
            expectations = scenario.get("expectations") or []
            mismatch_by_eid = {
                m.get("expectation_id"): m for m in scenario.get("mismatches") or [] if m.get("expectation_id")
            }
            passed = []
            failed = []
            disallowed_local = []
            expected_rows = []
            for expect in expectations:
                eid = expect.get("expectation_id") or f"{profile_id}:{expect.get('probe_name') or expect.get('operation')}"
                probe_name = expect.get("probe_name")
                mismatch = mismatch_by_eid.get(eid)
                allowed = True
                tags = set()
                if mismatch:
                    tags = mismatch_tags(eid, impact_map)
                    allowed = mismatch_allowed(eid, impact_map)
                    failed.append(
                        {
                            **mismatch,
                            "tags": sorted(tags),
                            "allowed": allowed,
                        }
                    )
                    if not allowed:
                        disallowed_local.append(eid)
                        disallowed.append(
                            {"scenario_id": scenario_id, "expectation_id": eid, "op_name": op_name}
                        )
                    actual = mismatch.get("actual")
                else:
                    actual = expect.get("expected")
                    passed.append(eid)

                if probe_name:
                    profiles.setdefault(profile_id, {})[probe_name] = actual

                expectation_index[eid] = {
                    "scenario_id": scenario_id,
                    "profile_id": profile_id,
                    "op_name": op_name,
                    "op_id": op_id,
                    "mismatch": bool(mismatch),
                    "allowed": allowed,
                    "tags": sorted(tags),
                }
                expected_rows.append(eid)

            scenario_status = "ok" if not disallowed_local else "partial"
            # Do not allow a scenario to look better than its coverage entry.
            if cov_status and cov_status != "ok":
                scenario_status = cov_status

            scenarios[scenario_id] = {
                "scenario_id": scenario_id,
                "op_name": op_name,
                "op_id": op_id,
                "profile_id": profile_id,
                "status": scenario_status,
                "coverage_status": cov_status,
                "results": scenario.get("results") or {},
                "expected_row_ids": expected_rows,
                "runtime_only": not bool(expected_rows),
                "passed_probes": passed,
                "failed_probes": failed,
                "mismatches": sorted(mismatch_by_eid.keys()),
                "disallowed_mismatches": sorted(disallowed_local),
            }

    return scenarios, profiles, expectation_index, disallowed


def classify_expected(
    expected_matrix: Dict[str, Any], expectation_index: Dict[str, Any]
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    profiles_out: Dict[str, Any] = {}
    summary_by_op: Dict[str, Dict[str, Any]] = {}
    buckets = ("covered_ok", "covered_mismatch_allowed", "covered_mismatch_disallowed", "uncovered")

    for profile_id, profile in (expected_matrix.get("profiles") or {}).items():
        probes_out = []
        for probe in profile.get("probes") or []:
            eid = probe.get("expectation_id") or f"{profile_id}:{probe.get('name') or probe.get('operation')}"
            info = expectation_index.get(eid)
            if info:
                if info.get("mismatch"):
                    cls = "covered_mismatch_allowed" if info.get("allowed", False) else "covered_mismatch_disallowed"
                else:
                    cls = "covered_ok"
            else:
                cls = "uncovered"
            probe_out = dict(probe)
            probe_out["expectation_id"] = eid
            probe_out["classification"] = cls
            if info:
                probe_out["scenario_id"] = info.get("scenario_id")
            probes_out.append(probe_out)

            op_name = probe.get("operation")
            if op_name:
                summary = summary_by_op.setdefault(
                    op_name, {bucket: 0 for bucket in buckets}
                )
                summary[cls] += 1

        profiles_out[profile_id] = {**profile, "probes": probes_out}

    classification_summary: Dict[str, Any] = {}
    for op_name, counts in summary_by_op.items():
        total = sum(counts.values())
        covered = counts["covered_ok"] + counts["covered_mismatch_allowed"] + counts["covered_mismatch_disallowed"]
        ratio = float(covered) / float(total) if total else 0.0
        classification_summary[op_name] = {
            **counts,
            "total_expected_rows": total,
            "covered_rows": covered,
            "coverage_ratio": ratio,
        }

    return {"profiles": profiles_out}, classification_summary


def summarize_field2(field2_ir: Dict[str, Any]) -> Dict[str, Any]:
    profiles = field2_ir.get("profiles") or {}
    summary = {}
    for name, entry in profiles.items():
        vals = entry.get("field2") or []
        summary[name] = {
            "field2_entries": len(vals),
            "unknown_named": sum(1 for v in vals if v.get("name") is None),
        }
    unknown_nodes = field2_ir.get("unknown_nodes", {})
    return {"profiles": summary, "unknown_nodes": unknown_nodes}

def extract_runtime_profile_from_command(cmd: Any) -> str | None:
    if not isinstance(cmd, list) or not cmd:
        return None
    argv0 = cmd[0]
    if not isinstance(argv0, str):
        return None

    base = argv0.rsplit("/", 1)[-1]
    if base == "wrapper":
        if len(cmd) >= 3 and cmd[1] in {"--sbpl", "--blob"} and isinstance(cmd[2], str):
            return cmd[2]
        return None

    if base in {"sandbox_runner", "sandbox_reader", "sandbox_writer"}:
        if len(cmd) >= 2 and isinstance(cmd[1], str):
            return cmd[1]
        return None

    if base == "sandbox-exec":
        try:
            idx = cmd.index("-f")
        except ValueError:
            return None
        if idx + 1 < len(cmd) and isinstance(cmd[idx + 1], str):
            return cmd[idx + 1]
        return None

    return None


def main() -> None:
    run_smoke_validation()
    for job_id in EXPECTED_JOBS:
        load_status(job_id)

    runtime_ir = load_json(RUNTIME_IR)
    field2_ir = load_json(FIELD2_IR)
    story_doc = load_json(RUNTIME_STORY)
    coverage_doc = load_json(RUNTIME_COVERAGE)
    impact_map: Dict[str, Any] = load_json(IMPACT_MAP) if IMPACT_MAP.exists() else {}
    world_id = load_baseline_world()

    expected_matrix_doc = runtime_ir.get("expected_matrix") or {}
    events = list(runtime_ir.get("events") or [])

    # Merge in runtime-adversarial expected/results for additional runtime-backed ops (e.g., network-outbound).
    if ADV_EXPECTED.exists():
        adv_expected = load_json(ADV_EXPECTED)
        expected_matrix_doc.setdefault("profiles", {}).update((adv_expected.get("profiles") or {}))
    if ADV_RESULTS.exists():
        adv_obs = (
            runtime_observations.normalize_from_paths(ADV_EXPECTED, ADV_RESULTS, world_id=world_id)
            if ADV_EXPECTED.exists()
            else []
        )
        events.extend([runtime_observations.serialize_observation(o) for o in adv_obs])

    extra_jobs = set()
    if ADV_EXPECTED.exists() or ADV_RESULTS.exists() or ADV_MISMATCH.exists():
        extra_jobs.add("experiment:runtime-adversarial")
    if RUNTIME_COVERAGE.exists():
        extra_jobs.add("experiment:runtime-adversarial")

    scenarios, profiles, expectation_index, disallowed = build_from_story(story_doc, coverage_doc, impact_map)
    # Preserve runtime_profile paths from validation IR, but drive actual results from runtime_story.
    profiles_meta: Dict[str, Dict[str, Any]] = {}
    for ev in events:
        if not isinstance(ev, dict):
            continue
        profile_id = ev.get("profile_id")
        if not profile_id or profile_id in profiles_meta:
            continue
        runtime_profile = extract_runtime_profile_from_command(ev.get("command"))
        if runtime_profile:
            profiles_meta[profile_id] = {"runtime_profile": runtime_profile}

    field2_summary = summarize_field2(field2_ir)

    cov_meta = coverage_doc.get("metadata") or {}
    status = cov_meta.get("status") or "partial"
    notes = "Derived from runtime_story with coverage gating; status cannot exceed runtime_coverage."
    if disallowed:
        status = "partial"
        notes += f" Disallowed mismatches present: {len(disallowed)}."

    inputs = [
        str(RUNTIME_STORY.relative_to(ROOT)),
        str(RUNTIME_COVERAGE.relative_to(ROOT)),
        str(IMPACT_MAP.relative_to(ROOT)),
        str(RUNTIME_IR.relative_to(ROOT)),
        str(FIELD2_IR.relative_to(ROOT)),
        str(ADV_EXPECTED.relative_to(ROOT)),
        str(ADV_RESULTS.relative_to(ROOT)),
    ]

    classified_matrix, classification_summary = classify_expected(expected_matrix_doc, expectation_index)

    mapping = {
        "metadata": {
            "world_id": world_id,
            "inputs": inputs,
            "source_jobs": sorted(EXPECTED_JOBS | extra_jobs),
            "status": status,
            "notes": notes,
            "input_hashes": {
                "expected_matrix": hash_expected_matrix(expected_matrix_doc),
            },
            "provenance": {
                "runtime_story": story_doc.get("meta"),
                "runtime_coverage": cov_meta,
            },
        },
        "signatures": profiles,
        "scenarios": scenarios,
        "expected_matrix": classified_matrix,
        "expected_summary": classification_summary,
        "field2_summary": field2_summary,
        "profiles_metadata": profiles_meta,
        "mismatches": disallowed,
    }
    OUT_PATH.write_text(json.dumps(mapping, indent=2, sort_keys=True))
    print(f"[+] wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
