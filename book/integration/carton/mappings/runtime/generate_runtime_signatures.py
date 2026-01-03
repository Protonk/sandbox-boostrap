#!/usr/bin/env python3
"""
Generate runtime_signatures.json from promotion packets + field2 IR.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, Any, Tuple

ROOT = Path(__file__).resolve().parents[5]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api import path_utils
from book.api.runtime.contracts import normalize as runtime_normalize
from book.api import evidence_tiers
from book.api import world as world_mod

SCRIPT_ROOT = Path(__file__).resolve().parent
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

import promotion_packets
FIELD2_IR = ROOT / "book/evidence/graph/concepts/validation/out/experiments/field2/field2_ir.json"
STATUS_PATH = ROOT / "book/evidence/graph/concepts/validation/out/validation_status.json"
OUT_PATH = ROOT / "book/integration/carton/bundle/relationships/mappings/runtime/runtime_signatures.json"
EXPECTED_JOBS = {"experiment:field2"}
RUNTIME_STORY = ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "runtime_cuts" / "runtime_story.json"
RUNTIME_COVERAGE = ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "runtime" / "runtime_coverage.json"


def run_field2_validation():
    cmd = [sys.executable, "-m", "book.graph.concepts.validation", "--experiment", "field2"]
    subprocess.check_call(cmd, cwd=ROOT)


def load_status(job_id: str) -> Dict[str, Any]:
    if not STATUS_PATH.exists():
        raise FileNotFoundError(f"missing validation status: {STATUS_PATH}")
    status = json.loads(STATUS_PATH.read_text())
    jobs = {j.get("job_id") or j.get("id"): j for j in status.get("jobs", [])}
    job = jobs.get(job_id)
    if not job:
        raise RuntimeError(f"job {job_id} missing from validation_status.json")
    if job.get("status") != "ok":
        raise RuntimeError(f"job {job_id} not ok: {job.get('status')}")
    return job


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"missing input: {path}")
    return json.loads(path.read_text())


def load_baseline_world() -> str:
    data, resolution = world_mod.load_world(repo_root=ROOT)
    return world_mod.require_world_id(data, world_path=resolution.entry.world_path)


def hash_expected_matrix(matrix: Dict[str, Any]) -> str:
    payload = json.dumps(matrix or {}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


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


def generate(packet_paths: list[Path] | None = None) -> Path:
    run_field2_validation()
    for job_id in EXPECTED_JOBS:
        load_status(job_id)

    field2_ir = load_json(FIELD2_IR)
    story_doc = load_json(RUNTIME_STORY)
    coverage_doc = load_json(RUNTIME_COVERAGE)
    world_id = load_baseline_world()

    packets = promotion_packets.load_packets(
        packet_paths or promotion_packets.DEFAULT_PACKET_PATHS,
        allow_missing=True,
    )
    for packet in packets:
        promotion_packets.require_clean_manifest(packet, str(packet.packet_path))

    expected_matrix_doc, packet_world = promotion_packets.merge_expected_matrices(packets)
    if packet_world and packet_world != world_id:
        raise RuntimeError(f"world_id mismatch between packets ({packet_world}) and baseline ({world_id})")
    world_id = packet_world or world_id

    impact_map_path = promotion_packets.select_impact_map(packets)
    impact_map: Dict[str, Any] = load_json(impact_map_path) if impact_map_path else {}

    events: list[Dict[str, Any]] = []
    for packet in packets:
        observations = promotion_packets.load_observations(packet)
        events.extend([runtime_normalize.observation_to_dict(o) for o in observations])

    scenarios, profiles, expectation_index, disallowed = build_from_story(story_doc, coverage_doc, impact_map)
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
    notes += " Decision-stage inputs require launchd_clean run manifests."
    if disallowed:
        status = "partial"
        notes += f" Disallowed mismatches present: {len(disallowed)}."

    inputs: list[str] = []
    input_hashes: Dict[str, str] = {}
    for path in (RUNTIME_STORY, RUNTIME_COVERAGE, FIELD2_IR):
        rel = path_utils.to_repo_relative(path, ROOT)
        inputs.append(rel)
        input_hashes[rel] = sha256_path(path)
    if impact_map_path:
        rel = path_utils.to_repo_relative(impact_map_path, ROOT)
        inputs.append(rel)
        input_hashes[rel] = sha256_path(impact_map_path)

    run_manifest_inputs = []
    run_ids = []
    repo_root_contexts = []
    source_jobs = set(EXPECTED_JOBS)
    source_jobs.add("promotion_packet")
    for packet in packets:
        rel_packet = path_utils.to_repo_relative(packet.packet_path, ROOT)
        inputs.append(rel_packet)
        input_hashes[rel_packet] = sha256_path(packet.packet_path)
        manifest_path = packet.paths.get("run_manifest")
        if manifest_path:
            rel_manifest = path_utils.to_repo_relative(manifest_path, ROOT)
            run_manifest_inputs.append(rel_manifest)
            input_hashes[rel_manifest] = sha256_path(manifest_path)
        plan_id = packet.run_manifest.get("plan_id")
        if plan_id:
            source_jobs.add(f"plan:{plan_id}")
        if packet.run_manifest.get("run_id"):
            run_ids.append(packet.run_manifest.get("run_id"))
        if packet.run_manifest.get("repo_root_context"):
            repo_root_contexts.append(packet.run_manifest.get("repo_root_context"))

    classified_matrix, classification_summary = classify_expected(expected_matrix_doc, expectation_index)

    input_hashes["expected_matrix"] = hash_expected_matrix(expected_matrix_doc)
    mapping = {
        "metadata": {
            "world_id": world_id,
            "inputs": inputs,
            "source_jobs": sorted(source_jobs),
            "status": status,
            "tier": evidence_tiers.evidence_tier_for_artifact(
                path=OUT_PATH,
                tier="mapped",
            ),
            "notes": notes,
            "input_hashes": input_hashes,
            "provenance": {
                "runtime_story": story_doc.get("meta"),
                "runtime_coverage": cov_meta,
            },
            "run_provenance": {
                "run_ids": run_ids,
                "manifests": run_manifest_inputs,
                "repo_root_contexts": repo_root_contexts,
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
    return OUT_PATH


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate runtime_signatures.json from promotion packets.")
    parser.add_argument("--packets", type=Path, action="append", help="Promotion packet paths")
    args = parser.parse_args()
    generate(packet_paths=args.packets)


if __name__ == "__main__":
    main()
