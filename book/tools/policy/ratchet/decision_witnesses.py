#!/usr/bin/env python3
"""
Generate decision witness records for field2 claims from a promotion packet.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve()
for parent in REPO_ROOT.parents:
    if (parent / "book").is_dir():
        REPO_ROOT = parent
        break
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils
from book.api.runtime.analysis import packet_utils

FIELD2_ROOT = REPO_ROOT / "book" / "evidence" / "experiments" / "field2-final-final"
DEFAULT_MILESTONE = FIELD2_ROOT / "active_milestone.json"
DEFAULT_DECISIONS = FIELD2_ROOT / "decisions.jsonl"
DEFAULT_SEEDS = FIELD2_ROOT / "field2-atlas" / "field2_seeds.json"
DEFAULT_OUT = FIELD2_ROOT / "decision_witnesses.jsonl"
RUNTIME_SUITES_ROOT = (
    REPO_ROOT / "book" / "evidence" / "experiments" / "runtime-final-final" / "suites"
)
INSIDE_TOOL = REPO_ROOT / "book" / "tools" / "inside" / "inside.py"


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")


def _load_driver_map(suites_root: Path) -> dict[str, str]:
    driver_map: dict[str, str] = {}
    for probes_path in suites_root.glob("*/registry/probes.json"):
        doc = _load_json(probes_path)
        probes = doc.get("probes") or {}
        if not isinstance(probes, dict):
            continue
        for scenario_id, probe in probes.items():
            if not isinstance(probe, dict):
                continue
            driver = probe.get("driver")
            if scenario_id and driver:
                driver_map[scenario_id] = driver
    return driver_map


def _load_seed_profile_map(seeds_path: Path) -> dict[int, str]:
    doc = _load_json(seeds_path)
    mapping: dict[int, str] = {}
    for seed in doc.get("seeds") or []:
        if not isinstance(seed, dict):
            continue
        fid = seed.get("field2")
        candidate = seed.get("runtime_candidate") or {}
        profile_id = candidate.get("profile_id") if isinstance(candidate, dict) else None
        if isinstance(fid, int) and profile_id:
            mapping[fid] = profile_id
    return mapping


def _collect_runtime_events(path: Path, *, repo_root: Path) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]]]:
    events: list[dict[str, Any]] = []
    by_profile: dict[str, list[dict[str, Any]]] = {}
    by_scenario: dict[str, list[dict[str, Any]]] = {}
    raw = _load_json(path)
    for row in raw or []:
        if not isinstance(row, dict):
            continue
        row = dict(row)
        row_source = row.get("source")
        if not row_source:
            row["source"] = path_utils.to_repo_relative(path, repo_root=repo_root)
        events.append(row)
        profile_id = row.get("profile_id")
        scenario_id = row.get("scenario_id") or row.get("expectation_id")
        if profile_id:
            by_profile.setdefault(profile_id, []).append(row)
        if scenario_id:
            by_scenario.setdefault(scenario_id, []).append(row)
    return events, by_profile, by_scenario


def _relativize_path(value: Optional[str], *, repo_root: Path) -> Optional[str]:
    if not value:
        return value
    path = Path(value)
    if path.is_absolute():
        return str(path_utils.to_repo_relative(path, repo_root=repo_root))
    return value


def _run_inside(*, repo_root: Path, include_apply: bool, with_logs: bool) -> dict[str, Any]:
    cmd = [sys.executable, str(INSIDE_TOOL), "--json"]
    if include_apply:
        cmd.append("--include-apply")
    if with_logs:
        cmd.append("--with-logs")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root)
    proc = subprocess.run(
        cmd,
        cwd=repo_root,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    stdout = proc.stdout.strip()
    if not stdout:
        raise RuntimeError("inside tool returned empty output")
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("inside tool returned non-JSON output") from exc


def _resolve_inside(
    *,
    repo_root: Path,
    bundle_dir: Path,
    inside_path: Optional[Path],
    inside_out: Optional[Path],
    run_inside: bool,
    include_apply: bool,
    with_logs: bool,
) -> tuple[Optional[dict[str, Any]], Optional[str]]:
    if inside_path and run_inside:
        raise ValueError("--inside and --run-inside are mutually exclusive")

    if inside_path:
        inside_path = path_utils.ensure_absolute(inside_path, repo_root=repo_root)
        if inside_path.exists():
            return _load_json(inside_path), str(path_utils.to_repo_relative(inside_path, repo_root=repo_root))
        return None, None

    if run_inside:
        inside_doc = _run_inside(repo_root=repo_root, include_apply=include_apply, with_logs=with_logs)
        target = inside_out
        if target is None:
            target = bundle_dir / "inside.json"
        target = path_utils.ensure_absolute(target, repo_root=repo_root)
        _write_json(target, inside_doc)
        return inside_doc, str(path_utils.to_repo_relative(target, repo_root=repo_root))

    auto_path = bundle_dir / "inside.json"
    if auto_path.exists():
        return _load_json(auto_path), str(path_utils.to_repo_relative(auto_path, repo_root=repo_root))

    return None, None


def _load_claim_field2(milestone_path: Path) -> dict[str, int]:
    milestone = _load_json(milestone_path)
    mapping: dict[str, int] = {}
    for entry in milestone.get("candidates") or []:
        if not isinstance(entry, dict):
            continue
        key = entry.get("claim_key")
        field2 = entry.get("field2")
        if key and isinstance(field2, int):
            mapping[key] = field2
    return mapping


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--milestone", type=Path, default=DEFAULT_MILESTONE)
    parser.add_argument("--decisions", type=Path, default=DEFAULT_DECISIONS)
    parser.add_argument("--seeds", type=Path, default=DEFAULT_SEEDS)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--inside", type=Path)
    parser.add_argument("--inside-out", type=Path)
    parser.add_argument("--run-inside", action="store_true")
    parser.add_argument("--inside-include-apply", action="store_true")
    parser.add_argument("--inside-with-logs", action="store_true")
    parser.add_argument("--allow-missing-decisions", action="store_true")
    args = parser.parse_args()

    repo_root = path_utils.find_repo_root(Path(__file__).resolve())
    packet_path = path_utils.ensure_absolute(args.packet, repo_root=repo_root)
    ctx = packet_utils.resolve_packet_context(packet_path, required_exports=("runtime_events",), repo_root=repo_root)
    runtime_events_path = ctx.export_paths["runtime_events"]

    decisions = _load_jsonl(path_utils.ensure_absolute(args.decisions, repo_root=repo_root))
    decision_map = {rec.get("claim_key"): rec for rec in decisions if rec.get("claim_key")}
    claim_field2 = _load_claim_field2(path_utils.ensure_absolute(args.milestone, repo_root=repo_root))
    if not claim_field2:
        raise ValueError("active milestone contains no claim keys")

    driver_map = _load_driver_map(RUNTIME_SUITES_ROOT)
    seed_profile_map = _load_seed_profile_map(path_utils.ensure_absolute(args.seeds, repo_root=repo_root))

    _events, events_by_profile, events_by_scenario = _collect_runtime_events(runtime_events_path, repo_root=repo_root)

    inside_doc, inside_relpath = _resolve_inside(
        repo_root=repo_root,
        bundle_dir=ctx.bundle_dir,
        inside_path=args.inside,
        inside_out=args.inside_out,
        run_inside=args.run_inside,
        include_apply=args.inside_include_apply,
        with_logs=args.inside_with_logs,
    )
    inside_summary = inside_doc.get("summary") if isinstance(inside_doc, dict) else None

    output_path = path_utils.ensure_absolute(args.out, repo_root=repo_root)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    packet_relpath = path_utils.to_repo_relative(packet_path, repo_root=repo_root)
    runtime_events_relpath = path_utils.to_repo_relative(runtime_events_path, repo_root=repo_root)

    with output_path.open("a", encoding="utf-8") as fh:
        for claim_key, field2 in claim_field2.items():
            decision = decision_map.get(claim_key)
            if not decision:
                if args.allow_missing_decisions:
                    continue
                raise ValueError(f"missing decision for {claim_key}")

            evidence = decision.get("evidence") or {}
            suite_id = evidence.get("suite_id")
            profile_id = seed_profile_map.get(field2)
            scope: dict[str, Any] = {}
            selected_events: list[dict[str, Any]] = []
            if profile_id:
                selected_events = events_by_profile.get(profile_id, [])
                scope = {"profile_id": profile_id, "source": "field2_seeds"}
            elif suite_id:
                selected_events = events_by_scenario.get(suite_id, [])
                scope = {"scenario_id": suite_id, "source": "decision_evidence"}
            elif suite_id is not None:
                scope = {"scenario_id": suite_id, "source": "decision_evidence"}

            witnesses: list[dict[str, Any]] = []
            for event in selected_events:
                scenario_id = event.get("scenario_id") or event.get("expectation_id")
                preflight = event.get("preflight") if isinstance(event.get("preflight"), dict) else {}
                witness = {
                    "scenario_id": scenario_id,
                    "profile_id": event.get("profile_id"),
                    "probe_name": event.get("probe_name"),
                    "driver": driver_map.get(scenario_id),
                    "operation": event.get("operation"),
                    "target": event.get("target"),
                    "runtime_status": event.get("runtime_status"),
                    "failure_stage": event.get("failure_stage"),
                    "failure_kind": event.get("failure_kind"),
                    "match": event.get("match"),
                    "preflight": {
                        "classification": preflight.get("classification"),
                        "input_ref": _relativize_path(preflight.get("input_ref"), repo_root=repo_root),
                        "tool": preflight.get("tool"),
                    },
                }
                witnesses.append(witness)

            record = {
                "schema_version": "field2-decision-witness.v0",
                "world_id": ctx.run_manifest.get("world_id"),
                "claim_key": claim_key,
                "field2": field2,
                "decision": decision.get("decision"),
                "packet_run_id": ctx.run_id,
                "artifact_index_digest": ctx.artifact_index_sha256,
                "packet_relpath": str(packet_relpath),
                "runtime_events_relpath": str(runtime_events_relpath),
                "inside": {
                    "path": inside_relpath,
                    "summary": inside_summary,
                }
                if inside_relpath or inside_summary
                else None,
                "probe_scope": scope,
                "witnesses": witnesses,
                "generated_by": "book/tools/policy/ratchet/decision_witnesses.py",
            }
            fh.write(json.dumps(record, ensure_ascii=True) + "\n")

    out_relpath = path_utils.to_repo_relative(output_path, repo_root=repo_root)
    print(f"[+] wrote {out_relpath}")


if __name__ == "__main__":
    main()
