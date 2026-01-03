#!/usr/bin/env python3
"""
Generate a frontier delta report for runtime-frontiers.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils
from book.graph.mappings.runtime import promotion_packets

REPO_ROOT = path_utils.find_repo_root(Path(__file__))
DEFAULT_PACKET_SET = REPO_ROOT / "book/integration/carton/bundle/relationships/mappings/runtime/packet_set.json"


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def _load_observations(path: Path) -> List[Dict[str, Any]]:
    data = _load_json(path)
    if not isinstance(data, list):
        raise ValueError(f"runtime_events is not a list: {path}")
    return [row for row in data if isinstance(row, dict)]


def _load_launchctl_diagnostics(run_dir: Path) -> tuple[Optional[Path], Optional[Dict[str, Any]]]:
    status_path = run_dir / "run_status.json"
    if not status_path.exists():
        return None, None
    status = _load_json(status_path)
    if not isinstance(status, dict):
        return None, None
    diag_ref = status.get("launchctl_diagnostics")
    if not isinstance(diag_ref, str) or not diag_ref:
        return None, None
    diag_path = path_utils.ensure_absolute(Path(diag_ref), REPO_ROOT)
    if not diag_path.exists():
        return diag_path, None
    diag_doc = _load_json(diag_path)
    if not isinstance(diag_doc, dict):
        return diag_path, None
    return diag_path, diag_doc


def _load_path_pairs(path: Optional[Path]) -> Set[Tuple[str, str]]:
    if not path or not path.exists():
        return set()
    data = _load_json(path)
    records = data.get("records") or []
    pairs: Set[Tuple[str, str]] = set()
    for rec in records:
        if not isinstance(rec, dict):
            continue
        requested = rec.get("requested_path")
        normalized = rec.get("normalized_path") or rec.get("observed_path")
        if requested and normalized:
            pairs.add((requested, normalized))
    return pairs


def _candidate_literals(obs: Dict[str, Any]) -> Set[str]:
    candidates = set()
    for key in ("target", "requested_path", "normalized_path", "observed_path"):
        value = obs.get(key)
        if isinstance(value, str) and value:
            candidates.add(value)
    return candidates


def _expected_filter_type(obs: Dict[str, Any]) -> Optional[str]:
    prepass = obs.get("sandbox_check_prepass") or {}
    primary = prepass.get("primary") or {}
    value = primary.get("filter_type_name")
    return value if isinstance(value, str) else None


def _matching_callouts(obs: Dict[str, Any]) -> List[Dict[str, Any]]:
    op = obs.get("operation")
    if not op:
        return []
    expected_filter = _expected_filter_type(obs)
    literals = _candidate_literals(obs)
    matches: List[Dict[str, Any]] = []
    for callout in obs.get("seatbelt_callouts") or []:
        if callout.get("operation") != op:
            continue
        if expected_filter and callout.get("filter_type_name") != expected_filter:
            continue
        if literals:
            if callout.get("argument") not in literals:
                continue
        matches.append(callout)
    return matches


def _policy_disagreement(obs: Dict[str, Any]) -> bool:
    layers = obs.get("policy_layers") or {}
    platform = (layers.get("platform_policy") or {}).get("decision")
    process = (layers.get("process_policy") or {}).get("decision")
    return bool(platform and process and platform != process)


def _coverage_sets(observations: Iterable[Dict[str, Any]]) -> Tuple[Set[str], Set[str], Set[str]]:
    ops: Set[str] = set()
    filters: Set[str] = set()
    disagreements: Set[str] = set()
    for obs in observations:
        matches = _matching_callouts(obs)
        if matches:
            op = obs.get("operation")
            if isinstance(op, str):
                ops.add(op)
            for callout in matches:
                filt = callout.get("filter_type_name")
                if isinstance(filt, str) and filt:
                    filters.add(filt)
        if _policy_disagreement(obs):
            scenario_id = obs.get("scenario_id") or obs.get("expectation_id") or ""
            if scenario_id:
                disagreements.add(scenario_id)
    return ops, filters, disagreements


def _fidelity_summary(observations: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    total = 0
    intended = 0
    matched = 0
    misses: List[Dict[str, Any]] = []
    for obs in observations:
        total += 1
        if obs.get("intended_op_witnessed"):
            intended += 1
        matches = _matching_callouts(obs)
        if matches:
            matched += 1
            continue
        misses.append(
            {
                "scenario_id": obs.get("scenario_id"),
                "expectation_id": obs.get("expectation_id"),
                "operation": obs.get("operation"),
                "target": obs.get("target") or obs.get("requested_path"),
                "expected_filter_type": _expected_filter_type(obs),
                "intended_op_witnessed": bool(obs.get("intended_op_witnessed")),
            }
        )
    return {
        "total": total,
        "intended_op_witnessed": intended,
        "op_filter_literal_witnessed": matched,
        "missing": misses,
    }


def _render_path_pairs(pairs: Set[Tuple[str, str]]) -> List[str]:
    return [f"{req} -> {norm}" for req, norm in sorted(pairs)]


def generate_report(run_dir: Path, packet_set_path: Path) -> Path:
    run_dir = path_utils.ensure_absolute(run_dir, REPO_ROOT)
    packet_set = promotion_packets.load_packet_set(packet_set_path)
    packets = promotion_packets.load_packets(packet_set.packet_paths, allow_missing=packet_set.allow_missing)

    baseline_obs: List[Dict[str, Any]] = []
    baseline_pairs: Set[Tuple[str, str]] = set()
    baseline_packet_paths = []
    for packet in packets:
        baseline_packet_paths.append(path_utils.to_repo_relative(packet.packet_path, REPO_ROOT))
        baseline_obs.extend(_load_observations(packet.paths["runtime_events"]))
        path_ref = packet.packet.get("path_witnesses")
        if path_ref:
            path_path = path_utils.ensure_absolute(Path(path_ref), REPO_ROOT)
            baseline_pairs |= _load_path_pairs(path_path)

    new_obs = _load_observations(run_dir / "runtime_events.normalized.json")
    new_pairs = _load_path_pairs(run_dir / "path_witnesses.json")

    baseline_ops, baseline_filters, baseline_disagreements = _coverage_sets(baseline_obs)
    new_ops, new_filters, new_disagreements = _coverage_sets(new_obs)

    delta_ops = sorted(new_ops - baseline_ops)
    delta_filters = sorted(new_filters - baseline_filters)
    delta_pairs = sorted(new_pairs - baseline_pairs)
    delta_disagreements = sorted(new_disagreements - baseline_disagreements)

    fidelity = _fidelity_summary(new_obs)
    diag_path, diag_doc = _load_launchctl_diagnostics(run_dir)
    report_lines = [
        "# Frontier Delta Report",
        "",
        f"world_id: {new_obs[0].get('world_id') if new_obs else 'unknown'}",
        f"run_id: {run_dir.name}",
        f"new_run: {path_utils.to_repo_relative(run_dir, REPO_ROOT)}",
        f"baseline_packets: {', '.join(baseline_packet_paths)}",
        f"generated_by: {path_utils.to_repo_relative(Path(__file__), REPO_ROOT)}",
        "",
        "## Probe fidelity",
        "status: host-bound",
        f"evidence: {path_utils.to_repo_relative(run_dir / 'runtime_events.normalized.json', REPO_ROOT)}",
        f"- total_observations: {fidelity['total']}",
        f"- intended_op_witnessed: {fidelity['intended_op_witnessed']}",
        f"- op_filter_literal_witnessed: {fidelity['op_filter_literal_witnessed']}",
        f"- missing_callout: {len(fidelity['missing'])}",
    ]
    if fidelity["missing"]:
        report_lines.append("missing_details:")
        for miss in fidelity["missing"]:
            report_lines.append(
                f"- {miss.get('scenario_id') or miss.get('expectation_id')}: "
                f"{miss.get('operation')} "
                f"target={miss.get('target')} "
                f"filter={miss.get('expected_filter_type')} "
                f"intended_op_witnessed={miss.get('intended_op_witnessed')}"
            )
    if diag_path and diag_doc is not None:
        failure = diag_doc.get("bootstrap_failure") if isinstance(diag_doc, dict) else None
        report_lines += [
            "",
            "## Bootstrap diagnostics",
            "status: host-bound",
            f"evidence: {path_utils.to_repo_relative(diag_path, REPO_ROOT)}",
        ]
        if isinstance(failure, dict):
            classification = failure.get("classification")
            rc = failure.get("rc")
            report_lines.append(f"- bootstrap_failure: {classification} rc={rc}")
        else:
            report_lines.append("- bootstrap_failure: none")
        domain = diag_doc.get("domain")
        if isinstance(domain, str) and domain:
            report_lines.append(f"- domain: {domain}")
        domain_reason = diag_doc.get("domain_reason")
        if isinstance(domain_reason, str) and domain_reason:
            report_lines.append(f"- domain_reason: {domain_reason}")
        session_types = diag_doc.get("session_types")
        if session_types is not None:
            report_lines.append(f"- session_types: {session_types}")
    report_lines += [
        "",
        "## Coverage delta",
        "status: host-bound",
        f"evidence: {path_utils.to_repo_relative(packet_set.packet_set_path, REPO_ROOT)}, "
        f"{path_utils.to_repo_relative(run_dir / 'runtime_events.normalized.json', REPO_ROOT)}, "
        f"{path_utils.to_repo_relative(run_dir / 'path_witnesses.json', REPO_ROOT)}",
        "notes: filter coverage uses seatbelt callout filter_type_name; path pairs are requested_path -> normalized_path.",
        f"- ops: baseline={len(baseline_ops)} new={len(new_ops)} added={len(delta_ops)}",
        f"- filters: baseline={len(baseline_filters)} new={len(new_filters)} added={len(delta_filters)}",
        f"- path_resolution_pairs: baseline={len(baseline_pairs)} new={len(new_pairs)} added={len(delta_pairs)}",
        f"- policy_layers_disagreements: baseline={len(baseline_disagreements)} new={len(new_disagreements)} added={len(delta_disagreements)}",
    ]
    if delta_ops:
        report_lines.append(f"added_ops: {', '.join(delta_ops)}")
    if delta_filters:
        report_lines.append(f"added_filters: {', '.join(delta_filters)}")
    if delta_pairs:
        report_lines.append("added_path_pairs:")
        for pair in _render_path_pairs(delta_pairs):
            report_lines.append(f"- {pair}")
    if delta_disagreements:
        report_lines.append(f"added_policy_disagreements: {', '.join(delta_disagreements)}")

    report_path = run_dir / "frontier_delta.md"
    report_path.write_text("\n".join(report_lines) + "\n")
    return report_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate runtime-frontiers delta report.")
    parser.add_argument("--run-dir", type=Path, required=True, help="Run directory under out/")
    parser.add_argument("--packet-set", type=Path, default=DEFAULT_PACKET_SET, help="Runtime packet_set.json path")
    args = parser.parse_args()
    report_path = generate_report(args.run_dir, args.packet_set)
    print(f"[+] wrote {report_path}")


if __name__ == "__main__":
    main()
