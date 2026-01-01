"""
Runtime mapping builders and loaders.

These helpers produce the canonical runtime mapping shapes for this world:
- Per-scenario event traces (JSONL) plus an events_index.
- Scenario-level summaries (expectations, results, mismatches, impact).
- Op-level coverage + signature summaries.
- Global manifest + navigation indexes.
- Divergence annotations kept orthogonal to regenerated artifacts.

Event traces are per-scenario JSONL; APIs should stream them via the index
instead of depending on a monolithic events blob.

Runtime mapping builders sit between "raw evidence" and "narrative."
They intentionally keep schema versions explicit so later readers can diff
changes without reverse-engineering formats.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from book.api import path_utils
from book.api import evidence_tiers
from book.api.runtime.contracts import models
from book.api.runtime.contracts import normalize

REPO_ROOT = path_utils.find_repo_root(Path(__file__))
OPS_VOCAB = REPO_ROOT / "book" / "graph" / "mappings" / "vocab" / "ops.json"

# Default schema versions used across runtime mappings.
RUNTIME_LOG_SCHEMA = "runtime_log_schema.v0.1.json"
RUNTIME_MAPPING_SCHEMA = "runtime-mapping.v0.1"


def mapping_metadata(
    world_id: str,
    schema_version: str = RUNTIME_MAPPING_SCHEMA,
    runtime_log_schema: str = RUNTIME_LOG_SCHEMA,
    source_jobs: Optional[List[str]] = None,
    status: str = "partial",
    notes: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Shared metadata envelope for all runtime mappings.
    """

    meta: Dict[str, Any] = {
        "world_id": world_id,
        "schema_version": schema_version,
        "runtime_log_schema": runtime_log_schema,
        "status": status,
        "tier": evidence_tiers.evidence_tier_for_artifact(tier="mapped"),
        "source_jobs": source_jobs or [],
    }
    if notes:
        meta["notes"] = notes
    return meta


def _sanitize_name(name: str) -> str:
    """Make a scenario_id safe for filesystem paths."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    return cleaned.strip("_") or "scenario"


def _load_ops_vocab() -> Dict[str, Any]:
    if not OPS_VOCAB.exists():
        return {}
    with OPS_VOCAB.open("r", encoding="utf-8") as fh:
        return json.load(fh).get("ops", {})


def write_traces(
    observations: Iterable[models.RuntimeObservation],
    traces_root: Path,
    world_id: Optional[str] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Write per-scenario JSONL traces and return (events_index, manifest_entry).

    events_index: scenario_id -> list of trace file repo-relative paths
    manifest_entry: describes the traces_root for the global manifest
    """

    traces_root = path_utils.ensure_absolute(traces_root, REPO_ROOT)
    traces_root.mkdir(parents=True, exist_ok=True)
    index: Dict[str, List[str]] = defaultdict(list)
    resolved_world = world_id
    truncated: set[str] = set()

    for obs in observations:
        resolved_world = resolved_world or obs.world_id
        scenario_id = obs.scenario_id
        safe = _sanitize_name(scenario_id)
        trace_path = traces_root / f"{safe}.jsonl"
        if scenario_id not in truncated and trace_path.exists():
            # Remove stale traces before appending new observations.
            trace_path.unlink()
        truncated.add(scenario_id)
        with trace_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(normalize.observation_to_dict(obs)) + "\n")
        index[scenario_id].append(path_utils.to_repo_relative(trace_path, REPO_ROOT))

    events_index = {
        "meta": mapping_metadata(resolved_world or models.WORLD_ID, status="partial", notes="per-scenario traces"),
        "traces": index,
    }
    manifest_entry = {
        "traces_root": path_utils.to_repo_relative(traces_root, REPO_ROOT),
        "index": path_utils.to_repo_relative(traces_root.parent / "events_index.json", REPO_ROOT),
    }
    return events_index, manifest_entry


def write_events_index(events_index: Mapping[str, Any], out_path: Path) -> Path:
    """Write the per-scenario events index and return its path."""
    out_path = path_utils.ensure_absolute(out_path, REPO_ROOT)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(events_index, indent=2))
    return out_path


def build_scenarios(
    observations: Iterable[models.RuntimeObservation],
    expectations: Mapping[str, Any],
    world_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build scenario-level summaries keyed by scenario_id.
    expectations: parsed expected_matrix.json to populate the expectations block.
    """

    expected_idx: Dict[str, Dict[str, Any]] = {}
    profile_family: Dict[str, str] = {}
    for profile_id, rec in (expectations.get("profiles") or {}).items():
        family = rec.get("family")
        if not family and ":" in profile_id:
            family = profile_id.split(":", 1)[0]
        profile_family[profile_id] = family or "unknown"
        for probe in rec.get("probes") or []:
            eid = probe.get("expectation_id") or normalize.derive_expectation_id(
                profile_id, probe.get("operation"), probe.get("target")
            )
            expected_idx[eid] = {
                "expectation_id": eid,
                "profile_id": profile_id,
                "operation": probe.get("operation"),
                "target": probe.get("target"),
                "expected": probe.get("expected"),
                "probe_name": probe.get("name"),
            }

    scenarios: Dict[str, Dict[str, Any]] = {}
    hist_overall = {
        "total": 0,
        "stages": {"apply": 0, "bootstrap": 0, "preflight": 0, "probe": 0},
        "blocked": {"total": 0, "by_stage": {}, "by_kind": {}},
        "probe": {"total": 0, "allow": 0, "deny": 0, "mismatches": 0, "unobserved": 0},
    }
    hist_by_family: Dict[str, Dict[str, Any]] = {}

    def _hist_for(family: str) -> Dict[str, Any]:
        return hist_by_family.setdefault(
            family,
            {
                "total": 0,
                "stages": {"apply": 0, "bootstrap": 0, "preflight": 0, "probe": 0},
                "blocked": {"total": 0, "by_stage": {}, "by_kind": {}},
                "probe": {"total": 0, "allow": 0, "deny": 0, "mismatches": 0, "unobserved": 0},
            },
        )

    def _bump(d: Dict[str, Any], key: str, amount: int = 1) -> None:
        d[key] = int(d.get(key, 0)) + amount

    for obs in observations:
        resolved_world = world_id or obs.world_id
        family = profile_family.get(obs.profile_id) or ("unknown" if ":" not in obs.profile_id else obs.profile_id.split(":", 1)[0])
        for hist in (hist_overall, _hist_for(family)):
            hist["total"] += 1

            stage = obs.failure_stage or "probe"
            if stage not in {"apply", "bootstrap", "preflight", "probe"}:
                stage = "probe"
            hist["stages"][stage] = int(hist["stages"].get(stage, 0)) + 1

            if stage in {"apply", "bootstrap", "preflight"}:
                blocked = hist["blocked"]
                blocked["total"] += 1
                _bump(blocked["by_stage"], stage)
                if obs.failure_kind:
                    _bump(blocked["by_kind"], obs.failure_kind)
            else:
                probe_hist = hist["probe"]
                if obs.intended_op_witnessed is False:
                    # Do not count non-witnessed probes as coverage; track separately.
                    probe_hist["unobserved"] += 1
                else:
                    probe_hist["total"] += 1
                    if obs.actual == "allow":
                        probe_hist["allow"] += 1
                    elif obs.actual == "deny":
                        probe_hist["deny"] += 1
                    if obs.match is False:
                        probe_hist["mismatches"] += 1

        scenario = scenarios.setdefault(
            obs.scenario_id,
            {
                "world_id": resolved_world,
                "profile_id": obs.profile_id,
                "expectations": [],
                "results": {
                    "total": 0,
                    "matches": 0,
                    "mismatches": 0,
                    "unobserved": 0,
                    "total_including_blocked": 0,
                    "blocked": {"total": 0, "by_stage": {}, "by_kind": {}},
                    "status": "partial",
                },
                "mismatches": [],
                "impact": None,
            },
        )
        scenario["results"]["total_including_blocked"] += 1

        failure_stage = obs.failure_stage or "probe"
        if failure_stage in {"apply", "bootstrap", "preflight"}:
            blocked = scenario["results"]["blocked"]
            blocked["total"] += 1
            by_stage = blocked["by_stage"]
            by_stage[failure_stage] = int(by_stage.get(failure_stage, 0)) + 1
            if obs.failure_kind:
                by_kind = blocked["by_kind"]
                by_kind[obs.failure_kind] = int(by_kind.get(obs.failure_kind, 0)) + 1
        else:
            if obs.intended_op_witnessed is False:
                scenario["results"]["unobserved"] += 1
            else:
                scenario["results"]["total"] += 1
                if obs.match is True:
                    scenario["results"]["matches"] += 1
                elif obs.match is False:
                    scenario["results"]["mismatches"] += 1

        if obs.match is False:
            mismatch_type = "filter_diff"
            if failure_stage == "apply":
                mismatch_type = "apply_gate"
            elif failure_stage == "preflight":
                mismatch_type = "preflight_blocked"
            elif failure_stage == "bootstrap" and obs.failure_kind == "bootstrap_deny_process_exec":
                mismatch_type = "bootstrap_deny_process_exec"
            elif failure_stage == "bootstrap":
                mismatch_type = "bootstrap_failed"
            elif obs.expected == "allow" and obs.actual == "deny":
                mismatch_type = "unexpected_deny"
            elif obs.expected == "deny" and obs.actual == "allow":
                mismatch_type = "unexpected_allow"
            scenario["mismatches"].append(
                {
                    "expectation_id": obs.expectation_id,
                    "expected": obs.expected,
                    "actual": obs.actual,
                    "operation": obs.operation,
                    "target": obs.target,
                    "failure_stage": obs.failure_stage,
                    "failure_kind": obs.failure_kind,
                    "mismatch_type": mismatch_type,
                    "violation_summary": obs.violation_summary,
                    "stderr": obs.stderr,
                }
            )
        eid = obs.expectation_id
        if eid and eid not in [e.get("expectation_id") for e in scenario["expectations"]]:
            scenario["expectations"].append(expected_idx.get(eid, {"expectation_id": eid}))

    for scenario_id, body in scenarios.items():
        matches = body["results"]["matches"]
        total = body["results"]["total"]
        mismatches = body["results"]["mismatches"]
        unobserved = body["results"].get("unobserved", 0)
        blocked_total = (body["results"].get("blocked") or {}).get("total", 0)
        if total == 0 and blocked_total:
            body["results"]["status"] = "blocked"
        elif total == 0 and unobserved:
            body["results"]["status"] = "brittle"
        elif total and mismatches == 0:
            body["results"]["status"] = "ok"
        elif total and matches > 0:
            body["results"]["status"] = "partial"
        else:
            body["results"]["status"] = "brittle"
        body["scenario_id"] = scenario_id

    meta = mapping_metadata(world_id or models.WORLD_ID, status="partial", notes="scenario-level runtime summaries")
    return {
        "meta": meta,
        "phase_histograms": {"overall": hist_overall, "by_family": hist_by_family},
        "scenarios": scenarios,
    }


def write_scenarios(doc: Mapping[str, Any], out_path: Path) -> Path:
    """Write the scenario-level mapping document and return its path."""
    out_path = path_utils.ensure_absolute(out_path, REPO_ROOT)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(doc, indent=2))
    return out_path


def build_ops(
    observations: Iterable[models.RuntimeObservation],
    world_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build op-level coverage + signature summaries keyed by op_id/operation.
    """

    vocab = _load_ops_vocab()
    op_by_name = {entry.get("name"): entry.get("id") for entry in vocab}
    ops: Dict[str, Dict[str, Any]] = {}
    for obs in observations:
        op_name = obs.operation
        entry = ops.setdefault(
            op_name,
            {
                "op_name": op_name,
                "op_id": op_by_name.get(op_name),
                "world_id": world_id or obs.world_id,
                "probes": 0,
                "matches": 0,
                "mismatches": 0,
                "probes_including_blocked": 0,
                "blocked": {"total": 0, "by_stage": {}, "by_kind": {}},
                "unobserved": 0,
                "examples": [],
                "scenarios": set(),
            },
        )
        entry["probes_including_blocked"] += 1
        entry["scenarios"].add(obs.scenario_id)
        if (obs.failure_stage or "probe") in {"apply", "bootstrap", "preflight"}:
            blocked = entry["blocked"]
            blocked["total"] += 1
            stage = obs.failure_stage or "unknown"
            by_stage = blocked["by_stage"]
            by_stage[stage] = int(by_stage.get(stage, 0)) + 1
            if obs.failure_kind:
                by_kind = blocked["by_kind"]
                by_kind[obs.failure_kind] = int(by_kind.get(obs.failure_kind, 0)) + 1
        elif obs.intended_op_witnessed is False:
            entry["unobserved"] += 1
        else:
            entry["probes"] += 1
            if obs.match is True:
                entry["matches"] += 1
            elif obs.match is False:
                entry["mismatches"] += 1
                entry.setdefault("mismatch_details", []).append(
                    {
                        "scenario_id": obs.scenario_id,
                        "expectation_id": obs.expectation_id,
                        "expected": obs.expected,
                        "actual": obs.actual,
                        "target": obs.target,
                    }
                )
            if len(entry["examples"]) < 5:
                entry["examples"].append(
                    {
                        "scenario_id": obs.scenario_id,
                        "expectation_id": obs.expectation_id,
                        "expected": obs.expected,
                        "actual": obs.actual,
                        "match": obs.match,
                    }
                )

    for op_name, entry in ops.items():
        entry["scenarios"] = sorted(entry["scenarios"])
        if entry["probes"] and entry["mismatches"] == 0:
            entry["coverage_status"] = "ok"
        elif entry["probes"]:
            entry["coverage_status"] = "partial"
        else:
            entry["coverage_status"] = "brittle"

    meta = mapping_metadata(world_id or models.WORLD_ID, status="partial", notes="op-level runtime summary")
    return {"meta": meta, "ops": ops}


def write_ops(doc: Mapping[str, Any], out_path: Path) -> Path:
    """Write the op-level mapping document and return its path."""
    out_path = path_utils.ensure_absolute(out_path, REPO_ROOT)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(doc, indent=2))
    return out_path


def build_indexes(
    scenario_summaries: Mapping[str, Any],
    events_index: Mapping[str, Any],
) -> Dict[str, Any]:
    """
    Build navigation indexes: op -> scenarios, scenario -> traces.
    """

    op_to_scenarios: Dict[str, List[str]] = defaultdict(list)
    scenario_to_traces: Dict[str, List[str]] = {}

    for scenario_id, body in (scenario_summaries.get("scenarios") or {}).items():
        op_names = {expect.get("operation") for expect in (body.get("expectations") or []) if expect.get("operation")}
        for op_name in op_names:
            if scenario_id not in op_to_scenarios[op_name]:
                op_to_scenarios[op_name].append(scenario_id)

    for scenario_id, traces in (events_index.get("traces") or {}).items():
        scenario_to_traces[scenario_id] = traces

    meta = scenario_summaries.get("meta") or mapping_metadata(models.WORLD_ID, status="partial")
    return {"meta": meta, "op_to_scenarios": op_to_scenarios, "scenario_to_traces": scenario_to_traces}


def write_indexes(doc: Mapping[str, Any], out_path: Path) -> Path:
    """Write the runtime mapping indexes document and return its path."""
    out_path = path_utils.ensure_absolute(out_path, REPO_ROOT)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(doc, indent=2))
    return out_path


def build_manifest(
    world_id: str,
    traces_index_path: Path,
    scenario_path: Path,
    op_path: Path,
    divergence_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Global jump table for runtime artifacts.
    """

    meta = mapping_metadata(world_id, status="partial", notes="runtime manifest")
    manifest = {
        "meta": meta,
        "events_index": path_utils.to_repo_relative(traces_index_path, REPO_ROOT),
        "scenarios": path_utils.to_repo_relative(scenario_path, REPO_ROOT),
        "ops": path_utils.to_repo_relative(op_path, REPO_ROOT),
    }
    if divergence_path:
        manifest["divergence_annotations"] = path_utils.to_repo_relative(divergence_path, REPO_ROOT)
    return manifest


def write_manifest(doc: Mapping[str, Any], out_path: Path) -> Path:
    """Write the runtime mapping manifest document and return its path."""
    out_path = path_utils.ensure_absolute(out_path, REPO_ROOT)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(doc, indent=2))
    return out_path


def append_divergence(
    annotations_path: Path,
    world_id: str,
    op_id: Optional[int],
    operation: str,
    scenario_id: str,
    note: str,
    tags: Optional[List[str]] = None,
) -> Path:
    """
    Append an annotation about expectation vs reality divergence.
    """

    annotations_path = path_utils.ensure_absolute(annotations_path, REPO_ROOT)
    annotations_path.parent.mkdir(parents=True, exist_ok=True)
    if annotations_path.exists():
        existing = json.loads(annotations_path.read_text())
    else:
        existing = {"meta": mapping_metadata(world_id, status="partial", notes="divergence annotations"), "annotations": []}
    existing["annotations"].append(
        {
            "world_id": world_id,
            "op_id": op_id,
            "operation": operation,
            "scenario_id": scenario_id,
            "note": note,
            "tags": tags or [],
        }
    )
    annotations_path.write_text(json.dumps(existing, indent=2))
    return annotations_path
